#!/bin/bash
# Real VPN traffic, per-user accounting and quota enforcement in the lab VM.
# Client: the installed sing-box binary in the separate peer namespace, VLESS
# REALITY with a panel-created user's credentials. Target: HTTP server in the
# peer namespace on 192.0.2.10 (routed back through the VM). LAB ONLY.
VM=$1; PEER=$VM-peer; PY=python3; LAB=${SBOX_LAB_ROOT:-/var/tmp/sbox-lab}; R=$LAB/vms/$VM/root; W=$LAB/work/traffic-$VM; mkdir -p $W
V() { $PY $(dirname "$0")/vm.py exec $VM -- "$@"; }; P() { ip netns exec $PEER "$@"; }
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; bad(){ echo "FAIL $*"; fail=$((fail+1)); }
NAME=${2:-lab-acct-$RANDOM}
P ip addr add 192.0.2.10/32 dev lo 2>/dev/null
V ip route replace 192.0.2.10/32 via 10.77.0.1 >/dev/null 2>&1
head -c 31457280 /dev/urandom > $W/payload.bin
P bash -c "cd $W && exec python3 -m http.server 8080 --bind 192.0.2.10" > $W/http.log 2>&1 & HTTPPID=$!
echo "{\"kind\":\"user-create\",\"data\":{\"name\":\"$NAME\",\"protocols\":[\"reality\"]}}" > $R/root/req.json
TOKEN=$(V bash -c 'sbox _webui-control prepare < /root/req.json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "{\"token\":\"$TOKEN\"}" > $R/root/commit.json
V bash -c 'sbox _webui-control commit < /root/commit.json' > $W/commit.json 2>&1 && ok "user-create committed through the journalled manager transaction" || { bad "user-create"; cat $W/commit.json; }
UID_=$(python3 -c "import json;s=json.load(open('$R/etc/sbox-manager/state.json'));print([x['id'] for x in s['managed_users'] if x['name']=='$NAME'][0])")
python3 - "$R/etc/sbox-manager/state.json" "$R/etc/sbox-manager/config.json" "$UID_" > $W/client.json <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));c=json.load(open(sys.argv[2]));r=s['protocols']['reality']
inb=[i for i in c['inbounds'] if i['type']=='vless'][0];u=[x for x in inb['users'] if x['name']=='user-%s@reality'%sys.argv[3]][0]
print(json.dumps({'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':1080}],
 'outbounds':[{'type':'vless','server':'10.77.0.2','server_port':r['port'],'uuid':u['uuid'],'flow':'xtls-rprx-vision',
 'tls':{'enabled':True,'server_name':r['sni'],'utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':r['public_key'],'short_id':r['short_id'] if isinstance(r['short_id'],str) else r['short_id'][0]}}}]}))
PY
P $R/usr/local/lib/sbox-manager/sing-box run -c $W/client.json > $W/client.log 2>&1 & CPID=$!; sleep 2
used() { V sbox quota show $UID_ 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);u=d["users"][0]["usage"];print(u.get("used_bytes") or 0)'; }
B0=$(used); echo "before: $B0 bytes"
others() { V sbox quota show 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print(sum((u['usage'].get('used_bytes') or 0) for u in d['users'] if u['id']!='$UID_'))"; }
O0=$(others)
P curl -s --max-time 60 -x socks5h://127.0.0.1:1080 -o $W/dl1.bin -w '%{http_code} %{size_download}\n' http://192.0.2.10:8080/payload.bin > $W/curl1.txt
cmp -s $W/dl1.bin $W/payload.bin && ok "30 MiB download through VLESS REALITY tunnel is byte-identical ($(cat $W/curl1.txt))" || bad "tunnel download failed: $(cat $W/curl1.txt); $(tail -3 $W/client.log)"
sleep 8; B1=$(used); D=$((B1-B0)); echo "after: $B1 bytes (delta $D)"
[ "$D" -ge 31457280 ] && [ "$D" -le 33554432 ] && ok "per-user accounting counted $D bytes for a 31457280-byte payload (+<7% protocol overhead)" || bad "accounting delta $D not within [31457280, 33554432]"
OTHER=$(( $(others) - O0 ))
[ "$OTHER" -lt 1048576 ] && ok "no traffic attributed to other users during the transfer ($OTHER bytes)" || bad "other users got $OTHER bytes"
echo "-- quota enforcement: 40 MB limit, already ~31 MB used"
V sbox quota set $UID_ --bytes "40 MB" --period monthly --timezone Asia/Hong_Kong --reset-day 1 > $W/quota-set.txt 2>&1 && ok "quota set to 40 MB (monthly, Asia/Hong_Kong)" || { bad "quota set"; tail -3 $W/quota-set.txt; }
P curl -s --max-time 60 -x socks5h://127.0.0.1:1080 -o $W/dl2.bin -w '%{http_code} %{size_download}\n' http://192.0.2.10:8080/payload.bin > $W/curl2.txt; echo "second transfer: $(cat $W/curl2.txt)"
sleep 8
STATUS=$(V sbox quota show $UID_ | python3 -c 'import sys,json;u=json.load(sys.stdin)["users"][0]["usage"];print(u.get("status"),u.get("used_bytes"),u.get("remaining_bytes"))'); echo "status: $STATUS"
P curl -s --max-time 15 -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code} %{size_download}\n' http://192.0.2.10:8080/payload.bin > $W/curl3.txt 2>&1
SZ=$(awk '{print $2}' $W/curl3.txt); [ "${SZ:-0}" -lt 1000000 ] && ok "after the quota is used up, a new transfer is refused (got ${SZ:-0} bytes)" || bad "transfer still allowed after quota exhausted: $(cat $W/curl3.txt)"
echo "$STATUS" | grep -qi 'exhaust\|exceed\|used\|limit\|blocked' && ok "status reports the quota is used up ($STATUS)" || echo "INFO status text: $STATUS"
V sbox quota reset $UID_ > $W/reset.txt 2>&1 && ok "quota reset command succeeded" || { bad "quota reset"; tail -3 $W/reset.txt; }
sleep 6
P curl -s --max-time 60 -x socks5h://127.0.0.1:1080 -o $W/dl4.bin -w '%{http_code} %{size_download}\n' http://192.0.2.10:8080/payload.bin > $W/curl4.txt
cmp -s $W/dl4.bin $W/payload.bin && ok "after reset the user can transfer again" || bad "after reset still blocked: $(cat $W/curl4.txt)"
echo "-- wrong REALITY key is refused (no tunnel)"
sed -E 's/"public_key": ?"[^"]*"/"public_key": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHdyb25nIGtleSE"/' $W/client.json > $W/bad.json
pkill -f "$W/client.json"; for i in $(seq 1 20); do pgrep -f "$W/client.json" >/dev/null || break; sleep 0.5; done; sleep 1; P $R/usr/local/lib/sbox-manager/sing-box run -c $W/bad.json > $W/bad.log 2>&1 & BPID=$!; sleep 2
P curl -s --max-time 10 -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{size_download}' http://192.0.2.10:8080/payload.bin > $W/curl5.txt 2>&1
[ "$(cat $W/curl5.txt)" = 0 ] || [ -z "$(cat $W/curl5.txt)" ] && ok "client with wrong REALITY key gets no tunnel" || bad "wrong key tunnelled $(cat $W/curl5.txt)"
pkill -f "$W/bad.json"; pkill -f "http.server 8080 --bind 192.0.2.10"; echo "USER_ID=$UID_"; echo "RESULT pass=$pass fail=$fail"
