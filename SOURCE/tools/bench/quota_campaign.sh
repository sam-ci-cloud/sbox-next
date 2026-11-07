#!/usr/bin/env bash
# Five-protocol quota enforcement campaign (authorized disposable hosts only).
# usage: quota_campaign.sh SSH_CONFIG SERVER SERVER_IP CLIENT OUTDIR [QUOTA_MIB] [TRANSFER_MIB]
# Creates a temporary managed user through the same controller as the WebUI,
# then per protocol: quota reset + QUOTA_MIB limit, one large download, read the
# authenticated usage (overshoot = used - quota), verify a reconnect is refused;
# the same for a large upload; finally reset + raise and verify traffic resumes.
# The user is revoked at the end. Prints one JSON line per measurement.
set -Eeuo pipefail
cfg="$1" server="$2" sip="$3" client="$4" out="$5" qmib="${6:-20}" tmib="${7:-512}"
S=(ssh -F "$cfg"); mkdir -p "$out"; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log="$out/quota-campaign-$server-$(date -u +%Y%m%dT%H%M%SZ).log"
scp -q -F "$cfg" "$here/client_bench.py" "$client:/root/"
scp -q -F "$cfg" "$here/server_endpoints.py" "$server:/root/"
name="quota-bench-$(date +%s)"
id="$("${S[@]}" "$server" "printf '%s' '{\"kind\":\"user-create\",\"data\":{\"name\":\"$name\"}}' | sbox _webui-control prepare 2>/dev/null | jq -r .token | xargs -I{} sh -c 'printf \"{\\\"token\\\":\\\"%s\\\"}\" {} | sbox _webui-control commit >/dev/null 2>&1'; jq -r --arg n '$name' '.managed_users[]|select(.name==\$n)|.id' /etc/sbox-manager/state.json")"
[ -n "$id" ] || { echo "user creation failed" >&2; exit 1; }
"${S[@]}" "$server" "systemctl stop sbox-bench-target 2>/dev/null; systemd-run --quiet --unit sbox-bench-target /root/sbox-bench-target -http $sip:18080 -udp $sip:18081; sleep 4; python3 /root/server_endpoints.py --user user-$id" | "${S[@]}" "$client" 'umask 077; cat > /root/ep-quota.json'
usage() { "${S[@]}" "$server" "sbox quota show $id | jq -c '.users[0].usage|{used:.used_bytes,up:.upload_bytes,down:.download_bytes,quota:.quota_bytes,status:.status}'"; }
setq() { "${S[@]}" "$server" "sbox quota reset $id >/dev/null 2>&1; sbox quota set $id --bytes '$1' --period monthly --timezone UTC --reset-day 1 >/dev/null 2>&1; sleep 3"; }
xfer() { # proto direction
  "${S[@]}" "$client" "cd /root && python3 - '$1' '$2' '$sip' '$tmib' <<'PY'
import json,os,sys,time,client_bench as cb
proto,direction,sip,mib=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4])
ep=json.load(open('/root/ep-quota.json'))
c=cb.Client('/usr/local/lib/sbox-manager/sing-box',cb.client_config(ep,[proto],28100),'/root','quota-'+proto);c.start([28100])
t=time.time()
if direction=='down':
    r,e=cb.curl(28100,'http://%s:18080/bytes?n=%d&seed=1'%(sip,mib<<20),timeout=240)
else:
    path='/root/quota-up.bin'
    if not os.path.exists(path) or os.path.getsize(path)!=mib<<20:
        with open(path,'wb') as f:f.write(os.urandom(1<<20)*mib)
    r,e=cb.curl(28100,'http://%s:18080/upload'%sip,data=path,timeout=240)
el=time.time()-t
f,e2=cb.curl(28100,'http://%s:18080/204'%sip,timeout=10)
c.stop()
print(json.dumps({'protocol':proto,'direction':direction,'completed':bool(r and r['code']==200),'error':(e or '')[:70],'seconds':round(el,2),'reconnect_code':f['code'] if f else None}))
PY"
}
{
  echo "# quota campaign $(date -u +%FT%TZ) server=$server user=$id quota=${qmib}MiB transfer=${tmib}MiB"
  "${S[@]}" "$server" "sbox version; sha256sum /usr/local/lib/sbox-manager/sing-box | cut -c1-16"
  for p in reality vmess hy2 tuic anytls; do
    for d in down up; do
      setq "$qmib MiB"
      r="$(xfer "$p" "$d")"; sleep 4; u="$(usage)"
      python3 -c "import json,sys;r=json.loads(sys.argv[1]);u=json.loads(sys.argv[2]);r.update(used=u['used'],quota=u['quota'],status=u['status'],overshoot_mib=round((u['used']-u['quota'])/2**20,2));print(json.dumps(r))" "$r" "$u"
    done
  done
  setq "10 GiB"
  for p in reality vmess hy2 tuic anytls; do "${S[@]}" "$client" "cd /root && python3 -c \"
import json,client_bench as cb
ep=json.load(open('/root/ep-quota.json'));c=cb.Client('/usr/local/lib/sbox-manager/sing-box',cb.client_config(ep,['$p'],28200),'/root','quota-after');c.start([28200])
r,e=cb.curl(28200,'http://$sip:18080/204',timeout=15);c.stop();print(json.dumps({'protocol':'$p','after_reset_code':r['code'] if r else None}))\""; done
  "${S[@]}" "$server" "printf '%s' '{\"kind\":\"user-revoke\",\"id\":\"$id\",\"data\":{}}' | sbox _webui-control prepare 2>/dev/null | jq -r .token | xargs -I{} sh -c 'printf \"{\\\"token\\\":\\\"%s\\\"}\" {} | sbox _webui-control commit >/dev/null 2>&1'; echo revoked=\$(jq --arg i $id '[.managed_users[]|select(.id==\$i)]|length==0' /etc/sbox-manager/state.json)"
  "${S[@]}" "$client" 'rm -f /root/ep-quota.json /root/quota-up.bin /root/quota-*.json'
} | tee "$log"
