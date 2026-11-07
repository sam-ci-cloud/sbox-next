#!/usr/bin/env bash
# Server resolver outage test (authorized disposable hosts only).
# usage: dns_outage.sh SSH_CONFIG SERVER SERVER_IP CLIENT OUTDIR [HOLD_SECONDS]
# The client host needs client_bench.py and a sing-box binary; the server needs
# server_endpoints.py and the bench target binary. Phases:
#   warm      REALITY/Hysteria2 requests to an IP literal and a hostname
#   outage    server udp/tcp 53 and tcp 853 dropped, systemd-resolved cache flushed;
#             tested at once and again after HOLD_SECONDS (> typical TTL), with an
#             uncached random name as the negative control; a rate-limited download
#             started before the outage must complete
#   recover   rules removed; everything must work again
# A safety timer removes the drop table after 15 minutes even if this script dies.
set -Eeuo pipefail
cfg="$1" server="$2" sip="$3" client="$4" out="$5" hold="${6:-330}"
S=(ssh -F "$cfg"); mkdir -p "$out"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${S[@]}" "$server" "systemctl stop sbox-bench-target 2>/dev/null; systemd-run --quiet --unit sbox-bench-target /root/sbox-bench-target -http $sip:18080 -udp $sip:18081; python3 /root/server_endpoints.py" | "${S[@]}" "$client" 'umask 077; cat > /root/ep-dns.json'
scp -q -F "$cfg" "$here/client_bench.py" "$client:/root/"
probe() {
  "${S[@]}" "$client" "cd /root && python3 - '$1' '$sip' <<'PY'
import json,sys,uuid,client_bench as cb
phase,sip=sys.argv[1],sys.argv[2]
ep=json.load(open('/root/ep-dns.json'))
import glob,os
binary=next(p for p in ('/usr/local/lib/sbox-manager/sing-box',) if os.path.exists(p))
c=cb.Client(binary,cb.client_config(ep,['reality','hy2'],27100),'/root','dns-'+phase);c.start([27100,27101])
for port,name in ((27100,'reality'),(27101,'hy2')):
    for label,url in (('ip-literal','http://%s:18080/204'%sip),('cached-name','http://www.gstatic.com/generate_204'),('uncached-name','http://sbox-%s.example.org/'%uuid.uuid4().hex[:10])):
        r,e=cb.curl(port,url,timeout=15)
        print(json.dumps({'phase':phase,'protocol':name,'target':label,'code':r['code'] if r else None,'ttfb_ms':round(r['ttfb_ms'],1) if r else None,'error':None if r else e[:80]}))
c.stop()
PY"
}
{
  echo "# dns outage test $(date -u +%FT%TZ) server=$server hold=${hold}s"
  "${S[@]}" "$server" "jq -c '{dns:.dns,resolver:.route.default_domain_resolver}' /etc/sbox-manager/config.json"
  probe warm
  # The long download must overlap the outage: detach it from this SSH session.
  "${S[@]}" "$client" "cat > /root/dns-long.py <<'PY'
import json,client_bench as cb
ep=json.load(open('/root/ep-dns.json'))
c=cb.Client('/usr/local/lib/sbox-manager/sing-box',cb.client_config(ep,['reality'],27200),'/root','dns-long');c.start([27200])
r,e=cb.curl(27200,'http://$sip:18080/bytes?n=$((96<<20))&seed=1',out='/root/dns-long.bin',timeout=1200,extra=('--limit-rate','160k'))
open('/root/dns-long.result','w').write(json.dumps({'bytes':r['bytes'] if r else None,'error':e}))
c.stop()
PY
systemctl stop sbox-dns-long 2>/dev/null; systemd-run --quiet --unit sbox-dns-long --working-directory=/root /usr/bin/python3 /root/dns-long.py; echo started-long-download"
  sleep 3
  "${S[@]}" "$server" 'nft add table inet sbox_dns_outage; nft add chain inet sbox_dns_outage o "{ type filter hook output priority -20; }"; nft add rule inet sbox_dns_outage o udp dport 53 counter drop; nft add rule inet sbox_dns_outage o tcp dport 53 counter drop; nft add rule inet sbox_dns_outage o tcp dport 853 counter drop; systemd-run --quiet --on-active=15min nft delete table inet sbox_dns_outage; resolvectl flush-caches; echo outage-start $(date -u +%T)'
  probe outage-immediate
  sleep "$hold"
  probe outage-after-ttl
  "${S[@]}" "$server" 'nft list table inet sbox_dns_outage | grep -o "packets [0-9]*" | tr "\n" " "; nft delete table inet sbox_dns_outage; resolvectl flush-caches; echo outage-end $(date -u +%T)'
  probe recovered
  for _ in $(seq 1 240); do "${S[@]}" "$client" 'test -s /root/dns-long.result' && break; sleep 5; done
  "${S[@]}" "$client" 'echo "long download across outage: $(cat /root/dns-long.result 2>/dev/null)"; rm -f /root/dns-long.bin /root/dns-long.result /root/dns-long.py /root/ep-dns.json /root/dns-*.json'
} | tee "$out/dns-outage-$server-$(date -u +%Y%m%dT%H%M%SZ).log"
