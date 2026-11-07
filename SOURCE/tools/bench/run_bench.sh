#!/usr/bin/env bash
# Orchestrate one paired benchmark run from an operator workstation.
# usage: run_bench.sh SSH_CONFIG SERVER_ALIAS SERVER_IP CLIENT_ALIAS VARIANT OUTDIR [client_bench args...]
# Starts the bench target and resource sampler on the server (transient systemd
# units), exports endpoints, runs client_bench.py on the client and fetches results.
set -Eeuo pipefail
cfg="$1" server="$2" server_ip="$3" client="$4" variant="$5" out="$6"; shift 6
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_bin="${SBOX_BENCH_TARGET_BIN:?set SBOX_BENCH_TARGET_BIN to the built target binary}"
S=(ssh -F "$cfg"); C=(scp -q -F "$cfg")
mkdir -p "$out"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
# Upload under a temporary name and rename: a running copy (e.g. the IPv6 lab) keeps the old inode.
"${C[@]}" "$target_bin" "$server:/root/sbox-bench-target.new"
"${C[@]}" "$here/server_sampler.py" "$here/server_endpoints.py" "$server:/root/"
"${C[@]}" "$here/client_bench.py" "$client:/root/"
"${S[@]}" "$server" "set -e; chmod 0755 /root/sbox-bench-target.new; mv -f /root/sbox-bench-target.new /root/sbox-bench-target
  systemctl stop sbox-bench-target sbox-bench-sampler 2>/dev/null || true
  systemd-run --quiet --unit sbox-bench-target -p MemoryMax=200M /root/sbox-bench-target -http $server_ip:18080 -udp $server_ip:18081
  systemd-run --quiet --unit sbox-bench-sampler /usr/bin/python3 /root/server_sampler.py /root/sampler-$variant-$stamp.csv
  python3 /root/server_endpoints.py ${SBOX_BENCH_USER:+--user $SBOX_BENCH_USER} > /root/endpoints.json
  sha256sum /usr/local/lib/sbox-manager/sing-box /etc/sbox-manager/config.json; cat /etc/sbox-manager/state.json | python3 -c 'import json,sys;print(json.load(sys.stdin).get(\"manager_version\"))'" > "$out/server-ident-$variant-$stamp.txt"
"${S[@]}" "$server" cat /root/endpoints.json | "${S[@]}" "$client" 'umask 077; cat > /root/endpoints.json'
set +e
"${S[@]}" "$client" "python3 /root/client_bench.py /root/endpoints.json --target $server_ip --variant $variant --out /root/bench-$variant-$stamp $*" > "$out/client-stdout-$variant-$stamp.json" 2> "$out/client-stderr-$variant-$stamp.log"
rc=$?
set -e
"${S[@]}" "$server" "systemctl stop sbox-bench-sampler sbox-bench-target 2>/dev/null || true"
"${C[@]}" "$server:/root/sampler-$variant-$stamp.csv" "$out/"
"${S[@]}" "$client" "cd /root/bench-$variant-$stamp && tar -czf - --exclude='*.bin' ." > "$out/client-$variant-$stamp.tgz"
"${S[@]}" "$client" "rm -f /root/endpoints.json"
echo "$out stamp=$stamp rc=$rc"
exit $rc
