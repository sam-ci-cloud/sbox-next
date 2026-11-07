#!/usr/bin/env bash
# SBOX live acceptance on a DISPOSABLE server you own. Run as root on the VPS
# after installing SBOX. It changes nothing except, with --fail2ban-from, a
# short-lived ban of your own second test host, which it removes again.
#
#   bash tools/vps_acceptance.sh [--fail2ban-from USER@SECOND_TEST_HOST] [--out DIR]
#
# --fail2ban-from uses YOUR existing SSH access (agent/key) to the second test
# host to make 8 failed SSH logins with a non-existent user back to this server,
# then checks the ban from both sides and unbans. Its source IPv4 is derived
# from the second host's route to this server; no third-party IP service is used.
#
# Output: DIR/summary.txt (PASS/FAIL/NOT RUN lines) and DIR/evidence/*. No state
# file, key, password, subscription URL or certificate private key is copied.
set -uo pipefail
umask 077
OUT="/root/sbox-acceptance-$(date -u +%Y%m%dT%H%M%SZ)"; ATTACKER=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fail2ban-from) ATTACKER="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    -h|--help) sed -n 2,14p "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
command -v sbox >/dev/null || { echo "sbox is not installed" >&2; exit 2; }
mkdir -p "$OUT/evidence"; E="$OUT/evidence"; S="$OUT/summary.txt"; : > "$S"
pass=0; fail=0; notrun=0
ok()  { echo "PASS    $*" | tee -a "$S"; pass=$((pass+1)); }
bad() { echo "FAIL    $*" | tee -a "$S"; fail=$((fail+1)); }
nr()  { echo "NOT RUN $*" | tee -a "$S"; notrun=$((notrun+1)); }
redact() { sed -E 's#(vless|vmess|hysteria2|hy2|tuic|anytls)://[^ "]+#\1://<redacted>#g; s#("?(password|uuid|private_key|short_id|token|secret)"?[:=] *"?)[^", ]+#\1<redacted>#Ig'; }

STATE=/etc/sbox-manager/state.json
DOMAIN="$(jq -r '.domain // empty' "$STATE")"
SH="$(jq -r 'if (.protocols.reality.enabled and ((.protocols.reality.fallback.mode // "remote")=="self_hosted")) then "yes" else "no" end' "$STATE")"
RPORT="$(jq -r '.protocols.reality.port // empty' "$STATE")"
PUB4="$(jq -r '.server.ipv4 // empty' "$STATE")"

echo "== environment" | tee -a "$S"
{ uname -a; cat /etc/os-release; systemctl --version | head -1; python3 --version; mv --version | head -1; sbox version; sbox _build-id 2>/dev/null; date -u; } > "$E/environment.txt" 2>&1
head -1 "$E/environment.txt" | tee -a "$S"; grep -E '^PRETTY_NAME|^mv' "$E/environment.txt" | tee -a "$S"
echo "domain=$DOMAIN self_hosted=$SH reality_port=$RPORT ipv4=$PUB4" | tee -a "$S"

echo "== health" | tee -a "$S"
sbox doctor > "$E/doctor.txt" 2>&1; redact < "$E/doctor.txt" > "$E/doctor.redacted.txt"; rm -f "$E/doctor.txt"
grep -q 'Result: 0 failure(s)' "$E/doctor.redacted.txt" && ok "sbox doctor: 0 failures" || bad "sbox doctor: $(grep Result "$E/doctor.redacted.txt")"
for u in sing-box sbox-manager-firewall fail2ban sbox-webui sbox-accounting; do
  systemctl is-active --quiet "$u" && ok "$u active" || bad "$u not active"
done
ss -H -lntup > "$E/listeners.txt" 2>&1

echo "== Personal Cloud (self-hosted REALITY target)" | tee -a "$S"
if [ "$SH" = yes ]; then
  W=/usr/local/lib/sbox-manager/fallback-web
  find "$W" -printf '%m %u:%g %y %P\n' | sort > "$E/website-tree.txt"
  awk '($3=="d" && $1!="755") || ($3=="f" && $1!="644") || $2!="root:root" || $3=="l"' "$E/website-tree.txt" | grep -q . && bad "website tree modes/owners (see website-tree.txt)" || ok "website tree: dirs 0755, files 0644, root-owned, no symlinks"
  systemctl show sbox-fallback-web -p User -p DynamicUser -p BindReadOnlyPaths -p TemporaryFileSystem -p InaccessiblePaths -p ExecStartPre > "$E/website-unit.txt"
  systemctl cat sbox-fallback-web > "$E/website-unit-file.txt" 2>&1
  grep -q 'DynamicUser=yes' "$E/website-unit.txt" && ok "website runs as a dynamic unprivileged user" || bad "DynamicUser not set"
  [ "$(grep -c '^BindReadOnlyPaths=' "$E/website-unit-file.txt")" = 1 ] && ok "one read-only bind of the complete website tree" || bad "unexpected bind layout"
  ss -H -lntp | awk '{print $4}' | grep -E ':8443$|:'"$(jq -r .protocols.reality.fallback.port "$STATE")"'$' > "$E/website-listener.txt"
  grep -Evq '^(127\.0\.0\.1|\[::1\]):' "$E/website-listener.txt" && bad "website listens beyond loopback" || ok "website listener is loopback only ($(paste -sd' ' "$E/website-listener.txt"))"
  sbox reality-fallback check > "$E/reality-fallback-check.json" 2>&1 && ok "loopback HTTPS + REALITY relay check (sbox reality-fallback check)" || bad "sbox reality-fallback check"
  PID="$(systemctl show -p MainPID --value sbox-fallback-web)"
  if [ "${PID:-0}" -gt 0 ]; then
    U="$(stat -c %u /proc/$PID)"; G="$(stat -c %g /proc/$PID)"; leaked=''
    for p in /etc/sbox-manager /var/lib/sbox-manager /etc/letsencrypt /var/lib/sbox-accounting /etc/sbox-webui /var/lib/sbox-webui /var/backups/sbox-manager /root /etc/shadow; do
      nsenter -t "$PID" -m -r -w -S "$U" -G "$G" -- /usr/bin/test -r "$p" 2>/dev/null && leaked="$leaked $p"
    done
    [ -z "$leaked" ] && ok "sandbox cannot read SBOX state, keys, panel/accounting data, backups or /root" || bad "sandbox can read:$leaked"
  else bad "website service has no main PID"; fi
  if [ -n "$PUB4" ] && [ -n "$DOMAIN" ]; then
    curl -s --max-time 15 --resolve "$DOMAIN:$RPORT:$PUB4" "https://$DOMAIN:$RPORT/about/" -o "$E/public-about.html" -w '%{http_code} verify=%{ssl_verify_result}\n' > "$E/public-https.txt" 2>&1
    grep -q '^200 verify=0' "$E/public-https.txt" && grep -q sbox-personal-cloud "$E/public-about.html" && ok "public IPv4 $PUB4:$RPORT serves the Personal Cloud with a publicly trusted certificate (hairpin from this host)" || bad "public HTTPS via REALITY port: $(cat "$E/public-https.txt")"
    curl -s --max-time 8 -k "https://$PUB4:$(jq -r .protocols.reality.fallback.port "$STATE")/" -o /dev/null -w '%{http_code}' > "$E/public-website-port.txt" 2>&1
    [ "$(cat "$E/public-website-port.txt")" = 000 ] && ok "website port is not reachable on the public address" || bad "website port answered publicly"
  fi
else
  nr "Personal Cloud checks (REALITY target is remote)"
fi

echo "== Fail2Ban SSH protection" | tee -a "$S"
fail2ban-client status > "$E/fail2ban-status.txt" 2>&1; fail2ban-client status sbox-sshd >> "$E/fail2ban-status.txt" 2>&1
fail2ban-client status sbox-sshd >/dev/null 2>&1 && ok "sbox-sshd jail running" || bad "sbox-sshd jail missing"
nft list table inet sbox_guard > "$E/nft-guard.txt" 2>&1 && ok "early all-port nftables guard table present" || bad "guard table missing"
if [ -n "$ATTACKER" ]; then
    AIP="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$ATTACKER" "ip -4 route get '$PUB4' | awk '{for (i=1; i<=NF; i++) if (\$i==\"src\") print \$(i+1)}'" 2>/dev/null)"
  if [ -z "$AIP" ]; then bad "cannot reach $ATTACKER over SSH"; else
    echo "attacker public IPv4: $AIP" | tee -a "$S"
    sbox security unban "$AIP" >/dev/null 2>&1
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$ATTACKER" "for i in 1 2 3 4 5 6 7 8; do timeout 8 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 sbox-acceptance-nouser@$PUB4 true </dev/null >/dev/null 2>&1; done" >/dev/null 2>&1
    for i in $(seq 1 30); do fail2ban-client get sbox-sshd banip 2>/dev/null | tr ' ,' '\n\n' | grep -Fxq "$AIP" && break; sleep 1; done
    fail2ban-client get sbox-sshd banip | tr ' ,' '\n\n' | grep -Fxq "$AIP" && ok "real failed logins from $AIP produced a ban" || bad "no ban for $AIP (sshd may only allow publickey: then failures are 'Connection closed [preauth]' and need a password-capable sshd)"
    ssh -o BatchMode=yes "$ATTACKER" "timeout 5 bash -c 'exec 3<>/dev/tcp/$PUB4/22' && echo open || echo blocked" > "$E/f2b-ssh-from-attacker.txt" 2>&1
    ssh -o BatchMode=yes "$ATTACKER" "timeout 5 bash -c 'exec 3<>/dev/tcp/$PUB4/$RPORT' && echo open || echo blocked" > "$E/f2b-vpn-from-attacker.txt" 2>&1
    grep -q blocked "$E/f2b-ssh-from-attacker.txt" && ok "banned host cannot open SSH" || bad "banned host still reaches SSH"
    grep -q blocked "$E/f2b-vpn-from-attacker.txt" && ok "banned host cannot open the VPN port $RPORT (all-port guard)" || bad "banned host still reaches VPN port"
    sbox security unban "$AIP" | tee -a "$E/f2b-unban.txt"
    sleep 2; ssh -o BatchMode=yes "$ATTACKER" "timeout 5 bash -c 'exec 3<>/dev/tcp/$PUB4/22' && echo open || echo blocked" > "$E/f2b-after-unban.txt" 2>&1
    grep -q open "$E/f2b-after-unban.txt" && ok "unban restores access" || bad "still blocked after unban"
  fi
else
  nr "live Fail2Ban ban/unban (pass --fail2ban-from USER@SECOND_TEST_HOST)"
fi

echo "== summary" | tee -a "$S"
echo "PASS=$pass FAIL=$fail NOT_RUN=$notrun" | tee -a "$S"
tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")" && echo "Evidence: $OUT.tar.gz (review before sharing)"
[ "$fail" -eq 0 ]
