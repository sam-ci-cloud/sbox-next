#!/bin/bash
# LAB ONLY. Run as root INSIDE a disposable lab machine with SBOX installed.
# Real sshd, Fail2Ban and nftables; real packets from a separate network
# namespace (attacker 198.19.200.2, innocent 198.19.200.3). Never run on a VPS.
set -u
NS=sbox-f2b; H=sbf-host; P_IF=sbf-peer; SRV=198.19.200.1; ATT=198.19.200.2; INN=198.19.200.3
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; bad(){ echo "FAIL $*"; fail=$((fail+1)); }
[ -e /opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS ] || { echo "Refusing: not a marked lab machine"; exit 2; }
command -v sshpass >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass openssh-client >/dev/null
P() { ip netns exec $NS "$@"; }
reach() { P timeout 3 python3 -c "import socket,sys;s=socket.socket();s.bind((sys.argv[1],0));s.settimeout(2.5);s.connect(('$SRV',int(sys.argv[2])))" "$1" "$2" >/dev/null 2>&1; }
attack() { P timeout 8 sshpass -p "wrong-$1" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=3 -b $ATT nosuchuser@$SRV true >/dev/null 2>&1; }
banned() { fail2ban-client get sbox-sshd banip 2>/dev/null | grep -qw "$ATT"; }
cleanup() { sbox security unban $ATT >/dev/null 2>&1; ip netns del $NS 2>/dev/null; ip link del $H 2>/dev/null; fail2ban-client set sbox-sshd bantime 600 >/dev/null 2>&1; }
trap cleanup EXIT
ip netns del $NS 2>/dev/null; ip link del $H 2>/dev/null
ip netns add $NS; ip link add $H type veth peer name $P_IF; ip link set $P_IF netns $NS
ip addr add $SRV/24 dev $H; ip link set $H up
P ip link set lo up; P ip link set $P_IF up; P ip addr add $ATT/24 dev $P_IF; P ip addr add $INN/24 dev $P_IF
VPN=$(jq -r '.protocols.reality.port // .protocols.vmess.port' /etc/sbox-manager/state.json)
systemctl is-active --quiet fail2ban && fail2ban-client status sbox-sshd >/dev/null 2>&1 && ok "sbox-sshd jail active" || { bad "sbox-sshd jail not active"; echo "RESULT pass=$pass fail=$fail"; exit 1; }
sbox security unban $ATT >/dev/null 2>&1; sleep 1
reach $ATT 22 && ok "baseline: SSH reachable from $ATT" || bad "baseline SSH unreachable"
reach $ATT "$VPN" && ok "baseline: VPN TCP $VPN reachable" || bad "baseline VPN unreachable"
for i in $(seq 1 8); do attack $i; banned && break; done
for i in $(seq 1 20); do banned && break; sleep 1; done
banned && ok "fail2ban sbox-sshd banned $ATT from real sshd failures" || { bad "no ban"; fail2ban-client status sbox-sshd; }
sbox security bans 2>&1 | grep -qw $ATT && ok "sbox security bans lists $ATT" || bad "sbox security bans missing entry"
nft list ruleset | grep -qw $ATT && ok "nft ruleset contains the banned address" || bad "banned address not in nft"
reach $ATT 22 && bad "banned source still reaches SSH" || ok "banned source: SSH dropped"
reach $ATT "$VPN" && bad "banned source still reaches VPN $VPN" || ok "banned source: VPN $VPN dropped (all-port guard)"
reach $INN 22 && ok "innocent source $INN still reaches SSH (no collateral lockout)" || bad "innocent source blocked"
systemctl restart fail2ban
for i in $(seq 1 90); do banned && break; sleep 1; done
banned && ok "ban persisted across fail2ban restart" || bad "ban lost after fail2ban restart"
systemctl restart sbox-manager-firewall; sleep 2
reach $ATT 22 && bad "ban ineffective after firewall service restart" || ok "ban enforced after sbox-manager-firewall restart"
sbox security unban $ATT >/dev/null 2>&1; sleep 2
reach $ATT 22 && ok "sbox security unban restored SSH" || bad "unban did not restore SSH"
reach $ATT "$VPN" && ok "unban restored VPN $VPN" || bad "unban did not restore VPN"
fail2ban-client set sbox-sshd bantime 30 >/dev/null
for i in $(seq 1 8); do banned && break; attack $i; done
for i in $(seq 1 20); do banned && break; sleep 1; done
reach $ATT 22 && bad "second ban not applied" || ok "second ban applied (bantime 30s)"
sleep 40
banned && bad "ban did not expire" || ok "ban expired automatically after bantime"
nft list set inet sbox_guard banned4 2>/dev/null | grep -qw $ATT && bad "guard element survived expiry" || ok "early nft guard element removed on expiry"
fail2ban-client get sbox-sshd ignoreip | grep -q 127.0.0.0/8 && ok "loopback allowlisted" || bad "loopback not allowlisted"
systemctl is-enabled fail2ban >/dev/null && ok "fail2ban enabled for reboot" || bad "fail2ban not enabled"
echo "RESULT pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
