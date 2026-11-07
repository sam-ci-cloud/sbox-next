#!/bin/bash
# Live Fail2Ban acceptance in the lab VM: real sshd, real fail2ban, real nftables,
# real packets from a separate network namespace. Usage: f2b_live.sh VM
VM=$1; PEER=$VM-peer; PY=python3; LAB=${SBOX_LAB_ROOT:-/var/tmp/sbox-lab}
V() { $PY $(dirname "$0")/vm.py exec $VM -- "$@"; }
P() { ip netns exec $PEER "$@"; }
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; bad(){ echo "FAIL $*"; fail=$((fail+1)); }
reach() { P timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
P ip addr add 10.77.0.3/24 dev vh-${VM:0:10} 2>/dev/null
V sbox security unban 10.77.0.1 >/dev/null 2>&1; V sbox security unban 10.77.0.3 >/dev/null 2>&1; sleep 1
reach 10.77.0.2 22 && ok "baseline: SSH reachable from attacker 10.77.0.1" || bad "baseline SSH unreachable"
reach 10.77.0.2 443 && ok "baseline: REALITY 443 reachable" || bad "baseline 443 unreachable"
echo "-- 8 failed password logins from 10.77.0.1 (bogus user)"
for i in $(seq 1 8); do P timeout 8 sshpass -p wrong-$i ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=3 -b 10.77.0.1 nosuchuser@10.77.0.2 true >/dev/null 2>&1; done
for i in $(seq 1 20); do V fail2ban-client get sbox-sshd banip | grep -q 10.77.0.1 && break; sleep 1; done
V fail2ban-client status sbox-sshd | grep -q '10.77.0.1' && ok "fail2ban sbox-sshd banned 10.77.0.1 (from real sshd-session journal events)" || { bad "no ban"; V fail2ban-client status sbox-sshd; V journalctl -u ssh -n 20 --no-pager; }
V sbox security bans 2>&1 | grep -q 10.77.0.1 && ok "sbox security bans lists 10.77.0.1" || bad "sbox security bans missing entry"
V nft list ruleset | grep -q '10.77.0.1' && ok "nft ruleset contains banned address" || bad "banned address not in nft"
reach 10.77.0.2 22 && bad "banned IP still reaches SSH" || ok "banned IP: SSH packets dropped"
reach 10.77.0.2 443 && bad "banned IP still reaches REALITY 443" || ok "banned IP: VPN 443 packets dropped (all-port guard)"
P timeout 3 bash -c 'exec 3<>/dev/tcp/10.77.0.2/22' 2>/dev/null; true
P ip route get 10.77.0.2 from 10.77.0.3 >/dev/null 2>&1
P timeout 3 bash -c 'source /dev/stdin' <<<'' ; true
# Second, innocent source address on the same link is unaffected (no collateral lockout).
P timeout 4 python3 -c "import socket;s=socket.socket();s.bind(('10.77.0.3',0));s.settimeout(3);s.connect(('10.77.0.2',22));print('ok')" >/dev/null 2>&1 && ok "other source 10.77.0.3 still reaches SSH (no collateral lockout)" || bad "innocent source blocked"
echo "-- persistence across fail2ban restart and firewall reapply"
V systemctl restart fail2ban
# Jails start asynchronously; Fail2Ban 1.0.x can take ~30 s to restore bans.
for i in $(seq 1 90); do V fail2ban-client get sbox-sshd banip 2>/dev/null | grep -q 10.77.0.1 && break; sleep 1; done
V fail2ban-client status sbox-sshd | grep -q '10.77.0.1' && ok "ban persisted across fail2ban restart" || bad "ban lost after fail2ban restart"
V systemctl restart sbox-manager-firewall; sleep 2
reach 10.77.0.2 22 && bad "ban ineffective after firewall service restart" || ok "ban still enforced after sbox-manager-firewall restart"
echo "-- unban"
V sbox security unban 10.77.0.1 >/dev/null 2>&1; sleep 2
reach 10.77.0.2 22 && ok "sbox security unban restored SSH reachability" || bad "unban did not restore"
reach 10.77.0.2 443 && ok "unban restored VPN 443" || bad "unban did not restore 443"
echo "-- expiry (temporary 40s bantime)"
V fail2ban-client set sbox-sshd bantime 40 >/dev/null
for i in $(seq 1 8); do V fail2ban-client get sbox-sshd banip | grep -q 10.77.0.1 && break; P timeout 8 sshpass -p wrong-$i ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=3 -b 10.77.0.1 nosuchuser@10.77.0.2 true >/dev/null 2>&1; done
for i in $(seq 1 20); do V fail2ban-client get sbox-sshd banip | grep -q 10.77.0.1 && break; sleep 1; done
reach 10.77.0.2 22 && bad "second ban not applied" || ok "second ban applied (bantime 40s)"
sleep 48; V fail2ban-client get sbox-sshd banip | grep -q 10.77.0.1 && bad "sbox-sshd ban did not expire" || ok "sbox-sshd ban expired automatically after its bantime"
V nft list set inet sbox_guard banned4 2>/dev/null | grep -q 10.77.0.1 && bad "guard element survived expiry" || ok "early nft guard element removed on expiry"
V fail2ban-client get sshd banip 2>/dev/null | grep -q 10.77.0.1 && echo "INFO distribution [sshd] jail still holds its own independent 10-minute port-22 ban (expected; cleared by sbox security unban)"
V sbox security unban 10.77.0.1 | sed "s/^/INFO /"
V fail2ban-client set sbox-sshd bantime 600 >/dev/null
echo "-- allowlist (ignoreip loopback) and jail config"
V fail2ban-client get sbox-sshd ignoreip | grep -q 127.0.0.0/8 && ok "loopback allowlisted" || bad "loopback not allowlisted"
V systemctl is-enabled fail2ban >/dev/null && ok "fail2ban enabled for reboot" || bad "fail2ban not enabled"
echo "RESULT pass=$pass fail=$fail"
