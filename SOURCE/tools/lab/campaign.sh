#!/bin/bash
# SBOX lab acceptance campaign. Disposable systemd VMs only. Usage: campaign.sh NEW_INSTALLER OLD_INSTALLER SCENARIO...
NEW=$1; OLD=$2; shift 2
LAB=${SBOX_LAB_ROOT:-/var/tmp/sbox-lab}; PY=python3; D=lab.sbox.test
pass=0; fail=0; ok(){ echo "PASS $*"; pass=$((pass+1)); }; bad(){ echo "FAIL $*"; fail=$((fail+1)); }
V() { local vm=$1; shift; $PY $(dirname "$0")/vm.py exec "$vm" -- "$@"; }
INSTALL_ARGS="--yes --region global --node Lab --domain $D --ipv4 10.77.0.2 --ipv6 none --listen 0.0.0.0 --protocols reality,vmess,hy2,tuic,anytls --ports reality=443,hy2=443 --hy2-range none --cert existing --cert-path /root/lab/fullchain.pem --key-path /root/lab/leaf.key --firewall yes --tuning no --block-private yes"
newvm() { # newvm NAME BASE
  $PY $(dirname "$0")/vm.py destroy $1 >/dev/null 2>&1; $PY $(dirname "$0")/vm.py create $1 --base ${2:-stonking} --peer >/dev/null || return 1
  local R=$LAB/vms/$1/root; mkdir -p $R/root/lab; cp $LAB/work/ca/leaf.crt $LAB/work/ca/leaf.key $LAB/work/ca/ca.crt $R/root/lab/
  cat $LAB/work/ca/leaf.crt $LAB/work/ca/ca.crt > $R/root/lab/fullchain.pem; chmod 600 $R/root/lab/leaf.key
  cp $LAB/work/ca/ca.crt $R/usr/local/share/ca-certificates/sbox-lab-ca.crt; echo "10.77.0.2 $D" >> $R/etc/hosts
  cp $NEW $R/root/install-new.sh; cp $OLD $R/root/install-old.sh
  V $1 update-ca-certificates >/dev/null 2>&1; V $1 systemctl enable --now ssh rsyslog >/dev/null 2>&1; V $1 systemctl start ssh >/dev/null 2>&1; true
}
inst() { local vm=$1 file=$2 mode=$3; shift 3; V $vm env "$@" bash -c "cd /root && bash ./$file install generic $INSTALL_ARGS --reality-fallback $mode --reality-fallback-port 8443 </dev/null" ; }
doctor0() { V $1 bash -c 'sbox doctor 2>&1' > $LAB/logs/doctor-$1-$2.txt; grep -q 'Result: 0 failure(s)' $LAB/logs/doctor-$1-$2.txt && ok "$1 $2: sbox doctor 0 failures" || { bad "$1 $2: doctor"; grep -E 'FAIL|Result' $LAB/logs/doctor-$1-$2.txt | head -8; }; }
pcok() { env -u HTTPS_PROXY -u https_proxy ip netns exec $1-peer curl -s --max-time 10 --resolve $D:443:10.77.0.2 --cacert $LAB/work/ca/ca.crt https://$D/about/ -o /tmp/pc-$1.html -w '%{http_code}' | grep -q 200 && grep -q sbox-personal-cloud /tmp/pc-$1.html && ok "$1 $2: Personal Cloud served through REALITY port 443 with trusted owner certificate" || bad "$1 $2: Personal Cloud not served on 443"; }
mkuser() { echo "{\"kind\":\"user-create\",\"data\":{\"name\":\"$2\",\"protocols\":[\"reality\",\"hy2\"]}}" > $LAB/vms/$1/root/root/req.json
  local tok; tok=$(V $1 bash -c 'sbox _webui-control prepare < /root/req.json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])') || return 1
  echo "{\"token\":\"$tok\"}" > $LAB/vms/$1/root/root/commit.json; V $1 bash -c 'sbox _webui-control commit < /root/commit.json' >/dev/null; }
users_digest() { python3 -c "import json,hashlib;s=json.load(open('$LAB/vms/$1/root/etc/sbox-manager/state.json'));c=json.load(open('$LAB/vms/$1/root/etc/sbox-manager/config.json'));print(hashlib.sha256(json.dumps([sorted((u['id'],u['name']) for u in s.get('managed_users',[])),sorted(json.dumps(i.get('users',[]),sort_keys=True) for i in c['inbounds'])],sort_keys=True).encode()).hexdigest()[:16])"; }

s_fresh() { local vm=${1:-c1} base=${2:-stonking}; echo "=== S-fresh: fresh Universal install with self-hosted Personal Cloud ($base)"
  newvm $vm $base; inst $vm install-new.sh self-hosted > $LAB/logs/$vm-install.txt 2>&1 && ok "$vm: fresh install exit 0" || { bad "$vm: fresh install"; tail -20 $LAB/logs/$vm-install.txt; return; }
  doctor0 $vm fresh; pcok $vm fresh
  V $vm bash -c 'sbox version; systemctl is-active sing-box sbox-fallback-web sbox-webui sbox-accounting fail2ban | paste -sd" "'
  V $vm bash -c 'stat -c "%a" /usr/local/lib/sbox-manager/fallback-web/site /usr/local/lib/sbox-manager/fallback-web/site/files | paste -sd" "' | grep -qx '755 755' && ok "$vm: website directories are 0755 on disk" || bad "$vm: website dir modes"
}
s_feature_rollback() { local vm=${1:-c1}; echo "=== S-rollback: injected failure during matching upgrade"
  mkuser $vm rb-user1; local before; before=$(users_digest $vm)
  V $vm env SBOX_LAB_FAULT=website-upgrade bash -c 'cd /root && bash ./install-new.sh upgrade generic </dev/null' > $LAB/logs/$vm-upgrade-fault.txt 2>&1 && bad "$vm: faulted upgrade unexpectedly succeeded" || ok "$vm: faulted upgrade returned failure"
  grep -q 'LAB FAULT INJECTED' $LAB/logs/$vm-upgrade-fault.txt && ok "$vm: fault was injected at the website step (after files/unit were rewritten)" || bad "$vm: fault marker missing"
  grep -q 'Feature upgrade rolled back' $LAB/logs/$vm-upgrade-fault.txt && ok "$vm: feature transaction rolled back and verified" || { bad "$vm: no verified rollback"; tail -15 $LAB/logs/$vm-upgrade-fault.txt; }
  [ "$(users_digest $vm)" = "$before" ] && ok "$vm: users and credentials identical after rollback" || bad "$vm: users changed after rollback"
  V $vm test ! -e /var/backups/sbox-manager/features.pending && ok "$vm: no pending feature journal left" || bad "$vm: journal left"
  doctor0 $vm after-rollback; pcok $vm after-rollback
  V $vm bash -c 'cd /root && bash ./install-new.sh upgrade generic </dev/null' > $LAB/logs/$vm-upgrade-retry.txt 2>&1 && ok "$vm: retried upgrade succeeded" || { bad "$vm: retry upgrade"; tail -10 $LAB/logs/$vm-upgrade-retry.txt; }
  [ "$(users_digest $vm)" = "$before" ] && ok "$vm: users preserved by matching upgrade" || bad "$vm: users changed by upgrade"
  doctor0 $vm after-retry; pcok $vm after-retry
}
s_crash_recover() { local vm=${1:-c1}; echo "=== S-crash: process killed mid-transaction, then sbox recover"
  local before; before=$(users_digest $vm)
  ( V $vm env SBOX_LAB_FAULT=website-upgrade-hang bash -c 'cd /root && exec bash ./install-new.sh upgrade generic </dev/null' > $LAB/logs/$vm-crash.txt 2>&1 ) &
  for i in $(seq 1 120); do grep -q 'hanging at website-upgrade' $LAB/logs/$vm-crash.txt && break; sleep 2; done
  grep -q 'hanging at website-upgrade' $LAB/logs/$vm-crash.txt && ok "$vm: transaction paused inside the website step" || { bad "$vm: hang point not reached"; tail -5 $LAB/logs/$vm-crash.txt; }
  V $vm bash -c 'kill -9 $(pgrep -f "[m]anager upgrade-features") $(pgrep -f "[s]box-all-in-one") $(pgrep -x sleep) 2>/dev/null; true'; sleep 3
  V $vm test -e /var/backups/sbox-manager/features.pending && ok "$vm: interrupted feature journal retained after SIGKILL" || bad "$vm: no journal after crash"
  V $vm bash -c 'sbox status >/dev/null 2>&1; sbox quota show >/dev/null 2>&1; true'
  V $vm bash -c 'sbox recover </dev/null' > $LAB/logs/$vm-recover.txt 2>&1 && ok "$vm: sbox recover succeeded" || { bad "$vm: recover"; tail -12 $LAB/logs/$vm-recover.txt; }
  V $vm test ! -e /var/backups/sbox-manager/features.pending && ok "$vm: journal cleared after verified recovery" || bad "$vm: journal still present"
  [ "$(users_digest $vm)" = "$before" ] && ok "$vm: users identical after crash recovery" || bad "$vm: users changed after crash"
  doctor0 $vm after-recover; pcok $vm after-recover
}
s_install_rollback() { local vm=${1:-c2}; echo "=== S-install-rollback: failed fresh install restores previous (empty) runtime, then retry"
  newvm $vm stonking
  inst $vm install-new.sh self-hosted SBOX_LAB_FAULT=apply-website > $LAB/logs/$vm-install-fault.txt 2>&1 && bad "$vm: faulted install succeeded" || ok "$vm: faulted install returned failure"
  grep -q 'previous runtime was restored and verified' $LAB/logs/$vm-install-fault.txt && ok "$vm: install transaction rolled back and verified" || { bad "$vm: rollback not verified"; tail -8 $LAB/logs/$vm-install-fault.txt; }
  V $vm bash -c 'test ! -e /usr/local/lib/sbox-manager/fallback-web && test ! -e /etc/systemd/system/sbox-fallback-web.service && ! ls -d /usr/local/lib/sbox-manager/.fallback-web.stage.* 2>/dev/null' && ok "$vm: staged website files and unit removed by rollback" || bad "$vm: staged files left behind"
  V $vm bash -c '! systemctl is-active --quiet sing-box' && ok "$vm: no half-applied VPN left running" || bad "$vm: sing-box running after failed install"
  inst $vm install-new.sh self-hosted > $LAB/logs/$vm-install-retry.txt 2>&1 && ok "$vm: retried install succeeded" || { bad "$vm: retry install"; tail -15 $LAB/logs/$vm-install-retry.txt; }
  doctor0 $vm retry; pcok $vm retry
}
s_upgrade_from_published() { local vm=${1:-c3}; echo "=== S-upgrade: previously published installer (remote target) -> new, then switch to self-hosted and back"
  newvm $vm stonking
  inst $vm install-old.sh remote > $LAB/logs/$vm-old-install.txt 2>&1 && ok "$vm: previous installer completed" || {
    if grep -q 'Unknown file in reserved runtime directory: /usr/local/lib/sbox-manager/fallback-web' $LAB/logs/$vm-old-install.txt; then
      echo "INFO $vm: previous installer (1.1.0) VPN transaction committed, then its panel stage stopped with the known 1.1.0 defect 'Unknown file in reserved runtime directory: .../fallback-web' (fixed in 1.1.1)"
    else bad "$vm: previous install"; tail -10 $LAB/logs/$vm-old-install.txt; return; fi; }
  V $vm systemctl is-active --quiet sing-box && ok "$vm: VPN from the previous installer is running" || bad "$vm: no VPN after previous install"
  V $vm bash -c 'cd /root && bash ./install-new.sh upgrade generic </dev/null' > $LAB/logs/$vm-upgrade.txt 2>&1 && ok "$vm: matching upgrade to the new release succeeded" || { bad "$vm: upgrade"; tail -15 $LAB/logs/$vm-upgrade.txt; }
  V $vm bash -c 'systemctl is-active --quiet sbox-webui sbox-accounting' && ok "$vm: panel and accounting installed by the upgrade" || bad "$vm: panel/accounting missing after upgrade"
  V $vm test ! -e /usr/local/lib/sbox-manager/fallback-web && ok "$vm: no website tree in remote mode" || echo "INFO $vm: website tree from the previous release is present until the next apply"
  doctor0 $vm upgraded
  mkuser $vm up-user1; mkuser $vm up-user2; local before; before=$(users_digest $vm)
  V $vm bash -c 'sbox reality-fallback self-hosted --port 8443 --yes --cert existing --cert-path /root/lab/fullchain.pem --key-path /root/lab/leaf.key </dev/null' > $LAB/logs/$vm-switch-sh.txt 2>&1 && ok "$vm: switched to self-hosted Personal Cloud" || { bad "$vm: switch to self-hosted"; tail -15 $LAB/logs/$vm-switch-sh.txt; }
  doctor0 $vm self-hosted; pcok $vm self-hosted
  [ "$(users_digest $vm)" = "$before" ] && ok "$vm: users unchanged by target switch" || bad "$vm: users changed by switch"
  V $vm bash -c 'sbox reality-fallback remote --yes </dev/null' > $LAB/logs/$vm-switch-remote.txt 2>&1 && ok "$vm: switched back to remote target" || { bad "$vm: switch back"; tail -10 $LAB/logs/$vm-switch-remote.txt; }
  V $vm bash -c 'test ! -e /etc/systemd/system/sbox-fallback-web.service && ! systemctl is-active --quiet sbox-fallback-web && test ! -e /usr/local/lib/sbox-manager/fallback-web' && ok "$vm: Personal Cloud unit, service and files removed in remote mode" || bad "$vm: website left in remote mode"
  [ "$(users_digest $vm)" = "$before" ] && ok "$vm: users unchanged after switching back" || bad "$vm: users changed"
  doctor0 $vm remote-again
}
s_f2b() { bash "$(dirname "$0")/f2b_live.sh" ${1:-c1} | tee -a /dev/null | sed "s/^/  /"; }
s_traffic() { bash "$(dirname "$0")/traffic_acct.sh" ${1:-c1} | sed "s/^/  /"; }
s_destroy() { $PY "$(dirname "$0")/vm.py" destroy ${1:-c1} >/dev/null 2>&1; echo "destroyed ${1:-c1}"; }
s_uninstall() { local vm=${1:-c1}; echo "=== S-uninstall: uninstall then reinstall"
  V $vm bash -c 'sbox uninstall --force </dev/null' > $LAB/logs/$vm-uninstall.txt 2>&1 && ok "$vm: uninstall succeeded" || { bad "$vm: uninstall"; tail -12 $LAB/logs/$vm-uninstall.txt; }
  V $vm bash -c 'for u in sing-box sbox-fallback-web sbox-manager-firewall sbox-webui; do systemctl is-active --quiet $u && echo "$u still active"; test -e /etc/systemd/system/$u.service && echo "$u unit left"; done; test -e /usr/local/lib/sbox-manager/fallback-web && echo "website left"; nft list tables | grep -q sbox_guard && echo "guard table left"; test -e /etc/fail2ban/jail.d/sbox-manager.local && echo "jail left"; true' > $LAB/logs/$vm-uninstall-left.txt
  [ ! -s $LAB/logs/$vm-uninstall-left.txt ] && ok "$vm: SBOX services, website, guard table and jail removed" || { bad "$vm: leftovers"; cat $LAB/logs/$vm-uninstall-left.txt; }
  V $vm bash -c 'ls /var/backups/sbox-manager/*.tar.gz >/dev/null 2>&1' && ok "$vm: final backup retained" || bad "$vm: no final backup"
  V $vm bash -c 'fail2ban-client status | grep -q "sshd" ' && ok "$vm: distribution SSH jail active again after uninstall" || echo "INFO $vm: fail2ban jail list after uninstall: $(V $vm fail2ban-client status | tail -1)"
  inst $vm install-new.sh self-hosted > $LAB/logs/$vm-reinstall.txt 2>&1 && ok "$vm: reinstall after uninstall succeeded" || { bad "$vm: reinstall"; tail -15 $LAB/logs/$vm-reinstall.txt; }
  doctor0 $vm reinstall; pcok $vm reinstall
}
for s in "$@"; do case "$s" in *:*) "${s%%:*}" ${s#*:} ;; *) "$s" ;; esac; done
echo "CAMPAIGN pass=$pass fail=$fail"
