#!/bin/bash
# Prepare disposable lab roots for tools/lab (LAB ONLY; root required).
#   bash tools/lab/make_lab.sh [stonking|resolute|noble]...   (default: stonking noble)
# Builds debootstrap root filesystems from archive.ubuntu.com and a throw-away
# lab CA plus a leaf certificate for lab.sbox.test. Nothing is installed
# on, or trusted by, the host.
set -euo pipefail
LAB=${SBOX_LAB_ROOT:-/var/tmp/sbox-lab}; D=${SBOX_LAB_DOMAIN:-lab.sbox.test}
mkdir -p "$LAB/rootfs" "$LAB/work/ca" "$LAB/logs"
PKGS=systemd,systemd-sysv,dbus,udev,iproute2,nftables,iptables,curl,jq,openssl,ca-certificates,python3,python3-yaml,python3-systemd,python3-h2,bind9-dnsutils,rsyslog,psmisc,whois,kmod,procps,fail2ban,qrencode,openssh-server,sudo,sqlite3,tar,gzip,xz-utils,python3-pyinotify,netcat-openbsd,python3-cffi-backend
for suite in "${@:-stonking noble}"; do
  for s in $suite; do
    [ -e "/usr/share/debootstrap/scripts/$s" ] || ln -s gutsy "/usr/share/debootstrap/scripts/$s"
    R="$LAB/rootfs/$s"; [ -x "$R/usr/bin/python3" ] && continue
    debootstrap --keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg --variant=minbase --components=main,universe --include="$PKGS" "$s" "$R" http://archive.ubuntu.com/ubuntu || true
    printf 'deb http://archive.ubuntu.com/ubuntu %s main universe\n' "$s" > "$R/etc/apt/sources.list"
    mount --bind /proc "$R/proc"; mount --bind /dev "$R/dev"; cp /etc/resolv.conf "$R/etc/resolv.conf"
    chroot "$R" env -u http_proxy -u https_proxy DEBIAN_FRONTEND=noninteractive bash -c 'apt-get update && apt-get -y -f install && apt-get -y install python3-cffi-backend fail2ban openssh-server python3-h2' || true
    umount "$R/proc" "$R/dev"; rm -f "$R/usr/sbin/policy-rc.d"
    chroot "$R" bash -c 'systemctl --version | head -1; python3 --version; mv --version | head -1'
  done
done
cd "$LAB/work/ca"
if [ ! -s ca.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj '/CN=SBOX DISPOSABLE LAB CA (not public)' -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -addext subjectKeyIdentifier=hash -keyout ca.key -out ca.crt
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$D" -keyout leaf.key -out leaf.csr
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$D" > leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 20 -extfile leaf.ext -out leaf.crt
fi
echo "lab ready under $LAB"
