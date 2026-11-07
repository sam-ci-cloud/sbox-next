#!/bin/bash
# LAB ONLY: disposable systemd machines as privileged Docker containers on a
# Linux workstation/CI host (replaces the namespace harness that failed with
# status=200/CHDIR and journal-socket permission errors). Never point at a VPS.
#
#   docker_lab.sh image  OS            build sbox-lab:OS (ubuntu-24.04|ubuntu-26.04|ubuntu-26.10|debian-12)
#   docker_lab.sh new    NAME OS CA_DIR boot a machine, install the lab CA, map lab domains
#   docker_lab.sh exec   NAME CMD...
#   docker_lab.sh rm     NAME
#
# Root causes fixed versus the previous harness:
#  * Docker makes the root mount private. systemd sets up LoadCredential= and
#    per-unit mounts in a child namespace and relies on shared propagation, so
#    units saw no $CREDENTIALS_DIRECTORY (the Personal Cloud refused to start)
#    or failed to chdir. `mount --make-rshared /` restores real-host behaviour.
#  * systemd >= 258 (Ubuntu 26.04/26.10) refuses legacy cgroup v1. On a v1/hybrid
#    host each machine gets its own private cgroup2 subtree.
# Machines start from distribution images with only systemd/ssh added: the SBOX
# installer itself installs python3, nftables, fail2ban, certbot... through apt.
set -euo pipefail
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cg2_root=/run/sbox-lab-cg2
case "${1:-}" in
  image)
    os="$2"; base="${os/-/:}"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    cat > "$tmp/Dockerfile" <<EOF
FROM $base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates iproute2 openssh-server curl && rm -rf /var/lib/apt/lists/* \\
 && systemctl mask systemd-firstboot.service getty@tty1.service console-getty.service systemd-udevd.service systemd-modules-load.service sys-kernel-config.mount sys-kernel-debug.mount \\
 && rm -f /etc/machine-id && systemd-machine-id-setup
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
    docker build -q -t "sbox-lab:$os" "$tmp" ;;
  new)
    name="$2"; os="$3"; ca="$4"
    docker rm -f "$name" >/dev/null 2>&1 || true
    cgroup=(-v /sys/fs/cgroup:/sys/fs/cgroup:rw)
    if [ "$(stat -fc %T /sys/fs/cgroup)" != cgroup2fs ]; then
      mkdir -p "$cg2_root"; mountpoint -q "$cg2_root" || mount -t cgroup2 none "$cg2_root"
      mkdir -p "$cg2_root/$name"; cgroup=(-v "$cg2_root/$name:/sys/fs/cgroup:rw")
      case "$os" in ubuntu-24.04|debian-12) cgroup=(-v /sys/fs/cgroup:/sys/fs/cgroup:rw) ;; esac
    fi
    docker run -d --name "$name" --hostname "$name" --privileged --cgroupns=host "${cgroup[@]}" \
      --tmpfs /run --tmpfs /run/lock "sbox-lab:$os" >/dev/null
    for _ in $(seq 1 60); do
      state="$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)"
      case "$state" in running|degraded) break ;; esac; sleep 1
    done
    docker exec "$name" mount --make-rshared /
    ip="$(docker exec "$name" hostname -I | awk '{print $1}')"
    docker exec "$name" bash -c 'mkdir -p /root/lab /opt/sbox-lab && touch /opt/sbox-lab/ALLOW_DESTRUCTIVE_TESTS'
    for f in "$ca"/*; do docker cp "$f" "$name:/root/lab/" >/dev/null; done
    docker exec "$name" bash -c "chmod 600 /root/lab/*.key; cp /root/lab/ca.crt /usr/local/share/ca-certificates/sbox-lab-ca.crt; update-ca-certificates >/dev/null 2>&1; printf '%s lab.sbox.test\n%s ${SBOX_ZGO_TEST_DOMAIN:-zgo.example.test}\n' $ip $ip >> /etc/hosts; systemctl enable --now ssh >/dev/null 2>&1 || true"
    echo "$ip" ;;
  exec) name="$2"; shift 2; docker exec -i "$name" "$@" ;;
  rm) docker rm -f "$2" >/dev/null; rmdir "$cg2_root/$2" 2>/dev/null || true ;;
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
