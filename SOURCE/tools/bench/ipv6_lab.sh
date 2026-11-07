#!/usr/bin/env bash
# Isolated IPv6 destination lab on an IPv4-only server (root, disposable hosts).
#
#   ipv6_lab.sh up N [MTU] [TARGET_BIN]   create namespace sbox-v6lab with an IPv6 bench target
#   ipv6_lab.sh down                     remove it
#   ipv6_lab.sh status
#
# Host veth sbox6h0 = 2001:db8:5b00:N::1/64, namespace veth sbox6t0 = 2001:db8:5b00:N::2/64.
# The documentation prefix (RFC 3849) is never routed publicly; the host gets no
# IPv6 default route, the IPv4 default route and SSH are untouched. sing-box on
# the host reaches the namespace through the connected /64, so a proxied client
# request for [2001:db8:5b00:N::2] carries a real IPv6 payload end to end over an
# IPv4 VPN carrier. This is ISOLATED_IPV6_OVER_IPV4_LAB evidence, not public IPv6.
set -Eeuo pipefail
NS=sbox-v6lab
action="${1:-status}"
case "$action" in
  up)
    n="${2:?usage: ipv6_lab.sh up N [MTU] [TARGET_BIN]}"; mtu="${3:-1500}"; bin="${4:-/root/sbox-bench-target}"
    [[ "$n" =~ ^[0-9a-f]{1,4}$ ]] || { echo 'N must be 1-4 hex digits' >&2; exit 2; }
    "$0" down >/dev/null 2>&1 || true
    ip netns add "$NS"
    ip link add sbox6h0 type veth peer name sbox6t0
    ip link set sbox6t0 netns "$NS"
    ip link set sbox6h0 mtu "$mtu" up
    ip -n "$NS" link set sbox6t0 mtu "$mtu" up
    ip -n "$NS" link set lo up
    ip -6 addr add "2001:db8:5b00:$n::1/64" dev sbox6h0 nodad
    ip -n "$NS" -6 addr add "2001:db8:5b00:$n::2/64" dev sbox6t0 nodad
    ip -n "$NS" -6 route add default via "2001:db8:5b00:$n::1"
    systemd-run --quiet --unit sbox-v6lab-target -p NetworkNamespacePath="/run/netns/$NS" -p MemoryMax=200M \
      "$bin" -http "[2001:db8:5b00:$n::2]:18080" -udp "[2001:db8:5b00:$n::2]:18081"
    for _ in $(seq 1 30); do curl -s -g -o /dev/null --max-time 1 "http://[2001:db8:5b00:$n::2]:18080/204" && break; sleep 0.2; done
    curl -s -g -o /dev/null -w 'lab target via host IPv6: HTTP %{http_code}\n' --max-time 3 "http://[2001:db8:5b00:$n::2]:18080/204"
    ip -6 route show dev sbox6h0
    ;;
  down)
    systemctl stop sbox-v6lab-target 2>/dev/null || true
    ip link del sbox6h0 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    echo 'IPv6 lab removed'
    ;;
  status)
    ip netns list | grep -qx "$NS" && echo "namespace $NS present" || echo "namespace $NS absent"
    ip -6 addr show dev sbox6h0 2>/dev/null | grep inet6 || true
    ip -6 route show default || true
    ;;
  *) echo 'usage: ipv6_lab.sh up N [MTU] [TARGET_BIN] | down | status' >&2; exit 2 ;;
esac
