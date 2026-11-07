#!/usr/bin/env python3
"""Minimal rtnetlink client for disposable test namespaces (no iproute2 needed).

LAB TOOL ONLY: creates veth pairs, moves an end into another network
namespace, assigns IPv4 addresses, brings links up and adds a default route.
Run inside the target namespace with `nsenter -t PID -n python3 lab_netlink.py ...`.

  lab_netlink.py veth NAME PEER [PEER_NETNS_PID]
  lab_netlink.py addr IFNAME 10.0.0.1/24
  lab_netlink.py up IFNAME
  lab_netlink.py route-default GATEWAY
  lab_netlink.py route DEST/LEN GATEWAY
  lab_netlink.py show
"""
import ipaddress
import os
import socket
import struct
import sys

NETLINK_ROUTE = 0
RTM_NEWLINK, RTM_GETLINK, RTM_NEWADDR, RTM_NEWROUTE = 16, 18, 20, 24
F_REQUEST, F_ACK, F_EXCL, F_CREATE, F_DUMP = 1, 4, 0x200, 0x400, 0x300
IFLA_IFNAME, IFLA_LINKINFO, IFLA_NET_NS_PID = 3, 18, 19
IFLA_INFO_KIND, IFLA_INFO_DATA, VETH_INFO_PEER = 1, 2, 1
IFA_ADDRESS, IFA_LOCAL = 1, 2
RTA_GATEWAY = 5
IFF_UP = 1


def attr(kind, payload):
    length = 4 + len(payload)
    return struct.pack('HH', length, kind) + payload + b'\0' * ((4 - length % 4) % 4)


def ifinfo(index=0, flags=0, change=0):
    return struct.pack('BxHiII', socket.AF_UNSPEC, 0, index, flags, change)


class Netlink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.sock.bind((0, 0))
        self.seq = 0

    def request(self, kind, payload, flags=F_REQUEST | F_ACK):
        self.seq += 1
        message = struct.pack('IHHII', 16 + len(payload), kind, flags, self.seq, 0) + payload
        self.sock.send(message)
        replies = []
        while True:
            data = self.sock.recv(65536)
            offset = 0
            while offset < len(data):
                length, mtype, _, seq, _ = struct.unpack_from('IHHII', data, offset)
                body = data[offset + 16: offset + length]
                offset += (length + 3) & ~3
                if mtype == 2:  # NLMSG_ERROR
                    err = struct.unpack_from('i', body)[0]
                    if err:
                        raise OSError(-err, os.strerror(-err))
                    return replies
                if mtype == 3:  # NLMSG_DONE
                    return replies
                replies.append((mtype, body))

    def links(self):
        out = {}
        for mtype, body in self.request(RTM_GETLINK, ifinfo(), F_REQUEST | F_DUMP):
            index = struct.unpack_from('i', body, 4)[0]
            offset = 16
            while offset < len(body):
                length, kind = struct.unpack_from('HH', body, offset)
                if kind == IFLA_IFNAME:
                    out[body[offset + 4: offset + length].rstrip(b'\0').decode()] = index
                offset += (length + 3) & ~3
        return out

    def index(self, name):
        return self.links()[name]

    def veth(self, name, peer, peer_pid=None):
        peer_attrs = attr(IFLA_IFNAME, peer.encode() + b'\0')
        if peer_pid:
            peer_attrs += attr(IFLA_NET_NS_PID, struct.pack('I', int(peer_pid)))
        info = attr(IFLA_INFO_KIND, b'veth\0') + attr(IFLA_INFO_DATA, attr(VETH_INFO_PEER, ifinfo() + peer_attrs))
        self.request(RTM_NEWLINK, ifinfo() + attr(IFLA_IFNAME, name.encode() + b'\0') + attr(IFLA_LINKINFO, info), F_REQUEST | F_ACK | F_CREATE | F_EXCL)

    def up(self, name):
        self.request(RTM_NEWLINK, ifinfo(self.index(name), IFF_UP, IFF_UP))

    def addr(self, name, cidr):
        net = ipaddress.ip_interface(cidr)
        family = socket.AF_INET if net.version == 4 else socket.AF_INET6
        raw = net.ip.packed
        payload = struct.pack('BBBBI', family, net.network.prefixlen, 0, 0, self.index(name)) + attr(IFA_LOCAL, raw) + attr(IFA_ADDRESS, raw)
        self.request(RTM_NEWADDR, payload, F_REQUEST | F_ACK | F_CREATE | F_EXCL)

    def route_default(self, gateway):
        self.route('0.0.0.0/0' if ipaddress.ip_address(gateway).version == 4 else '::/0', gateway)

    def route(self, destination, gateway):
        gw = ipaddress.ip_address(gateway); dst = ipaddress.ip_network(destination)
        family = socket.AF_INET if gw.version == 4 else socket.AF_INET6
        payload = struct.pack('BBBBBBBBI', family, dst.prefixlen, 0, 0, 254, 3, 0, 1, 0) + attr(RTA_GATEWAY, gw.packed)
        if dst.prefixlen:
            payload += attr(1, dst.network_address.packed)  # RTA_DST
        self.request(RTM_NEWROUTE, payload, F_REQUEST | F_ACK | F_CREATE | F_EXCL)


def main():
    nl = Netlink()
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == 'veth': nl.veth(*args)
    elif cmd == 'addr': nl.addr(*args)
    elif cmd == 'up': nl.up(*args)
    elif cmd == 'route-default': nl.route_default(*args)
    elif cmd == 'route': nl.route(*args)
    elif cmd == 'show': print(nl.links())
    else: raise SystemExit(__doc__)


if __name__ == '__main__':
    main()
