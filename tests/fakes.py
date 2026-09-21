from __future__ import annotations

import ipaddress

from tunnelvisionvision.model import DhcpLease, Interface, Route, Snapshot
from tunnelvisionvision.platforms.base import Platform


def net(s):
    return ipaddress.ip_network(s, strict=False)


def iface(name, *addrs, vpn=False, wireless=False):
    return Interface(name=name, addresses=[ipaddress.ip_interface(a) for a in addrs], is_vpn=vpn, is_wireless=wireless)


class FakePlatform(Platform):
    """In-memory platform. `lookup` maps probe IP -> interface; default: longest-prefix match over non-scoped routes."""

    name = "fake"

    def __init__(self, ifaces, routes, leases=(), lookup=None, endpoints=()):
        super().__init__()
        self._ifaces = {i.name: i for i in ifaces}
        self._routes = list(routes)
        self._leases = list(leases)
        self._lookup = lookup
        self._endpoints = set(endpoints)
        self.deleted: list[Route] = []
        self.disconnected: list[str] = []
        self.dry_run = True  # skip the admin check in actions

    def snapshot(self) -> Snapshot:
        return Snapshot("fake", dict(self._ifaces), list(self._routes), list(self._leases), set(self._endpoints))

    def route_lookup(self, ips):
        out = {}
        for ip in ips:
            if self._lookup is not None:
                out[ip] = self._lookup.get(ip, self._lpm(ip))
            else:
                out[ip] = self._lpm(ip)
        return out

    def _lpm(self, ip):
        addr = ipaddress.ip_address(ip)
        best = None
        for r in self._routes:
            if r.scoped or r.dest.version != addr.version or addr not in r.dest:
                continue
            if best is None or r.dest.prefixlen > best.dest.prefixlen or (
                r.dest.prefixlen == best.dest.prefixlen and (r.metric or 0) < (best.metric or 0)):
                best = r
        return best.iface if best else None

    def delete_route(self, route):
        self._routes = [r for r in self._routes if r.key() != route.key()]
        self.deleted.append(route)
        return [f"del {route.describe()}"]

    def disconnect(self, iface):
        self.disconnected.append(iface.name)
        return [f"down {iface.name}"]

    def manual_steps(self, findings, snap):
        return ["manual step"]


def wg_attack_platform(lookup=None, with_lease=True):
    """Linux wg-quick style full tunnel + TunnelVision /1 routes pushed by a rogue DHCP server."""
    ifaces = [iface("eth0", "192.168.1.50/24", wireless=True), iface("wg0", "10.0.0.2/32", vpn=True)]
    routes = [
        Route(net("0.0.0.0/0"), "wg0", table="51820"),
        Route(net("0.0.0.0/0"), "eth0", gateway="192.168.1.1", metric=100, proto="dhcp"),
        Route(net("192.168.1.0/24"), "eth0", proto="kernel"),
        Route(net("0.0.0.0/1"), "eth0", gateway="192.168.1.66", proto="static"),
        Route(net("128.0.0.0/1"), "eth0", gateway="192.168.1.66", proto="static"),
    ]
    leases = [DhcpLease("eth0", "192.168.1.66", [(net("0.0.0.0/1"), "192.168.1.66"), (net("128.0.0.0/1"), "192.168.1.66")], "test")] if with_lease else []
    return FakePlatform(ifaces, routes, leases, lookup=lookup)
