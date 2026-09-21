from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import socket
import struct
from pathlib import Path
from typing import Optional, Sequence

from .. import dhcp
from ..model import DhcpLease, Finding, Interface, Route, Snapshot
from ..util import have, ip_net, log, run
from .base import VPN_NAME_RE, Platform

VPN_KINDS = {"wireguard", "tun", "xfrm", "vti", "vti6", "ipsec"}
SKIP_ROUTE_TYPES = {"local", "broadcast", "multicast", "unreachable", "blackhole", "prohibit", "throw", "anycast", "nat"}

DHCLIENT_GLOBS = [
    "/var/lib/dhcp/dhclient*.lease*",
    "/var/lib/dhclient/*.lease*",
    "/var/lib/NetworkManager/dhclient-*.lease",
]
NETWORKD_LEASE_DIR = "/run/systemd/netif/leases"
NM_INTERNAL_GLOB = "/var/lib/NetworkManager/internal-*.lease"
DHCPCD_GLOBS = ["/var/lib/dhcpcd/*.lease", "/var/db/dhcpcd/*.lease", "/var/lib/dhcpcd5/*.lease"]


# ---------------------------------------------------------------------------------------------
# Pure parsers (unit-tested with fixtures)
# ---------------------------------------------------------------------------------------------
def parse_ip_addr_json(data: list, sysfs: Optional[Path] = Path("/sys/class/net")) -> dict[str, Interface]:
    ifaces: dict[str, Interface] = {}
    for link in data:
        name = link.get("ifname")
        if not name:
            continue
        flags = link.get("flags", [])
        kind = (link.get("linkinfo") or {}).get("info_kind", "")
        link_type = link.get("link_type", "")
        iface = Interface(
            name=name,
            index=link.get("ifindex"),
            up="UP" in flags,
            kind=kind or link_type,
            is_loopback="LOOPBACK" in flags or link_type == "loopback",
        )
        for a in link.get("addr_info", []):
            if a.get("family") in ("inet", "inet6") and a.get("local"):
                try:
                    iface.addresses.append(ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 32)}"))
                except ValueError:
                    pass
        iface.is_vpn = not iface.is_loopback and (
            kind in VPN_KINDS or link_type in ("none", "ppp") or bool(VPN_NAME_RE.match(name))
        )
        if sysfs is not None:
            iface.is_wireless = (sysfs / name / "wireless").exists() or (sysfs / name / "phy80211").exists()
        ifaces[name] = iface
    return ifaces


def parse_ip_route_json(data: list, family: int) -> list[Route]:
    routes = []
    for r in data:
        if r.get("type", "unicast") in SKIP_ROUTE_TYPES or r.get("table") == "local":
            continue
        dev = r.get("dev")
        dst = r.get("dst")
        if not dev or not dst:
            continue
        if dst == "default":
            dst = "0.0.0.0/0" if family == 4 else "::/0"
        try:
            net = ip_net(dst)
        except ValueError:
            continue
        routes.append(
            Route(
                dest=net,
                iface=dev,
                gateway=r.get("gateway"),
                metric=r.get("metric"),
                table=str(r.get("table", "main")),
                proto=str(r.get("protocol", "")),
                flags=",".join(r.get("flags", [])),
            )
        )
    return routes


def _hex_le_ip(h: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(h, 16)))


def parse_proc_net_route(text: str) -> list[Route]:
    """Fallback for minimal containers without iproute2 (IPv4 main table only)."""
    routes = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        iface, dest, gw, flags, metric, mask = f[0], f[1], f[2], int(f[3], 16), int(f[6]), f[7]
        if not flags & 0x1:  # RTF_UP
            continue
        net = ipaddress.IPv4Network((_hex_le_ip(dest), _hex_le_ip(mask)), strict=False)
        gateway = _hex_le_ip(gw) if flags & 0x2 else None
        routes.append(Route(dest=net, iface=iface, gateway=gateway, metric=metric))
    return routes


def parse_proc_ipv6_route(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 10:
            continue
        dest = ipaddress.IPv6Address(bytes.fromhex(f[0]))
        plen = int(f[1], 16)
        nh = ipaddress.IPv6Address(bytes.fromhex(f[4]))
        flags = int(f[8], 16)
        if flags & 0x200 or flags & 0x80000000:  # RTF_REJECT / RTF_LOCAL
            continue
        routes.append(Route(dest=ipaddress.IPv6Network((dest, plen), strict=False), iface=f[9],
                            gateway=None if nh.is_unspecified else str(nh), metric=int(f[5], 16)))
    return routes


def parse_dhclient_leases(text: str, source: str = "dhclient") -> list[DhcpLease]:
    """Return the most recent lease per interface from a dhclient lease file."""
    latest: dict[str, DhcpLease] = {}
    for block in re.findall(r"lease\s*\{(.*?)\}", text, re.S):
        m = re.search(r'interface\s+"([^"]+)"', block)
        if not m:
            continue
        lease = DhcpLease(iface=m.group(1), source=source)
        m = re.search(r"option\s+dhcp-server-identifier\s+([\d.]+)", block)
        if m:
            lease.server = m.group(1)
        for m in re.finditer(r"option\s+(?:rfc3442-classless-static-routes|ms-classless-static-routes|classless-static-routes)\s+([^;]+);", block):
            try:
                lease.classless_routes.extend(dhcp.parse_route_text(m.group(1)))
            except ValueError as e:
                log.debug("dhclient route parse: %s", e)
        latest[lease.iface] = lease
    return list(latest.values())


def parse_sd_lease(text: str, iface: str, source: str) -> DhcpLease:
    """systemd-networkd / NetworkManager-internal lease file (KEY=VALUE)."""
    lease = DhcpLease(iface=iface, source=source)
    for line in text.splitlines():
        key, _, value = line.partition("=")
        key = key.strip()
        if key == "SERVER_ADDRESS":
            lease.server = value.strip()
        elif key in ("CLASSLESS_ROUTES", "ROUTES", "STATIC_ROUTES") and value.strip():
            try:
                lease.classless_routes.extend(dhcp.parse_route_text(value))
            except ValueError as e:
                log.debug("sd lease route parse: %s", e)
    return lease


def parse_nmcli(text: str) -> list[DhcpLease]:
    """`nmcli -t -f GENERAL.DEVICE,DHCP4 device show`"""
    leases: list[DhcpLease] = []
    cur: Optional[DhcpLease] = None
    for line in text.splitlines():
        if line.startswith("GENERAL.DEVICE:"):
            cur = DhcpLease(iface=line.split(":", 1)[1], source="NetworkManager")
            leases.append(cur)
            continue
        if cur is None or not line.startswith("DHCP4.OPTION"):
            continue
        _, _, kv = line.partition(":")
        key, _, value = kv.partition("=")
        key, value = key.strip(), value.strip()
        if key in ("dhcp_server_identifier", "server_identifier"):
            cur.server = value
        elif key in ("classless_static_routes", "rfc3442_classless_static_routes", "ms_classless_static_routes"):
            try:
                cur.classless_routes.extend(dhcp.parse_route_text(value))
            except ValueError as e:
                log.debug("nmcli route parse: %s", e)
    return [l for l in leases if l.server or l.classless_routes]


# ---------------------------------------------------------------------------------------------
class LinuxPlatform(Platform):
    name = "linux"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.has_ip = have("ip")

    def interfaces(self) -> dict[str, Interface]:
        if self.has_ip:
            proc = run(["ip", "-j", "-d", "addr", "show"])
            if proc.returncode == 0 and proc.stdout.strip():
                return parse_ip_addr_json(json.loads(proc.stdout))
        # Fallback: sysfs only (no addresses available).
        ifaces = {}
        for p in Path("/sys/class/net").iterdir():
            name = p.name
            try:
                arphrd = int((p / "type").read_text().strip())
                operstate = (p / "operstate").read_text().strip()
            except OSError:
                continue
            is_lo = arphrd == 772
            ifaces[name] = Interface(
                name=name,
                up=operstate in ("up", "unknown"),
                is_loopback=is_lo,
                is_vpn=not is_lo and (arphrd in (65534, 512) or (p / "tun_flags").exists() or bool(VPN_NAME_RE.match(name))),
                is_wireless=(p / "wireless").exists(),
            )
        return ifaces

    def routes(self) -> list[Route]:
        if self.has_ip:
            routes: list[Route] = []
            for fam in (4, 6):
                proc = run(["ip", "-j", f"-{fam}", "route", "show", "table", "all"])
                if proc.returncode == 0 and proc.stdout.strip():
                    routes += parse_ip_route_json(json.loads(proc.stdout), fam)
            return routes
        routes = parse_proc_net_route(Path("/proc/net/route").read_text())
        if os.path.exists("/proc/net/ipv6_route"):
            routes += parse_proc_ipv6_route(Path("/proc/net/ipv6_route").read_text())
        return routes

    def leases(self, interfaces: dict[str, Interface]) -> list[DhcpLease]:
        found: dict[str, DhcpLease] = {}

        def add(lease: DhcpLease):
            if lease.iface in interfaces and (lease.server or lease.classless_routes):
                # Prefer the source that actually reports routes.
                if lease.iface not in found or (lease.classless_routes and not found[lease.iface].classless_routes):
                    found[lease.iface] = lease

        if have("nmcli"):
            proc = run(["nmcli", "-t", "-f", "GENERAL.DEVICE,DHCP4", "device", "show"])
            if proc.returncode == 0:
                for l in parse_nmcli(proc.stdout):
                    add(l)
        by_index = {str(i.index): n for n, i in interfaces.items() if i.index is not None}
        if os.path.isdir(NETWORKD_LEASE_DIR):
            for path in glob.glob(os.path.join(NETWORKD_LEASE_DIR, "*")):
                name = by_index.get(os.path.basename(path))
                if name:
                    add(parse_sd_lease(_read(path), name, "systemd-networkd"))
        for path in glob.glob(NM_INTERNAL_GLOB):
            name = Path(path).stem.rsplit("-", 1)[-1]
            add(parse_sd_lease(_read(path), name, "NetworkManager"))
        for pattern in DHCLIENT_GLOBS:
            for path in sorted(glob.glob(pattern), key=os.path.getmtime):
                for l in parse_dhclient_leases(_read(path), f"dhclient ({path})"):
                    add(l)
        for pattern in DHCPCD_GLOBS:
            for path in glob.glob(pattern):
                name = Path(path).stem.split("-")[0]
                try:
                    pkt = dhcp.parse_bootp(Path(path).read_bytes())
                except OSError:
                    continue
                if pkt:
                    add(DhcpLease(iface=name, server=pkt["server"], classless_routes=pkt["classless_routes"], source=f"dhcpcd ({path})"))
        return list(found.values())

    def vpn_endpoints(self) -> set[str]:
        eps: set[str] = set()
        if have("wg"):
            proc = run(["wg", "show", "all", "endpoints"])
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2] != "(none)":
                    host = parts[2].rsplit(":", 1)[0].strip("[]")
                    eps.add(host)
        return eps

    def route_lookup(self, ips: Sequence[str]) -> dict[str, Optional[str]]:
        out: dict[str, Optional[str]] = {}
        if not self.has_ip:
            return out
        for ip in ips:
            proc = run(["ip", "-j", "route", "get", ip], timeout=5)
            try:
                out[ip] = json.loads(proc.stdout)[0].get("dev") if proc.returncode == 0 else None
            except (ValueError, IndexError):
                out[ip] = None
        return out

    def delete_route(self, route: Route) -> list[str]:
        cmd = ["ip", "route", "del", str(route.dest)]
        if route.gateway:
            cmd += ["via", route.gateway]
        cmd += ["dev", route.iface, "table", route.table or "main"]
        if route.metric is not None:
            cmd += ["metric", str(route.metric)]
        return [self.exec(cmd)]

    def disconnect(self, iface: Interface) -> list[str]:
        if have("nmcli") and run(["nmcli", "-t", "general", "status"]).returncode == 0:
            try:
                return [self.exec(["nmcli", "device", "disconnect", iface.name])]
            except RuntimeError as e:
                log.warning("nmcli disconnect failed, falling back to ip link: %s", e)
        return [self.exec(["ip", "link", "set", "dev", iface.name, "down"])]

    def manual_steps(self, findings: list[Finding], snap: Snapshot) -> list[str]:
        ifaces = sorted({f.iface for f in findings if f.iface and f.iface not in snap.vpn_interfaces()}) or ["<wifi/ethernet interface>"]
        sources = " ".join(l.source for l in snap.leases)
        steps = []
        if "NetworkManager" in sources or have("nmcli"):
            steps.append(
                "Stop accepting DHCP option 121 routes on this network (NetworkManager):\n"
                f"  nmcli -g GENERAL.CONNECTION device show {ifaces[0]}   # find the connection name\n"
                "  nmcli connection modify \"<connection>\" ipv4.ignore-auto-routes yes\n"
                "  nmcli connection up \"<connection>\""
            )
        if "systemd-networkd" in sources:
            steps.append("systemd-networkd: add to the [DHCPv4] section of the .network file:\n  UseRoutes=no\nthen: networkctl reload && networkctl reconfigure " + ifaces[0])
        if "dhclient" in sources:
            steps.append("dhclient: remove 'rfc3442-classless-static-routes' from the 'request' line in /etc/dhcp/dhclient.conf, then renew the lease (dhclient -r && dhclient).")
        if "dhcpcd" in sources:
            steps.append("dhcpcd: add 'nooption classless_static_routes' to /etc/dhcpcd.conf, then: dhcpcd -n " + ifaces[0])
        steps += [
            "Strongest fix (Leviathan's recommendation): run the VPN in a dedicated network namespace so the physical "
            "interface is only reachable by the VPN process, e.g. `ip netns add physical; ip link set " + ifaces[0] + " netns physical` "
            "and start the VPN client with its socket in that namespace (wg-quick: see 'Improved Rule-based Routing'/netns docs).",
            "Enable a firewall kill switch that drops traffic leaving the physical interface except to the VPN server and DHCP, e.g.:\n"
            f"  nft add rule inet filter output oifname \"{ifaces[0]}\" udp dport 67 accept\n"
            f"  nft add rule inet filter output oifname \"{ifaces[0]}\" ip daddr <VPN_SERVER_IP> accept\n"
            f"  nft add rule inet filter output oifname \"{ifaces[0]}\" drop",
            "If you cannot do the above, leave this network and use a trusted one (e.g. a mobile hotspot).",
        ]
        return steps


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""
