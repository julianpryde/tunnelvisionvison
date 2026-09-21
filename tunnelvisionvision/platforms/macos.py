from __future__ import annotations

import ipaddress
import re
from typing import Optional, Sequence

from .. import dhcp
from ..model import DhcpLease, Finding, Interface, Route, Snapshot
from ..util import have, log, run
from .base import VPN_NAME_RE, Platform

# netstat flags we ignore: W cloned, L link-layer (ARP/NDP), b broadcast, m multicast, R/B reject/blackhole
SKIP_FLAGS = set("WLbmRB")


# ---------------------------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------------------------
def parse_ifconfig(text: str) -> dict[str, Interface]:
    ifaces: dict[str, Interface] = {}
    cur: Optional[Interface] = None
    for line in text.splitlines():
        m = re.match(r"^(\S+?):\s+flags=\w+<([^>]*)>", line)
        if m:
            flags = m.group(2).split(",")
            name = m.group(1)
            cur = Interface(name=name, up="UP" in flags, is_loopback="LOOPBACK" in flags)
            cur.is_vpn = not cur.is_loopback and bool(VPN_NAME_RE.match(name))
            ifaces[name] = cur
            continue
        if cur is None:
            continue
        line = line.strip()
        m = re.match(r"inet (\S+)(?: --> \S+)? netmask (0x[0-9a-f]+)", line)
        if m:
            plen = bin(int(m.group(2), 16)).count("1")
            cur.addresses.append(ipaddress.ip_interface(f"{m.group(1)}/{plen}"))
            continue
        m = re.match(r"inet6 (\S+?)(?:%\S+)? prefixlen (\d+)", line)
        if m:
            cur.addresses.append(ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}"))
    return ifaces


def _mac_v4_dest(dest: str, flags: str) -> ipaddress.IPv4Network:
    if dest == "default":
        return ipaddress.IPv4Network("0.0.0.0/0")
    addr, _, plen = dest.partition("/")
    octets = addr.split(".")
    full = ".".join((octets + ["0", "0", "0"])[:4])
    if plen:
        return ipaddress.IPv4Network(f"{full}/{plen}", strict=False)
    if "H" in flags or len(octets) == 4:
        return ipaddress.IPv4Network(f"{full}/32")
    return ipaddress.IPv4Network(f"{full}/{8 * len(octets)}", strict=False)


def _mac_v6_dest(dest: str) -> ipaddress.IPv6Network:
    if dest == "default":
        return ipaddress.IPv6Network("::/0")
    addr, _, plen = dest.partition("/")
    addr = addr.split("%")[0]
    return ipaddress.IPv6Network(f"{addr}/{plen or 128}", strict=False)


def parse_netstat(text: str, family: int) -> list[Route]:
    routes = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[0] in ("Destination", "Routing", "Internet:", "Internet6:"):
            continue
        dest, gw, flags, iface = f[0], f[1], f[2], f[3]
        if SKIP_FLAGS & set(flags) or "U" not in flags:
            continue
        try:
            net = _mac_v4_dest(dest, flags) if family == 4 else _mac_v6_dest(dest)
        except ValueError:
            continue
        gateway: Optional[str] = None
        if not gw.startswith("link#"):
            g = gw.split("%")[0]
            if not re.fullmatch(r"([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", g):  # a MAC address means on-link
                gateway = g
        routes.append(Route(dest=net, iface=iface, gateway=gateway, scoped="I" in flags, flags=flags,
                            proto="static" if "S" in flags else ""))
    return routes


def parse_route_get(text: str) -> Optional[str]:
    m = re.search(r"^\s*interface:\s*(\S+)", text, re.M)
    return m.group(1) if m else None


def parse_getpacket(text: str, iface: str) -> Optional[DhcpLease]:
    if "options:" not in text:
        return None
    lease = DhcpLease(iface=iface, source="macOS ipconfig getpacket")
    for line in text.splitlines():
        m = re.match(r"server_identifier \(ip\):\s*(\S+)", line)
        if m:
            lease.server = m.group(1)
            continue
        m = re.match(r"(classless_static_route|option_121|option_249)\s*\((\w+)\):\s*(.*)", line)
        if m:
            value = m.group(3)
            try:
                if m.group(2) == "opaque" or re.match(r"^[0-9a-f]{4}\s", value):
                    # hex dump: "0000  18 0a 00 00 ..." -> strip offsets
                    hexbytes = re.findall(r"\b[0-9a-f]{2}\b", re.sub(r"^\s*[0-9a-f]{4}\s", "", value))
                    lease.classless_routes.extend(dhcp.decode_rfc3442(int(b, 16) for b in hexbytes))
                else:
                    lease.classless_routes.extend(dhcp.parse_route_text(value.replace(";", " ")))
            except ValueError as e:
                log.debug("getpacket option 121 parse: %s", e)
    return lease


def parse_hardware_ports(text: str) -> dict[str, str]:
    """networksetup -listallhardwareports -> {device: port name}"""
    out = {}
    for port, dev in re.findall(r"Hardware Port: (.+)\nDevice: (\S+)", text):
        out[dev] = port
    return out


# ---------------------------------------------------------------------------------------------
class MacPlatform(Platform):
    name = "macos"

    def interfaces(self) -> dict[str, Interface]:
        ifaces = parse_ifconfig(run(["ifconfig", "-a"], check=True).stdout)
        ports = parse_hardware_ports(run(["networksetup", "-listallhardwareports"]).stdout)
        for dev, port in ports.items():
            if dev in ifaces:
                ifaces[dev].description = port
                ifaces[dev].is_wireless = port.lower() in ("wi-fi", "airport")
        return ifaces

    def routes(self) -> list[Route]:
        routes = parse_netstat(run(["netstat", "-rn", "-f", "inet"], check=True).stdout, 4)
        routes += parse_netstat(run(["netstat", "-rn", "-f", "inet6"]).stdout, 6)
        return routes

    def leases(self, interfaces: dict[str, Interface]) -> list[DhcpLease]:
        out = []
        for name, iface in interfaces.items():
            if iface.is_vpn or iface.is_loopback or not iface.up or not any(a.version == 4 for a in iface.addresses):
                continue
            proc = run(["ipconfig", "getpacket", name], timeout=5)
            if proc.returncode == 0:
                lease = parse_getpacket(proc.stdout, name)
                if lease:
                    out.append(lease)
        return out

    def vpn_endpoints(self) -> set[str]:
        eps: set[str] = set()
        if have("wg"):
            for line in run(["wg", "show", "all", "endpoints"]).stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2] != "(none)":
                    eps.add(parts[2].rsplit(":", 1)[0].strip("[]"))
        return eps

    def route_lookup(self, ips: Sequence[str]) -> dict[str, Optional[str]]:
        out = {}
        for ip in ips:
            cmd = ["route", "-n", "get"] + (["-inet6"] if ":" in ip else []) + [ip]
            proc = run(cmd, timeout=5)
            out[ip] = parse_route_get(proc.stdout) if proc.returncode == 0 else None
        return out

    def delete_route(self, route: Route) -> list[str]:
        cmd = ["route", "-n", "delete"]
        if route.dest.version == 6:
            cmd.append("-inet6")
        cmd += ["-host", str(route.dest.network_address)] if route.is_host else ["-net", str(route.dest)]
        cmd += [route.gateway] if route.gateway else ["-interface", route.iface]
        return [self.exec(cmd)]

    def disconnect(self, iface: Interface) -> list[str]:
        if iface.is_wireless:
            return [self.exec(["networksetup", "-setairportpower", iface.name, "off"])]
        return [self.exec(["ifconfig", iface.name, "down"])]

    def manual_steps(self, findings: list[Finding], snap: Snapshot) -> list[str]:
        phys = sorted({f.iface for f in findings if f.iface and f.iface not in snap.vpn_interfaces()}) or ["en0"]
        service = snap.interfaces.get(phys[0]).description if phys[0] in snap.interfaces else "Wi-Fi"
        return [
            "macOS has no switch to ignore DHCP option 121. Routes removed by this tool may be re-added on the next "
            "DHCP renewal; keep TunnelVisionVision running so it can re-apply the fix.",
            "Enable your VPN client's kill switch / 'block connections without VPN' / 'include all networks' option "
            "(Network Extension VPNs honour includeAllNetworks, which routes all traffic into the tunnel regardless of the routing table).",
            "Stop using DHCP on this network by configuring the interface manually (the rogue server can then no longer push routes):\n"
            f"  networksetup -setmanual \"{service or 'Wi-Fi'}\" <your-ip> <subnet-mask> <router>",
            "Or block everything except the VPN server and DHCP on the physical interface with pf (anchor is loaded by the default pf.conf):\n"
            f"  printf 'pass out quick on {phys[0]} proto udp to any port 67\\npass out quick on {phys[0]} to <VPN_SERVER_IP>\\nblock drop out quick on {phys[0]} all\\n' \\\n"
            "    | sudo pfctl -a com.apple/tunnelvisionvision -f - && sudo pfctl -E",
            "If none of that is possible, leave this network and use a trusted one (e.g. a phone hotspot).",
        ]
