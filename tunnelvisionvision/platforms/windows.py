from __future__ import annotations

import base64
import ipaddress
import json
import re
import struct
from typing import Optional, Sequence

from .. import dhcp
from ..model import DhcpLease, Finding, Interface, Route, Snapshot
from ..util import log, run
from .base import VPN_NAME_RE, Platform

VPN_DESC_RE = re.compile(
    r"(tap-windows|tap-win32|wintun|wireguard|openvpn|anyconnect|cisco|fortinet|forticlient|pangp|globalprotect|juniper|"
    r"pulse secure|ivanti|check ?point|sonicwall|zscaler|tailscale|zerotier|nordlynx|mullvad|proton|windscribe|expressvpn|"
    r"private internet access|surfshark|cloudflare warp|netbird|\bvpn\b|ppp adapter|wan miniport)",
    re.IGNORECASE,
)

COLLECT_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object { [pscustomobject]@{ Name=$_.Name; InterfaceIndex=$_.InterfaceIndex; Description=$_.InterfaceDescription; Status="$($_.Status)"; PhysicalMediaType="$($_.PhysicalMediaType)"; NdisPhysicalMedium=[int]$_.NdisPhysicalMedium } })
$ipifs = @(Get-NetIPInterface | ForEach-Object { [pscustomobject]@{ Alias=$_.InterfaceAlias; InterfaceIndex=$_.InterfaceIndex; Family="$($_.AddressFamily)"; Metric=[int]$_.InterfaceMetric; State="$($_.ConnectionState)" } })
$addrs = @(Get-NetIPAddress | ForEach-Object { [pscustomobject]@{ InterfaceIndex=$_.InterfaceIndex; Alias=$_.InterfaceAlias; IP="$($_.IPAddress)"; Prefix=[int]$_.PrefixLength } })
$routes = @(Get-NetRoute -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{ Dest=$_.DestinationPrefix; NextHop=$_.NextHop; InterfaceIndex=$_.InterfaceIndex; Alias=$_.InterfaceAlias; Metric=[int]$_.RouteMetric; Protocol="$($_.Protocol)" } })
$vpn = @(@(Get-VpnConnection) + @(Get-VpnConnection -AllUserConnection) | Where-Object { "$($_.ConnectionStatus)" -eq 'Connected' } | ForEach-Object { $_.Name })
$dhcp = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
  $opts = $null
  $p = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.SettingID)"
  if ($p.DhcpInterfaceOptions) { $opts = [Convert]::ToBase64String([byte[]]$p.DhcpInterfaceOptions) }
  [pscustomobject]@{ InterfaceIndex=$_.InterfaceIndex; DHCPEnabled=[bool]$_.DHCPEnabled; DHCPServer=$_.DHCPServer; Options=$opts } })
ConvertTo-Json -InputObject ([pscustomobject]@{ adapters=$adapters; ipifs=$ipifs; addrs=$addrs; routes=$routes; vpn=$vpn; dhcp=$dhcp }) -Depth 4 -Compress
"""

LOOKUP_PS = r"""
$ips = @(%s)
$out = foreach ($ip in $ips) {
  $r = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1
  [pscustomobject]@{ ip=$ip; iface=$r.InterfaceAlias }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def powershell(script: str) -> list[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]


def _aslist(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------------------------
def parse_dhcp_interface_options(blob: bytes) -> dict[int, bytes]:
    """Best-effort decoder for the undocumented DhcpInterfaceOptions registry value.

    Observed layout: repeated records of {u32 option, u32 is_vendor, u32 length, u32 expiry, data, pad to 4}.
    Some builds omit the expiry field; we accept whichever layout consumes the buffer cleanly.
    """
    for header in (16, 12):
        opts: dict[int, bytes] = {}
        i, ok = 0, True
        while i + header <= len(blob):
            code, vendor, length = struct.unpack_from("<III", blob, i)
            if code > 255 or length > len(blob) - i - header or vendor > 1:
                ok = False
                break
            data = blob[i + header : i + header + length]
            if not vendor:
                opts[code] = data
            i += header + length + ((4 - length % 4) % 4)
        if ok and len(blob) - i < 4:
            return opts
    return {}


def parse_windows_state(data: dict, extra_vpn: set[str] = frozenset()) -> tuple[dict[str, Interface], list[Route], list[DhcpLease]]:
    vpn_conns = set(_aslist(data.get("vpn")))
    ifaces: dict[str, Interface] = {}
    by_index: dict[int, Interface] = {}
    for a in _aslist(data.get("adapters")):
        iface = Interface(
            name=a["Name"],
            index=a.get("InterfaceIndex"),
            description=a.get("Description") or "",
            up=a.get("Status") == "Up",
            is_wireless="802.11" in (a.get("PhysicalMediaType") or "") or a.get("NdisPhysicalMedium") == 9,
        )
        ifaces[iface.name] = iface
        if iface.index is not None:
            by_index[iface.index] = iface
    metrics: dict[tuple[int, int], int] = {}
    for i in _aslist(data.get("ipifs")):
        idx = i.get("InterfaceIndex")
        fam = 6 if "6" in (i.get("Family") or "") else 4
        metrics[(idx, fam)] = i.get("Metric") or 0
        if idx not in by_index:
            iface = Interface(name=i["Alias"], index=idx, up=i.get("State") == "Connected")
            ifaces[iface.name] = by_index[idx] = iface
        elif i.get("State") == "Connected":
            by_index[idx].up = True
        if "loopback" in (i.get("Alias") or "").lower():
            by_index[idx].is_loopback = True
    for iface in ifaces.values():
        iface.is_vpn = not iface.is_loopback and (
            iface.name in vpn_conns or iface.name in extra_vpn or bool(VPN_DESC_RE.search(iface.description)) or bool(VPN_NAME_RE.match(iface.name))
        )
    for a in _aslist(data.get("addrs")):
        iface = by_index.get(a.get("InterfaceIndex"))
        if iface is None:
            continue
        try:
            iface.addresses.append(ipaddress.ip_interface(f"{a['IP'].split('%')[0]}/{a['Prefix']}"))
        except (ValueError, KeyError):
            pass
    routes = []
    for r in _aslist(data.get("routes")):
        iface = by_index.get(r.get("InterfaceIndex"))
        if iface is None or iface.is_loopback:
            continue
        try:
            net = ipaddress.ip_network(r["Dest"], strict=False)
        except (ValueError, KeyError):
            continue
        nh = r.get("NextHop") or ""
        gateway = None if nh in ("0.0.0.0", "::", "") else nh
        metric = (r.get("Metric") or 0) + metrics.get((iface.index, net.version), 0)
        routes.append(Route(dest=net, iface=iface.name, gateway=gateway, metric=metric, proto=r.get("Protocol") or "", iface_index=iface.index))
    leases = []
    for d in _aslist(data.get("dhcp")):
        iface = by_index.get(d.get("InterfaceIndex"))
        if iface is None or not d.get("DHCPEnabled"):
            continue
        lease = DhcpLease(iface=iface.name, server=d.get("DHCPServer"), source="Windows DHCP client")
        if d.get("Options"):
            try:
                opts = parse_dhcp_interface_options(base64.b64decode(d["Options"]))
                for code in (dhcp.OPT_CLASSLESS_ROUTES, dhcp.OPT_MS_CLASSLESS_ROUTES):
                    if code in opts:
                        lease.classless_routes.extend(dhcp.decode_rfc3442(opts[code]))
                        lease.source = "Windows DHCP client (registry DhcpInterfaceOptions)"
            except ValueError as e:
                log.debug("DhcpInterfaceOptions parse: %s", e)
        leases.append(lease)
    return ifaces, routes, leases


# ---------------------------------------------------------------------------------------------
class WindowsPlatform(Platform):
    name = "windows"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._cache: Optional[tuple] = None

    def _collect(self):
        proc = run(powershell(COLLECT_PS), timeout=60, check=True)
        self._cache = parse_windows_state(json.loads(proc.stdout), self.extra_vpn)
        return self._cache

    def interfaces(self) -> dict[str, Interface]:
        return self._collect()[0]

    def routes(self) -> list[Route]:
        return (self._cache or self._collect())[1]

    def leases(self, interfaces) -> list[DhcpLease]:
        leases = (self._cache or self._collect())[2]
        self._cache = None
        return leases

    def route_lookup(self, ips: Sequence[str]) -> dict[str, Optional[str]]:
        if not ips:
            return {}
        proc = run(powershell(LOOKUP_PS % ",".join(ps_quote(i) for i in ips)), timeout=60)
        try:
            return {row["ip"]: row.get("iface") for row in _aslist(json.loads(proc.stdout))}
        except (ValueError, TypeError, KeyError):
            return {}

    def delete_route(self, route: Route) -> list[str]:
        nh = route.gateway or ("0.0.0.0" if route.dest.version == 4 else "::")
        script = (
            f"Remove-NetRoute -DestinationPrefix {ps_quote(route.dest)} -InterfaceIndex {int(route.iface_index or 0)} "
            f"-NextHop {ps_quote(nh)} -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop"
        )
        self.exec(powershell(script))
        return [f"powershell: {script}"]

    def disconnect(self, iface: Interface) -> list[str]:
        if iface.is_wireless:
            return [self.exec(["netsh", "wlan", "disconnect", f"interface={iface.name}"])]
        script = f"Disable-NetAdapter -Name {ps_quote(iface.name)} -Confirm:$false -ErrorAction Stop"
        self.exec(powershell(script))
        return [f"powershell: {script}"]

    def manual_steps(self, findings: list[Finding], snap: Snapshot) -> list[str]:
        phys = sorted({f.iface for f in findings if f.iface and f.iface not in snap.vpn_interfaces()}) or ["Wi-Fi"]
        return [
            "Windows has no supported setting to ignore DHCP option 121. Routes removed by this tool may return on the next "
            "DHCP renewal; keep TunnelVisionVision running so it can re-apply the fix.",
            "Turn on your VPN client's firewall-based lockdown ('block traffic outside the VPN', 'always require VPN', WFP kill switch). "
            "A kill switch that only reacts to the VPN disconnecting will NOT trip during TunnelVision.",
            "Stop using DHCP on this network so the rogue server cannot push routes (elevated prompt):\n"
            f"  netsh interface ipv4 set address name=\"{phys[0]}\" static <your-ip> <subnet-mask> <gateway>\n"
            f"  netsh interface ipv4 set dnsservers name=\"{phys[0]}\" static <dns-server> primary",
            "Or block the physical adapter for everything except the VPN server (Windows Firewall block rules beat allow rules, "
            "so exclude the VPN server from the blocked range):\n"
            f"  New-NetFirewallRule -DisplayName 'TVV non-VPN block' -Direction Outbound -InterfaceAlias '{phys[0]}' -Action Block "
            "-RemoteAddress 0.0.0.0-<VPN_IP minus 1>,<VPN_IP plus 1>-255.255.255.254",
            "If none of that is possible, leave this network and use a trusted one (e.g. a phone hotspot).",
        ]
