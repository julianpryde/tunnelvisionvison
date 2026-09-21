"""TunnelVision detection logic (platform independent)."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional

from .config import Config
from .model import DhcpObservation, Finding, Network, Route, Severity, Snapshot
from .util import is_special, probe_address

SNIFF_WINDOW = 600  # seconds of DHCP observations considered


@dataclass
class DetectContext:
    # Keys of physical-interface host routes that existed when the VPN came up (None = unknown).
    baseline: Optional[set[str]] = None
    sniffed: list[DhcpObservation] = field(default_factory=list)


def _relevant(r: Route) -> bool:
    return not r.scoped and not is_special(r.dest)


def _covering(dest: Network, vpn_routes: list[Route]) -> Optional[Route]:
    best = None
    for v in vpn_routes:
        if v.dest.version == dest.version and dest.subnet_of(v.dest):
            if best is None or v.dest.prefixlen > best.dest.prefixlen:
                best = v
    return best


def analyze(snap: Snapshot, cfg: Config, platform=None, ctx: Optional[DetectContext] = None) -> list[Finding]:
    ctx = ctx or DetectContext()
    findings: list[Finding] = []
    vpn_ifaces = snap.vpn_interfaces()
    vpn_routes = [r for r in snap.routes if r.iface in vpn_ifaces and _relevant(r)]
    vpn_active = bool(vpn_routes)
    endpoints = set(snap.vpn_endpoints) | set(cfg.vpn_endpoints)
    trusted_servers = set(cfg.trusted_dhcp_servers)

    lease_routes: dict[Network, tuple] = {}
    for lease in snap.leases:
        for dest, gw in lease.classless_routes:
            lease_routes.setdefault(dest, (lease, gw))

    phys_routes = [r for r in snap.routes if r.iface not in vpn_ifaces and _relevant(r)]
    # Filter out interfaces the collector knows are loopback.
    phys_routes = [r for r in phys_routes if not (snap.interfaces.get(r.iface) and snap.interfaces[r.iface].is_loopback)]
    reported_lease_routes: set[Network] = set()
    pending_probes: list[tuple[str, Finding]] = []  # (destination to look up, finding it confirms)

    if vpn_active:
        for r in phys_routes:
            if r.dest.prefixlen == 0:
                continue  # default vs default is decided by metrics/policy; checked by canary probes
            cover = _covering(r.dest, vpn_routes)
            if cover is None:
                continue
            if any(r.dest.subnet_of(t) for t in cfg.trusted_routes if t.version == r.dest.version):
                continue
            iface = snap.interfaces.get(r.iface)
            connected = [c for c in (iface.connected_networks() if iface else []) if c.version == r.dest.version]
            if r.gateway is None and (any(r.dest.subnet_of(c) for c in connected) or (not connected and r.proto == "kernel")):
                limit = cfg.max_local_prefix_v4 if r.dest.version == 4 else cfg.max_local_prefix_v6
                if r.dest in connected and r.dest.prefixlen < limit:
                    f = Finding(
                        Severity.MEDIUM, "oversized-local-subnet",
                        f"Unusually large local subnet {r.dest} on {r.iface} overlaps the VPN",
                        f"{r.iface} has a {r.dest} on-link subnet. Everything in that range is sent directly on the local "
                        f"network instead of through the VPN ({cover.iface}). A rogue DHCP server can widen the subnet mask to do this.",
                        iface=r.iface, evidence=[f"covering VPN route: {cover.describe()}"],
                    )
                    findings.append(f)
                    pending_probes.append((str(r.dest.network_address + r.dest.num_addresses // 2), f))
                continue  # normal LAN / own-address / broadcast routes

            f = Finding(Severity.HIGH, "route-overrides-vpn", "", "", iface=r.iface, route=r, vpn_route=cover)
            f.evidence.append(f"more specific than VPN route {cover.describe()}")
            match = lease_routes.get(r.dest)
            if match:
                lease, gw = match
                reported_lease_routes.add(r.dest)
                f.severity = Severity.CRITICAL
                f.code = "dhcp-route-overrides-vpn"
                f.evidence.append(f"pushed by DHCP server {lease.server or '?'} via option 121 (source: {lease.source})")
            elif r.proto.lower() == "dhcp":
                f.severity = Severity.CRITICAL
                f.code = "dhcp-route-overrides-vpn"
                f.evidence.append("the OS reports this route was installed by the DHCP client")
            elif r.is_host:
                ip = str(r.dest.network_address)
                if ip in endpoints:
                    continue
                if ctx.baseline is not None and r.key() not in ctx.baseline:
                    f.severity = Severity.HIGH
                    f.evidence.append("host route appeared after the VPN connected")
                elif ctx.baseline is not None:
                    f.severity = Severity.LOW
                    f.evidence.append("host route existed when the VPN connected (usually the VPN server route)")
                else:
                    f.severity = Severity.MEDIUM
                    f.evidence.append("host route via the physical network; expected only for the VPN server itself")
            f.title = f"Traffic to {r.dest} bypasses the VPN via {r.iface}"
            f.detail = (f"Route {r.describe()} is more specific than the VPN's {cover.dest} route on {cover.iface}, so traffic "
                        f"to {r.dest} is sent unencrypted on the local network (TunnelVision / CVE-2024-3661).")
            findings.append(f)
            pending_probes.append((probe_address(r.dest), f))

    # --- Confirm route findings with the OS routing engine (handles policy routing & scoping) ---
    if platform is not None and vpn_active:
        probes: dict[str, list[Finding]] = {}
        for ip, f in pending_probes:
            probes.setdefault(ip, []).append(f)
        lookup = platform.route_lookup(list(probes)) if probes else {}
        for ip, fs in probes.items():
            dev = lookup.get(ip)
            for f in fs:
                if dev is None:
                    f.evidence.append(f"could not confirm with an OS route lookup for {ip}")
                elif dev in vpn_ifaces:
                    f.evidence.append(f"OS route lookup for {ip} still selects VPN interface {dev} (not currently leaking)")
                    f.severity = Severity.LOW if f.code == "dhcp-route-overrides-vpn" else Severity.INFO
                    f.title = "[not effective] " + f.title
                else:
                    f.evidence.append(f"confirmed: OS routes {ip} via {dev}, outside the VPN")

        # --- Canary probes: catch leaks the table analysis could not attribute ---
        flagged = [f.route.dest for f in findings if f.route is not None]
        excluded = flagged + [r.dest for r in phys_routes if r.is_host] + list(cfg.trusted_routes)
        for iface in snap.interfaces.values():
            if iface.name not in vpn_ifaces:
                excluded += iface.connected_networks()
        candidates: list[tuple[str, Route]] = []
        samples = list(cfg.canary_ips) + [probe_address(v.dest) for v in vpn_routes if 0 < v.dest.prefixlen <= (24 if v.dest.version == 4 else 64)]
        seen = set()
        for ip in samples:
            if ip in seen or ip in endpoints:
                continue
            seen.add(ip)
            addr = ipaddress.ip_address(ip)
            cover = _covering(ipaddress.ip_network(addr), vpn_routes)
            if cover is None or any(addr in n for n in excluded if n.version == addr.version):
                continue
            candidates.append((ip, cover))
            if len(candidates) >= 24:
                break
        if candidates:
            res = platform.route_lookup([ip for ip, _ in candidates])
            for ip, cover in candidates:
                dev = res.get(ip)
                if dev and dev not in vpn_ifaces:
                    findings.append(Finding(
                        Severity.HIGH, "canary-leak", f"Traffic to {ip} leaves via {dev} instead of the VPN",
                        f"The VPN route {cover.describe()} should carry traffic to {ip}, but the OS routes it via {dev}.",
                        iface=dev, evidence=[f"OS route lookup for {ip} selected {dev}"],
                    ))

    # --- DHCP lease observations -------------------------------------------------------------
    for lease in snap.leases:
        extra = [(d, g) for d, g in lease.classless_routes if d not in reported_lease_routes]
        trusted = lease.server in trusted_servers
        if extra:
            overlapping = [(d, g) for d, g in extra if _covering(d, vpn_routes)]
            sev = Severity.INFO if trusted else (Severity.MEDIUM if vpn_active and overlapping else Severity.LOW)
            listing = ", ".join(f"{d} via {g}" for d, g in extra[:8]) + (" ..." if len(extra) > 8 else "")
            findings.append(Finding(
                sev, "dhcp-option-121-present",
                f"DHCP server {lease.server or '?'} on {lease.iface} pushes static routes (option 121)",
                ("These routes overlap your VPN but are not in effect right now." if vpn_active and overlapping else
                 "Harmless without a VPN, but a VPN started on this network could be bypassed (TunnelVision).")
                + f" Routes: {listing}",
                iface=lease.iface, evidence=[f"source: {lease.source}"] + (["server is in trusted_dhcp_servers"] if trusted else []),
            ))
        if trusted_servers and lease.server and not trusted:
            findings.append(Finding(
                Severity.LOW, "untrusted-dhcp-server", f"DHCP server {lease.server} on {lease.iface} is not in trusted_dhcp_servers",
                "The lease on this interface came from a DHCP server you have not marked as trusted.", iface=lease.iface,
            ))

    # --- Passive sniffer observations -------------------------------------------------------
    now = time.time()
    recent = [o for o in ctx.sniffed if now - o.seen_at < SNIFF_WINDOW]
    servers: dict[str, set[str]] = {}
    for o in recent:
        if o.server:
            servers.setdefault(o.iface, set()).add(o.server)
        bad = [(d, g) for d, g in o.classless_routes if _covering(d, vpn_routes) and d.prefixlen > 0]
        if vpn_active and bad and o.server not in trusted_servers:
            findings.append(Finding(
                Severity.CRITICAL, "rogue-dhcp-offer",
                f"DHCP {o.msg_type} from {o.server} on {o.iface} carries routes that would bypass the VPN",
                "Observed on the wire: " + ", ".join(f"{d} via {g}" for d, g in bad[:8]),
                iface=o.iface, evidence=["passive DHCP sniffer"],
            ))
    for iface, srv in servers.items():
        if len(srv) > 1:
            findings.append(Finding(
                Severity.MEDIUM, "multiple-dhcp-servers", f"Multiple DHCP servers answering on {iface}: {', '.join(sorted(srv))}",
                "More than one DHCP server is responding on this network. One of them may be rogue (DHCP starvation/race is how TunnelVision is delivered).",
                iface=iface, evidence=["passive DHCP sniffer"],
            ))

    # Deduplicate by fingerprint, keep the most severe.
    unique: dict[str, Finding] = {}
    for f in findings:
        k = f.fingerprint()
        if k not in unique or f.severity > unique[k].severity:
            unique[k] = f
    return sorted(unique.values(), key=lambda f: -f.severity)


def summarize(snap: Snapshot) -> dict:
    vpn_routes = [r for r in snap.routes if r.iface in snap.vpn_interfaces() and _relevant(r)]
    return {
        "platform": snap.platform,
        "in_container": snap.in_container,
        # tunnel interfaces that actually carry routes (macOS keeps several idle utunN around)
        "vpn_interfaces": sorted({r.iface for r in vpn_routes}),
        "vpn_active": bool(vpn_routes),
        "vpn_routes": [r.describe() for r in vpn_routes[:20]],
        "dhcp_leases": [l.to_dict() for l in snap.leases],
        "errors": snap.errors,
    }
