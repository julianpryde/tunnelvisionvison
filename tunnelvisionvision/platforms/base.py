from __future__ import annotations

import re
import shlex
from typing import Iterable, Optional, Sequence

from ..model import DhcpLease, Finding, Interface, Route, Snapshot
from ..util import in_container, log, run

# Interface names commonly used by VPN clients across platforms.
VPN_NAME_RE = re.compile(
    r"^(tun|tap|wg|ppp|utun|ipsec|tailscale|zt|nordlynx|proton|mullvad|vpn|gpd|cscotun|nebula|ovpn|wt|netbird|warp|cloudflare)",
    re.IGNORECASE,
)


class Platform:
    name = "base"

    def __init__(self, extra_vpn_ifaces: Iterable[str] = (), ignore_ifaces: Iterable[str] = (), dry_run: bool = False):
        self.extra_vpn = set(extra_vpn_ifaces)
        self.ignore = set(ignore_ifaces)
        self.dry_run = dry_run

    # ---- collection -------------------------------------------------------------------------
    def interfaces(self) -> dict[str, Interface]:
        raise NotImplementedError

    def routes(self) -> list[Route]:
        raise NotImplementedError

    def leases(self, interfaces: dict[str, Interface]) -> list[DhcpLease]:
        return []

    def vpn_endpoints(self) -> set[str]:
        return set()

    def route_lookup(self, ips: Sequence[str]) -> dict[str, Optional[str]]:
        """Ask the OS which interface it would actually use for each destination."""
        return {}

    def snapshot(self) -> Snapshot:
        errors: list[str] = []
        ifaces: dict[str, Interface] = {}
        routes: list[Route] = []
        leases: list[DhcpLease] = []
        endpoints: set[str] = set()
        try:
            ifaces = self.interfaces()
        except Exception as e:  # keep going with partial data; surface the problem
            errors.append(f"interfaces: {e}")
        for name in self.extra_vpn:
            if name in ifaces:
                ifaces[name].is_vpn = True
        for name in self.ignore:
            ifaces.pop(name, None)
        try:
            routes = [r for r in self.routes() if r.iface not in self.ignore]
        except Exception as e:
            errors.append(f"routes: {e}")
        try:
            leases = self.leases(ifaces)
        except Exception as e:
            errors.append(f"leases: {e}")
        try:
            endpoints = self.vpn_endpoints()
        except Exception as e:
            errors.append(f"vpn endpoints: {e}")
        for err in errors:
            log.warning("collection error: %s", err)
        return Snapshot(self.name, ifaces, routes, leases, endpoints, in_container(), errors=errors)

    # ---- response ---------------------------------------------------------------------------
    def exec(self, cmd: Sequence[str]) -> str:
        """Run a state-changing command (or just describe it in dry-run mode)."""
        pretty = " ".join(shlex.quote(c) for c in cmd)
        if self.dry_run:
            return f"[dry-run] {pretty}"
        proc = run(cmd, timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"{pretty}: {(proc.stderr or proc.stdout).strip()}")
        return pretty

    def pin_route(self, route: Route, vpn_route: Route) -> list[str]:
        """Point `route.dest` at the VPN (same next hop as the covering VPN route)."""
        raise NotImplementedError

    def delete_route(self, route: Route) -> list[str]:
        raise NotImplementedError

    def disconnect(self, iface: Interface) -> list[str]:
        raise NotImplementedError

    def manual_steps(self, findings: list[Finding], snap: Snapshot) -> list[str]:
        return []
