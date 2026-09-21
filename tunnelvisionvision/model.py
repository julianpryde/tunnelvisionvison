from __future__ import annotations

import enum
import hashlib
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IfAddr = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]


class Severity(enum.IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            return cls[value.strip().upper()]
        return cls(int(value))


@dataclass
class Interface:
    name: str
    index: Optional[int] = None
    addresses: list[IfAddr] = field(default_factory=list)
    up: bool = True
    is_vpn: bool = False
    is_wireless: bool = False
    is_loopback: bool = False
    description: str = ""
    kind: str = ""

    def connected_networks(self) -> list[Network]:
        return [a.network for a in self.addresses]


@dataclass
class Route:
    dest: Network
    iface: str
    gateway: Optional[str] = None  # None means on-link / directly connected
    metric: Optional[int] = None
    table: str = "main"
    proto: str = ""  # OS-reported origin, e.g. "dhcp", "static", "kernel", "NetMgmt"
    scoped: bool = False  # macOS interface-scoped route (only used by sockets bound to iface)
    flags: str = ""
    iface_index: Optional[int] = None

    @property
    def is_host(self) -> bool:
        return self.dest.prefixlen == self.dest.max_prefixlen

    def key(self) -> str:
        return f"{self.dest}|{self.gateway or 'link'}|{self.iface}|{self.table}"

    def describe(self) -> str:
        via = f"via {self.gateway}" if self.gateway else "on-link"
        extra = f" table {self.table}" if self.table not in ("main", "") else ""
        proto = f" proto {self.proto}" if self.proto else ""
        return f"{self.dest} {via} dev {self.iface}{extra}{proto}"

    def to_dict(self) -> dict:
        return {
            "dest": str(self.dest),
            "iface": self.iface,
            "gateway": self.gateway,
            "metric": self.metric,
            "table": self.table,
            "proto": self.proto,
            "scoped": self.scoped,
        }


@dataclass
class DhcpLease:
    iface: str
    server: Optional[str] = None
    classless_routes: list[tuple[Network, str]] = field(default_factory=list)  # (dest, gateway)
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "iface": self.iface,
            "server": self.server,
            "classless_routes": [[str(d), g] for d, g in self.classless_routes],
            "source": self.source,
        }


@dataclass
class DhcpObservation:
    """A DHCP OFFER/ACK seen on the wire by the optional sniffer."""

    iface: str
    server: Optional[str]
    msg_type: str
    classless_routes: list[tuple[Network, str]] = field(default_factory=list)
    seen_at: float = field(default_factory=time.time)


@dataclass
class Snapshot:
    platform: str
    interfaces: dict[str, Interface]
    routes: list[Route]
    leases: list[DhcpLease]
    vpn_endpoints: set[str] = field(default_factory=set)
    in_container: bool = False
    taken_at: float = field(default_factory=time.time)
    errors: list[str] = field(default_factory=list)

    def vpn_interfaces(self) -> set[str]:
        return {n for n, i in self.interfaces.items() if i.is_vpn and i.up}


@dataclass
class Finding:
    severity: Severity
    code: str
    title: str
    detail: str
    iface: Optional[str] = None
    route: Optional[Route] = None
    vpn_route: Optional[Route] = None
    evidence: list[str] = field(default_factory=list)

    @property
    def mitigable(self) -> bool:
        return self.route is not None and self.vpn_route is not None

    def fingerprint(self) -> str:
        basis = f"{self.code}|{self.iface}|{self.route.key() if self.route else self.detail}"
        return hashlib.sha1(basis.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.name,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "iface": self.iface,
            "route": self.route.to_dict() if self.route else None,
            "vpn_route": self.vpn_route.to_dict() if self.vpn_route else None,
            "evidence": self.evidence,
            "mitigable": self.mitigable,
            "fingerprint": self.fingerprint(),
        }
