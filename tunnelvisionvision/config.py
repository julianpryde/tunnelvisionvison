from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .model import Network, Severity
from .util import IS_MACOS, IS_WINDOWS


def default_state_dir() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "TunnelVisionVision"
    if IS_MACOS:
        return Path("/Library/Application Support/TunnelVisionVision")
    return Path("/var/lib/tunnelvisionvision")


def default_config_path() -> Path:
    env = os.environ.get("TVV_CONFIG")
    if env:
        return Path(env)
    if IS_WINDOWS or IS_MACOS:
        return default_state_dir() / "config.json"
    return Path("/etc/tunnelvisionvision/config.json")


@dataclass
class Config:
    poll_interval: float = 5.0
    # Findings at or above this severity raise a user-facing alert.
    notify_min_severity: Severity = Severity.HIGH
    # What the daemon does on its own when nobody answers the prompt: "none", "mitigate", "disconnect".
    auto_action: str = "none"
    # Seconds to wait for a user decision before auto_action is applied (0 = immediately).
    auto_action_delay: float = 120.0
    # Re-prompt about an acknowledged ("continue") alert after this many seconds (0 = never).
    remind_after: float = 3600.0
    trusted_dhcp_servers: list[str] = field(default_factory=list)
    trusted_routes: list[Network] = field(default_factory=list)
    vpn_interfaces: list[str] = field(default_factory=list)  # extra interface names to treat as VPN
    ignore_interfaces: list[str] = field(default_factory=list)
    vpn_endpoints: list[str] = field(default_factory=list)  # VPN server IPs whose host routes are expected
    # Local subnets larger than this (smaller prefix) that overlap VPN coverage are flagged.
    max_local_prefix_v4: int = 16
    max_local_prefix_v6: int = 48
    # Seconds after a VPN interface appears during which new physical routes are treated as the VPN's own.
    vpn_grace_seconds: float = 20.0
    canary_ips: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "64.6.64.6", "129.250.35.250", "2606:4700:4700::1111", "2001:4860:4860::8888"])
    sniff: bool = False  # passive DHCP sniffing (requires scapy + raw socket privileges)
    alert_command: str = ""  # run with alert JSON on stdin (e.g. forward to SIEM/webhook)
    api_host: str = "127.0.0.1"
    api_port: int = 47121
    state_dir: Path = field(default_factory=default_state_dir)
    dry_run: bool = False

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        cfg = cls()
        path = path or default_config_path()
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            cfg.update(data)
        return cfg

    def update(self, data: dict) -> None:
        for key, value in data.items():
            if key.startswith("_"):
                continue
            if not hasattr(self, key):
                raise ValueError(f"unknown config key: {key}")
            if key == "notify_min_severity":
                value = Severity.parse(value)
            elif key == "trusted_routes":
                value = [ipaddress.ip_network(v, strict=False) for v in value]
            elif key == "state_dir":
                value = Path(value)
            elif key == "auto_action" and value not in ("none", "mitigate", "disconnect"):
                raise ValueError("auto_action must be none, mitigate or disconnect")
            setattr(self, key, value)
