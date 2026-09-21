from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
import sys
from typing import Sequence

log = logging.getLogger("tvv")

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Hide console windows when the daemon/agent shell out on Windows.
_CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


class CommandError(RuntimeError):
    pass


def run(cmd: Sequence[str], timeout: float = 15, check: bool = False, input: str | None = None) -> subprocess.CompletedProcess:
    """Run a command, returning the CompletedProcess. Never raises for missing binaries unless check=True."""
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input,
            creationflags=_CREATE_NO_WINDOW,
        )
    except FileNotFoundError as e:
        if check:
            raise CommandError(f"command not found: {cmd[0]}") from e
        return subprocess.CompletedProcess(list(cmd), 127, "", f"command not found: {cmd[0]}")
    except subprocess.TimeoutExpired as e:
        if check:
            raise CommandError(f"timeout: {' '.join(cmd)}") from e
        return subprocess.CompletedProcess(list(cmd), 124, "", "timeout")
    if check and proc.returncode != 0:
        raise CommandError(f"{' '.join(cmd)} failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def in_container() -> bool:
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return True
    if os.environ.get("KUBERNETES_SERVICE_HOST") or os.environ.get("container"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as f:
            data = f.read()
        return any(k in data for k in ("docker", "kubepods", "containerd", "lxc", "libpod"))
    except OSError:
        return False


def ip_net(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(_strip_scope(text.strip()), strict=False)


def _strip_scope(text: str) -> str:
    # "fe80::%en0/64" -> "fe80::/64"
    if "%" in text:
        addr, _, rest = text.partition("%")
        _, _, plen = rest.partition("/")
        return f"{addr}/{plen}" if plen else addr
    return text


def is_special(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Destinations that are never interesting for TunnelVision (local/link/multicast/broadcast)."""
    addr = net.network_address
    if net.version == 4 and net == ipaddress.ip_network("255.255.255.255/32"):
        return True
    return bool(addr.is_loopback or addr.is_link_local or addr.is_multicast or (addr.is_unspecified and net.prefixlen == net.max_prefixlen))


def probe_address(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """A representative host inside `net` to ask the OS routing engine about."""
    if net.prefixlen >= net.max_prefixlen - 1:
        return str(net.network_address)
    return str(net.network_address + 1)
