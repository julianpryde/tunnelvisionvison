from __future__ import annotations

from ..util import IS_LINUX, IS_MACOS, IS_WINDOWS
from .base import Platform


def get_platform(cfg) -> Platform:
    kwargs = dict(extra_vpn_ifaces=cfg.vpn_interfaces, ignore_ifaces=cfg.ignore_interfaces, dry_run=cfg.dry_run)
    if IS_LINUX:
        from .linux import LinuxPlatform

        return LinuxPlatform(**kwargs)
    if IS_MACOS:
        from .macos import MacPlatform

        return MacPlatform(**kwargs)
    if IS_WINDOWS:
        from .windows import WindowsPlatform

        return WindowsPlatform(**kwargs)
    raise SystemExit("unsupported platform")
