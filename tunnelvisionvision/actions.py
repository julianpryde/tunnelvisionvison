"""User-selectable responses: mitigate, disconnect, continue."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Finding, Severity, Snapshot
from .util import is_admin, log

ACTIONS = ("mitigate", "disconnect", "continue")


@dataclass
class ActionResult:
    action: str
    ok: bool
    log: list[str] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"action": self.action, "ok": self.ok, "log": self.log, "manual_steps": self.manual_steps}


def _needs_admin(platform, action: str) -> ActionResult | None:
    if platform.dry_run or is_admin():
        return None
    return ActionResult(action, False, [f"'{action}' needs administrator/root privileges. Run the TunnelVisionVision "
                                        "service (tvv daemon) or re-run this command elevated."])


def actionable(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity >= Severity.MEDIUM]


def mitigate(platform, snap: Snapshot, findings: list[Finding]) -> ActionResult:
    manual = platform.manual_steps(findings, snap)
    denied = _needs_admin(platform, "mitigate")
    if denied:
        denied.manual_steps = manual
        return denied
    res = ActionResult("mitigate", True, manual_steps=manual)
    targets = [f for f in actionable(findings) if f.mitigable]
    for f in targets:
        try:
            res.log += platform.delete_route(f.route)
            res.log.append(f"removed rogue route {f.route.describe()}; traffic falls back to VPN route {f.vpn_route.dest} on {f.vpn_route.iface}")
        except Exception as e:
            res.ok = False
            res.log.append(f"FAILED to remove {f.route.describe()}: {e}")
    manual_only = [f for f in actionable(findings) if not f.mitigable]
    for f in manual_only:
        res.log.append(f"cannot fix automatically: {f.title} (see manual steps)")
    if manual_only and not targets:
        res.ok = False
    if targets:
        res.log.append("Mitigation stays active while the VPN is up: routes re-pushed by DHCP will be removed again.")
    log.info("mitigate: %s", "; ".join(res.log))
    return res


def physical_ifaces(snap: Snapshot, findings: list[Finding]) -> list[str]:
    vpn = snap.vpn_interfaces()
    names = [f.iface for f in actionable(findings) if f.iface and f.iface not in vpn and f.iface in snap.interfaces]
    if not names:
        # fall back to whatever carries a physical default route
        names = [r.iface for r in snap.routes if r.dest.prefixlen == 0 and r.iface not in vpn and r.iface in snap.interfaces
                 and not snap.interfaces[r.iface].is_loopback]
    return list(dict.fromkeys(names))


def disconnect(platform, snap: Snapshot, findings: list[Finding]) -> ActionResult:
    denied = _needs_admin(platform, "disconnect")
    if denied:
        return denied
    res = ActionResult("disconnect", True)
    names = physical_ifaces(snap, findings)
    if not names:
        return ActionResult("disconnect", False, ["could not determine which network interface to disconnect"])
    for name in names:
        try:
            res.log += platform.disconnect(snap.interfaces[name])
            res.log.append(f"disconnected {name}")
        except Exception as e:
            res.ok = False
            res.log.append(f"FAILED to disconnect {name}: {e}")
    res.manual_steps = [
        f"Your connection on {', '.join(names)} was shut down to stop VPN traffic leaking. Reconnect only to a network you trust "
        "(or a phone hotspot); if the alert reappears, the new network is also pushing hostile routes."
    ]
    log.warning("disconnect: %s", "; ".join(res.log))
    return res


def acknowledge(platform, snap: Snapshot, findings: list[Finding], remind_after: float) -> ActionResult:
    when = f"in {int(remind_after // 60)} minutes" if remind_after else "not again for these findings"
    return ActionResult(
        "continue", True,
        [f"Continuing on a vulnerable network. Traffic matching the routes listed in the alert is NOT protected by your VPN. "
         f"You will be reminded {when}, or immediately if the situation changes."],
        platform.manual_steps(findings, snap),
    )
