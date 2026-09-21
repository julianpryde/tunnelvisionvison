"""Monitoring loop shared by `tvv daemon` (service) and `tvv monitor` (foreground)."""

from __future__ import annotations

import json
import shlex
import subprocess
import threading
import time
import uuid
from typing import Callable, Optional

from . import __version__, actions
from .config import Config
from .detect import DetectContext, analyze, summarize
from .model import Finding, Severity, Snapshot
from .util import IS_LINUX, have, log

AGENT_FRESH = 30  # seconds: an agent that polled this recently is considered present


class Monitor:
    def __init__(self, cfg: Config, platform, on_alert: Optional[Callable[[dict], None]] = None, sniffer=None):
        self.cfg = cfg
        self.platform = platform
        self.on_alert = on_alert
        self.sniffer = sniffer
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.alert: Optional[dict] = None
        self.history: list[dict] = []
        self.acked: dict[str, float] = {}
        self.enforce = False
        self.vpn_since: Optional[float] = None
        self.baseline: set[str] = set()
        self.snap: Optional[Snapshot] = None
        self.findings: list[Finding] = []
        self.last_cycle = 0.0
        self.agents: dict[str, float] = {}

    # ------------------------------------------------------------------------------------------
    def _context(self, snap: Snapshot, vpn_active: bool) -> DetectContext:
        now = time.time()
        ctx = DetectContext(sniffed=self.sniffer.recent() if self.sniffer else [])
        if not vpn_active:
            self.vpn_since, self.baseline = None, set()
            if self.enforce:
                log.info("VPN down: mitigation enforcement stopped")
            self.enforce = False
            return ctx
        vpn = snap.vpn_interfaces()
        host_keys = {r.key() for r in snap.routes if r.iface not in vpn and r.is_host}
        if self.vpn_since is None:
            self.vpn_since = now
            log.info("VPN detected on %s; learning VPN server routes for %ss", ", ".join(summarize(snap)["vpn_interfaces"]), self.cfg.vpn_grace_seconds)
        if now - self.vpn_since < self.cfg.vpn_grace_seconds:
            self.baseline |= host_keys
        else:
            ctx.baseline = self.baseline
        return ctx

    def _evaluate(self) -> tuple[Snapshot, list[Finding]]:
        snap = self.platform.snapshot()
        vpn_active = summarize(snap)["vpn_active"]
        findings = analyze(snap, self.cfg, self.platform, self._context(snap, vpn_active))
        return snap, findings

    def cycle(self) -> None:
        with self.lock:
            snap, findings = self._evaluate()
            alertable = [f for f in findings if f.severity >= self.cfg.notify_min_severity]
            if self.enforce and any(f.mitigable for f in alertable):
                res = actions.mitigate(self.platform, snap, alertable)
                log.warning("re-applied mitigation: %s", "; ".join(res.log))
                snap, findings = self._evaluate()
                alertable = [f for f in findings if f.severity >= self.cfg.notify_min_severity]
            self.snap, self.findings, self.last_cycle = snap, findings, time.time()
            self._update_alert(alertable)
            self._maybe_auto_act()

    def _update_alert(self, alertable: list[Finding]) -> None:
        now = time.time()
        fps = sorted(f.fingerprint() for f in alertable)
        if not alertable:
            if self.alert:
                self._close("resolved" if self.alert["status"] in ("open", "continued") else self.alert["status"])
            return
        remind = self.cfg.remind_after
        unacked = [fp for fp in fps if fp not in self.acked or (remind and now - self.acked[fp] > remind)]
        if self.alert and self.alert["fingerprints"] == fps:
            self.alert["findings"] = [f.to_dict() for f in alertable]  # refresh evidence
            if self.alert["status"] != "continued" or not unacked:
                return  # same situation; re-prompt only once a "continue" acknowledgement expires
        elif not unacked:
            return
        if self.alert:
            self._close("superseded" if self.alert["status"] == "open" else self.alert["status"])
        self.alert = {
            "id": uuid.uuid4().hex[:12],
            "created": now,
            "status": "open",
            "severity": max(f.severity for f in alertable).name,
            "fingerprints": fps,
            "findings": [f.to_dict() for f in alertable],
            "mitigable": any(f.mitigable for f in alertable),
            "vpn_interfaces": summarize(self.snap)["vpn_interfaces"] if self.snap else [],
            "manual_steps": self.platform.manual_steps(alertable, self.snap) if self.snap else [],
            "result": None,
        }
        self._emit(self.alert)

    def _close(self, status: str) -> None:
        log.info("alert %s %s", self.alert["id"], status)
        self.alert["status"] = status
        self.history = (self.history + [self.alert])[-20:]
        self.alert = None

    def _emit(self, alert: dict) -> None:
        log.warning("ALERT %s [%s] %s", alert["id"], alert["severity"], " | ".join(f["title"] for f in alert["findings"]))
        if self.cfg.alert_command:
            try:
                subprocess.run(shlex.split(self.cfg.alert_command), input=json.dumps(alert, default=str), text=True, timeout=30)
            except Exception as e:
                log.error("alert_command failed: %s", e)
        agent_present = any(time.time() - t < AGENT_FRESH for t in self.agents.values())
        if not agent_present and not self.on_alert and IS_LINUX and have("wall"):
            subprocess.run(["wall"], input=f"TunnelVisionVision: possible TunnelVision attack ({alert['severity']}). "
                           f"Run 'tvv status' and 'tvv action mitigate|disconnect|continue'.\n", text=True, timeout=10)
        if self.on_alert:
            threading.Thread(target=self.on_alert, args=(dict(alert),), daemon=True).start()

    def _maybe_auto_act(self) -> None:
        a = self.alert
        if not a or a["status"] != "open" or self.cfg.auto_action == "none":
            return
        if time.time() - a["created"] >= self.cfg.auto_action_delay:
            log.warning("no user response within %ss; applying auto_action=%s", self.cfg.auto_action_delay, self.cfg.auto_action)
            self.perform(self.cfg.auto_action, a["id"], by="auto")

    # ------------------------------------------------------------------------------------------
    def perform(self, action: str, alert_id: Optional[str] = None, by: str = "user") -> dict:
        if action not in actions.ACTIONS:
            raise ValueError(f"unknown action {action!r}; expected one of {', '.join(actions.ACTIONS)}")
        with self.lock:
            if alert_id and (not self.alert or self.alert["id"] != alert_id):
                return {"action": action, "ok": False, "log": ["This alert is no longer current (it was resolved or already answered)."], "manual_steps": []}
            if self.snap is None:
                self.cycle()
            alertable = [f for f in self.findings if f.severity >= Severity.MEDIUM]
            if action == "mitigate":
                res = actions.mitigate(self.platform, self.snap, alertable)
                if any(f.mitigable for f in alertable) and res.ok:
                    self.enforce = True
            elif action == "disconnect":
                res = actions.disconnect(self.platform, self.snap, alertable)
            else:
                for f in alertable:
                    self.acked[f.fingerprint()] = time.time()
                res = actions.acknowledge(self.platform, self.snap, alertable, self.cfg.remind_after)
            log.warning("action %s by %s: ok=%s", action, by, res.ok)
            if self.alert:
                self.alert["result"] = res.to_dict() | {"by": by}
                self.alert["status"] = {"mitigate": "mitigated", "disconnect": "disconnected", "continue": "continued"}[action]
            self.wake.set()
            return res.to_dict()

    def status(self, agent: Optional[str] = None) -> dict:
        if agent:
            self.agents[agent] = time.time()
        with self.lock:
            return {
                "version": __version__,
                "last_cycle": self.last_cycle,
                "alert": self.alert,
                "recent_alerts": self.history[-5:],
                "enforcing_mitigation": self.enforce,
                "findings": [f.to_dict() for f in self.findings],
                "summary": summarize(self.snap) if self.snap else None,
                "sniffer": None if not self.sniffer else (self.sniffer.error or "running"),
            }

    def run_forever(self) -> None:
        while True:
            try:
                self.cycle()
            except Exception:
                log.exception("monitor cycle failed")
            self.wake.wait(self.cfg.poll_interval)
            self.wake.clear()
