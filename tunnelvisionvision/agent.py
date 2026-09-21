"""Per-user session agent: shows the daemon's alerts and relays the user's choice back to it."""

from __future__ import annotations

import time

from . import api, notify
from .config import Config
from .util import log

POLL = 3.0


def run_agent(cfg: Config) -> None:
    handled: set[str] = set()
    warned = False
    while True:
        try:
            st = api.call(cfg, "/status", timeout=10)
            warned = False
        except Exception as e:
            if not warned:
                log.warning("cannot reach TunnelVisionVision daemon (%s); retrying", e)
                warned = True
            time.sleep(10)
            continue
        alert = st.get("alert")
        if alert and alert["status"] == "open" and alert["id"] not in handled:
            handled.add(alert["id"])
            handle_alert(cfg, alert)
        time.sleep(POLL)


def handle_alert(cfg: Config, alert: dict) -> None:
    notify.notify(notify.TITLE, alert["findings"][0]["title"] if alert.get("findings") else "")
    timeout = cfg.auto_action_delay if cfg.auto_action != "none" else 0
    choice = notify.prompt(alert, timeout=timeout)
    if choice is None:
        log.info("no answer for alert %s", alert["id"])
        return
    try:
        result = api.call(cfg, "/action", {"action": choice, "alert_id": alert["id"], "by": "agent"})
    except Exception as e:
        result = {"action": choice, "ok": False, "log": [f"could not reach the daemon: {e}"], "manual_steps": alert.get("manual_steps", [])}
    notify.show_result(result)
