import socket
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from tunnelvisionvision import api, notify
from tunnelvisionvision.config import Config
from tunnelvisionvision.daemon import Monitor
from tunnelvisionvision.model import Route

from .fakes import net, wg_attack_platform


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.p = wg_attack_platform()
        self.alerts = []
        self.cfg = Config(vpn_grace_seconds=0)
        self.m = Monitor(self.cfg, self.p)
        self.m._emit = lambda a: self.alerts.append(a)

    def test_alert_mitigate_enforce_resolve(self):
        self.m.cycle()
        self.assertEqual(len(self.alerts), 1)
        alert = self.m.alert
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertTrue(alert["mitigable"])
        text = notify.alert_text(alert)
        self.assertIn("0.0.0.0/1", text)
        self.assertIn("Mitigate", text)

        res = self.m.perform("mitigate", alert["id"])
        self.assertTrue(res["ok"], res)
        self.assertTrue(self.m.enforce)
        self.m.cycle()
        self.assertIsNone(self.m.alert)  # resolved
        self.assertEqual(self.m.history[-1]["status"], "mitigated")

        # DHCP renewal re-installs the rogue route: enforcement removes it without a new prompt
        self.p._routes.append(Route(net("0.0.0.0/1"), "eth0", gateway="192.168.1.66", proto="static"))
        self.m.cycle()
        self.assertEqual(len(self.alerts), 1)
        self.assertFalse(any(str(r.dest) == "0.0.0.0/1" and r.iface == "eth0" for r in self.p._routes))

        # VPN goes away -> enforcement stops
        self.p._routes = [r for r in self.p._routes if r.iface != "wg0"]
        self.m.cycle()
        self.assertFalse(self.m.enforce)

    def test_continue_suppresses_until_change(self):
        self.m.cycle()
        a = self.m.alert
        res = self.m.perform("continue", a["id"])
        self.assertTrue(res["ok"])
        self.m.cycle()
        self.m.cycle()
        self.assertEqual(len(self.alerts), 1)
        # a new attack route appears -> new alert
        self.p._routes.append(Route(net("8.8.8.0/24"), "eth0", gateway="192.168.1.66"))
        self.m.cycle()
        self.assertEqual(len(self.alerts), 2)

    def test_remind_after_continue(self):
        self.cfg.remind_after = 0.01
        self.m.cycle()
        self.m.perform("continue", self.m.alert["id"])
        import time
        time.sleep(0.02)
        self.m.cycle()
        self.assertEqual(len(self.alerts), 2)

    def test_disconnect(self):
        self.m.cycle()
        res = self.m.perform("disconnect", self.m.alert["id"])
        self.assertTrue(res["ok"])
        self.assertEqual(self.p.disconnected, ["eth0"])

    def test_stale_alert_id(self):
        self.m.cycle()
        res = self.m.perform("mitigate", "nope")
        self.assertFalse(res["ok"])
        with self.assertRaises(ValueError):
            self.m.perform("explode")

    def test_auto_action(self):
        self.cfg.auto_action, self.cfg.auto_action_delay = "mitigate", 0
        self.m.cycle()
        self.assertEqual(self.m.alert["status"], "mitigated")
        self.assertEqual(self.m.alert["result"]["by"], "auto")


class ApiTests(unittest.TestCase):
    def test_roundtrip_and_auth(self):
        with TemporaryDirectory() as d:
            cfg = Config(state_dir=Path(d), api_port=free_port(), vpn_grace_seconds=0)
            m = Monitor(cfg, wg_attack_platform())
            m._emit = lambda a: None
            m.cycle()
            token = api.write_token(cfg).read_text()
            server = api.serve(cfg, m, token)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                st = api.call(cfg, "/status")
                self.assertEqual(st["alert"]["severity"], "CRITICAL")
                res = api.call(cfg, "/action", {"action": "continue", "alert_id": st["alert"]["id"]})
                self.assertTrue(res["ok"])
                req = urllib.request.Request(f"http://127.0.0.1:{cfg.api_port}/status", headers={"X-TVV-Token": "wrong"})
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req, timeout=5)
                self.assertEqual(cm.exception.code, 401)
            finally:
                server.shutdown()


if __name__ == "__main__":
    unittest.main()
