import unittest

from tunnelvisionvision import actions
from tunnelvisionvision.config import Config
from tunnelvisionvision.detect import DetectContext, analyze
from tunnelvisionvision.model import DhcpLease, DhcpObservation, Route, Severity

from .fakes import FakePlatform, iface, net, wg_attack_platform


def run(p, cfg=None, ctx=None):
    return analyze(p.snapshot(), cfg or Config(), p, ctx)


class DetectTests(unittest.TestCase):
    def test_tunnelvision_with_lease_is_critical_and_confirmed(self):
        p = wg_attack_platform()
        fs = run(p)
        crit = [f for f in fs if f.severity == Severity.CRITICAL]
        self.assertEqual({str(f.route.dest) for f in crit}, {"0.0.0.0/1", "128.0.0.0/1"})
        for f in crit:
            self.assertTrue(f.mitigable)
            self.assertTrue(any("confirmed" in e for e in f.evidence), f.evidence)
            self.assertTrue(any("192.168.1.66" in e for e in f.evidence))

    def test_route_without_lease_is_high(self):
        fs = run(wg_attack_platform(with_lease=False))
        self.assertEqual({f.severity for f in fs if f.route}, {Severity.HIGH})

    def test_policy_routing_shadowed_route_is_not_effective(self):
        # e.g. Tailscale: its rule table is consulted before main, so the OS still picks the VPN.
        p = wg_attack_platform(lookup={"0.0.0.1": "wg0", "128.0.0.1": "wg0"})
        p._lookup.update({ip: "wg0" for ip in Config().canary_ips})
        fs = run(p)
        self.assertTrue(all(f.severity <= Severity.LOW for f in fs), [(f.severity, f.title) for f in fs])
        self.assertTrue(any(f.title.startswith("[not effective]") for f in fs))

    def test_clean_full_tunnel(self):
        ifaces = [iface("en0", "192.168.1.254/24", wireless=True), iface("utun4", "10.8.0.2/32", vpn=True)]
        routes = [
            Route(net("0.0.0.0/0"), "utun4"),
            Route(net("0.0.0.0/0"), "en0", gateway="192.168.1.1", scoped=True),
            Route(net("192.168.1.1/32"), "en0"),                        # on-link router, inside LAN
            Route(net("192.168.1.0/24"), "en0", scoped=True),
            Route(net("169.254.0.0/16"), "en0"),
            Route(net("224.0.0.0/4"), "en0"),
            Route(net("255.255.255.255/32"), "en0"),
            Route(net("203.0.113.10/32"), "en0", gateway="192.168.1.1"),  # VPN server route
        ]
        p = FakePlatform(ifaces, routes, [DhcpLease("en0", "192.168.1.1", [], "test")])
        cfg = Config(vpn_endpoints=["203.0.113.10"])
        self.assertEqual(run(p, cfg), [])
        # without knowing the endpoint it is only a MEDIUM (below the default alert threshold)
        fs = run(p)
        self.assertEqual([f.severity for f in fs], [Severity.MEDIUM])

    def test_host_route_baseline(self):
        ifaces = [iface("eth0", "192.168.1.50/24"), iface("tun0", "10.8.0.2/24", vpn=True)]
        server = Route(net("203.0.113.10/32"), "eth0", gateway="192.168.1.1")
        target = Route(net("198.51.100.7/32"), "eth0", gateway="192.168.1.66")
        routes = [Route(net("0.0.0.0/1"), "tun0"), Route(net("128.0.0.0/1"), "tun0"), server, target]
        p = FakePlatform(ifaces, routes)
        fs = {str(f.route.dest): f.severity for f in run(p, ctx=DetectContext(baseline={server.key()})) if f.route}
        self.assertEqual(fs, {"203.0.113.10/32": Severity.LOW, "198.51.100.7/32": Severity.HIGH})

    def test_split_tunnel_only_covered_space_matters(self):
        ifaces = [iface("eth0", "192.168.1.50/24"), iface("wg0", "10.10.0.2/32", vpn=True)]
        routes = [
            Route(net("10.10.0.0/16"), "wg0"),
            Route(net("0.0.0.0/0"), "eth0", gateway="192.168.1.1"),
            Route(net("8.8.8.0/24"), "eth0", gateway="192.168.1.66"),   # not VPN traffic anyway
            Route(net("10.10.5.0/24"), "eth0", gateway="192.168.1.66"),  # steals corporate subnet
        ]
        fs = run(FakePlatform(ifaces, routes))
        self.assertEqual([str(f.route.dest) for f in fs if f.route], ["10.10.5.0/24"])
        self.assertEqual(fs[0].severity, Severity.HIGH)

    def test_oversized_subnet(self):
        ifaces = [iface("eth0", "10.0.0.5/8"), iface("wg0", "172.16.0.2/32", vpn=True)]
        routes = [Route(net("0.0.0.0/0"), "wg0"), Route(net("10.0.0.0/8"), "eth0")]
        fs = run(FakePlatform(ifaces, routes, lookup={}))
        self.assertEqual([f.code for f in fs], ["oversized-local-subnet"])

    def test_canary_leak(self):
        ifaces = [iface("eth0", "192.168.1.50/24"), iface("wg0", "10.0.0.2/32", vpn=True)]
        routes = [Route(net("0.0.0.0/0"), "wg0", table="51820"), Route(net("0.0.0.0/0"), "eth0", gateway="192.168.1.1")]
        p = FakePlatform(ifaces, routes, lookup={ip: "eth0" for ip in Config().canary_ips})
        fs = run(p)
        self.assertIn("canary-leak", {f.code for f in fs})
        self.assertFalse(any(f.mitigable for f in fs))

    def test_no_vpn_option121_is_low(self):
        ifaces = [iface("eth0", "192.168.1.50/24")]
        lease = DhcpLease("eth0", "192.168.1.66", [(net("0.0.0.0/1"), "192.168.1.66")], "test")
        fs = run(FakePlatform(ifaces, [Route(net("0.0.0.0/1"), "eth0", gateway="192.168.1.66")], [lease]))
        self.assertEqual([(f.code, f.severity) for f in fs], [("dhcp-option-121-present", Severity.LOW)])
        fs = run(FakePlatform(ifaces, [], [lease]), Config(trusted_dhcp_servers=["192.168.1.66"]))
        self.assertEqual([f.severity for f in fs], [Severity.INFO])

    def test_sniffed_rogue_offer(self):
        p = wg_attack_platform(with_lease=False)
        obs = [DhcpObservation("eth0", "192.168.1.66", "OFFER", [(net("0.0.0.0/1"), "192.168.1.66")]),
               DhcpObservation("eth0", "192.168.1.1", "OFFER", [])]
        codes = {f.code: f.severity for f in run(p, ctx=DetectContext(sniffed=obs))}
        self.assertEqual(codes["rogue-dhcp-offer"], Severity.CRITICAL)
        self.assertEqual(codes["multiple-dhcp-servers"], Severity.MEDIUM)

    def test_trusted_routes(self):
        fs = run(wg_attack_platform(), Config(trusted_routes=[net("0.0.0.0/0")]))
        self.assertFalse([f for f in fs if f.route])

    def test_ipv6(self):
        ifaces = [iface("eth0", "2001:db8:1::5/64"), iface("wg0", "fd00::2/128", vpn=True)]
        routes = [Route(net("::/0"), "wg0"), Route(net("2000::/4"), "eth0", gateway="fe80::66")]
        fs = run(FakePlatform(ifaces, routes))
        self.assertEqual([str(f.route.dest) for f in fs if f.route], ["2000::/4"])


class ActionTests(unittest.TestCase):
    def test_mitigate_and_disconnect(self):
        p = wg_attack_platform()
        snap = p.snapshot()
        fs = analyze(snap, Config(), p)
        res = actions.mitigate(p, snap, fs)
        self.assertTrue(res.ok, res.log)
        self.assertEqual({str(r.dest) for r in p.deleted}, {"0.0.0.0/1", "128.0.0.0/1"})
        self.assertFalse([f for f in run(p) if f.route])  # lease still advertises them, but nothing is installed
        res = actions.disconnect(p, snap, fs)
        self.assertEqual(p.disconnected, ["eth0"])

    def test_unmitigable_gives_manual_steps(self):
        ifaces = [iface("eth0", "10.0.0.5/8"), iface("wg0", "172.16.0.2/32", vpn=True)]
        p = FakePlatform(ifaces, [Route(net("0.0.0.0/0"), "wg0"), Route(net("10.0.0.0/8"), "eth0")], lookup={})
        snap = p.snapshot()
        res = actions.mitigate(p, snap, analyze(snap, Config(), p))
        self.assertFalse(res.ok)
        self.assertEqual(res.manual_steps, ["manual step"])


if __name__ == "__main__":
    unittest.main()
