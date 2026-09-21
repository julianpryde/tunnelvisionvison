import base64
import ipaddress
import json
import struct
import unittest
from pathlib import Path

from tunnelvisionvision import dhcp, sniff
from tunnelvisionvision.config import Config
from tunnelvisionvision.detect import analyze
from tunnelvisionvision.model import Severity
from tunnelvisionvision.platforms import linux, macos, windows

from .fakes import FakePlatform

FIX = Path(__file__).parent / "fixtures"


class DhcpTests(unittest.TestCase):
    def test_rfc3442_roundtrip(self):
        routes = [("0.0.0.0/1", "192.168.1.66"), ("128.0.0.0/1", "192.168.1.66"), ("10.1.2.0/24", "192.168.1.1"), ("0.0.0.0/0", "192.168.1.1")]
        enc = dhcp.encode_rfc3442(routes)
        self.assertEqual(enc[:6], bytes([1, 0, 192, 168, 1, 66]))
        self.assertEqual([(str(d), g) for d, g in dhcp.decode_rfc3442(enc)], routes)

    def test_decode_rejects_garbage(self):
        with self.assertRaises(ValueError):
            dhcp.decode_rfc3442(bytes([33, 1, 2, 3, 4, 5]))
        with self.assertRaises(ValueError):
            dhcp.decode_rfc3442(bytes([24, 10, 1]))

    def test_text_formats(self):
        expect = [("10.0.0.0/8", "192.168.1.1"), ("172.16.0.0/12", "192.168.1.1")]
        for text in ("10.0.0.0/8 192.168.1.1 172.16.0.0/12 192.168.1.1",
                     "10.0.0.0/8,192.168.1.1 172.16.0.0/12,192.168.1.1",
                     "8,10,192,168,1,1,12,172,16,192,168,1,1",
                     "8 10 192 168 1 1 12 172 16 192 168 1 1",
                     "08 0a c0 a8 01 01 0c ac 10 c0 a8 01 01",
                     "0x080ac0a801010cac10c0a80101"):
            self.assertEqual([(str(d), g) for d, g in dhcp.parse_route_text(text)], expect, text)

    def test_bootp_packet(self):
        pkt = dhcp.build_dhcp_packet(2, "192.168.1.66", [("0.0.0.0/1", "192.168.1.66")])
        info = dhcp.parse_bootp(pkt)
        self.assertEqual(info["msg_type"], "OFFER")
        self.assertEqual(info["server"], "192.168.1.66")
        self.assertEqual(str(info["classless_routes"][0][0]), "0.0.0.0/1")
        self.assertIsNone(dhcp.parse_bootp(b"\x00" * 100))

    def test_sniffer_ip_udp(self):
        payload = dhcp.build_dhcp_packet(5, "192.168.1.66")
        udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([192, 168, 1, 66]), bytes([255] * 4))
        self.assertEqual(sniff.parse_ip_udp(ip + udp), payload)
        self.assertIsNone(sniff.parse_ip_udp(ip + struct.pack("!HHHH", 68, 67, 8, 0) + payload))
        s = sniff.DhcpSniffer()
        s._record("eth0", payload)
        self.assertEqual(s.recent()[0].msg_type, "ACK")


class LinuxParserTests(unittest.TestCase):
    def test_ip_json(self):
        ifaces = linux.parse_ip_addr_json(json.loads((FIX / "linux_ip_addr.json").read_text()), sysfs=None)
        self.assertTrue(ifaces["wg0"].is_vpn)
        self.assertTrue(ifaces["tun0"].is_vpn)
        self.assertFalse(ifaces["eth0"].is_vpn)
        self.assertFalse(ifaces["docker0"].is_vpn)
        self.assertTrue(ifaces["lo"].is_loopback)
        self.assertEqual(str(ifaces["eth0"].addresses[0]), "192.168.1.50/24")
        routes = linux.parse_ip_route_json(json.loads((FIX / "linux_ip_route4.json").read_text()), 4)
        keys = {(str(r.dest), r.iface, r.table, r.proto) for r in routes}
        self.assertIn(("0.0.0.0/0", "wg0", "51820", ""), keys)
        self.assertIn(("0.0.0.0/1", "eth0", "main", "dhcp"), keys)
        self.assertFalse(any(r.table == "local" for r in routes))

    def test_end_to_end_linux_fixture(self):
        ifaces = linux.parse_ip_addr_json(json.loads((FIX / "linux_ip_addr.json").read_text()), sysfs=None)
        routes = linux.parse_ip_route_json(json.loads((FIX / "linux_ip_route4.json").read_text()), 4)
        leases = linux.parse_dhclient_leases((FIX / "dhclient.leases").read_text())
        p = FakePlatform(ifaces.values(), routes, leases)
        fs = analyze(p.snapshot(), Config(), p)
        crit = sorted(str(f.route.dest) for f in fs if f.severity == Severity.CRITICAL)
        self.assertEqual(crit, ["0.0.0.0/1", "128.0.0.0/1"])

    def test_dhclient(self):
        leases = linux.parse_dhclient_leases((FIX / "dhclient.leases").read_text())
        self.assertEqual(len(leases), 1)  # latest lease for eth0 only
        self.assertEqual(leases[0].server, "192.168.1.66")
        self.assertEqual([str(d) for d, _ in leases[0].classless_routes], ["0.0.0.0/1", "128.0.0.0/1"])

    def test_sd_lease_and_nmcli(self):
        lease = linux.parse_sd_lease("ADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.1.66\nCLASSLESS_ROUTES=0.0.0.0/1,192.168.1.66 128.0.0.0/1,192.168.1.66\n", "eth0", "networkd")
        self.assertEqual(lease.server, "192.168.1.66")
        self.assertEqual(len(lease.classless_routes), 2)
        nm = linux.parse_nmcli("GENERAL.DEVICE:wlp2s0\nDHCP4.OPTION[1]:dhcp_server_identifier = 192.168.1.66\n"
                               "DHCP4.OPTION[2]:classless_static_routes = 0.0.0.0/1 192.168.1.66 128.0.0.0/1 192.168.1.66\n"
                               "GENERAL.DEVICE:lo\n")
        self.assertEqual([(l.iface, l.server, len(l.classless_routes)) for l in nm], [("wlp2s0", "192.168.1.66", 2)])

    def test_proc_net_route(self):
        text = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                "eth0\t00000000\t4201A8C0\t0003\t0\t0\t0\t00000080\t0\t0\t0\n"
                "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
        rs = linux.parse_proc_net_route(text)
        self.assertEqual([(str(r.dest), r.gateway) for r in rs],
                         [("0.0.0.0/0", "192.168.1.1"), ("0.0.0.0/1", "192.168.1.66"), ("192.168.1.0/24", None)])


class MacParserTests(unittest.TestCase):
    def test_ifconfig(self):
        ifaces = macos.parse_ifconfig((FIX / "mac_ifconfig.txt").read_text())
        self.assertEqual(str(ifaces["en0"].addresses[-1]), "192.168.1.254/24")
        self.assertTrue(ifaces["utun4"].is_vpn)
        self.assertTrue(ifaces["lo0"].is_loopback)

    def test_netstat(self):
        rs = macos.parse_netstat((FIX / "mac_netstat_inet.txt").read_text(), 4)
        by = {(str(r.dest), r.iface): r for r in rs}
        self.assertTrue(by[("0.0.0.0/0", "en0")].scoped)
        self.assertEqual(by[("0.0.0.0/1", "en0")].gateway, "192.168.1.66")
        self.assertIn(("128.0.0.0/1", "en0"), by)
        self.assertIn(("192.168.1.0/24", "en0"), by)
        self.assertIn(("169.254.0.0/16", "en0"), by)
        self.assertNotIn(("192.168.1.32/32", "en0"), by)  # ARP entry skipped
        self.assertIsNone(by[("192.168.1.1/32", "en0")].gateway)

    def test_getpacket(self):
        lease = macos.parse_getpacket((FIX / "mac_getpacket.txt").read_text(), "en0")
        self.assertEqual(lease.server, "192.168.1.66")
        self.assertEqual([str(d) for d, _ in lease.classless_routes], ["0.0.0.0/1", "128.0.0.0/1"])
        clean = macos.parse_getpacket("options:\nserver_identifier (ip): 192.168.1.1\n", "en0")
        self.assertEqual(clean.classless_routes, [])

    def test_end_to_end_mac_fixture(self):
        ifaces = macos.parse_ifconfig((FIX / "mac_ifconfig.txt").read_text())
        routes = macos.parse_netstat((FIX / "mac_netstat_inet.txt").read_text(), 4)
        lease = macos.parse_getpacket((FIX / "mac_getpacket.txt").read_text(), "en0")
        p = FakePlatform(ifaces.values(), routes, [lease])
        fs = analyze(p.snapshot(), Config(), p)
        self.assertEqual({str(f.route.dest): f.severity for f in fs if f.route},
                         {"0.0.0.0/1": Severity.CRITICAL, "128.0.0.0/1": Severity.CRITICAL, "203.0.113.10/32": Severity.MEDIUM})

    def test_route_get(self):
        self.assertEqual(macos.parse_route_get("   route to: 1.1.1.1\ndestination: default\n  interface: utun10\n"), "utun10")


class WindowsParserTests(unittest.TestCase):
    def test_state_and_detection(self):
        data = json.loads((FIX / "windows_state.json").read_text())
        blob = b""
        enc = dhcp.encode_rfc3442([("10.0.0.0/8", "192.168.1.66")])
        blob += struct.pack("<IIII", 121, 0, len(enc), 0) + enc + b"\0" * ((4 - len(enc) % 4) % 4)
        blob += struct.pack("<IIII", 54, 0, 4, 0) + bytes([192, 168, 1, 66])
        data["dhcp"][0]["Options"] = base64.b64encode(blob).decode()
        ifaces, routes, leases = windows.parse_windows_state(data)
        self.assertTrue(ifaces["WireGuard Tunnel"].is_vpn)
        self.assertTrue(ifaces["Corp VPN"].is_vpn)  # RAS connection from Get-VpnConnection
        self.assertTrue(ifaces["Wi-Fi"].is_wireless)
        self.assertFalse(ifaces["Wi-Fi"].is_vpn)
        self.assertEqual([str(d) for d, _ in leases[0].classless_routes], ["10.0.0.0/8"])
        p = FakePlatform(ifaces.values(), routes, leases)
        fs = analyze(p.snapshot(), Config(), p)
        top = {str(f.route.dest): f.severity for f in fs if f.route}
        self.assertEqual(top["10.0.0.0/8"], Severity.CRITICAL)
        self.assertEqual(top["203.0.113.10/32"], Severity.MEDIUM)
        self.assertEqual(len(top), 2, top)
        fs = analyze(p.snapshot(), Config(vpn_endpoints=["203.0.113.10"]), p)
        self.assertEqual({str(f.route.dest) for f in fs if f.route}, {"10.0.0.0/8"})

    def test_bad_blob_ignored(self):
        self.assertEqual(windows.parse_dhcp_interface_options(b"\xff" * 40), {})


if __name__ == "__main__":
    unittest.main()
