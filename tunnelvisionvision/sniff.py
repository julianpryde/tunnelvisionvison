"""Optional passive DHCP sniffer: sees rogue OFFER/ACKs (and competing DHCP servers) as they happen.

Linux uses an AF_PACKET socket with an in-kernel BPF filter (no dependencies, needs CAP_NET_RAW).
Other platforms use scapy if it is installed (Windows additionally needs Npcap).
"""

from __future__ import annotations

import collections
import socket
import struct
import threading
from typing import Optional

from . import dhcp
from .model import DhcpObservation
from .util import IS_LINUX, log

# cBPF for SOCK_DGRAM packet sockets (offsets start at the IP header): IPv4/UDP, not a fragment, src port 67.
_BPF = [
    (0x30, 0, 0, 9),          # ldb [9]            ip proto
    (0x15, 0, 5, 17),         # jeq #17 ? next : drop
    (0x28, 0, 0, 6),          # ldh [6]            flags/frag offset
    (0x45, 3, 0, 0x1FFF),     # jset #0x1fff ? drop : next
    (0xB1, 0, 0, 0),          # ldxb 4*([0]&0xf)   x = ip header length
    (0x48, 0, 0, 0),          # ldh [x+0]          udp src port
    (0x15, 1, 0, 67),         # jeq #67 ? accept : drop
    (0x06, 0, 0, 0),          # drop
    (0x06, 0, 0, 0x40000),    # accept
]


def parse_ip_udp(data: bytes) -> Optional[bytes]:
    """Return the UDP payload of an IPv4 packet from a DHCP server (src port 67), else None."""
    if len(data) < 28 or data[0] >> 4 != 4 or data[9] != 17:
        return None
    ihl = (data[0] & 0x0F) * 4
    sport, dport = struct.unpack("!HH", data[ihl : ihl + 4])
    if sport != 67 or dport != 68:
        return None
    return data[ihl + 8 :]


class DhcpSniffer(threading.Thread):
    def __init__(self, maxlen: int = 500):
        super().__init__(daemon=True, name="dhcp-sniffer")
        self.observations: collections.deque[DhcpObservation] = collections.deque(maxlen=maxlen)
        self.error: Optional[str] = None
        self._bpf_buf = None

    def recent(self) -> list[DhcpObservation]:
        return list(self.observations)

    def _record(self, iface: str, payload: bytes) -> None:
        info = dhcp.parse_bootp(payload)
        if not info or info["msg_type"] not in ("OFFER", "ACK"):
            return
        obs = DhcpObservation(iface=iface, server=info["server"], msg_type=info["msg_type"], classless_routes=info["classless_routes"])
        self.observations.append(obs)
        log.info("DHCP %s from %s on %s%s", obs.msg_type, obs.server, iface,
                 f" with option 121: {', '.join(f'{d} via {g}' for d, g in obs.classless_routes)}" if obs.classless_routes else "")

    def run(self) -> None:
        try:
            if IS_LINUX and hasattr(socket, "AF_PACKET"):
                self._run_af_packet()
            else:
                self._run_scapy()
        except Exception as e:
            self.error = str(e)
            log.warning("DHCP sniffer disabled: %s", e)

    def _run_af_packet(self) -> None:
        import ctypes

        s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        try:
            prog = b"".join(struct.pack("HBBI", *ins) for ins in _BPF)
            self._bpf_buf = ctypes.create_string_buffer(prog)
            s.setsockopt(socket.SOL_SOCKET, 26, struct.pack("HL", len(_BPF), ctypes.addressof(self._bpf_buf)))  # SO_ATTACH_FILTER
        except OSError as e:
            log.info("BPF filter not attached (%s); filtering in userspace", e)
        log.info("DHCP sniffer running (AF_PACKET)")
        while True:
            data, addr = s.recvfrom(65535)
            payload = parse_ip_udp(data)
            if payload:
                self._record(addr[0], payload)

    def _run_scapy(self) -> None:
        try:
            from scapy.all import UDP, sniff  # type: ignore
        except ImportError as e:
            raise RuntimeError("scapy is not installed (pip install scapy; Windows also needs Npcap)") from e
        log.info("DHCP sniffer running (scapy)")

        def on_pkt(pkt):
            if UDP in pkt and pkt[UDP].sport == 67:
                self._record(getattr(pkt, "sniffed_on", None) or "?", bytes(pkt[UDP].payload))

        sniff(filter="udp and src port 67", prn=on_pkt, store=False)
