"""DHCP helpers: RFC 3442 decoding and a minimal BOOTP/DHCP packet parser."""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
from typing import Iterable, Optional

from .model import Network

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_CLASSLESS_ROUTES = 121
OPT_MS_CLASSLESS_ROUTES = 249  # Microsoft's pre-standard copy of option 121
OPT_PAD = 0
OPT_END = 255

MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
DHCP_MAGIC = b"\x63\x82\x53\x63"


def decode_rfc3442(data: Iterable[int]) -> list[tuple[Network, str]]:
    """Decode the RFC 3442 wire format: <width><significant dest octets><4-byte router>..."""
    b = bytes(data)
    routes: list[tuple[Network, str]] = []
    i = 0
    while i < len(b):
        width = b[i]
        i += 1
        if width > 32:
            raise ValueError(f"invalid prefix width {width}")
        sig = (width + 7) // 8
        if i + sig + 4 > len(b):
            raise ValueError("truncated classless route option")
        dest = b[i : i + sig] + b"\x00" * (4 - sig)
        i += sig
        router = socket.inet_ntoa(b[i : i + 4])
        i += 4
        net = ipaddress.IPv4Network((socket.inet_ntoa(dest), width), strict=False)
        routes.append((net, router))
    return routes


def parse_route_text(text: str) -> list[tuple[Network, str]]:
    """Parse the many textual renderings DHCP clients use for option 121.

    Handles:
      * "10.0.0.0/8 192.168.1.1 172.16.0.0/12 192.168.1.1"   (NetworkManager, dhcpcd)
      * "10.0.0.0/8,192.168.1.1 172.16.0.0/12,192.168.1.1"   (systemd-networkd lease files)
      * "24,10,1,2,192,168,1,1"  /  "24 10 1 2 192 168 1 1"  (dhclient / NM-dhclient byte lists)
      * "18 0a 00 00 c0 a8 01 01" or "0x180a0000c0a80101"      (hex dumps)
    """
    text = text.strip().strip("'\"{}")
    if not text:
        return []
    if "/" in text:
        tokens = [t for t in re.split(r"[\s,;]+", text) if t]
        out = []
        it = iter(tokens)
        for tok in it:
            if "/" not in tok:
                continue
            gw = next(it, "0.0.0.0")
            out.append((ipaddress.ip_network(tok, strict=False), gw))
        return out
    tokens = [t for t in re.split(r"[\s,:]+", text) if t]
    if len(tokens) == 1 and tokens[0].lower().startswith("0x"):
        return decode_rfc3442(bytes.fromhex(tokens[0][2:]))
    if all(re.fullmatch(r"\d{1,3}", t) for t in tokens):
        return decode_rfc3442(int(t) for t in tokens)
    if all(re.fullmatch(r"[0-9a-fA-F]{1,2}", t) for t in tokens):
        return decode_rfc3442(int(t, 16) for t in tokens)
    raise ValueError(f"unrecognised classless route format: {text[:80]}")


def parse_options(data: bytes) -> dict[int, bytes]:
    """Parse a DHCP options field (after the magic cookie). Repeated options are concatenated (RFC 3396)."""
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == OPT_PAD:
            i += 1
            continue
        if code == OPT_END:
            break
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2 : i + 2 + length]
        opts[code] = opts.get(code, b"") + value
        i += 2 + length
    return opts


def parse_bootp(payload: bytes) -> Optional[dict]:
    """Parse a BOOTP/DHCP message. Returns None if it is not DHCP."""
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC:
        return None
    op = payload[0]
    yiaddr = socket.inet_ntoa(payload[16:20])
    siaddr = socket.inet_ntoa(payload[20:24])
    opts = parse_options(payload[240:])
    msg_type = MSG_TYPES.get(opts.get(OPT_MSG_TYPE, b"\x00")[0], "UNKNOWN") if opts.get(OPT_MSG_TYPE) else "BOOTP"
    server = socket.inet_ntoa(opts[OPT_SERVER_ID][:4]) if len(opts.get(OPT_SERVER_ID, b"")) >= 4 else None
    routes: list[tuple[Network, str]] = []
    for code in (OPT_CLASSLESS_ROUTES, OPT_MS_CLASSLESS_ROUTES):
        if code in opts:
            try:
                routes.extend(decode_rfc3442(opts[code]))
            except ValueError:
                pass
    return {
        "op": op,
        "msg_type": msg_type,
        "yiaddr": yiaddr,
        "siaddr": siaddr,
        "server": server,
        "classless_routes": routes,
        "options": opts,
    }


def encode_rfc3442(routes: Iterable[tuple[str, str]]) -> bytes:
    """Inverse of decode_rfc3442; used by tests and the lab tooling."""
    out = bytearray()
    for dest, gw in routes:
        net = ipaddress.IPv4Network(dest, strict=False)
        sig = (net.prefixlen + 7) // 8
        out.append(net.prefixlen)
        out += net.network_address.packed[:sig]
        out += socket.inet_aton(gw)
    return bytes(out)


def build_dhcp_packet(msg_type: int, server: str, routes: Iterable[tuple[str, str]] = ()) -> bytes:
    """Build a minimal DHCP reply (for tests)."""
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, 0x1234, 0, 0,
                         b"\0" * 4, socket.inet_aton("192.168.1.50"), socket.inet_aton(server), b"\0" * 4,
                         b"\0" * 16, b"\0" * 64, b"\0" * 128)
    opts = bytearray(DHCP_MAGIC)
    opts += bytes([OPT_MSG_TYPE, 1, msg_type])
    opts += bytes([OPT_SERVER_ID, 4]) + socket.inet_aton(server)
    enc = encode_rfc3442(routes)
    if enc:
        opts += bytes([OPT_CLASSLESS_ROUTES, len(enc)]) + enc
    opts.append(OPT_END)
    return header + bytes(opts)
