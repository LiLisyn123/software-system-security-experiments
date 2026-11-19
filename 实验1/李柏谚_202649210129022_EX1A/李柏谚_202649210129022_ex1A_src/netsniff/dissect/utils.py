"""Small helpers shared by the protocol dissectors."""

from __future__ import annotations

import socket
import struct
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# checksums
# ---------------------------------------------------------------------------

def ones_complement_sum(data: bytes, initial: int = 0) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = initial
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum16(data: bytes, initial: int = 0) -> int:
    total = ones_complement_sum(data, initial)
    return (~total) & 0xFFFF


def verify_checksum(data: bytes) -> bool:
    """True if the buffer (including its checksum field) checks out."""
    return ones_complement_sum(data) == 0xFFFF


def pseudo_header_v4(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!BBH", 0, int(proto), int(length))


def pseudo_header_v6(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!I", int(length)) + b"\x00\x00\x00" + bytes([int(proto)])


def transport_checksum(
    version: int, src: bytes, dst: bytes, proto: int, segment: bytes
) -> int:
    if version == 4:
        initial = ones_complement_sum(pseudo_header_v4(src, dst, proto, len(segment)))
    else:
        initial = ones_complement_sum(pseudo_header_v6(src, dst, proto, len(segment)))
    return checksum16(segment, initial)


def verify_transport_checksum(
    version: int, src: bytes, dst: bytes, proto: int, segment: bytes
) -> bool:
    """Verify a transport checksum including the pseudo header."""
    if version == 4:
        initial = ones_complement_sum(pseudo_header_v4(src, dst, proto, len(segment)))
    else:
        initial = ones_complement_sum(pseudo_header_v6(src, dst, proto, len(segment)))
    return ones_complement_sum(segment, initial) == 0xFFFF


# ---------------------------------------------------------------------------
# address formatting
# ---------------------------------------------------------------------------

def ipv4_str(raw: bytes) -> str:
    if len(raw) < 4:
        return "?.?.?.?"
    return socket.inet_ntoa(raw[:4])


def ipv6_str(raw: bytes) -> str:
    if len(raw) < 16:
        return "::"
    try:
        return socket.inet_ntop(socket.AF_INET6, raw[:16])
    except (OSError, ValueError):
        return ":".join(f"{b:02x}" for b in raw[:16])


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])


def normalize_ip(text: str) -> str:
    return text.split("%", 1)[0].strip()


def is_ipv4(text: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, text)
        return True
    except OSError:
        return False


def is_ipv6(text: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, text.split("%", 1)[0])
        return True
    except OSError:
        return False


def is_mac(text: str) -> bool:
    parts = text.split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)


def safe_text(data: bytes, limit: int = 4096) -> str:
    chunk = data[:limit]
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        return chunk.decode("latin-1", "replace")


def printable(data: bytes, limit: int = 2048) -> str:
    text = safe_text(data, limit)
    return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in text)


# ---------------------------------------------------------------------------
# protocol name tables
# ---------------------------------------------------------------------------

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x0842: "Wake on LAN",
    0x22F0: "AVTP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x8847: "MPLS",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x88A8: "802.1ad QinQ",
    0x88CC: "LLDP",
    0x88E5: "MACsec",
    0x9000: "Ethernet loopback",
}

IP_PROTOS = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    8: "EGP",
    17: "UDP",
    41: "IPv6",
    43: "Routing",
    44: "Fragment",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    60: "Destination Options",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
    136: "UDPLite",
}

TCP_FLAG_NAMES = (
    (0x002, "SYN"),
    (0x010, "ACK"),
    (0x008, "PSH"),
    (0x001, "FIN"),
    (0x004, "RST"),
    (0x020, "URG"),
    (0x040, "ECE"),
    (0x080, "CWR"),
    (0x100, "NS"),
)

TCP_FLAG_KEYS = {
    "fin": 0x001,
    "syn": 0x002,
    "rst": 0x004,
    "psh": 0x008,
    "ack": 0x010,
    "urg": 0x020,
    "ece": 0x040,
    "cwr": 0x080,
    "ns": 0x100,
}


def tcp_flags_text(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return ", ".join(names) if names else "None"


def tcp_flags_bracket(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return "[" + ", ".join(names) + "]" if names else "[]"


SERVICE_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "bootps",
    68: "bootpc",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1883: "mqtt",
    1900: "ssdp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5060: "sip",
    5353: "mdns",
    5355: "llmnr",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


def service_name(port: int) -> str:
    return SERVICE_PORTS.get(int(port), "")
