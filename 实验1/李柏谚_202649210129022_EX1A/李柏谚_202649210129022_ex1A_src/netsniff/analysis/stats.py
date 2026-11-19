"""Statistics: protocol hierarchy, conversations and throughput."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..model import Packet


PROTOCOL_NAMES = {
    "eth": "Ethernet",
    "vlan": "802.1Q VLAN",
    "ip": "IPv4",
    "ipv6": "IPv6",
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "arp": "ARP",
    "dns": "DNS",
    "http": "HTTP",
    "tls": "TLS",
    "dhcp": "DHCP",
    "ntp": "NTP",
    "quic": "QUIC",
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP",
    "mqtt": "MQTT",
    "redis": "Redis",
    "sctp": "SCTP",
    "gre": "GRE",
    "data": "Data",
    "null": "Loopback",
    "sll": "Linux cooked",
    "pppoed": "PPPoE",
    "ipv6.hop": "IPv6 Hop-by-Hop",
    "ipv6.routing": "IPv6 Routing",
    "ipv6.dstopts": "IPv6 Destination Options",
    "ipv6.fragment": "IPv6 Fragment",
    "ipv6.ah": "AH",
    "ipv6.esp": "ESP",
    "esp": "ESP",
    "radiotap": "Radiotap",
    "expert": "Expert Info",
}


@dataclass
class HierarchyNode:
    name: str
    packets: int = 0
    bytes: int = 0
    children: Dict[str, "HierarchyNode"] = field(default_factory=dict)

    def sorted_children(self) -> List["HierarchyNode"]:
        return sorted(self.children.values(), key=lambda n: (-n.packets, n.name))


def protocol_hierarchy(packets: Iterable[Packet]) -> HierarchyNode:
    root = HierarchyNode("Frame")
    for packet in packets:
        root.packets += 1
        root.bytes += packet.wirelen
        node = root
        seen: set[str] = set()
        for key in packet.protocols:
            name = PROTOCOL_NAMES.get(key, key.upper())
            # Guard against pathological loops / duplicated layers in one path
            child_key = name
            if child_key in seen:
                child_key = name + " (2)"
            seen.add(child_key)
            child = node.children.get(child_key)
            if child is None:
                child = HierarchyNode(name if child_key == name else child_key)
                node.children[child_key] = child
            child.packets += 1
            child.bytes += packet.wirelen
            node = child
    return root


@dataclass
class Conversation:
    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    bytes_ab: int = 0
    bytes_ba: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def a_text(self) -> str:
        return f"{self.a_ip}:{self.a_port}" if self.a_port else self.a_ip

    def b_text(self) -> str:
        return f"{self.b_ip}:{self.b_port}" if self.b_port else self.b_ip

    def filter_expression(self) -> str:
        if self.proto in ("ipv4", "ipv6"):
            prefix = "ip" if self.proto == "ipv4" else "ipv6"
            if self.a_ip == self.b_ip:
                return f"{prefix}.addr == {self.a_ip}"
            return f"{prefix}.addr == {self.a_ip} and {prefix}.addr == {self.b_ip}"
        layer = "tcp" if self.proto == "tcp" else "udp"
        ip_prefix = "ipv6" if ":" in self.a_ip else "ip"
        host = ""
        if self.a_ip != self.b_ip:
            host = (
                f" and (({ip_prefix}.src == {self.a_ip} and {ip_prefix}.dst == {self.b_ip})"
                f" or ({ip_prefix}.src == {self.b_ip} and {ip_prefix}.dst == {self.a_ip}))"
            )
        ports = ""
        if self.a_port == self.b_port:
            ports = f"{layer}.port == {self.a_port}"
        else:
            ports = f"{layer}.port == {self.a_port} and {layer}.port == {self.b_port}"
        return ports + host


def conversations(packets: Iterable[Packet], kind: str) -> List[Conversation]:
    """kind: ipv4 | ipv6 | tcp | udp."""
    table: Dict[tuple, Conversation] = {}
    for packet in packets:
        ip = packet.ip
        if ip is None:
            continue
        if kind == "ipv4" and ip.version != 4:
            continue
        if kind == "ipv6" and ip.version != 6:
            continue
        if kind == "tcp" and packet.tcp is None:
            continue
        if kind == "udp" and packet.udp is None:
            continue
        if kind in ("tcp", "udp"):
            layer = packet.tcp if kind == "tcp" else packet.udp
            e1 = (ip.src, layer.sport)
            e2 = (ip.dst, layer.dport)
        else:
            e1 = (ip.src, 0)
            e2 = (ip.dst, 0)
        a, b = (e1, e2) if e1 <= e2 else (e2, e1)
        key = (kind, a, b)
        conv = table.get(key)
        if conv is None:
            conv = Conversation(
                proto=kind,
                a_ip=a[0], a_port=a[1], b_ip=b[0], b_port=b[1],
                first_ts=packet.ts, last_ts=packet.ts,
            )
            table[key] = conv
        conv.packets += 1
        conv.bytes += packet.wirelen
        conv.first_ts = min(conv.first_ts, packet.ts)
        conv.last_ts = max(conv.last_ts, packet.ts)
        if e1 == a:
            conv.bytes_ab += packet.wirelen
        else:
            conv.bytes_ba += packet.wirelen
    return sorted(table.values(), key=lambda c: (-c.packets, c.a_ip, c.a_port))


@dataclass
class CaptureSummary:
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    error_packets: int = 0
    warning_packets: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def pps(self) -> float:
        return self.packets / self.duration if self.duration > 0 else 0.0

    @property
    def bps(self) -> float:
        return self.bytes / self.duration if self.duration > 0 else 0.0


def capture_summary(packets: Iterable[Packet]) -> CaptureSummary:
    summary = CaptureSummary()
    for packet in packets:
        summary.packets += 1
        summary.bytes += packet.wirelen
        if summary.first_ts == 0:
            summary.first_ts = packet.ts
        summary.first_ts = min(summary.first_ts, packet.ts)
        summary.last_ts = max(summary.last_ts, packet.ts)
        if any(msg.startswith("Error") for msg in packet.expert):
            summary.error_packets += 1
        elif any(msg.startswith("Warning") for msg in packet.expert):
            summary.warning_packets += 1
    return summary


def throughput_series(packets: Iterable[Packet], max_points: int = 150) -> List[Tuple[float, int, int]]:
    """Return ``(seconds_since_start, packets, bytes)`` buckets for a chart."""
    plist = list(packets)
    if not plist:
        return []
    start = plist[0].ts
    end = plist[-1].ts
    duration = max(end - start, 0.001)
    bucket = max(duration / max_points, 0.01)
    count = int(duration / bucket) + 1
    pkts = [0] * count
    byte_counts = [0] * count
    for packet in plist:
        index = int((packet.ts - start) / bucket)
        if index < 0:
            index = 0
        elif index >= count:
            index = count - 1
        pkts[index] += 1
        byte_counts[index] += packet.wirelen
    # cap at max_points, merging buckets if the packet timestamps have gaps
    if count > max_points:
        stride = (count + max_points - 1) // max_points
        merged = []
        for i in range(0, count, stride):
            p = sum(pkts[i:i + stride])
            b = sum(byte_counts[i:i + stride])
            merged.append((i * bucket, p, b))
        return merged
    return [(i * bucket, pkts[i], byte_counts[i]) for i in range(count)]


def protocol_counts(packets: Iterable[Packet]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for packet in packets:
        counts[packet.protocol] = counts.get(packet.protocol, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))
