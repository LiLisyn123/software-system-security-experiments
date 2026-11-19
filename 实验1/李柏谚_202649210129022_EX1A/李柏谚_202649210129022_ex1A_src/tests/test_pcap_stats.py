"""pcap I/O and statistics tests."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from netsniff.analysis.stats import (
    capture_summary,
    conversations,
    protocol_hierarchy,
    throughput_series,
)
from netsniff.capture.pcapfile import PcapFormatError, PcapWriter, iter_pcap, read_pcap, write_pcap
from netsniff.config import SAMPLES_DIR
from netsniff.dissect import dissect_packet

DEMO = SAMPLES_DIR / "demo.pcap"


def _load_demo():
    header, records = read_pcap(DEMO)
    packets = [
        dissect_packet(record.data, index, record.ts, record.wirelen, header.linktype)
        for index, record in enumerate(records, 1)
    ]
    return header, records, packets


def test_demo_pcap_exists_and_parses():
    assert DEMO.is_file(), "run tools/make_demo_pcap.py first"
    header, records, packets = _load_demo()
    assert header.linktype == 1
    assert len(records) == len(packets) == 40
    protocols = {pkt.protocol for pkt in packets}
    assert {"ARP", "DNS", "HTTP", "TCP", "ICMP", "ICMPv6", "TLSv1.3", "NTP", "QUIC"} <= protocols
    assert not [pkt for pkt in packets if pkt.has_error]


def test_pcap_round_trip(work_dir):
    header, records, packets = _load_demo()
    out = work_dir / "roundtrip.pcap"
    count = write_pcap(out, packets, header.linktype)
    assert count == len(packets)
    header2, records2 = read_pcap(out)
    assert header2.linktype == header.linktype
    assert len(records2) == len(records)
    for before, after in zip(records, records2):
        assert abs(before.ts - after.ts) < 1e-5
        assert before.data == after.data
        assert before.wirelen == after.wirelen


def test_pcap_writer_and_iter(work_dir):
    path = work_dir / "small.pcap"
    with PcapWriter(path, linktype=1) as writer:
        writer.write(1_770_000_000.123456, b"\x00\x01\x02", 3)
        writer.write(1_770_000_001.5, b"\x03" * 10, 12)
    items = list(iter_pcap(path))
    assert len(items) == 2
    header, first = items[0]
    assert header.linktype == 1
    assert first.data == b"\x00\x01\x02"
    assert first.wirelen == 3
    assert abs(first.ts - 1_770_000_000.123456) < 1e-5


def test_bad_file(work_dir):
    path = work_dir / "bad.pcap"
    path.write_bytes(b"not a pcap")
    with pytest.raises(PcapFormatError):
        read_pcap(path)


def test_protocol_hierarchy():
    _, _, packets = _load_demo()
    root = protocol_hierarchy(packets)
    assert root.packets == 40
    names = {child.name: child for child in root.sorted_children()}
    assert names["Ethernet"].packets == 40
    ipv4 = names["Ethernet"].children["IPv4"]
    assert ipv4.packets == 35
    assert names["Ethernet"].children["IPv6"].packets == 2
    http_node = ipv4.children["TCP"].children["HTTP"]
    assert http_node.packets == 4


def test_conversations():
    _, _, packets = _load_demo()
    tcp = conversations(packets, "tcp")
    assert len(tcp) >= 4
    http_conv = next(conv for conv in tcp if conv.a_port == 52000 or conv.b_port == 52000)
    assert http_conv.packets == 15
    assert http_conv.bytes_ab > 0 and http_conv.bytes_ba > 0
    expression = http_conv.filter_expression()
    assert "tcp.port == 52000" in expression
    ipv4 = conversations(packets, "ipv4")
    assert ipv4
    assert conversations(packets, "ipv6")


def test_summary_and_throughput():
    _, _, packets = _load_demo()
    summary = capture_summary(packets)
    assert summary.packets == 40
    assert summary.bytes > 0
    assert summary.duration > 3.0
    assert summary.error_packets == 0
    series = throughput_series(packets)
    assert series
    assert sum(item[1] for item in series) == 40
    assert all(item[1] >= 0 for item in series)
