"""Display filter language tests."""

from __future__ import annotations

import pytest

from netsniff.dissect import dissect_packet
from netsniff.filters.display import FilterError, compile_filter
from netsniff.packetgen import (
    Flow,
    arp,
    dns_answer_a,
    dns_query,
    dns_response,
    ethernet,
    http_request,
    http_response,
    icmp_echo,
    ipv4,
    mac,
    tls_client_hello,
    udp,
)

TS = 1_770_000_000.0
CLIENT = "192.168.1.100"
SERVER = "93.184.216.34"
CMAC = "aa:bb:cc:00:00:64"
SMAC = "00:50:56:12:34:56"


def build_packets():
    packets = []
    number = 0

    def add(frame):
        nonlocal number
        number += 1
        packets.append(dissect_packet(frame, number, TS + number * 0.01, len(frame), 1))

    flow = Flow(CLIENT, SERVER, 52000, 80, CMAC, SMAC)
    for frame in (
        flow.syn(), flow.syn_ack(), flow.ack(),
        flow.data(http_request("POST", "/api/login", "example.com", body=b'{"user":"a"}')),
        flow.data(http_response(401, "Unauthorized", b"no"), from_client=False),
    ):
        add(frame)
    add(ethernet(mac("00:11:22:33:44:55"), mac(CMAC), 0x0800,
                 ipv4(CLIENT, "8.8.8.8", 1, icmp_echo(1, 1))))
    add(ethernet(mac("00:11:22:33:44:55"), mac(CMAC), 0x0800,
                 ipv4(CLIENT, "8.8.8.8", 17, udp(CLIENT, "8.8.8.8", 5000, 53,
                                                   dns_query(0x1234, "example.com")))))
    add(ethernet(mac(CMAC), mac("00:11:22:33:44:55"), 0x0800,
                 ipv4("8.8.8.8", CLIENT, 17, udp("8.8.8.8", CLIENT, 53, 5000,
                                                   dns_response(0x1234, "example.com", [dns_answer_a(SERVER)])))))
    add(ethernet(b"\xff" * 6, mac(CMAC), 0x0806, arp(1, CMAC, CLIENT, "00:00:00:00:00:00", "192.168.1.1")))
    tls = Flow(CLIENT, SERVER, 52001, 443, CMAC, SMAC, 2000, 9000)
    add(tls.data(tls_client_hello("secure.example.com")))
    # annotate the last TCP packet as a stream and process
    for pkt in packets:
        if pkt.tcp is not None:
            pkt.stream = 7
            pkt.pid = 4242
            pkt.process = "python.exe"
    return packets


PACKETS = build_packets()


def numbers(expression: str):
    filt = compile_filter(expression)
    return [p.number for p in PACKETS if filt(p)]


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("tcp", [1, 2, 3, 4, 5, 10]),
        ("udp", [7, 8]),
        ("http", [4, 5]),
        ("dns", [7, 8]),
        ("arp", [9]),
        ("tls", [10]),
        ("icmp", [6]),
        ("not tcp", [6, 7, 8, 9]),
        ("tcp or udp", [1, 2, 3, 4, 5, 7, 8, 10]),
        ("http and not tcp.port == 80", []),
        ("(http or dns) and ip.addr == 93.184.216.34", [4, 5]),
        ("tcp.port == 80", [1, 2, 3, 4, 5]),
        ("tcp.srcport == 52000", [1, 3, 4]),
        ("ip.addr == 192.168.1.0/24", [1, 2, 3, 4, 5, 6, 7, 8, 10]),
        ("ip.src == 8.8.8.8", [8]),
        ('http.request.method == "POST"', [4]),
        ("http.response.code == 401", [5]),
        ('http.host contains "example"', [4]),
        ('http.request.uri matches "^/api/"', [4]),
        ("tcp.flags.syn == 1 and tcp.flags.ack == 0", [1]),
        ("tcp.flags.syn == 1 and tcp.flags.ack == 1", [2]),
        ("frame.len > 200", [5, 10]),
        ('tcp contains "POST "', [4]),
        ("tcp.stream == 7", [1, 2, 3, 4, 5, 10]),
        ('proc.name == "python.exe"', [1, 2, 3, 4, 5, 10]),
        ("proc.pid == 4242", [1, 2, 3, 4, 5, 10]),
        ("", list(range(1, 11))),
    ],
)
def test_filters(expression, expected):
    assert numbers(expression) == expected


def test_ipv4_alias_does_not_match_ipv6_literal():
    assert numbers("ip.addr == 2606:2800:220:1:248:1893:25c8:1946") == []


def test_boolean_bare_field_is_truthy():
    assert numbers("tcp.flags.syn") == [1, 2]


def test_invalid_filter_raises():
    for expression in ("tcp.port ==", "unknown.field == 1", "http and (", "and http", "tcp.port == 80 extra"):
        with pytest.raises(FilterError):
            compile_filter(expression)


def test_invalid_ip_literal_raises_at_evaluation():
    filt = compile_filter("ip.addr == 999.1.1.1")
    with pytest.raises(FilterError):
        filt(PACKETS[0])
