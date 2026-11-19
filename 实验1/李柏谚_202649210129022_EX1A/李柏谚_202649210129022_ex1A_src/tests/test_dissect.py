"""Dissector tests using deterministic, checksum-correct packets."""

from __future__ import annotations

import struct

import pytest

from netsniff.dissect import dissect_packet
from netsniff.packetgen import (
    ACK,
    SYN,
    Flow,
    arp,
    dns_answer_a,
    dns_answer_aaaa,
    dns_query,
    dns_response,
    ethernet,
    http_request,
    http_response,
    icmp_echo,
    icmpv6_echo,
    ipv4,
    ipv6,
    mac,
    tcp,
    tls_client_hello,
    udp,
    vlan_ethernet,
)

TS = 1_770_000_000.0
CLIENT = "192.168.1.100"
SERVER = "93.184.216.34"
CMAC = "aa:bb:cc:00:00:64"
SMAC = "00:50:56:12:34:56"


def parse(frame: bytes, number: int = 1, linktype: int = 1):
    return dissect_packet(frame, number, TS + number * 0.01, len(frame), linktype)


def http_flow_packets():
    flow = Flow(CLIENT, SERVER, 52000, 80, CMAC, SMAC)
    request = http_request("GET", "/index.html", "example.com")
    response = http_response(200, "OK", b"<html>hello</html>")
    frames = [
        flow.syn(), flow.syn_ack(), flow.ack(),
        flow.data(request), flow.ack(from_client=False), flow.data(response, from_client=False),
        flow.ack(),
    ]
    return flow, [parse(frame, i + 1) for i, frame in enumerate(frames)]


def test_ethernet_ipv4_tcp_http():
    flow, packets = http_flow_packets()
    syn = packets[0]
    assert syn.protocols == ["eth", "ip", "tcp"]
    assert syn.protocol == "TCP"
    assert syn.src == CLIENT and syn.dst == SERVER
    assert syn.first_value("ip.src") == CLIENT
    assert syn.first_value("tcp.dstport") == 80
    assert syn.first_value("tcp.flags.syn") is True
    assert syn.tcp is not None and syn.tcp.checksum_ok is True
    assert syn.expert == []

    synack = packets[1]
    assert "[SYN, ACK]" in synack.info

    request = packets[3]
    assert request.protocol == "HTTP"
    assert request.protocols[-1] == "http"
    assert request.first_value("http.request.method") == "GET"
    assert request.first_value("http.request.uri") == "/index.html"
    assert request.first_value("http.host") == "example.com"
    assert request.info == "GET /index.html HTTP/1.1"

    response = packets[5]
    assert response.protocol == "HTTP"
    assert response.first_value("http.response.code") == 200
    assert response.first_value("http.content_type").startswith("text/html")
    assert response.first_value("http.file_data") == len(b"<html>hello</html>")
    assert "200 OK" in response.info


def test_arp():
    frame = ethernet(
        b"\xff" * 6, mac(CMAC), 0x0806,
        arp(1, CMAC, CLIENT, "00:00:00:00:00:00", "192.168.1.1"),
    )
    pkt = parse(frame)
    assert pkt.protocol == "ARP"
    assert pkt.first_value("arp.opcode") == 1
    assert pkt.first_value("arp.src.proto_ipv4") == CLIENT
    assert "Who has 192.168.1.1?" in pkt.info


def test_dns_query_and_response():
    query = dns_query(0x1A2B, "example.com", 1)
    frame = ethernet(
        mac("00:11:22:33:44:55"), mac(CMAC), 0x0800,
        ipv4(CLIENT, "8.8.8.8", 17, udp(CLIENT, "8.8.8.8", 52010, 53, query)),
    )
    pkt = parse(frame)
    assert pkt.protocol == "DNS"
    assert pkt.first_value("dns.flags.response") is False
    assert pkt.first_value("dns.qry.name") == "example.com"
    assert pkt.first_value("dns.qry.type") == 1
    assert "Standard query 0x1a2b A example.com" == pkt.info

    response = dns_response(
        0x1A2B, "example.com",
        [dns_answer_a(SERVER), dns_answer_aaaa("2606:2800:220:1:248:1893:25c8:1946")],
    )
    frame = ethernet(
        mac(CMAC), mac("00:11:22:33:44:55"), 0x0800,
        ipv4("8.8.8.8", CLIENT, 17, udp("8.8.8.8", CLIENT, 53, 52010, response)),
    )
    pkt = parse(frame)
    assert pkt.protocol == "DNS"
    assert pkt.first_value("dns.flags.response") is True
    assert pkt.first_value("dns.a") == SERVER
    assert pkt.first_value("dns.aaaa") == "2606:2800:220:1:248:1893:25c8:1946"
    assert "Standard query response" in pkt.info


def test_tls_client_hello():
    flow = Flow(CLIENT, SERVER, 52001, 443, CMAC, SMAC, 2000, 9000)
    frame = flow.data(tls_client_hello("www.example.com"))
    pkt = parse(frame)
    assert pkt.protocol == "TLSv1.3"
    assert pkt.first_value("tls.handshake.type") == 1
    assert pkt.first_value("tls.sni") == "www.example.com"
    assert pkt.first_value("tls.handshake.extensions_alpn") == "h2, http/1.1"
    assert "SNI=www.example.com" in pkt.info


def test_icmp_and_ipv6():
    echo = icmp_echo(0x1234, 1, b"abcdefgh")
    frame = ethernet(mac("00:11:22:33:44:55"), mac(CMAC), 0x0800,
                     ipv4(CLIENT, "8.8.8.8", 1, echo))
    pkt = parse(frame)
    assert pkt.protocol == "ICMP"
    assert pkt.first_value("icmp.type") == 8
    assert pkt.first_value("icmp.ident") == 0x1234
    assert "Echo (ping) request" in pkt.info
    assert pkt.expert == []

    echo6 = icmpv6_echo("2001:db8::100", "2001:db8::1", 0x5678, 2, b"ping")
    frame = ethernet(mac("00:11:22:33:44:55"), mac(CMAC), 0x86DD,
                     ipv6("2001:db8::100", "2001:db8::1", 58, echo6))
    pkt = parse(frame)
    assert pkt.protocol == "ICMPv6"
    assert pkt.protocols == ["eth", "ipv6", "icmpv6"]
    assert pkt.first_value("icmpv6.type") == 128
    assert pkt.first_value("ipv6.hlim") == 64
    assert pkt.expert == []


def test_vlan():
    seg = tcp(CLIENT, SERVER, 52030, 8443, 7000, 0, SYN, options=struct.pack("!BBH", 2, 4, 1460))
    frame = vlan_ethernet(mac(SMAC), mac(CMAC), 100, 0x0800, ipv4(CLIENT, SERVER, 6, seg))
    pkt = parse(frame)
    assert pkt.protocols[1] == "vlan"
    assert pkt.first_value("vlan.id") == 100
    assert pkt.first_value("tcp.dstport") == 8443
    assert pkt.tcp.checksum_ok is True


def test_malformed_frames_do_not_raise():
    for raw, linktype in ((b"\x00" * 3, 1), (b"\xff" * 14, 1), (b"\x00" * 4, 0), (b"", 1)):
        pkt = dissect_packet(raw, 1, TS, len(raw), linktype)
        assert pkt.protocol
        assert pkt.layers


def test_loopback_null_header():
    frame = b"\x02\x00\x00\x00" + ipv4(CLIENT, SERVER, 17, udp(CLIENT, SERVER, 1, 2, b"x"))
    pkt = parse(frame, linktype=0)
    assert pkt.protocols[:3] == ["null", "ip", "udp"]
    assert pkt.first_value("null.family") == 2
