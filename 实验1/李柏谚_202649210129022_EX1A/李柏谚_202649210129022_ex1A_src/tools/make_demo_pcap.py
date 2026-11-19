#!/usr/bin/env python3
"""Generate ``samples/demo.pcap`` — a deterministic, self-contained capture used
for the report screenshots and for offline demos when no live traffic is
available.

The capture tells a small story: ARP + DNS resolution, an HTTP keep-alive
session with two request/response pairs, a TLS 1.3 handshake, ICMP/ICMPv6
echo, NTP and a QUIC Initial packet, plus a VLAN-tagged SYN and a RST.

Run from the source directory:

    python tools/make_demo_pcap.py
"""

from __future__ import annotations

import datetime as dt
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netsniff.capture.pcapfile import PcapWriter  # noqa: E402
from netsniff.packetgen import (  # noqa: E402
    ACK, FIN, PSH, RST, SYN,
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
    ntp_client,
    quic_initial,
    tcp,
    tls_app_data,
    tls_change_cipher_spec,
    tls_client_hello,
    tls_server_hello,
    udp,
    vlan_ethernet,
)

CLIENT_MAC = "aa:bb:cc:00:00:64"
GATEWAY_MAC = "00:11:22:33:44:55"
SERVER_MAC = "00:50:56:12:34:56"
SERVER_IP = "93.184.216.34"
CLIENT_IP = "192.168.1.100"


def _eth_to(dst: str, src: str, payload: bytes) -> bytes:
    return ethernet(mac(dst), mac(src), 0x0800, payload)


def _ip4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    return ipv4(src, dst, proto, payload)


def build_packets() -> list[tuple[float, bytes]]:
    base = dt.datetime(2026, 11, 15, 16, 0, 0).timestamp()
    packets: list[tuple[float, bytes]] = []
    t = base

    def add(frame: bytes, delta: float = 0.02) -> None:
        nonlocal t
        packets.append((t, frame))
        t += delta

    # -- ARP ---------------------------------------------------------------
    add(ethernet(b"\xff" * 6, mac(CLIENT_MAC), 0x0806,
                 arp(1, CLIENT_MAC, CLIENT_IP, "00:00:00:00:00:00", "192.168.1.1")), 0.03)
    add(ethernet(mac(CLIENT_MAC), mac(GATEWAY_MAC), 0x0806,
                 arp(2, GATEWAY_MAC, "192.168.1.1", CLIENT_MAC, CLIENT_IP)), 0.12)

    # -- DNS ---------------------------------------------------------------
    query = dns_query(0x1A2B, "example.com", 1)
    add(_eth_to(GATEWAY_MAC, CLIENT_MAC,
                _ip4(CLIENT_IP, "8.8.8.8", 17,
                     udp(CLIENT_IP, "8.8.8.8", 52010, 53, query))), 0.08)
    response = dns_response(
        0x1A2B,
        "example.com",
        [dns_answer_a(SERVER_IP),
         dns_answer_aaaa("2606:2800:220:1:248:1893:25c8:1946")],
    )
    add(_eth_to(CLIENT_MAC, GATEWAY_MAC,
                _ip4("8.8.8.8", CLIENT_IP, 17,
                     udp("8.8.8.8", CLIENT_IP, 53, 52010, response))), 0.25)

    # -- HTTP keep-alive session ------------------------------------------
    http = Flow(CLIENT_IP, SERVER_IP, 52000, 80, CLIENT_MAC, SERVER_MAC,
                client_seq=1000, server_seq=5000)
    add(http.syn(), 0.03)
    add(http.syn_ack(), 0.03)
    add(http.ack(), 0.12)

    request = http_request(
        "GET", "/index.html", "example.com",
        extra_headers=[("Accept-Encoding", "gzip, deflate"), ("Connection", "keep-alive")],
    )
    add(http.data(request), 0.10)
    add(http.ack(from_client=False), 0.04)
    body = (
        b"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        b"  <title>Example Domain</title>\n"
        b"  <link rel=\"stylesheet\" href=\"/style.css\">\n"
        b"</head>\n<body>\n  <h1>Example Domain</h1>\n"
        b"  <p>This domain is for use in illustrative examples.</p>\n</body>\n</html>\n"
    )
    reply = http_response(200, "OK", body)
    add(http.data(reply, from_client=False), 0.18)
    add(http.ack(), 0.12)

    request2 = http_request("GET", "/style.css", "example.com",
                            extra_headers=[("Referer", "http://example.com/")])
    add(http.data(request2), 0.06)
    add(http.ack(from_client=False), 0.03)
    css = b"body { font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 42rem; }\n"
    reply2 = http_response(200, "OK", css, content_type="text/css; charset=utf-8")
    add(http.data(reply2, from_client=False), 0.09)
    add(http.ack(), 0.08)
    add(http.fin(), 0.03)
    add(http.ack(from_client=False), 0.03)
    add(http.fin(from_client=False), 0.03)
    add(http.ack(), 0.20)

    # -- TLS 1.3 session ---------------------------------------------------
    tls = Flow(CLIENT_IP, SERVER_IP, 52001, 443, CLIENT_MAC, SERVER_MAC,
               client_seq=2000, server_seq=9000)
    add(tls.syn(), 0.03)
    add(tls.syn_ack(), 0.03)
    add(tls.ack(), 0.10)
    hello = tls_client_hello("www.example.com", ("h2", "http/1.1"))
    add(tls.data(hello), 0.12)
    add(tls.ack(from_client=False), 0.05)
    server_flight = (tls_server_hello() + tls_change_cipher_spec()
                     + tls_app_data(bytes(range(64))))
    add(tls.data(server_flight, from_client=False), 0.14)
    add(tls.ack(), 0.08)
    add(tls.data(tls_change_cipher_spec() + tls_app_data(b"GET / HTTP/2\r\n" + bytes(range(48)))), 0.12)
    add(tls.fin(), 0.05)
    add(tls.ack(from_client=False), 0.04)
    add(tls.fin(from_client=False), 0.04)
    add(tls.ack(), 0.22)

    # -- ICMP --------------------------------------------------------------
    echo = icmp_echo(0x1234, 1, b"abcdefghijklmnopqrstuvwabcdefghi")
    add(_eth_to(GATEWAY_MAC, CLIENT_MAC,
                _ip4(CLIENT_IP, "8.8.8.8", 1, echo)), 0.18)
    echo_reply = icmp_echo(0x1234, 1, b"abcdefghijklmnopqrstuvwabcdefghi", request=False)
    add(_eth_to(CLIENT_MAC, GATEWAY_MAC,
                _ip4("8.8.8.8", CLIENT_IP, 1, echo_reply)), 0.20)

    # -- IPv6 ICMPv6 -------------------------------------------------------
    req6 = icmpv6_echo("2001:db8::100", "2001:db8::1", 0x5678, 2, b"ping-v6-payload")
    add(ethernet(mac(GATEWAY_MAC), mac(CLIENT_MAC), 0x86DD,
                 ipv6("2001:db8::100", "2001:db8::1", 58, req6)), 0.18)
    rep6 = icmpv6_echo("2001:db8::1", "2001:db8::100", 0x5678, 2, b"ping-v6-payload")
    add(ethernet(mac(CLIENT_MAC), mac(GATEWAY_MAC), 0x86DD,
                 ipv6("2001:db8::1", "2001:db8::100", 58, rep6)), 0.20)

    # -- NTP ---------------------------------------------------------------
    ntp = ntp_client()
    add(_eth_to(GATEWAY_MAC, CLIENT_MAC,
                _ip4(CLIENT_IP, "192.168.1.1", 17,
                     udp(CLIENT_IP, "192.168.1.1", 52020, 123, ntp))), 0.15)
    ntp_reply = bytearray(ntp)
    ntp_reply[0] = 0x24  # LI=0, VN=4, mode=4 (server)
    ntp_reply[1] = 2     # stratum 2
    add(_eth_to(CLIENT_MAC, GATEWAY_MAC,
                _ip4("192.168.1.1", CLIENT_IP, 17,
                     udp("192.168.1.1", CLIENT_IP, 123, 52020, bytes(ntp_reply)))), 0.20)

    # -- QUIC Initial ------------------------------------------------------
    quic = quic_initial()
    add(_eth_to(GATEWAY_MAC, CLIENT_MAC,
                _ip4(CLIENT_IP, SERVER_IP, 17,
                     udp(CLIENT_IP, SERVER_IP, 52002, 443, quic))), 0.18)

    # -- VLAN tagged SYN and a RST ----------------------------------------
    vlan_tcp = tcp(CLIENT_IP, "203.0.113.10", 52030, 8443, 7000, 0, SYN,
                   options=struct.pack("!BBH", 2, 4, 1460))
    vlan_frame = vlan_ethernet(
        mac(SERVER_MAC), mac(CLIENT_MAC), 100, 0x0800,
        ipv4(CLIENT_IP, "203.0.113.10", 6, vlan_tcp),
    )
    add(vlan_frame, 0.20)
    rst_tcp = tcp("203.0.113.10", CLIENT_IP, 22, 52031, 4000, 3001, RST | ACK)
    add(ethernet(mac(CLIENT_MAC), mac(SERVER_MAC), 0x0800,
                 ipv4("203.0.113.10", CLIENT_IP, 6, rst_tcp)), 0.18)

    return packets


def main() -> int:
    packets = build_packets()
    out = ROOT / "samples" / "demo.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(out, linktype=1) as writer:
        for ts, frame in packets:
            writer.write(ts, frame, len(frame))
    print(f"wrote {len(packets)} packets to {out}")

    # Validate the capture with our own dissector.
    from netsniff.analysis.streams import StreamTracker
    from netsniff.capture.pcapfile import iter_pcap
    from netsniff.dissect import dissect_packet

    tracker = StreamTracker()
    protocols = {}
    for index, (header, record) in enumerate(iter_pcap(out), 1):
        pkt = dissect_packet(record.data, index, record.ts, record.wirelen, header.linktype)
        tracker.process(pkt)
        protocols[pkt.protocol] = protocols.get(pkt.protocol, 0) + 1
        if pkt.expert:
            print(f"  packet {index} expert: {pkt.expert}")
    print("protocols:", protocols)
    print("streams:", [(s.index, s.client, s.cport, s.server, s.sport, s.packets, s.state) for s in tracker.infos()])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
