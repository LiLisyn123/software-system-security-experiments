"""TCP stream tracking / reassembly tests."""

from __future__ import annotations

from netsniff.analysis.streams import StreamTracker
from netsniff.dissect import dissect_packet
from netsniff.packetgen import (
    ACK,
    FIN,
    PSH,
    SYN,
    Flow,
    ethernet,
    http_request,
    http_response,
    ipv4,
    mac,
    tcp,
)

TS = 1_770_000_000.0
CLIENT = "192.168.1.100"
SERVER = "93.184.216.34"
CMAC = "aa:bb:cc:00:00:64"
SMAC = "00:50:56:12:34:56"


def parse(frame: bytes, number: int):
    return dissect_packet(frame, number, TS + number * 0.01, len(frame), 1)


def test_stream_reassembly_and_state():
    flow = Flow(CLIENT, SERVER, 52000, 80, CMAC, SMAC)
    request = http_request("GET", "/index.html", "example.com")
    response = http_response(200, "OK", b"hello world")
    frames = [flow.syn(), flow.syn_ack(), flow.ack(), flow.data(request)]
    frames += [flow.ack(from_client=False), flow.data(response, from_client=False), flow.ack()]
    frames += [flow.fin(), flow.ack(from_client=False), flow.fin(from_client=False), flow.ack()]
    tracker = StreamTracker()
    packets = []
    for index, frame in enumerate(frames, 1):
        packet = parse(frame, index)
        tracker.process(packet)
        packets.append(packet)
    assert all(packet.stream == 1 for packet in packets)
    infos = tracker.infos()
    assert len(infos) == 1
    info = infos[0]
    assert info.client == CLIENT and info.cport == 52000
    assert info.server == SERVER and info.sport == 80
    assert info.packets == len(frames)
    assert info.state == "CLOSED"
    snapshot = tracker.snapshot(1)
    assert snapshot is not None
    assert snapshot.data_c2s == request
    assert snapshot.data_s2c == response
    assert snapshot.bytes == len(request) + len(response)
    assert snapshot.gaps_c2s == [] and snapshot.gaps_s2c == []


def test_out_of_order_and_retransmission():
    tracker = StreamTracker()
    flow = Flow(CLIENT, SERVER, 51000, 443, CMAC, SMAC, client_seq=1000, server_seq=5000)
    packets = [flow.syn(), flow.syn_ack(), flow.ack()]
    for index, frame in enumerate(packets, 1):
        tracker.process(parse(frame, index))
    # send the second data segment first, then the first, then a retransmission
    def seg(payload: bytes, seq: int, ack: int) -> bytes:
        return ethernet(mac(SMAC), mac(CMAC), 0x0800,
                        ipv4(CLIENT, SERVER, 6,
                             tcp(CLIENT, SERVER, 51000, 443, seq, ack, PSH | ACK, payload=payload)))
    frames = [
        seg(b"BBBB", 1005, 5001),
        seg(b"AAAA", 1001, 5001),
        seg(b"AAAA", 1001, 5001),
        seg(b"CCCC", 1009, 5001),
    ]
    for index, frame in enumerate(frames, 4):
        tracker.process(parse(frame, index))
    snapshot = tracker.snapshot(1)
    assert snapshot is not None
    assert snapshot.data_c2s == b"AAAABBBBCCCC"
    assert snapshot.segments[0].rel_seq == 0  # SYN relative 0
    assert snapshot.segments[4].rel_seq == 1  # first data (AAAA) relative 1


def test_gap_detection():
    tracker = StreamTracker()
    flow = Flow(CLIENT, SERVER, 51002, 80, CMAC, SMAC, 1000, 5000)
    for index, frame in enumerate([flow.syn(), flow.syn_ack(), flow.ack()], 1):
        tracker.process(parse(frame, index))

    def seg(payload: bytes, seq: int) -> bytes:
        return ethernet(mac(SMAC), mac(CMAC), 0x0800,
                        ipv4(CLIENT, SERVER, 6,
                             tcp(CLIENT, SERVER, 51002, 80, seq, 5001, PSH | ACK, payload=payload)))

    tracker.process(parse(seg(b"AAAA", 1001), 4))
    tracker.process(parse(seg(b"CCCC", 1009), 5))
    snapshot = tracker.snapshot(1)
    assert snapshot is not None
    assert snapshot.data_c2s == b"AAAACCCC"
    assert snapshot.gaps_c2s and snapshot.gaps_c2s[0][1] == 4


def test_multiple_streams_are_keyed_by_endpoints():
    tracker = StreamTracker()
    one = Flow(CLIENT, SERVER, 52000, 80, CMAC, SMAC, 1000, 5000)
    two = Flow(CLIENT, SERVER, 52001, 443, CMAC, SMAC, 7000, 9000)
    for index, frame in enumerate([one.syn(), one.syn_ack(), two.syn(), two.syn_ack()], 1):
        tracker.process(parse(frame, index))
    infos = tracker.infos()
    assert [info.index for info in infos] == [1, 2]
    assert {info.cport for info in infos} == {52000, 52001}


def test_non_tcp_packets_are_ignored():
    tracker = StreamTracker()
    packet = parse(ethernet(mac(SMAC), mac(CMAC), 0x0806,
                            b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20), 1)
    tracker.process(packet)
    assert tracker.infos() == []
