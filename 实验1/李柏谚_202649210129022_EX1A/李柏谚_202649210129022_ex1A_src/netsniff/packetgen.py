"""Deterministic packet builders used by the tests and by the demo capture.

Everything is built from raw bytes: no external packet library is required.
Checksums are computed so the dissector's ``[correct]`` annotations are real.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterable, List, Sequence, Tuple

from .dissect.utils import checksum16, ones_complement_sum, pseudo_header_v4, pseudo_header_v6


# ---------------------------------------------------------------------------
# low level helpers
# ---------------------------------------------------------------------------

def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", "").replace("-", ""))


def ip4(text: str) -> bytes:
    return socket.inet_aton(text)


def ip6(text: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, text)


def _pseudo4(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return pseudo_header_v4(src, dst, proto, length)


def _pseudo6(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return pseudo_header_v6(src, dst, proto, length)


def tcp_checksum(src: bytes, dst: bytes, segment: bytes, version: int = 4) -> int:
    pseudo = _pseudo4(src, dst, 6, len(segment)) if version == 4 else _pseudo6(src, dst, 6, len(segment))
    initial = ones_complement_sum(pseudo)
    return checksum16(segment, initial)


def udp_checksum(src: bytes, dst: bytes, segment: bytes, version: int = 4) -> int:
    pseudo = _pseudo4(src, dst, 17, len(segment)) if version == 4 else _pseudo6(src, dst, 17, len(segment))
    initial = ones_complement_sum(pseudo)
    return checksum16(segment, initial)


def icmp_checksum(segment: bytes) -> int:
    return checksum16(segment)


def icmpv6_checksum(src: bytes, dst: bytes, segment: bytes) -> int:
    initial = ones_complement_sum(pseudo_header_v6(src, dst, 58, len(segment)))
    return checksum16(segment, initial)


def _pad_options(options: bytes) -> bytes:
    padding = (-len(options)) % 4
    return options + b"\x01" * padding


# ---------------------------------------------------------------------------
# link and network layers
# ---------------------------------------------------------------------------

def ethernet(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def vlan_ethernet(dst: bytes, src: bytes, vlan_id: int, ethertype: int, payload: bytes) -> bytes:
    tci = vlan_id & 0x0FFF
    return dst + src + struct.pack("!HHH", 0x8100, tci, ethertype) + payload


def ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    ttl: int = 64,
    ident: int = 0x1234,
    tos: int = 0,
    flags: int = 0,
    frag_offset: int = 0,
) -> bytes:
    total_len = 20 + len(payload)
    flags_frag = ((flags & 0x7) << 13) | (frag_offset & 0x1FFF)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        0,
        ip4(src),
        ip4(dst),
    )
    csum = checksum16(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    first = (6 << 28) | (0 << 20) | 0
    return struct.pack("!IHBB16s16s", first, len(payload), next_header, hop_limit, ip6(src), ip6(dst)) + payload


def tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
    options: bytes = b"",
    version: int = 4,
) -> bytes:
    options = _pad_options(options)
    offset_flags = ((20 + len(options)) // 4) << 12 | (flags & 0x1FF)
    header = struct.pack(
        "!HHIIHHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        window,
        0,
        0,
    ) + options
    segment = header + payload
    csum = tcp_checksum(ip4(src_ip), ip4(dst_ip), segment, version) if version == 4 else tcp_checksum(
        ip6(src_ip), ip6(dst_ip), segment, version
    )
    segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
    return segment


def udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, version: int = 4) -> bytes:
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", sport, dport, length, 0) + payload
    if version == 4:
        csum = udp_checksum(ip4(src_ip), ip4(dst_ip), segment, 4)
    else:
        csum = udp_checksum(ip6(src_ip), ip6(dst_ip), segment, 6)
    return segment[:6] + struct.pack("!H", csum) + segment[8:]


def icmp_echo(ident: int, seq: int, payload: bytes = b"abcdefghijklmnop", request: bool = True) -> bytes:
    segment = struct.pack("!BBHHH", 8 if request else 0, 0, 0, ident, seq) + payload
    csum = icmp_checksum(segment)
    return segment[:2] + struct.pack("!H", csum) + segment[4:]


def icmpv6_echo(src: str, dst: str, ident: int, seq: int, payload: bytes = b"abcdefgh") -> bytes:
    segment = struct.pack("!BBHHH", 128, 0, 0, ident, seq) + payload
    csum = icmpv6_checksum(ip6(src), ip6(dst), segment)
    return segment[:2] + struct.pack("!H", csum) + segment[4:]


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, op, mac(sha), ip4(spa), mac(tha), ip4(tpa),
    )


# ---------------------------------------------------------------------------
# application payload builders
# ---------------------------------------------------------------------------

def http_request(
    method: str,
    uri: str,
    host: str,
    extra_headers: Sequence[Tuple[str, str]] = (),
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    headers = [("Host", host), ("User-Agent", "NetSniffer-Lab/1.0"), ("Accept", "*/*")]
    headers.extend(extra_headers)
    if body:
        headers.append(("Content-Length", str(len(body))))
    head = f"{method} {uri} {version}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return head.encode("latin-1") + body


def http_response(
    status: int,
    phrase: str,
    body: bytes = b"",
    content_type: str = "text/html; charset=utf-8",
    extra_headers: Sequence[Tuple[str, str]] = (),
) -> bytes:
    headers = [
        ("Server", "nginx/1.24.0"),
        ("Date", "Sat, 15 Nov 2026 08:00:00 GMT"),
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Connection", "keep-alive"),
    ]
    headers.extend(extra_headers)
    head = f"HTTP/1.1 {status} {phrase}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return head.encode("latin-1") + body


def _dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(ident: int, name: str, answers: Sequence[Tuple[int, bytes]], qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x8180, 1, len(answers), 0, 0)
    question = _dns_name(name) + struct.pack("!HH", qtype, 1)
    out = bytearray(header + question)
    for rtype, rdata in answers:
        out += b"\xC0\x0C" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return bytes(out)


def dns_answer_a(ip: str) -> Tuple[int, bytes]:
    return 1, ip4(ip)


def dns_answer_aaaa(ip: str) -> Tuple[int, bytes]:
    return 28, ip6(ip)


def dns_answer_cname(name: str) -> Tuple[int, bytes]:
    return 5, _dns_name(name)


def tls_client_hello(sni: str = "www.example.com", alpn: Sequence[str] = ("h2", "http/1.1")) -> bytes:
    legacy_version = struct.pack("!H", 0x0303)
    random = bytes(range(32))
    session_id = b""
    cipher_suites = struct.pack("!HHHH", 0x1301, 0x1302, 0x1303, 0xC02B)
    compression = b"\x01\x00"

    def ext(ext_type: int, data: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(data)) + data

    server_name = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(server_name)) + server_name
    sni_ext = ext(0, struct.pack("!H", len(sni_entry)) + sni_entry)
    groups = ext(10, struct.pack("!HHH", 4, 29, 23))
    sigalgs = ext(13, struct.pack("!H", 8) + struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0807))
    alpn_list = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_ext = ext(16, struct.pack("!H", len(alpn_list)) + alpn_list)
    versions = ext(43, b"\x04" + struct.pack("!HH", 0x0304, 0x0303))
    key = b"\x11" * 32
    key_share_entry = struct.pack("!HH", 29, len(key)) + key
    key_share = ext(51, struct.pack("!H", len(key_share_entry)) + key_share_entry)
    extensions = sni_ext + groups + sigalgs + alpn_ext + versions + key_share

    body = (
        legacy_version
        + random
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", len(cipher_suites))
        + cipher_suites
        + compression
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello() -> bytes:
    legacy_version = struct.pack("!H", 0x0303)
    random = bytes(range(32, 64))
    session_id = b"\xAA" * 32
    cipher = struct.pack("!H", 0x1301)
    compression = b"\x00"

    def ext(ext_type: int, data: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(data)) + data

    versions = ext(43, struct.pack("!H", 0x0304))
    alpn_list = b"\x02h2"
    alpn_ext = ext(16, struct.pack("!H", len(alpn_list)) + alpn_list)
    key_share = ext(51, struct.pack("!HH", 29, 32) + b"\x22" * 32)
    extensions = versions + alpn_ext + key_share
    body = (
        legacy_version + random + bytes([len(session_id)]) + session_id
        + cipher + compression + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def tls_app_data(data: bytes) -> bytes:
    return b"\x17\x03\x03" + struct.pack("!H", len(data)) + data


def tls_change_cipher_spec() -> bytes:
    return b"\x14\x03\x03\x00\x01\x01"


def ntp_client() -> bytes:
    # LI=0, VN=4, mode=3 (client), stratum=0, poll=6, precision=-20
    return struct.pack("!BBbb", 0x23, 0, 6, -20) + b"\x00" * 44


def quic_initial(dcid: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08",
                 scid: bytes = b"\x11\x12\x13\x14") -> bytes:
    version = struct.pack("!I", 0x00000001)
    header = b"\xC3" + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    token_len = b"\x00"
    length = b"\x1A"  # 1-byte varint length = 26
    payload = bytes(range(26))
    return header + token_len + length + payload


# ---------------------------------------------------------------------------
# TCP flags
# ---------------------------------------------------------------------------

FIN = 0x001
SYN = 0x002
RST = 0x004
PSH = 0x008
ACK = 0x010
URG = 0x020
ECE = 0x040
CWR = 0x080
NS = 0x100


class Flow:
    """Convenience builder for a TCP conversation with correct seq/ack."""

    def __init__(self, client_ip: str, server_ip: str, cport: int, sport: int,
                 client_mac: str, server_mac: str, client_seq: int = 1000,
                 server_seq: int = 5000):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.cport = cport
        self.sport = sport
        self.client_mac = mac(client_mac)
        self.server_mac = mac(server_mac)
        self.cseq = client_seq
        self.sseq = server_seq

    def _frame(self, from_client: bool, tcp_segment: bytes) -> bytes:
        src_ip, dst_ip = (self.client_ip, self.server_ip) if from_client else (self.server_ip, self.client_ip)
        packet = ipv4(src_ip, dst_ip, 6, tcp_segment)
        if from_client:
            return ethernet(self.server_mac, self.client_mac, 0x0800, packet)
        return ethernet(self.client_mac, self.server_mac, 0x0800, packet)

    def syn(self) -> bytes:
        seg = tcp(self.client_ip, self.server_ip, self.cport, self.sport, self.cseq, 0, SYN,
                  options=struct.pack("!BBH", 2, 4, 1460))
        return self._frame(True, seg)

    def syn_ack(self) -> bytes:
        seg = tcp(self.server_ip, self.client_ip, self.sport, self.cport, self.sseq,
                  self.cseq + 1, SYN | ACK, options=struct.pack("!BBH", 2, 4, 1460))
        return self._frame(False, seg)

    def ack(self, from_client: bool = True) -> bytes:
        if from_client:
            seg = tcp(self.client_ip, self.server_ip, self.cport, self.sport, self.cseq + 1,
                      self.sseq + 1, ACK)
        else:
            seg = tcp(self.server_ip, self.client_ip, self.sport, self.cport, self.sseq + 1,
                      self.cseq + 1, ACK)
        return self._frame(from_client, seg)

    def data(self, payload: bytes, from_client: bool = True) -> bytes:
        if from_client:
            seg = tcp(self.client_ip, self.server_ip, self.cport, self.sport, self.cseq + 1,
                      self.sseq + 1, PSH | ACK, payload=payload)
            self.cseq += len(payload)
        else:
            seg = tcp(self.server_ip, self.client_ip, self.sport, self.cport, self.sseq + 1,
                      self.cseq + 1, PSH | ACK, payload=payload)
            self.sseq += len(payload)
        return self._frame(from_client, seg)

    def fin(self, from_client: bool = True) -> bytes:
        if from_client:
            seg = tcp(self.client_ip, self.server_ip, self.cport, self.sport, self.cseq + 1,
                      self.sseq + 1, FIN | ACK)
            self.cseq += 1
        else:
            seg = tcp(self.server_ip, self.client_ip, self.sport, self.cport, self.sseq + 1,
                      self.cseq + 1, FIN | ACK)
            self.sseq += 1
        return self._frame(from_client, seg)
