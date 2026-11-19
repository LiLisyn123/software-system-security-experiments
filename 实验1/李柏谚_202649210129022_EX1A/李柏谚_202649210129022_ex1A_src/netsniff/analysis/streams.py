"""TCP flow tracking and byte-stream reassembly.

A stream is keyed by the unordered pair of TCP endpoints.  The first packet
decides the client/server orientation (SYN without ACK wins; otherwise the
first sender is called the client).  Sequence numbers are kept absolute in
the model and converted to stream-relative values for the sequence diagram.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..model import Packet


SYN = 0x002
ACK = 0x010
FIN = 0x001
RST = 0x004

MAX_SEGMENTS = 20000
MAX_STREAM_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class Segment:
    ts: float
    direction: int          # 0 = client -> server, 1 = server -> client
    seq: int
    ack: int
    flags: int
    window: int
    packet_number: int
    payload_len: int
    payload: bytes = b""
    rel_seq: int = 0
    gap_before: int = 0


@dataclass(slots=True)
class StreamInfo:
    index: int
    client: str
    server: str
    packets: int
    bytes: int
    first_ts: float
    last_ts: float
    state: str
    cport: int
    sport: int
    truncated: bool


@dataclass(slots=True)
class StreamSnapshot:
    index: int
    client: str
    server: str
    cport: int
    sport: int
    packets: int
    bytes: int
    first_ts: float
    last_ts: float
    state: str
    segments: List[Segment]
    data_c2s: bytes
    data_s2c: bytes
    gaps_c2s: List[Tuple[int, int]]
    gaps_s2c: List[Tuple[int, int]]
    truncated: bool


class TcpStream:
    def __init__(self, index: int, client: Tuple[str, int], server: Tuple[str, int], ts: float):
        self.index = index
        self.client = client
        self.server = server
        self.first_ts = ts
        self.last_ts = ts
        self.packets = 0
        self.bytes = 0
        self.bytes_c2s = 0
        self.bytes_s2c = 0
        self.syn: List[Optional[int]] = [None, None]
        self.base: List[Optional[int]] = [None, None]
        self.fin: List[bool] = [False, False]
        self.rst = False
        self.synack = False
        self.segments: List[Segment] = []
        self.truncated = False
        self._data_bytes = 0

    # -- updates ----------------------------------------------------------
    def add(self, packet: Packet) -> None:
        tcp = packet.tcp
        if tcp is None:
            return
        src = (packet.ip.src if packet.ip else packet.src, tcp.sport)
        direction = 0 if src == self.client else 1
        self.packets += 1
        self.first_ts = min(self.first_ts, packet.ts)
        self.last_ts = max(self.last_ts, packet.ts)
        flags = tcp.flags
        if flags & RST:
            self.rst = True
        if flags & SYN:
            self.syn[direction] = tcp.seq
            if self.base[direction] is None:
                self.base[direction] = tcp.seq
        if flags & SYN and flags & ACK:
            self.synack = True
        if flags & FIN:
            self.fin[direction] = True
        if tcp.payload:
            if self.base[direction] is None:
                self.base[direction] = tcp.seq
            self._data_bytes += len(tcp.payload)
            self.bytes += len(tcp.payload)
            if direction == 0:
                self.bytes_c2s += len(tcp.payload)
            else:
                self.bytes_s2c += len(tcp.payload)

        if len(self.segments) >= MAX_SEGMENTS or self._data_bytes > MAX_STREAM_BYTES:
            self.truncated = True
            return
        rel_seq = 0
        if self.base[direction] is not None:
            rel_seq = tcp.seq - self.base[direction]
        self.segments.append(
            Segment(
                ts=packet.ts,
                direction=direction,
                seq=tcp.seq,
                ack=tcp.ack,
                flags=flags,
                window=tcp.window,
                packet_number=packet.number,
                payload_len=len(tcp.payload),
                payload=tcp.payload,
                rel_seq=rel_seq,
            )
        )

    # -- views ------------------------------------------------------------
    @property
    def state(self) -> str:
        if self.rst:
            return "RESET"
        if self.fin[0] and self.fin[1]:
            return "CLOSED"
        if self.fin[0] or self.fin[1]:
            return "FIN_WAIT"
        if self.synack:
            return "ESTABLISHED"
        if self.syn[0] is not None:
            return "SYN_SENT"
        return "UNKNOWN"

    def info(self) -> StreamInfo:
        return StreamInfo(
            index=self.index,
            client=self.client[0],
            server=self.server[0],
            packets=self.packets,
            bytes=self.bytes,
            first_ts=self.first_ts,
            last_ts=self.last_ts,
            state=self.state,
            cport=self.client[1],
            sport=self.server[1],
            truncated=self.truncated,
        )

    def assemble(self, direction: int) -> Tuple[bytes, List[Tuple[int, int]]]:
        segments = [s for s in self.segments if s.direction == direction and s.payload]
        if not segments:
            return b"", []
        segments.sort(key=lambda s: s.seq)
        base = self.syn[direction]
        data_base = (base + 1) if base is not None else segments[0].seq
        out = bytearray()
        gaps: List[Tuple[int, int]] = []
        next_seq = data_base
        for seg in segments:
            start = seg.seq
            end = start + len(seg.payload)
            if end <= next_seq:
                continue
            if start > next_seq:
                gaps.append((len(out), start - next_seq))
                next_seq = start
            if start < next_seq:
                offset = next_seq - start
                out += seg.payload[offset:]
            else:
                out += seg.payload
            next_seq = end
            if len(out) > MAX_STREAM_BYTES:
                self.truncated = True
                break
        return bytes(out), gaps

    def snapshot(self) -> StreamSnapshot:
        data_c2s, gaps_c2s = self.assemble(0)
        data_s2c, gaps_s2c = self.assemble(1)
        segments: List[Segment] = []
        for seg in self.segments:
            rel = seg.rel_seq
            if self.base[seg.direction] is not None:
                rel = seg.seq - self.base[seg.direction]
            segments.append(
                Segment(
                    ts=seg.ts,
                    direction=seg.direction,
                    seq=seg.seq,
                    ack=seg.ack,
                    flags=seg.flags,
                    window=seg.window,
                    packet_number=seg.packet_number,
                    payload_len=seg.payload_len,
                    payload=seg.payload,
                    rel_seq=rel,
                )
            )
        return StreamSnapshot(
            index=self.index,
            client=self.client[0],
            server=self.server[0],
            cport=self.client[1],
            sport=self.server[1],
            packets=self.packets,
            bytes=self.bytes,
            first_ts=self.first_ts,
            last_ts=self.last_ts,
            state=self.state,
            segments=segments,
            data_c2s=data_c2s,
            data_s2c=data_s2c,
            gaps_c2s=gaps_c2s,
            gaps_s2c=gaps_s2c,
            truncated=self.truncated,
        )

    def text(self, direction: int, mode: str = "auto") -> str:
        data, gaps = self.assemble(direction)
        if not data:
            return ""
        if mode == "hex":
            return _hex_dump(data)
        text = _decode_text(data)
        return text


class StreamTracker:
    def __init__(self, max_streams: int = 20000):
        self._streams: Dict[tuple, TcpStream] = {}
        self._by_index: Dict[int, TcpStream] = {}
        self._next_index = 1
        self._lock = threading.RLock()
        self.max_streams = max_streams
        self.dropped_streams = 0

    def clear(self) -> None:
        with self._lock:
            self._streams.clear()
            self._by_index.clear()
            self._next_index = 1
            self.dropped_streams = 0

    def process(self, packet: Packet) -> None:
        tcp = packet.tcp
        ip = packet.ip
        if tcp is None or ip is None:
            return
        a = (ip.src, tcp.sport)
        b = (ip.dst, tcp.dport)
        key = ("tcp",) + tuple(sorted((a, b)))
        with self._lock:
            stream = self._streams.get(key)
            if stream is None:
                if len(self._streams) >= self.max_streams:
                    self.dropped_streams += 1
                    return
                flags = tcp.flags
                if flags & SYN and not flags & ACK:
                    client, server = a, b
                elif flags & SYN and flags & ACK:
                    client, server = b, a
                else:
                    client, server = a, b
                stream = TcpStream(self._next_index, client, server, packet.ts)
                self._next_index += 1
                self._streams[key] = stream
                self._by_index[stream.index] = stream
            packet.stream = stream.index
            stream.add(packet)

    def infos(self) -> List[StreamInfo]:
        with self._lock:
            return [s.info() for s in sorted(self._by_index.values(), key=lambda s: s.index)]

    def snapshot(self, index: int) -> Optional[StreamSnapshot]:
        with self._lock:
            stream = self._by_index.get(index)
            return stream.snapshot() if stream else None

    def get(self, index: int) -> Optional[TcpStream]:
        with self._lock:
            return self._by_index.get(index)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_index)


def _decode_text(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise UnicodeDecodeError("utf-8", data, 0, 1, "nul")
        return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in text)
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")
        return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in text)


def _hex_dump(data: bytes, limit: int = 2 * 1024 * 1024) -> str:
    chunk = data[:limit]
    lines = []
    for offset in range(0, len(chunk), 16):
        row = chunk[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        if len(row) > 8:
            hexpart = hexpart[:23] + "  " + hexpart[23:]
        lines.append(f"{offset:08x}  {hexpart:<49}  {ascii_text(row)}")
    if len(data) > limit:
        lines.append(f"... truncated at {limit} bytes ...")
    return "\n".join(lines)


def ascii_text(row: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in row)
