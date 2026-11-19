"""Minimal, dependency free reader/writer for classic pcap files.

The sniffer writes classic libpcap files (microsecond timestamps, little
endian) so they can be opened by Wireshark/tcpdump.  Reading supports both
byte orders and both microsecond/nanosecond magics.  pcapng files are
detected and reported with an actionable error; the live Npcap path can open
them through ``pcap_open_offline`` if desired.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, List, Optional, Sequence

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_RECORD = 256 * 1024 * 1024


class PcapFormatError(ValueError):
    pass


@dataclass(slots=True)
class PcapRecord:
    ts: float
    data: bytes
    wirelen: int


@dataclass(slots=True)
class PcapHeader:
    linktype: int
    snaplen: int
    nanosecond: bool
    endian: str
    version: tuple[int, int]


_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


def read_header(fh: BinaryIO) -> PcapHeader:
    magic = fh.read(4)
    if not magic:
        raise PcapFormatError("文件为空")
    if magic == PCAPNG_MAGIC:
        raise PcapFormatError(
            "检测到 pcapng 格式。请在 Wireshark 中“另存为 pcap”后再打开，"
            "或安装 Npcap 后使用内置的 pcapng 支持。"
        )
    info = _MAGICS.get(magic)
    if info is None:
        raise PcapFormatError(f"未知的 pcap 文件头: {magic.hex()}")
    endian, nanosecond = info
    rest = fh.read(20)
    if len(rest) != 20:
        raise PcapFormatError("pcap 全局头被截断")
    version_major, version_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
        endian + "HHiIII", rest
    )
    return PcapHeader(
        linktype=int(linktype),
        snaplen=int(snaplen),
        nanosecond=nanosecond,
        endian=endian,
        version=(int(version_major), int(version_minor)),
    )


def iter_pcap(path: str | Path) -> Iterator[tuple[PcapHeader, PcapRecord]]:
    with open(path, "rb") as fh:
        header = read_header(fh)
        scale = 1_000_000_000.0 if header.nanosecond else 1_000_000.0
        index = 0
        while True:
            raw = fh.read(16)
            if not raw:
                break
            if len(raw) != 16:
                raise PcapFormatError(f"第 {index + 1} 条记录头被截断")
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(header.endian + "IIII", raw)
            if incl_len > MAX_RECORD:
                raise PcapFormatError(f"第 {index + 1} 条记录长度异常: {incl_len}")
            data = fh.read(incl_len)
            if len(data) != incl_len:
                raise PcapFormatError(f"第 {index + 1} 条记录数据被截断")
            index += 1
            yield header, PcapRecord(
                ts=float(ts_sec) + float(ts_frac) / scale,
                data=data,
                wirelen=int(orig_len),
            )


def read_pcap(path: str | Path, limit: Optional[int] = None) -> tuple[PcapHeader, List[PcapRecord]]:
    records: List[PcapRecord] = []
    header: Optional[PcapHeader] = None
    for hdr, rec in iter_pcap(path):
        header = hdr
        records.append(rec)
        if limit is not None and len(records) >= limit:
            break
    if header is None:
        raise PcapFormatError("pcap 文件中没有数据包")
    return header, records


class PcapWriter:
    def __init__(self, path: str | Path, linktype: int = 1, snaplen: int = 65535):
        self.path = Path(path)
        self.linktype = int(linktype)
        self.snaplen = int(snaplen)
        self._fh: Optional[BinaryIO] = None
        self.count = 0

    def __enter__(self) -> "PcapWriter":
        self._fh = open(self.path, "wb")
        self._fh.write(
            struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, self.snaplen, self.linktype)
        )
        return self

    def write(self, ts: float, data: bytes, wirelen: Optional[int] = None) -> None:
        if self._fh is None:
            raise RuntimeError("writer is not open")
        whole = int(ts)
        frac = int(round((ts - whole) * 1_000_000))
        if frac >= 1_000_000:
            whole += 1
            frac -= 1_000_000
        if wirelen is None:
            wirelen = len(data)
        self._fh.write(struct.pack("<IIII", whole, frac, len(data), int(wirelen)))
        self._fh.write(data)
        self.count += 1

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __exit__(self, *exc) -> None:
        self.close()


def write_pcap(path: str | Path, packets: Sequence, linktype: int = 1) -> int:
    """Write :class:`~netsniff.model.Packet` objects (or raw records)."""
    with PcapWriter(path, linktype=linktype) as writer:
        for pkt in packets:
            if hasattr(pkt, "raw"):
                writer.write(float(pkt.ts), bytes(pkt.raw), int(pkt.wirelen))
            else:
                writer.write(float(pkt.ts), bytes(pkt.data), int(pkt.wirelen))
    return writer.count
