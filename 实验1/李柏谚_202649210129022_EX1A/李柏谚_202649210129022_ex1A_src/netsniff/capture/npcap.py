"""ctypes binding for Npcap / libpcap.

Only the small surface needed by the sniffer is wrapped:

* enumerate capture devices (with their IPv4/IPv6 addresses)
* open a live capture, set a BPF filter, read packets, read driver statistics
* report useful error strings

The module is import-safe on machines without Npcap: the DLL is loaded lazily
by :func:`get_npcap`, so the offline pcap viewer still works.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_ubyte,
    c_uint,
    c_uint32,
    c_ulong,
    c_ushort,
    c_void_p,
    create_string_buffer,
)
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from ..config import find_wpcap


class NpcapError(RuntimeError):
    """A libpcap call failed."""


class NpcapNotFound(NpcapError):
    """wpcap.dll could not be located or loaded."""


class CaptureEOF(Exception):
    """Raised by an offline handle when the file has no more packets."""


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

PCAP_ERRBUF_SIZE = 256

# link-layer header types
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127
DLT_LINUX_SLL2 = 276

DATALINK_NAMES = {
    DLT_NULL: "NULL/Loopback",
    DLT_EN10MB: "Ethernet",
    DLT_RAW: "Raw IP",
    DLT_LINUX_SLL: "Linux cooked",
    DLT_IEEE802_11: "IEEE 802.11",
    DLT_IEEE802_11_RADIO: "IEEE 802.11 + radiotap",
    DLT_LINUX_SLL2: "Linux cooked v2",
}

# pcap_if flags
PCAP_IF_LOOPBACK = 0x00000001
PCAP_IF_UP = 0x00000002
PCAP_IF_RUNNING = 0x00000004
PCAP_IF_WIRELESS = 0x00000008
PCAP_IF_CONNECTION_STATUS = 0x00000030
PCAP_IF_CONNECTION_STATUS_CONNECTED = 0x00000010


# ---------------------------------------------------------------------------
# ctypes structures
# ---------------------------------------------------------------------------

class pcap_if_t(ctypes.Structure):
    pass


class pcap_addr_t(ctypes.Structure):
    pass


pcap_if_t._fields_ = [
    ("next", POINTER(pcap_if_t)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(pcap_addr_t)),
    ("flags", c_uint),
]

pcap_addr_t._fields_ = [
    ("next", POINTER(pcap_addr_t)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
]


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_ubyte * 14)]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ("sin_family", c_ushort),
        ("sin_port", c_ushort),
        ("sin_addr", c_uint32),
        ("sin_zero", c_ubyte * 8),
    ]


class sockaddr_in6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", c_ubyte * 16),
        ("sin6_scope_id", c_uint32),
    ]


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [
        ("ts", timeval),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class pcap_stat(ctypes.Structure):
    _fields_ = [
        ("ps_recv", c_uint),
        ("ps_drop", c_uint),
        ("ps_ifdrop", c_uint),
        ("ps_capt", c_uint),
    ]


# ---------------------------------------------------------------------------
# helpers for device addresses
# ---------------------------------------------------------------------------

def _sockaddr_text(ptr: int) -> Optional[str]:
    if not ptr:
        return None
    sa = ctypes.cast(ptr, POINTER(sockaddr)).contents
    family = int(sa.sa_family)
    if family == socket.AF_INET:
        sin = ctypes.cast(ptr, POINTER(sockaddr_in)).contents
        return socket.inet_ntoa(struct.pack("<I", int(sin.sin_addr)))
    if family == socket.AF_INET6:
        sin6 = ctypes.cast(ptr, POINTER(sockaddr_in6)).contents
        try:
            return socket.inet_ntop(socket.AF_INET6, bytes(sin6.sin6_addr))
        except (OSError, ValueError):
            return None
    return None


# ---------------------------------------------------------------------------
# device description
# ---------------------------------------------------------------------------

@dataclass
class Device:
    name: str
    description: str
    addresses: List[str] = field(default_factory=list)
    flags: int = 0

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & PCAP_IF_LOOPBACK)

    @property
    def is_up(self) -> bool:
        return bool(self.flags & PCAP_IF_UP)

    @property
    def is_wireless(self) -> bool:
        return bool(self.flags & PCAP_IF_WIRELESS)

    @property
    def label(self) -> str:
        bits = [self.description or self.name]
        if self.addresses:
            bits.append(", ".join(self.addresses[:3]))
        if self.is_loopback:
            bits.append("[loopback]")
        return "  —  ".join(bits)

    def sort_key(self) -> tuple:
        text = (self.description or "").lower()
        # physical adapters first, then virtual, loopback last
        physical = any(k in text for k in ("ethernet", "wi-fi", "wifi", "wireless", "realtek", "intel", "broadcom", "qualcomm", "media"))
        virtual = any(k in text for k in ("vmware", "virtual", "hyper-v", "tailscale", "zerotier", "vpn", "wan miniport", "bluetooth", "npcap"))
        return (self.is_loopback, not self.is_up, not physical, virtual, text)


@dataclass
class CapturedPacket:
    ts: float
    data: bytes
    wirelen: int


# ---------------------------------------------------------------------------
# handle
# ---------------------------------------------------------------------------

class CaptureHandle:
    """A thin wrapper around an opened ``pcap_t``."""

    def __init__(self, npcap: "Npcap", handle: int, datalink: int, device: str = ""):
        self._npcap = npcap
        self._handle = handle
        self.datalink = datalink
        self.device = device
        self._closed = False

    @property
    def lib(self) -> "Npcap":
        return self._npcap

    def set_filter(self, expression: str) -> None:
        if not expression.strip():
            return
        lib = self._npcap.lib
        prog = bpf_program()
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        rc = lib.pcap_compile(
            c_void_p(self._handle), byref(prog), expression.encode("utf-8"), 1, c_uint32(0xFFFFFFFF)
        )
        if rc != 0:
            message = self._npcap.last_error(self._handle) or errbuf.value.decode("utf-8", "replace")
            raise NpcapError(f"BPF 过滤器编译失败: {message or expression}")
        try:
            rc = lib.pcap_setfilter(c_void_p(self._handle), byref(prog))
            if rc != 0:
                raise NpcapError(f"BPF 过滤器安装失败: {self._npcap.last_error(self._handle)}")
        finally:
            lib.pcap_freecode(byref(prog))

    def next_packet(self) -> Optional[CapturedPacket]:
        """Return the next packet, ``None`` on read timeout, raise on error."""
        if self._closed:
            raise NpcapError("capture handle already closed")
        lib = self._npcap.lib
        header = POINTER(pcap_pkthdr)()
        data = POINTER(c_ubyte)()
        rc = lib.pcap_next_ex(c_void_p(self._handle), byref(header), byref(data))
        if rc == 1:
            hdr = header.contents
            caplen = int(hdr.caplen)
            raw = ctypes.string_at(data, caplen) if caplen else b""
            ts = float(hdr.ts.tv_sec) + float(hdr.ts.tv_usec) / 1_000_000.0
            return CapturedPacket(ts=ts, data=raw, wirelen=int(hdr.len))
        if rc == 0:
            return None
        if rc == -2:
            raise CaptureEOF()
        message = self._npcap.last_error(self._handle)
        raise NpcapError(f"读包失败: {message}")

    def stats(self) -> Tuple[int, int, int]:
        lib = self._npcap.lib
        st = pcap_stat()
        rc = lib.pcap_stats(c_void_p(self._handle), byref(st))
        if rc != 0:
            return (0, 0, 0)
        return (int(st.ps_recv), int(st.ps_drop), int(st.ps_ifdrop))

    def breakloop(self) -> None:
        if not self._closed:
            try:
                self._npcap.lib.pcap_breakloop(c_void_p(self._handle))
            except Exception:
                pass

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._npcap.lib.pcap_close(c_void_p(self._handle))
            except Exception:
                pass
            self._handle = 0

    def __enter__(self) -> "CaptureHandle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# library
# ---------------------------------------------------------------------------

class Npcap:
    def __init__(self, dll_path: Path | str):
        self.dll_path = Path(dll_path)
        try:
            # WinDLL uses stdcall on 32-bit Windows; on 64-bit there is a
            # single calling convention, so either loader works.
            self.lib = ctypes.WinDLL(str(self.dll_path))
        except OSError as exc:
            raise NpcapNotFound(f"无法加载 {self.dll_path}: {exc}") from exc
        self._bind()

    # -- prototypes -------------------------------------------------------
    def _bind(self) -> None:
        lib = self.lib

        lib.pcap_lib_version.restype = c_char_p
        lib.pcap_lib_version.argtypes = []

        lib.pcap_findalldevs.restype = c_int
        lib.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if_t)), c_char_p]

        lib.pcap_freealldevs.restype = None
        lib.pcap_freealldevs.argtypes = [POINTER(pcap_if_t)]

        lib.pcap_create.restype = c_void_p
        lib.pcap_create.argtypes = [c_char_p, c_char_p]

        lib.pcap_open_live.restype = c_void_p
        lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

        for name in (
            "pcap_set_snaplen",
            "pcap_set_promisc",
            "pcap_set_timeout",
            "pcap_set_buffer_size",
            "pcap_set_immediate_mode",
        ):
            func = getattr(lib, name, None)
            if func is not None:
                func.restype = c_int
                func.argtypes = [c_void_p, c_int]

        lib.pcap_activate.restype = c_int
        lib.pcap_activate.argtypes = [c_void_p]

        lib.pcap_close.restype = None
        lib.pcap_close.argtypes = [c_void_p]

        lib.pcap_datalink.restype = c_int
        lib.pcap_datalink.argtypes = [c_void_p]

        lib.pcap_compile.restype = c_int
        lib.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint32]

        lib.pcap_setfilter.restype = c_int
        lib.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]

        lib.pcap_freecode.restype = None
        lib.pcap_freecode.argtypes = [POINTER(bpf_program)]

        lib.pcap_next_ex.restype = c_int
        lib.pcap_next_ex.argtypes = [
            c_void_p,
            POINTER(POINTER(pcap_pkthdr)),
            POINTER(POINTER(c_ubyte)),
        ]

        lib.pcap_stats.restype = c_int
        lib.pcap_stats.argtypes = [c_void_p, POINTER(pcap_stat)]

        lib.pcap_geterr.restype = c_char_p
        lib.pcap_geterr.argtypes = [c_void_p]

        lib.pcap_breakloop.restype = None
        lib.pcap_breakloop.argtypes = [c_void_p]

        if hasattr(lib, "pcap_statustostr"):
            lib.pcap_statustostr.restype = c_char_p
            lib.pcap_statustostr.argtypes = [c_int]

        # Optional performance knob (Npcap): reduce wakeups by delivering
        # batches of at least this many bytes.
        if hasattr(lib, "pcap_setmintocopy"):
            lib.pcap_setmintocopy.restype = c_int
            lib.pcap_setmintocopy.argtypes = [c_void_p, c_int]

    # -- info -------------------------------------------------------------
    def version(self) -> str:
        try:
            return self.lib.pcap_lib_version().decode("utf-8", "replace")
        except Exception:
            return "unknown"

    def last_error(self, handle: int | None = None) -> str:
        try:
            if handle:
                value = self.lib.pcap_geterr(c_void_p(handle))
                if value:
                    return value.decode("utf-8", "replace")
        except Exception:
            pass
        return ""

    def status_text(self, code: int) -> str:
        try:
            value = self.lib.pcap_statustostr(int(code))
            if value:
                return value.decode("utf-8", "replace")
        except Exception:
            pass
        return f"error code {code}"

    # -- devices ----------------------------------------------------------
    def devices(self) -> List[Device]:
        alldevs = POINTER(pcap_if_t)()
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        rc = self.lib.pcap_findalldevs(byref(alldevs), errbuf)
        if rc != 0:
            message = errbuf.value.decode("utf-8", "replace")
            raise NpcapError(f"枚举网卡失败: {message}")
        out: List[Device] = []
        try:
            node = alldevs
            while node:
                item = node.contents
                name = (item.name or b"").decode("utf-8", "replace")
                description = (item.description or b"").decode("utf-8", "replace")
                addresses: List[str] = []
                addr = item.addresses
                while addr:
                    text = _sockaddr_text(addr.contents.addr)
                    if text and text not in addresses:
                        addresses.append(text)
                    addr = addr.contents.next
                if name:
                    out.append(
                        Device(
                            name=name,
                            description=description or name,
                            addresses=addresses,
                            flags=int(item.flags),
                        )
                    )
                node = item.next
        finally:
            self.lib.pcap_freealldevs(alldevs)
        out.sort(key=lambda d: d.sort_key())
        return out

    # -- open -------------------------------------------------------------
    def open(
        self,
        device: str,
        snaplen: int = 65535,
        promisc: bool = True,
        timeout_ms: int = 100,
        buffer_mb: int = 32,
        immediate: bool = False,
    ) -> CaptureHandle:
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = None
        if hasattr(self.lib, "pcap_create"):
            handle = self.lib.pcap_create(device.encode("utf-8"), errbuf)
            if handle:
                self.lib.pcap_set_snaplen(handle, int(snaplen))
                self.lib.pcap_set_promisc(handle, 1 if promisc else 0)
                self.lib.pcap_set_timeout(handle, int(timeout_ms))
                if hasattr(self.lib, "pcap_set_buffer_size"):
                    self.lib.pcap_set_buffer_size(handle, max(1, int(buffer_mb)) * 1024 * 1024)
                if hasattr(self.lib, "pcap_set_immediate_mode"):
                    self.lib.pcap_set_immediate_mode(handle, 1 if immediate else 0)
                if hasattr(self.lib, "pcap_setmintocopy"):
                    try:
                        self.lib.pcap_setmintocopy(handle, 65536)
                    except Exception:
                        pass
                rc = self.lib.pcap_activate(handle)
                if rc < 0:
                    message = self.last_error(handle) or self.status_text(rc)
                    self.lib.pcap_close(handle)
                    raise NpcapError(f"打开网卡失败: {message}")
                # rc > 0 is a warning (e.g. promiscuous mode not supported).
                datalink = int(self.lib.pcap_datalink(handle))
                cap = CaptureHandle(self, int(handle), datalink, device)
                if hasattr(self.lib, "pcap_setmintocopy"):
                    try:
                        self.lib.pcap_setmintocopy(handle, 65536)
                    except Exception:
                        pass
                return cap
            # pcap_create failed; fall through to pcap_open_live
        handle = self.lib.pcap_open_live(
            device.encode("utf-8"),
            int(snaplen),
            1 if promisc else 0,
            int(timeout_ms),
            errbuf,
        )
        if not handle:
            message = errbuf.value.decode("utf-8", "replace")
            raise NpcapError(f"打开网卡失败: {message}")
        datalink = int(self.lib.pcap_datalink(handle))
        return CaptureHandle(self, int(handle), datalink, device)

    def open_offline(self, path: str) -> CaptureHandle:
        """Open a pcap/pcapng file through libpcap (pcapng support comes free)."""
        if not hasattr(self.lib, "pcap_open_offline"):
            raise NpcapError("当前 wpcap.dll 不支持 pcap_open_offline")
        self.lib.pcap_open_offline.restype = c_void_p
        self.lib.pcap_open_offline.argtypes = [c_char_p, c_char_p]
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = self.lib.pcap_open_offline(str(path).encode("utf-8"), errbuf)
        if not handle:
            message = errbuf.value.decode("utf-8", "replace")
            raise NpcapError(f"打开文件失败: {message}")
        datalink = int(self.lib.pcap_datalink(handle))
        return CaptureHandle(self, int(handle), datalink, str(path))


# ---------------------------------------------------------------------------
# process wide singleton
# ---------------------------------------------------------------------------

_NPCAP: Optional[Npcap] = None
_NPCAP_ERROR: Optional[str] = None


def get_npcap(force_reload: bool = False) -> Npcap:
    global _NPCAP, _NPCAP_ERROR
    if _NPCAP is not None and not force_reload:
        return _NPCAP
    if force_reload:
        _NPCAP = None
        _NPCAP_ERROR = None
    path = find_wpcap()
    if path is None:
        _NPCAP_ERROR = (
            "未找到 wpcap.dll。请先安装 Npcap（安装时勾选 “Install Npcap in WinPcap API-compatible Mode” 可选），"
            "或设置环境变量 NETSNIFF_WPCAP 指向 wpcap.dll。"
        )
        raise NpcapNotFound(_NPCAP_ERROR)
    try:
        _NPCAP = Npcap(path)
    except NpcapError as exc:
        _NPCAP_ERROR = str(exc)
        raise
    return _NPCAP


def npcap_status() -> tuple[bool, str]:
    """Return ``(available, detail)`` without raising."""
    try:
        lib = get_npcap()
        return True, f"{lib.version()}  ({lib.dll_path})"
    except NpcapError as exc:
        return False, str(exc)


def last_npcap_error() -> str:
    return _NPCAP_ERROR or ""
