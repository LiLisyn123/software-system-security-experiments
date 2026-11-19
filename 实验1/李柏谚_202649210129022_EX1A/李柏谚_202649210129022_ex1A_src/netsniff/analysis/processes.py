"""Map local TCP/UDP endpoints to Windows PIDs and process names.

Uses ``GetExtendedTcpTable`` / ``GetExtendedUdpTable`` (OWNER_PID tables) from
iphlpapi.dll and ``QueryFullProcessImageNameW`` from kernel32.dll.  No third
party dependency and no administrator rights are required for the current
user's own sockets; some system processes may be visible with a restricted
name only.

The table is refreshed periodically by the GUI; lookups are cheap.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
import threading
from ctypes import wintypes
from typing import Dict, Optional, Tuple


AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

IS_WINDOWS = sys.platform.startswith("win")


if IS_WINDOWS:
    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("ucRemoteAddr", ctypes.c_ubyte * 16),
            ("dwRemoteScopeId", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
            ("dwState", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwOwningPid", wintypes.DWORD),
        ]

    _iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    _kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    _iphlpapi.GetExtendedTcpTable.restype = wintypes.ULONG
    _iphlpapi.GetExtendedTcpTable.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _iphlpapi.GetExtendedUdpTable.restype = wintypes.ULONG
    _iphlpapi.GetExtendedUdpTable.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
    ]

    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]


def _v4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value & 0xFFFFFFFF))


def _port(value: int) -> int:
    return socket.ntohs(value & 0xFFFF)


def _v6(raw) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw))
    except (OSError, ValueError):
        return "::"


def _get_tcp_table(af: int, row_type, table_class: int) -> list:
    size = wintypes.DWORD(0)
    _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, af, table_class, 0)
    if size.value == 0:
        return []
    buffer = ctypes.create_string_buffer(size.value)
    rc = _iphlpapi.GetExtendedTcpTable(
        buffer, ctypes.byref(size), False, af, table_class, 0
    )
    if rc != 0:
        raise OSError(rc, f"GetExtendedTcpTable failed with {rc}")
    count = wintypes.DWORD.from_buffer(buffer, 0).value
    row_size = ctypes.sizeof(row_type)
    rows = []
    for index in range(count):
        offset = 4 + index * row_size
        if offset + row_size > len(buffer):
            break
        row = row_type.from_buffer_copy(buffer, offset)
        rows.append(row)
    return rows


def _get_udp_table(af: int, row_type, table_class: int) -> list:
    size = wintypes.DWORD(0)
    _iphlpapi.GetExtendedUdpTable(None, ctypes.byref(size), False, af, table_class, 0)
    if size.value == 0:
        return []
    buffer = ctypes.create_string_buffer(size.value)
    rc = _iphlpapi.GetExtendedUdpTable(
        buffer, ctypes.byref(size), False, af, table_class, 0
    )
    if rc != 0:
        raise OSError(rc, f"GetExtendedUdpTable failed with {rc}")
    count = wintypes.DWORD.from_buffer(buffer, 0).value
    row_size = ctypes.sizeof(row_type)
    rows = []
    for index in range(count):
        offset = 4 + index * row_size
        if offset + row_size > len(buffer):
            break
        rows.append(row_type.from_buffer_copy(buffer, offset))
    return rows


class ProcessTable:
    def __init__(self):
        self._lock = threading.RLock()
        self._endpoints: Dict[Tuple[str, str, int], int] = {}
        self._names: Dict[int, str] = {}
        self._paths: Dict[int, str] = {}
        self.local_ips: set[str] = {"127.0.0.1", "::1"}
        self.last_error = ""
        self.available = IS_WINDOWS
        self.updated_at = 0.0

    # -- public -----------------------------------------------------------
    def refresh(self) -> None:
        if not IS_WINDOWS:
            return
        endpoints: Dict[Tuple[str, str, int], int] = {}
        local_ips: set[str] = {"127.0.0.1", "::1"}
        try:
            for af, row_type in ((AF_INET, MIB_TCPROW_OWNER_PID), (AF_INET6, MIB_TCP6ROW_OWNER_PID)):
                for row in _get_tcp_table(af, row_type, TCP_TABLE_OWNER_PID_ALL):
                    if af == AF_INET:
                        ip = _v4(int(row.dwLocalAddr))
                    else:
                        ip = _v6(row.ucLocalAddr)
                    port = _port(int(row.dwLocalPort))
                    pid = int(row.dwOwningPid)
                    if pid <= 0:
                        # TIME_WAIT rows report PID 0 and can overwrite the
                        # real listener's PID for the same local port.
                        continue
                    endpoints[("tcp", ip, port)] = pid
                    if ip not in ("0.0.0.0", "::"):
                        local_ips.add(ip)
            for af, row_type in ((AF_INET, MIB_UDPROW_OWNER_PID), (AF_INET6, MIB_UDP6ROW_OWNER_PID)):
                for row in _get_udp_table(af, row_type, UDP_TABLE_OWNER_PID):
                    if af == AF_INET:
                        ip = _v4(int(row.dwLocalAddr))
                    else:
                        ip = _v6(row.ucLocalAddr)
                    port = _port(int(row.dwLocalPort))
                    pid = int(row.dwOwningPid)
                    if pid <= 0:
                        continue
                    endpoints[("udp", ip, port)] = pid
                    if ip not in ("0.0.0.0", "::"):
                        local_ips.add(ip)
            with self._lock:
                self._endpoints = endpoints
                self.local_ips = local_ips
                self.last_error = ""
                self.updated_at = __import__("time").time()
        except OSError as exc:
            with self._lock:
                self.last_error = str(exc)

    def lookup(self, proto: str, src_ip: str, sport: int,
               dst_ip: str, dport: int) -> Optional[Tuple[int, str]]:
        if not IS_WINDOWS:
            return None
        with self._lock:
            endpoints = self._endpoints
            local_ips = self.local_ips
        for ip, port in ((src_ip, sport), (dst_ip, dport)):
            ip = (ip or "").split("%", 1)[0]
            pid = endpoints.get((proto, ip, port))
            if pid is None and (ip in local_ips or ip.startswith("127.") or ip == "::1"):
                pid = endpoints.get((proto, "0.0.0.0", port))
                if pid is None:
                    pid = endpoints.get((proto, "::", port))
            if pid is not None:
                return pid, self.process_name(pid)
        return None

    def process_name(self, pid: int) -> str:
        with self._lock:
            if pid in self._names:
                return self._names[pid]
        name = self._query_name(pid)
        with self._lock:
            self._names[pid] = name
        return name

    def process_path(self, pid: int) -> str:
        self.process_name(pid)
        with self._lock:
            return self._paths.get(pid, "")

    def _query_name(self, pid: int) -> str:
        if not IS_WINDOWS:
            return f"PID {pid}"
        if pid == 0:
            return "System Idle Process"
        if pid == 4:
            return "System"
        handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return f"PID {pid} (拒绝访问)"
        try:
            size = wintypes.DWORD(1024)
            buffer = ctypes.create_unicode_buffer(1024)
            if _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                path = buffer.value
                with self._lock:
                    self._paths[pid] = path
                return path.rsplit("\\", 1)[-1] or path
            return f"PID {pid}"
        finally:
            _kernel32.CloseHandle(handle)

    def summary(self) -> str:
        with self._lock:
            return f"{len(self._endpoints)} local endpoints, {len(self._names)} processes"


def _selftest() -> None:
    table = ProcessTable()
    table.refresh()
    print("available:", table.available, "error:", table.last_error)
    print(table.summary())
    for key, pid in list(table._endpoints.items())[:10]:
        print(key, "->", pid, table.process_name(pid))


if __name__ == "__main__":
    _selftest()
