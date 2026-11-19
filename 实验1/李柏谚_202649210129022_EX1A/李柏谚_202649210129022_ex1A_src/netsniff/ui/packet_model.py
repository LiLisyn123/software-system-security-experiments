"""Qt table model for the packet list."""

from __future__ import annotations

import datetime as _dt
from typing import Iterable, List, Optional

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt5.QtGui import QColor, QFont

from ..model import Packet, format_timestamp
from .theme import packet_background, packet_foreground


class PacketListModel(QAbstractTableModel):
    HEADERS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Process"]
    HEADER_TIPS = [
        "帧序号",
        "时间（相对/绝对/增量，可在“视图 → 时间格式”切换）",
        "源地址",
        "目的地址",
        "最高层协议",
        "线上帧长度（字节）",
        "协议摘要",
        "产生该包的本地进程（Windows）",
    ]

    def __init__(self, max_packets: int = 200000, parent=None):
        super().__init__(parent)
        self.packets: List[Packet] = []
        self.visible: List[Packet] = []
        self.max_packets = max_packets
        self._display_filter = None
        self.t0: Optional[float] = None
        self.time_mode = "relative"
        self.dark = True
        self._font_mono = QFont("Consolas", 9)
        self._font_ui = QFont("Microsoft YaHei UI", 9)
        self._bg_cache: dict[tuple[str, bool], QColor] = {}
        self._fg_cache: dict[tuple[str, bool], QColor] = {}

    # -- Qt API -----------------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.visible)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal:
            if role == Qt.DisplayRole:
                return self.HEADERS[section] if 0 <= section < len(self.HEADERS) else ""
            if role == Qt.ToolTipRole:
                return self.HEADER_TIPS[section] if 0 <= section < len(self.HEADER_TIPS) else ""
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.visible):
            return None
        packet = self.visible[index.row()]
        column = index.column()
        if role == Qt.DisplayRole:
            if column == 0:
                return str(packet.number)
            if column == 1:
                return self._time_text(packet, index.row())
            if column == 2:
                return packet.src
            if column == 3:
                return packet.dst
            if column == 4:
                return packet.protocol
            if column == 5:
                return str(packet.wirelen)
            if column == 6:
                return packet.info
            if column == 7:
                return packet.process or ""
        if role == Qt.TextAlignmentRole:
            if column in (0, 1, 5):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        if role == Qt.BackgroundRole:
            return self._background(packet)
        if role == Qt.ForegroundRole and column == 4:
            return self._foreground(packet.color)
        if role == Qt.FontRole and column in (0, 1, 3, 5):
            return self._font_mono if column != 3 else self._font_ui
        if role == Qt.ToolTipRole:
            bits = [
                f"#{packet.number}  {packet.protocol}",
                f"{packet.src} → {packet.dst}",
                packet.info,
                f"时间: {format_timestamp(packet.ts)}",
                f"长度: {packet.wirelen} bytes (捕获 {packet.caplen})",
                f"协议栈: {packet.protocols_string()}",
            ]
            if packet.process:
                bits.append(f"进程: {packet.process} (PID {packet.pid})")
            if packet.expert:
                bits.append("专家信息: " + "; ".join(packet.expert))
            return "\n".join(bits)
        if role == Qt.UserRole:
            return packet
        return None

    # -- data management --------------------------------------------------
    def append_packets(self, packets: Iterable[Packet]) -> int:
        packets = list(packets)
        if not packets:
            return 0
        if self.t0 is None and packets:
            self.t0 = packets[0].ts
        if len(self.packets) + len(packets) > self.max_packets:
            self.beginResetModel()
            combined = self.packets + packets
            self.packets = combined[-self.max_packets:]
            self.visible = [p for p in self.packets if self._passes(p)]
            self.endResetModel()
            return len(self.visible)
        start = len(self.visible)
        new_visible: List[Packet] = []
        for packet in packets:
            self.packets.append(packet)
            if self._passes(packet):
                new_visible.append(packet)
        if new_visible:
            self.beginInsertRows(QModelIndex(), start, start + len(new_visible) - 1)
            self.visible.extend(new_visible)
            self.endInsertRows()
        return len(new_visible)

    def set_filter(self, display_filter) -> None:
        self.beginResetModel()
        self._display_filter = display_filter
        self.visible = [p for p in self.packets if self._passes(p)]
        self.endResetModel()

    def refilter(self) -> None:
        self.set_filter(self._display_filter)

    def clear(self) -> None:
        self.beginResetModel()
        self.packets.clear()
        self.visible.clear()
        self.t0 = None
        self.endResetModel()

    def set_time_mode(self, mode: str) -> None:
        if mode not in ("relative", "absolute", "delta"):
            return
        if mode == self.time_mode:
            return
        self.time_mode = mode
        if self.visible:
            self.dataChanged.emit(
                self.index(0, 1), self.index(len(self.visible) - 1, 1),
                [Qt.DisplayRole],
            )

    def set_dark(self, dark: bool) -> None:
        if dark == self.dark:
            return
        self.dark = dark
        self._bg_cache.clear()
        self._fg_cache.clear()
        if self.visible:
            self.dataChanged.emit(
                self.index(0, 0), self.index(len(self.visible) - 1, len(self.HEADERS) - 1),
                [Qt.BackgroundRole, Qt.ForegroundRole],
            )

    def set_max_packets(self, maximum: int) -> None:
        self.max_packets = max(1000, int(maximum))

    # -- helpers ----------------------------------------------------------
    def _passes(self, packet: Packet) -> bool:
        return True if self._display_filter is None else bool(self._display_filter(packet))

    def _time_text(self, packet: Packet, row: int) -> str:
        if self.time_mode == "absolute":
            try:
                dt = _dt.datetime.fromtimestamp(packet.ts)
                return dt.strftime("%H:%M:%S.%f")
            except (OSError, ValueError):
                return f"{packet.ts:.6f}"
        if self.time_mode == "delta":
            if row == 0:
                base = self.t0 if self.t0 is not None else packet.ts
            else:
                base = self.visible[row - 1].ts
            return f"{packet.ts - base:.6f}"
        base = self.t0 if self.t0 is not None else packet.ts
        return f"{packet.ts - base:.6f}"

    def _background(self, packet: Packet) -> QColor:
        key = (packet.color, self.dark)
        color = self._bg_cache.get(key)
        if color is None:
            color = packet_background(packet.color, self.dark)
            self._bg_cache[key] = color
        return color

    def _foreground(self, key: str) -> QColor:
        cache_key = (key, self.dark)
        color = self._fg_cache.get(cache_key)
        if color is None:
            color = packet_foreground(key, self.dark)
            self._fg_cache[cache_key] = color
        return color

    # -- accessors --------------------------------------------------------
    def packet_at(self, row: int) -> Optional[Packet]:
        if 0 <= row < len(self.visible):
            return self.visible[row]
        return None

    def row_of_packet(self, number: int) -> int:
        for row, packet in enumerate(self.visible):
            if packet.number == number:
                return row
        return -1

    def all_packets(self) -> List[Packet]:
        return self.packets

    def visible_packets(self) -> List[Packet]:
        return self.visible

    @property
    def total_count(self) -> int:
        return len(self.packets)

    @property
    def visible_count(self) -> int:
        return len(self.visible)
