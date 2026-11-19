"""Protocol hierarchy, conversation and throughput statistics dialog."""

from __future__ import annotations

import csv
from typing import Dict, List, Optional

from PyQt5.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..analysis.stats import (
    CaptureSummary,
    Conversation,
    HierarchyNode,
    capture_summary,
    conversations,
    protocol_hierarchy,
    throughput_series,
)
from ..model import Packet


class NumericItem(QTableWidgetItem):
    def __init__(self, value, text: Optional[str] = None):
        super().__init__(text if text is not None else str(value))
        self.setData(Qt.UserRole, value)
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other) -> bool:
        try:
            return float(self.data(Qt.UserRole)) < float(other.data(Qt.UserRole))
        except (TypeError, ValueError):
            return super().__lt__(other)


class ThroughputChart(QWidget):
    def __init__(self, packets: List[Packet], parent=None):
        super().__init__(parent)
        self.setMinimumHeight(320)
        self._series = throughput_series(packets)
        self._font = QFont("Consolas", 8)
        self._font_ui = QFont("Microsoft YaHei UI", 9)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#1b1d21"))
        if not self._series:
            painter.setPen(QColor("#8b949e"))
            painter.setFont(self._font_ui)
            painter.drawText(self.rect(), Qt.AlignCenter, "没有可用于绘制吞吐曲线的数据")
            return
        left, right, top, bottom = 66, 96, 34, 40
        width = max(10, self.width() - left - right)
        height = max(10, self.height() - top - bottom)
        max_packets = max(1, max(p for _, p, _ in self._series))
        max_bytes = max(1, max(b for _, _, b in self._series))
        duration = self._series[-1][0] if self._series else 1.0
        # grid
        painter.setPen(QPen(QColor("#2c3036"), 1, Qt.DotLine))
        for index in range(5):
            y = top + height * index / 4
            painter.drawLine(QPointF(left, y), QPointF(left + width, y))
        # packets bars
        bar_width = max(1.0, width / len(self._series) * 0.7)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(77, 159, 255, 120))
        for index, (seconds, packets, _bytes) in enumerate(self._series):
            x = left + width * (seconds / duration if duration else 0)
            h = height * packets / max_packets
            painter.drawRect(QRectF(x - bar_width / 2, top + height - h, bar_width, h))
        # bytes line
        path = QPainterPath()
        for index, (seconds, _packets, bytes_count) in enumerate(self._series):
            x = left + width * (seconds / duration if duration else 0)
            y = top + height - height * bytes_count / max_bytes
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        pen = QPen(QColor("#3fb950"), 2)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)
        # axes labels
        painter.setFont(self._font)
        painter.setPen(QColor("#8b949e"))
        for index in range(5):
            y = top + height * index / 4
            value = max_packets * (4 - index) / 4
            label = f"{value:.0f}" if max_packets >= 8 else f"{value:.1f}"
            painter.drawText(QRectF(4, y - 8, left - 10, 16), Qt.AlignRight | Qt.AlignVCenter, label)
            bvalue = int(max_bytes * (4 - index) / 4)
            painter.drawText(QRectF(left + width + 6, y - 8, right - 10, 16), Qt.AlignLeft | Qt.AlignVCenter,
                             _human_bytes(bvalue) + "/s")
        painter.drawText(QRectF(left, self.height() - 22, 200, 16), Qt.AlignLeft,
                         f"时间 0s")
        painter.drawText(QRectF(left + width - 200, self.height() - 22, 200, 16), Qt.AlignRight,
                         f"{duration:.2f}s")
        painter.setFont(self._font_ui)
        painter.setPen(QColor("#4d9fff"))
        painter.drawText(QRectF(left, 8, 260, 18), Qt.AlignLeft, "■ 包/秒（左轴）")
        painter.setPen(QColor("#3fb950"))
        painter.drawText(QRectF(left + 150, 8, 300, 18), Qt.AlignLeft, "— 字节/秒（右轴）")


def _human_bytes(value: float) -> str:
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MiB"
    if value >= 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value:.0f} B"


class StatsDialog(QDialog):
    filter_requested = pyqtSignal(str)

    def __init__(self, packets: List[Packet], parent=None):
        super().__init__(parent)
        self.packets = packets
        self.setWindowTitle("统计")
        self.resize(1100, 760)
        self._summary = capture_summary(packets)
        self._conv_cache: Dict[str, List[Conversation]] = {}
        self._tables: Dict[str, QTableWidget] = {}
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)
        summary = self._summary
        title = QLabel(
            f"<b>{summary.packets}</b> 个数据包　"
            f"<b>{_human_bytes(summary.bytes)}</b>　"
            f"时长 <b>{summary.duration:.3f}s</b>　"
            f"平均 <b>{summary.pps:.1f}</b> pps / <b>{_human_bytes(summary.bps)}/s</b>"
            + (f"　<span style='color:#f85149'>错误 {summary.error_packets}</span>" if summary.error_packets else "")
            + (f"　<span style='color:#d29922'>警告 {summary.warning_packets}</span>" if summary.warning_packets else "")
        )
        title.setTextFormat(Qt.RichText)
        layout.addWidget(title)

        tabs = QTabWidget()
        layout.addWidget(tabs, 1)
        self._tabs = tabs

        # hierarchy -------------------------------------------------------
        hierarchy = protocol_hierarchy(self.packets)
        tree = QTreeWidget()
        tree.setHeaderLabels(["协议", "数据包", "包占比", "字节", "字节占比"])
        tree.setRootIsDecorated(True)
        tree.setUniformRowHeights(True)
        tree.setColumnWidth(0, 360)
        for column in range(1, 5):
            tree.headerItem().setTextAlignment(column, Qt.AlignRight | Qt.AlignVCenter)
        total_packets = max(1, hierarchy.packets)
        total_bytes = max(1, hierarchy.bytes)
        self._fill_hierarchy(tree, hierarchy, total_packets, total_bytes, None)
        tree.expandAll()
        tabs.addTab(tree, "协议分层")

        # conversations ---------------------------------------------------
        self._conv_tabs = QTabWidget()
        tabs.addTab(self._conv_tabs, "会话")
        for kind, label in (("ipv4", "IPv4"), ("ipv6", "IPv6"), ("tcp", "TCP"), ("udp", "UDP")):
            table = self._make_conversation_table(kind)
            self._tables[kind] = table
            self._conv_tabs.addTab(table, label)
        self._conv_tabs.currentChanged.connect(self._ensure_conversations)
        self._ensure_conversations(0)

        # throughput ------------------------------------------------------
        tabs.addTab(ThroughputChart(self.packets), "吞吐量")

        buttons = QDialogButtonBox()
        export = QPushButton("导出当前会话表 CSV")
        export.clicked.connect(self._export_csv)
        buttons.addButton(export, QDialogButtonBox.ActionRole)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        buttons.addButton(close, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

    def _fill_hierarchy(self, tree: QTreeWidget, node: HierarchyNode,
                        total_packets: int, total_bytes: int, parent) -> None:
        if parent is None:
            item = QTreeWidgetItem([
                "Frame",
                str(node.packets),
                "100.0%",
                _human_bytes(node.bytes),
                "100.0%",
            ])
            for column in range(1, 5):
                item.setTextAlignment(column, Qt.AlignRight | Qt.AlignVCenter)
            tree.addTopLevelItem(item)
            self._add_hierarchy_children(item, node, total_packets, total_bytes)
            return
        self._add_hierarchy_children(parent, node, total_packets, total_bytes)

    def _add_hierarchy_children(self, parent: QTreeWidgetItem, node: HierarchyNode,
                                total_packets: int, total_bytes: int) -> None:
        for child in node.sorted_children():
            item = QTreeWidgetItem([
                child.name,
                str(child.packets),
                f"{child.packets * 100.0 / total_packets:.1f}%",
                _human_bytes(child.bytes),
                f"{child.bytes * 100.0 / total_bytes:.1f}%",
            ])
            for column in range(1, 5):
                item.setTextAlignment(column, Qt.AlignRight | Qt.AlignVCenter)
            parent.addChild(item)
            self._add_hierarchy_children(item, child, total_packets, total_bytes)

    def _make_conversation_table(self, kind: str) -> QTableWidget:
        table = QTableWidget(0, 9)
        table.setHorizontalHeaderLabels(
            ["地址 A", "端口 A", "地址 B", "端口 B", "包", "字节", "时长", "A → B", "B → A"]
        )
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSortingEnabled(True)
        header = table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        for column in (1, 3, 4, 5, 6, 7, 8):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        table.doubleClicked.connect(lambda index, k=kind: self._emit_filter(k, index.row()))
        return table

    def _ensure_conversations(self, index: int) -> None:
        kinds = ["ipv4", "ipv6", "tcp", "udp"]
        if index < 0 or index >= len(kinds):
            return
        kind = kinds[index]
        if kind in self._conv_cache:
            return
        entries = conversations(self.packets, kind)
        self._conv_cache[kind] = entries
        table = self._tables[kind]
        table.setSortingEnabled(False)
        table.setRowCount(len(entries))
        for row, conv in enumerate(entries):
            address_item = QTableWidgetItem(conv.a_ip)
            address_item.setData(Qt.UserRole, conv)
            table.setItem(row, 0, address_item)
            table.setItem(row, 1, NumericItem(conv.a_port, str(conv.a_port) if conv.a_port else "—"))
            table.setItem(row, 2, QTableWidgetItem(conv.b_ip))
            table.setItem(row, 3, NumericItem(conv.b_port, str(conv.b_port) if conv.b_port else "—"))
            table.setItem(row, 4, NumericItem(conv.packets))
            table.setItem(row, 5, NumericItem(conv.bytes, _human_bytes(conv.bytes)))
            table.setItem(row, 6, NumericItem(round(conv.duration, 6), f"{conv.duration:.3f}s"))
            table.setItem(row, 7, NumericItem(conv.bytes_ab, _human_bytes(conv.bytes_ab)))
            table.setItem(row, 8, NumericItem(conv.bytes_ba, _human_bytes(conv.bytes_ba)))
        table.setSortingEnabled(True)
        table.sortItems(4, Qt.DescendingOrder)

    def _emit_filter(self, kind: str, row: int) -> None:
        table = self._tables.get(kind)
        if table is None:
            return
        item = table.item(row, 0)
        if item is None:
            return
        conv = item.data(Qt.UserRole)
        if conv is not None:
            self.filter_requested.emit(conv.filter_expression())

    def _export_csv(self) -> None:
        kinds = ["ipv4", "ipv6", "tcp", "udp"]
        index = self._conv_tabs.currentIndex()
        kind = kinds[index] if 0 <= index < len(kinds) else "tcp"
        entries = self._conv_cache.get(kind, [])
        path, _ = QFileDialog.getSaveFileName(self, "导出会话", f"conversations_{kind}.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(["address_a", "port_a", "address_b", "port_b", "packets", "bytes",
                             "duration_s", "bytes_a_to_b", "bytes_b_to_a"])
            for conv in entries:
                writer.writerow([conv.a_ip, conv.a_port, conv.b_ip, conv.b_port, conv.packets,
                                 conv.bytes, f"{conv.duration:.6f}", conv.bytes_ab, conv.bytes_ba])
