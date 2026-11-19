"""TCP stream dialog: sequence diagram, reassembled text/hex and HTTP view."""

from __future__ import annotations

import html
from typing import List, Optional, Tuple

from PyQt5.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen, QPolygonF
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..analysis.streams import Segment, StreamSnapshot
from ..dissect.http import HTTP_PORTS, parse_http_messages
from ..dissect.utils import tcp_flags_text


CLIENT_COLOR = "#4d9fff"
SERVER_COLOR = "#3fb950"
MUTED = "#8b949e"


def _hex_dump(data: bytes, limit: int = 256 * 1024) -> str:
    chunk = data[:limit]
    lines = []
    for offset in range(0, len(chunk), 16):
        row = chunk[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        if len(row) > 8:
            hexpart = hexpart[:23] + "  " + hexpart[23:]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset:08x}  {hexpart:<49}  {text}")
    if len(data) > limit:
        lines.append(f"... truncated at {limit} bytes ...")
    return "\n".join(lines)


class SequenceDiagram(QWidget):
    """A Wireshark-style TCP sequence diagram (time flows downwards)."""

    packet_clicked = pyqtSignal(int)
    ROW_HEIGHT = 30
    MAX_ROWS = 600
    WIDTH = 1000

    def __init__(self, snapshot: StreamSnapshot, parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self._segments = snapshot.segments[:self.MAX_ROWS]
        self._rows: List[Tuple[float, float, Segment]] = []
        self.setMinimumSize(self.WIDTH, max(420, 110 + len(self._segments) * self.ROW_HEIGHT))
        self.setMouseTracking(True)
        self._font = QFont("Consolas", 9)
        self._font_ui = QFont("Microsoft YaHei UI", 9)
        self._font_bold = QFont("Microsoft YaHei UI", 9, QFont.Bold)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#1b1d21"))
        width = self.width()
        height = self.height()
        x_client = int(width * 0.29)
        x_server = int(width * 0.71)
        top = 52
        if self.snapshot.segments:
            painter.setFont(self._font_bold)
            painter.setPen(QColor("#d9dee7"))
            painter.drawText(QRectF(14, 10, 120, 22), Qt.AlignLeft | Qt.AlignVCenter,
                             f"+{self.snapshot.segments[0].ts - self.snapshot.first_ts:.3f}s")
        # lifelines
        painter.setPen(QPen(QColor("#3a4048"), 1.5, Qt.DashLine))
        painter.drawLine(QPointF(x_client, top), QPointF(x_client, height - 20))
        painter.drawLine(QPointF(x_server, top), QPointF(x_server, height - 20))
        # endpoint boxes
        self._draw_endpoint(painter, x_client, 10, CLIENT_COLOR,
                            "客户端", f"{self.snapshot.client}:{self.snapshot.cport}")
        self._draw_endpoint(painter, x_server, 10, SERVER_COLOR,
                            "服务器", f"{self.snapshot.server}:{self.snapshot.sport}")
        if len(self.snapshot.segments) > self.MAX_ROWS:
            painter.drawText(QRectF(14, height - 24, width - 28, 18), Qt.AlignRight,
                             f"仅显示前 {self.MAX_ROWS} 个 TCP 段（共 {len(self.snapshot.segments)} 个）")
        self._rows.clear()
        base_ts = self.snapshot.first_ts
        for index, seg in enumerate(self._segments):
            y = top + 40 + index * self.ROW_HEIGHT
            if y > height - 26:
                break
            if index % 2 == 0:
                painter.fillRect(QRectF(0, y - self.ROW_HEIGHT / 2, width, self.ROW_HEIGHT),
                                 QColor(255, 255, 255, 4))
            color = QColor(CLIENT_COLOR if seg.direction == 0 else SERVER_COLOR)
            data_segment = seg.payload_len > 0
            if not data_segment:
                color.setAlpha(150)
            pen = QPen(color, 2.2 if data_segment else 1.3)
            if not data_segment:
                pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            if seg.direction == 0:
                x1, x2 = x_client + 8, x_server - 8
            else:
                x1, x2 = x_server - 8, x_client + 8
            painter.drawLine(QPointF(x1, y), QPointF(x2, y))
            self._arrow_head(painter, x1, x2, y, color)
            # time on the left
            painter.setFont(self._font)
            painter.setPen(QColor(MUTED))
            painter.drawText(QRectF(10, y - 10, 110, 20), Qt.AlignLeft | Qt.AlignVCenter,
                             f"+{seg.ts - base_ts:.3f}")
            # flags / length in the middle
            flags = tcp_flags_text(seg.flags)
            if data_segment:
                label = f"{flags}   Len={seg.payload_len}   Seq={seg.rel_seq}"
            else:
                label = flags
            painter.setFont(self._font)
            painter.setPen(QColor("#d9dee7"))
            metrics = QFontMetrics(self._font)
            text_width = metrics.horizontalAdvance(label)
            painter.drawText(QPointF((x1 + x2) / 2 - text_width / 2, y - 5), label)
            # packet number on the right
            painter.setPen(QColor(MUTED))
            painter.drawText(QRectF(width - 90, y - 10, 78, 20), Qt.AlignRight | Qt.AlignVCenter,
                             f"#{seg.packet_number}")
            self._rows.append((y - self.ROW_HEIGHT / 2, y + self.ROW_HEIGHT / 2, seg))
        painter.end()

    def _draw_endpoint(self, painter: QPainter, x: int, y: int, color: str, title: str, detail: str) -> None:
        painter.setPen(QPen(QColor(color), 1.5))
        painter.setBrush(QColor(36, 39, 44))
        painter.drawRoundedRect(QRectF(x - 135, y, 270, 42), 7, 7)
        painter.setFont(self._font_bold)
        painter.setPen(QColor(color))
        painter.drawText(QRectF(x - 125, y + 4, 250, 18), Qt.AlignCenter, title)
        painter.setFont(self._font)
        painter.setPen(QColor("#d9dee7"))
        painter.drawText(QRectF(x - 125, y + 21, 250, 17), Qt.AlignCenter, detail)

    @staticmethod
    def _arrow_head(painter: QPainter, x1: float, x2: float, y: float, color: QColor) -> None:
        direction = 1 if x2 > x1 else -1
        tip = QPointF(x2, y)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawPolygon(QPolygonF([
            tip,
            QPointF(x2 - direction * 10, y - 4.5),
            QPointF(x2 - direction * 10, y + 4.5),
        ]))

    def mouseMoveEvent(self, event) -> None:
        for top, bottom, seg in self._rows:
            if top <= event.y() <= bottom:
                text = (
                    f"#{seg.packet_number}  {tcp_flags_text(seg.flags)}\n"
                    f"Seq={seg.seq} (相对 {seg.rel_seq})  Ack={seg.ack}\n"
                    f"Len={seg.payload_len}  Win={seg.window}\n"
                    f"时间: +{seg.ts - self.snapshot.first_ts:.6f}s"
                )
                from PyQt5.QtWidgets import QToolTip
                QToolTip.showText(event.globalPos(), text, self)
                return
        from PyQt5.QtWidgets import QToolTip
        QToolTip.hideText()

    def mousePressEvent(self, event) -> None:
        for top, bottom, seg in self._rows:
            if top <= event.y() <= bottom:
                self.packet_clicked.emit(seg.packet_number)
                return


class TcpStreamDialog(QDialog):
    filter_requested = pyqtSignal(str)
    packet_selected = pyqtSignal(int)

    def __init__(self, snapshot: StreamSnapshot, parent=None, process: str = ""):
        super().__init__(parent)
        self.snapshot = snapshot
        self.process = process
        self.setWindowTitle(f"TCP 流 #{snapshot.index} — {snapshot.client}:{snapshot.cport} ↔ "
                            f"{snapshot.server}:{snapshot.sport}")
        self.resize(1180, 820)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)
        snap = self.snapshot
        header = QLabel(
            f"<span style='color:{CLIENT_COLOR}; font-weight:600'>"
            f"{html.escape(snap.client)}:{snap.cport}</span>"
            f" <span style='color:{MUTED}'>↔</span> "
            f"<span style='color:{SERVER_COLOR}; font-weight:600'>"
            f"{html.escape(snap.server)}:{snap.sport}</span>"
            f" <span style='color:{MUTED}'>　状态 {snap.state}　{snap.packets} 包　"
            f"{snap.bytes} 字节　{snap.last_ts - snap.first_ts:.3f}s"
            + (f"　进程 {html.escape(self.process)}" if self.process else "")
            + "</span>"
        )
        header.setTextFormat(Qt.RichText)
        header.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(header)
        if snap.truncated:
            note = QLabel("注意：流数据超过内存上限，后续内容未完整保留。")
            note.setStyleSheet("color: #d29922;")
            layout.addWidget(note)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        # sequence diagram
        diagram = SequenceDiagram(snap)
        diagram.packet_clicked.connect(self.packet_selected)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(diagram)
        scroll.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.tabs.addTab(scroll, "时序图")

        # text views
        self.tabs.addTab(self._text_tab(snap.data_c2s, "客户端 → 服务器"), "C → S")
        self.tabs.addTab(self._text_tab(snap.data_s2c, "服务器 → 客户端"), "S → C")
        self.tabs.addTab(self._bidirectional_tab(), "双向")
        self.tabs.addTab(self._hex_tab(), "十六进制")
        self.tabs.addTab(self._http_tab(), "HTTP 事务")

        buttons = QDialogButtonBox()
        apply_button = QPushButton("应用过滤器")
        apply_button.setObjectName("primary")
        apply_button.clicked.connect(self._apply_filter)
        buttons.addButton(apply_button, QDialogButtonBox.ActionRole)
        copy_button = QPushButton("复制全部")
        copy_button.clicked.connect(self._copy_all)
        buttons.addButton(copy_button, QDialogButtonBox.ActionRole)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        buttons.addButton(close_button, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

    def _text_tab(self, data: bytes, title: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        info = QLabel(f"{title} · {len(data)} bytes" + ("（存在重传/乱序，已按序列号重组）" if data else "（无数据）"))
        info.setObjectName("hint")
        layout.addWidget(info)
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        editor.setFont(QFont("Consolas", 9))
        text = data.decode("utf-8", "replace")
        text = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in text)
        editor.setPlainText(text)
        layout.addWidget(editor, 1)
        return widget

    def _bidirectional_tab(self) -> QWidget:
        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)
        parts = []
        if self.snapshot.data_c2s:
            parts.append(
                f"<div style='color:{CLIENT_COLOR}; font-weight:bold'>客户端 → 服务器</div>"
                f"<pre style='color:#6fb7ff; white-space:pre-wrap'>{html.escape(self._text(self.snapshot.data_c2s))}</pre>"
            )
        if self.snapshot.data_s2c:
            parts.append(
                f"<div style='color:{SERVER_COLOR}; font-weight:bold'>服务器 → 客户端</div>"
                f"<pre style='color:#82d99b; white-space:pre-wrap'>{html.escape(self._text(self.snapshot.data_s2c))}</pre>"
            )
        browser.setHtml("".join(parts) or "<i>没有可显示的载荷</i>")
        return browser

    def _hex_tab(self) -> QWidget:
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        editor.setFont(QFont("Consolas", 9))
        blocks = []
        if self.snapshot.data_c2s:
            blocks.append("== 客户端 → 服务器 ==")
            blocks.append(_hex_dump(self.snapshot.data_c2s))
        if self.snapshot.data_s2c:
            blocks.append("")
            blocks.append("== 服务器 → 客户端 ==")
            blocks.append(_hex_dump(self.snapshot.data_s2c))
        editor.setPlainText("\n".join(blocks) or "没有可显示的载荷")
        return editor

    def _http_tab(self) -> QWidget:
        browser = QTextBrowser()
        requests = parse_http_messages(self.snapshot.data_c2s)
        responses = parse_http_messages(self.snapshot.data_s2c)
        requests = [m for m in requests if m.get("request")]
        responses = [m for m in responses if m.get("response")]
        if not requests and not responses:
            browser.setHtml(
                "<p style='color:#8b949e'>未检测到 HTTP 消息。该流可能不是 HTTP，或使用了 TLS 加密。</p>"
            )
            return browser
        parts = []
        for index in range(max(len(requests), len(responses))):
            parts.append(f"<hr><h3>事务 #{index + 1}</h3>")
            if index < len(requests):
                parts.append(self._http_message_html(requests[index], "请求", CLIENT_COLOR))
            if index < len(responses):
                parts.append(self._http_message_html(responses[index], "响应", SERVER_COLOR))
        browser.setHtml("".join(parts))
        return browser

    @staticmethod
    def _http_message_html(message: dict, kind: str, color: str) -> str:
        headers = "".join(
            f"<tr><td style='color:#8b949e; padding-right:12px'>{html.escape(name)}</td>"
            f"<td>{html.escape(value)}</td></tr>"
            for name, value in message.get("headers", [])
        )
        body = message.get("body", b"")
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = body.decode("latin-1", "replace")
        body_text = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in body_text)
        if len(body_text) > 2000:
            body_text = body_text[:2000] + "\n... (truncated)"
        return (
            f"<div style='color:{color}; font-weight:bold; margin-top:6px'>{kind}</div>"
            f"<pre style='margin:2px 0; color:#d9dee7'>{html.escape(message.get('first_line', ''))}</pre>"
            f"<table cellspacing='0' cellpadding='1'>{headers}</table>"
            + (f"<pre style='background:#24272c; padding:6px; margin-top:6px'>{html.escape(body_text)}</pre>"
               if body_text else "")
        )

    @staticmethod
    def _text(data: bytes) -> str:
        text = data.decode("utf-8", "replace")
        return "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in text)

    def _apply_filter(self) -> None:
        self.filter_requested.emit(f"tcp.stream == {self.snapshot.index}")

    def _copy_all(self) -> None:
        from PyQt5.QtWidgets import QApplication
        parts = [
            f"TCP stream #{self.snapshot.index}",
            f"client: {self.snapshot.client}:{self.snapshot.cport}",
            f"server: {self.snapshot.server}:{self.snapshot.sport}",
            f"state: {self.snapshot.state}  packets: {self.snapshot.packets}  bytes: {self.snapshot.bytes}",
            "",
            "== client -> server ==",
            self._text(self.snapshot.data_c2s),
            "",
            "== server -> client ==",
            self._text(self.snapshot.data_s2c),
        ]
        QApplication.clipboard().setText("\n".join(parts))
