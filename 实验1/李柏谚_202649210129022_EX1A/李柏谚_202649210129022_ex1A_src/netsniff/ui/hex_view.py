"""Hex + ASCII dump view with field highlighting."""

from __future__ import annotations

import math
from typing import Optional, Tuple

from PyQt5.QtCore import QRect, QSize, Qt
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QPainter, QPalette, QPen
from PyQt5.QtWidgets import QAbstractScrollArea, QAction, QApplication, QMenu


class HexView(QAbstractScrollArea):
    BYTES_PER_ROW = 16

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = b""
        self._highlight = (-1, 0)
        self._font = QFont("Consolas")
        try:
            dpi = QApplication.primaryScreen().logicalDotsPerInch() or 96.0
        except Exception:
            dpi = 96.0
        self._font.setPointSizeF(max(5.5, 9.0 * 96.0 / dpi))
        self._font.setStyleHint(QFont.Monospace)
        self._metrics = QFontMetrics(self._font)
        self._line_height = self._metrics.height() + 4
        self._char_width = max(6, self._metrics.horizontalAdvance("0"))
        self._offset_width = self._metrics.horizontalAdvance("00000000")
        self.setFont(self._font)
        self.setFocusPolicy(Qt.StrongFocus)
        self.viewport().setCursor(Qt.IBeamCursor)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self._mono = QFont("Consolas", 8)
        self._sans = QFont("Microsoft YaHei UI", 9, QFont.Bold)

    # -- public -----------------------------------------------------------
    def set_data(self, data: bytes) -> None:
        self._data = bytes(data)
        self._highlight = (-1, 0)
        self._update_scrollbars()
        self.viewport().update()

    def clear(self) -> None:
        self._data = b""
        self._highlight = (-1, 0)
        self._update_scrollbars()
        self.viewport().update()

    def set_highlight(self, offset: int, length: int) -> None:
        if offset is None or offset < 0 or length <= 0:
            self._highlight = (-1, 0)
        else:
            self._highlight = (int(offset), int(length))
        self.viewport().update()

    # -- layout -----------------------------------------------------------
    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_scrollbars()

    def _content_width(self) -> int:
        hex_width = self.BYTES_PER_ROW * 3 * self._char_width + self._char_width
        ascii_width = self.BYTES_PER_ROW * self._char_width
        return 12 + self._offset_width + self._char_width * 2 + hex_width + self._char_width * 2 + ascii_width + 12

    def _update_scrollbars(self) -> None:
        rows = math.ceil(len(self._data) / self.BYTES_PER_ROW) if self._data else 0
        content_height = rows * self._line_height
        viewport_h = self.viewport().height()
        vbar = self.verticalScrollBar()
        vbar.setRange(0, max(0, content_height - viewport_h))
        vbar.setPageStep(viewport_h)
        vbar.setSingleStep(self._line_height)
        viewport_w = self.viewport().width()
        content_width = self._content_width()
        hbar = self.horizontalScrollBar()
        hbar.setRange(0, max(0, content_width - viewport_w))
        hbar.setPageStep(viewport_w)
        hbar.setSingleStep(self._char_width * 4)

    def scrollContentsBy(self, dx: int, dy: int) -> None:
        self.viewport().update()

    def sizeHint(self) -> QSize:
        return QSize(620, 220)

    # -- painting ---------------------------------------------------------
    def paintEvent(self, event) -> None:
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.TextAntialiasing, True)
        base = self.palette().color(QPalette.Base)
        painter.fillRect(self.viewport().rect(), base)
        if not self._data:
            painter.setPen(self.palette().color(QPalette.Mid))
            painter.setFont(self._sans)
            painter.drawText(self.viewport().rect(), Qt.AlignCenter, "选择一个数据包以查看原始字节")
            return
        painter.setFont(self._mono)
        vbar = self.verticalScrollBar()
        hbar = self.horizontalScrollBar()
        start_row = vbar.value() // self._line_height
        y_offset = -(vbar.value() % self._line_height)
        x_scroll = hbar.value()
        text_color = self.palette().color(QPalette.Text)
        muted = self.palette().color(QPalette.Mid)
        highlight_color = self.palette().color(QPalette.Highlight)
        highlight_color.setAlpha(150)
        highlight_text = self.palette().color(QPalette.HighlightedText)
        highlight_start, highlight_len = self._highlight
        highlight_end = highlight_start + highlight_len if highlight_start >= 0 else -1
        rows = math.ceil(len(self._data) / self.BYTES_PER_ROW)
        visible_rows = self.viewport().height() // self._line_height + 2
        offset_x = 8 - x_scroll
        hex_x = offset_x + self._offset_width + self._char_width * 2
        ascii_x = hex_x + (self.BYTES_PER_ROW * 3 + 1) * self._char_width + self._char_width
        left_bound = self.viewport().rect().left()
        right_bound = self.viewport().rect().right()
        for index in range(start_row, min(rows, start_row + visible_rows)):
            y = y_offset + (index - start_row) * self._line_height
            row = self._data[index * 16:(index + 1) * 16]
            painter.setPen(muted)
            painter.drawText(offset_x, y + self._metrics.ascent() + 2, f"{index * 16:08x}")
            for column, byte in enumerate(row):
                offset = index * 16 + column
                char_x = hex_x + column * 3 * self._char_width
                if column >= 8:
                    char_x += self._char_width
                if left_bound <= char_x <= right_bound:
                    if highlight_start <= offset < highlight_end:
                        painter.fillRect(
                            QRect(char_x - 1, y, self._char_width * 2 + 1, self._line_height - 1),
                            highlight_color,
                        )
                        painter.setPen(highlight_text)
                    else:
                        painter.setPen(text_color)
                    painter.drawText(char_x, y + self._metrics.ascent() + 2, f"{byte:02x}")
                ascii_char = chr(byte) if 32 <= byte < 127 else "."
                ascii_char_x = ascii_x + column * self._char_width
                if left_bound <= ascii_char_x <= right_bound:
                    if highlight_start <= offset < highlight_end:
                        painter.fillRect(
                            QRect(ascii_char_x - 1, y, self._char_width, self._line_height - 1),
                            highlight_color,
                        )
                        painter.setPen(highlight_text)
                    else:
                        painter.setPen(muted)
                    painter.drawText(ascii_char_x, y + self._metrics.ascent() + 2, ascii_char)

    # -- context menu -----------------------------------------------------
    def _show_menu(self, pos) -> None:
        if not self._data:
            return
        menu = QMenu(self)
        copy_hex = QAction("复制十六进制", self)
        copy_hex.triggered.connect(lambda: QApplication.clipboard().setText(self._data.hex(" ")))
        menu.addAction(copy_hex)
        copy_ascii = QAction("复制 ASCII", self)
        copy_ascii.triggered.connect(
            lambda: QApplication.clipboard().setText(
                "".join(chr(b) if 32 <= b < 127 else "." for b in self._data)
            )
        )
        menu.addAction(copy_ascii)
        menu.exec_(self.viewport().mapToGlobal(pos))
