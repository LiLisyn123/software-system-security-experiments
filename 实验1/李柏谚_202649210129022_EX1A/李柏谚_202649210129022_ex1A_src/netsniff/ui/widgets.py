"""Small reusable widgets."""

from __future__ import annotations

from collections import deque

from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QLabel, QSizePolicy, QWidget


class Sparkline(QWidget):
    """A tiny live throughput chart for the status bar."""

    def __init__(self, parent=None, capacity: int = 60):
        super().__init__(parent)
        self._values = deque([0.0] * capacity, maxlen=capacity)
        self.setFixedSize(110, 22)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self._color = QColor("#4d9fff")

    def set_color(self, color: str) -> None:
        self._color = QColor(color)
        self.update()

    def push(self, value: float) -> None:
        self._values.append(float(value))
        self.update()

    def clear(self) -> None:
        self._values = deque([0.0] * self._values.maxlen, maxlen=self._values.maxlen)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = self.rect().adjusted(1, 2, -1, -2)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(255, 255, 255, 10))
        painter.drawRoundedRect(rect, 3, 3)
        values = list(self._values)
        maximum = max(values) if values else 0.0
        if maximum <= 0:
            painter.setPen(QPen(QColor("#8b949e"), 1))
            painter.drawLine(rect.left() + 2, rect.bottom() - 1, rect.right() - 2, rect.bottom() - 1)
            return
        path = QPainterPath()
        width = rect.width()
        height = rect.height()
        step = width / max(1, len(values) - 1)
        path.moveTo(rect.left(), rect.bottom() - (values[0] / maximum) * height * 0.9)
        for index, value in enumerate(values[1:], 1):
            x = rect.left() + index * step
            y = rect.bottom() - (value / maximum) * height * 0.9
            path.lineTo(x, y)
        pen = QPen(self._color)
        pen.setWidthF(1.6)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)
        # soft fill under the line
        fill = QPainterPath(path)
        fill.lineTo(rect.right(), rect.bottom())
        fill.lineTo(rect.left(), rect.bottom())
        fill.closeSubpath()
        color = QColor(self._color)
        color.setAlpha(40)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawPath(fill)


class StatusDot(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(10, 10)
        self.set_state("idle")

    def set_state(self, state: str) -> None:
        colors = {
            "idle": "#8b949e",
            "running": "#3fb950",
            "loading": "#d29922",
            "error": "#f85149",
            "stopped": "#8b949e",
        }
        color = colors.get(state, "#8b949e")
        self.setStyleSheet(f"background-color: {color}; border-radius: 5px;")
