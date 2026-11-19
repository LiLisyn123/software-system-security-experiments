"""Dark / light theme, colours and programmatically drawn icons."""

from __future__ import annotations

from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import (
    QColor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
    QPixmap,
    QPolygonF,
)
from PyQt5.QtWidgets import QApplication

DARK_COLORS = {
    "bg": "#1b1d21",
    "surface": "#24272c",
    "surface2": "#2c3036",
    "surface3": "#343941",
    "border": "#3a4048",
    "text": "#d9dee7",
    "muted": "#8b949e",
    "accent": "#4d9fff",
    "accent2": "#2f81f7",
    "success": "#3fb950",
    "danger": "#f85149",
    "warning": "#d29922",
    "purple": "#bc8cff",
    "teal": "#39c5cf",
    "orange": "#f0883e",
    "selection": "#234a6f",
    "header": "#2e333a",
}

LIGHT_COLORS = {
    "bg": "#f4f6f8",
    "surface": "#ffffff",
    "surface2": "#eef1f5",
    "surface3": "#e2e7ee",
    "border": "#c9d1db",
    "text": "#1f2328",
    "muted": "#59636e",
    "accent": "#0969da",
    "accent2": "#0550ae",
    "success": "#1a7f37",
    "danger": "#cf222e",
    "warning": "#9a6700",
    "purple": "#8250df",
    "teal": "#0f7b83",
    "orange": "#bc4c00",
    "selection": "#cfe4ff",
    "header": "#eef1f5",
}

# packet background tints (RGBA strings understood by QColor)
PACKET_TINTS_DARK = {
    "http": "#1d3a29",
    "dns": "#332a4a",
    "tls": "#3d3520",
    "tcp": "#1d2c3d",
    "udp": "#193a3b",
    "icmp": "#432526",
    "arp": "#3f3020",
    "ipv6": "#1f2f42",
    "other": "#24272c",
    "error": "#4a2326",
}

PACKET_TINTS_LIGHT = {
    "http": "#e8f7ec",
    "dns": "#f0e9ff",
    "tls": "#fff6d9",
    "tcp": "#e8f2ff",
    "udp": "#e2f7f7",
    "icmp": "#ffe9ea",
    "arp": "#fff0df",
    "ipv6": "#e6efff",
    "other": "#ffffff",
    "error": "#ffe3e5",
}

PACKET_TEXTS_DARK = {
    "http": "#7ee787",
    "dns": "#d2a8ff",
    "tls": "#e3b341",
    "tcp": "#79c0ff",
    "udp": "#56d4dd",
    "icmp": "#ff7b72",
    "arp": "#ffa657",
    "ipv6": "#a5d6ff",
    "other": "#d9dee7",
    "error": "#ff7b72",
}

PACKET_TEXTS_LIGHT = {
    "http": "#116329",
    "dns": "#6639ba",
    "tls": "#7d4e00",
    "tcp": "#0550ae",
    "udp": "#0f6670",
    "icmp": "#a40e26",
    "arp": "#953800",
    "ipv6": "#0550ae",
    "other": "#1f2328",
    "error": "#a40e26",
}


def colors(dark: bool) -> dict:
    return DARK_COLORS if dark else LIGHT_COLORS


def packet_background(key: str, dark: bool) -> QColor:
    table = PACKET_TINTS_DARK if dark else PACKET_TINTS_LIGHT
    return QColor(table.get(key, table["other"]))


def packet_foreground(key: str, dark: bool) -> QColor:
    table = PACKET_TEXTS_DARK if dark else PACKET_TEXTS_LIGHT
    return QColor(table.get(key, table["other"]))


QSS_DARK = """
QWidget {
    color: %(text)s;
    background-color: %(bg)s;
    selection-background-color: %(selection)s;
    selection-color: #ffffff;
}
QMainWindow, QDialog { background-color: %(bg)s; }
QMenuBar { background-color: %(surface)s; border-bottom: 1px solid %(border)s; }
QMenuBar::item { padding: 4px 10px; background: transparent; }
QMenuBar::item:selected { background: %(surface3)s; border-radius: 4px; }
QMenu { background-color: %(surface2)s; border: 1px solid %(border)s; padding: 4px; }
QMenu::item { padding: 6px 26px 6px 24px; border-radius: 4px; }
QMenu::item:selected { background-color: %(selection)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 4px 8px; }
QToolBar {
    background-color: %(surface)s;
    border-bottom: 1px solid %(border)s;
    spacing: 4px;
    padding: 4px 6px;
}
QToolBar::separator { width: 1px; background: %(border)s; margin: 4px 5px; }
QToolButton {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 5px;
    padding: 3px;
}
QToolButton:hover { background: %(surface3)s; border-color: %(border)s; }
QToolButton:pressed { background: %(selection)s; }
QToolButton:checked { background: %(selection)s; }
QToolButton[popupMode="1"] { padding-right: 12px; }
QPushButton {
    background-color: %(surface2)s;
    border: 1px solid %(border)s;
    border-radius: 5px;
    padding: 5px 12px;
    min-height: 18px;
}
QPushButton:hover { background-color: %(surface3)s; }
QPushButton:pressed { background-color: %(selection)s; }
QPushButton:disabled { color: %(muted)s; background-color: %(surface)s; }
QPushButton#primary {
    background-color: %(accent2)s;
    color: #ffffff;
    border: 1px solid %(accent)s;
    font-weight: 600;
}
QPushButton#primary:hover { background-color: %(accent)s; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {
    background-color: %(surface)s;
    border: 1px solid %(border)s;
    border-radius: 5px;
    padding: 3px 6px;
    selection-background-color: %(selection)s;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid %(accent)s;
}
QLineEdit[invalid="true"] { border: 1px solid %(danger)s; }
QLineEdit[valid="true"] { border: 1px solid %(success)s; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView {
    background-color: %(surface2)s;
    border: 1px solid %(border)s;
    selection-background-color: %(selection)s;
}
QHeaderView::section {
    background-color: %(header)s;
    color: %(muted)s;
    border: none;
    border-right: 1px solid %(border)s;
    border-bottom: 1px solid %(border)s;
    padding: 4px 6px;
    font-weight: 600;
}
QTableView, QTreeWidget, QTreeView, QTableWidget, QListWidget {
    background-color: %(surface)s;
    alternate-background-color: %(surface)s;
    border: 1px solid %(border)s;
    gridline-color: %(border)s;
    outline: none;
}
QTableView::item { padding: 1px 4px; }
QTreeWidget::item, QTreeView::item { padding: 2px 3px; }
QTreeWidget::item:selected, QTreeView::item:selected, QTableView::item:selected,
QTableWidget::item:selected { background-color: %(selection)s; color: #ffffff; }
QDockWidget {
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
    color: %(muted)s;
}
QDockWidget::title {
    background-color: %(surface2)s;
    padding: 5px 8px;
    border-bottom: 1px solid %(border)s;
}
QTabWidget::pane { border: 1px solid %(border)s; top: -1px; }
QTabBar::tab {
    background: %(surface2)s;
    color: %(muted)s;
    padding: 6px 14px;
    border: 1px solid %(border)s;
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    margin-right: 2px;
}
QTabBar::tab:selected { background: %(surface)s; color: %(text)s; }
QTabBar::tab:hover { color: %(text)s; }
QStatusBar { background: %(surface)s; border-top: 1px solid %(border)s; color: %(muted)s; }
QStatusBar::item { border: none; }
QSplitter::handle { background: %(border)s; }
QSplitter::handle:horizontal { width: 3px; }
QSplitter::handle:vertical { height: 3px; }
QScrollBar:vertical { background: %(surface)s; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: %(surface3)s; min-height: 24px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: %(muted)s; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: %(surface)s; height: 11px; margin: 0; }
QScrollBar::handle:horizontal { background: %(surface3)s; min-width: 24px; border-radius: 5px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QGroupBox {
    border: 1px solid %(border)s;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 8px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: %(muted)s; }
QToolTip {
    background-color: %(surface3)s;
    color: %(text)s;
    border: 1px solid %(border)s;
    padding: 4px;
}
QCheckBox, QRadioButton { spacing: 6px; }
QLabel#hint { color: %(muted)s; padding: 6px; }
QLabel#filterStatus { color: %(muted)s; padding-left: 6px; }
QLabel#sectionTitle { font-weight: 600; color: %(accent)s; }
QFrame#filterBar { background: %(surface)s; border-bottom: 1px solid %(border)s; }
QFrame#hexHeader { background: %(surface2)s; border: 1px solid %(border)s; border-bottom: none; }
"""


def _render_qss(template: str, palette: dict) -> str:
    return template % palette


def _light_qss() -> str:
    return _render_qss(QSS_DARK, LIGHT_COLORS)


def apply_theme(app: QApplication, dark: bool = True) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    c = colors(dark)
    palette.setColor(QPalette.Window, QColor(c["bg"]))
    palette.setColor(QPalette.WindowText, QColor(c["text"]))
    palette.setColor(QPalette.Base, QColor(c["surface"]))
    palette.setColor(QPalette.AlternateBase, QColor(c["surface2"]))
    palette.setColor(QPalette.ToolTipBase, QColor(c["surface3"]))
    palette.setColor(QPalette.ToolTipText, QColor(c["text"]))
    palette.setColor(QPalette.Text, QColor(c["text"]))
    palette.setColor(QPalette.Button, QColor(c["surface2"]))
    palette.setColor(QPalette.ButtonText, QColor(c["text"]))
    palette.setColor(QPalette.BrightText, QColor(c["danger"]))
    palette.setColor(QPalette.Highlight, QColor(c["selection"]))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff" if dark else c["text"]))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(c["muted"]))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(c["muted"]))
    app.setPalette(palette)
    app.setStyleSheet(_render_qss(QSS_DARK, c))


# ---------------------------------------------------------------------------
# icons
# ---------------------------------------------------------------------------

def _tint(color: str, alpha: int = 58) -> QColor:
    tint = QColor(color)
    tint.setAlpha(alpha)
    return tint


def _pen(color: str, width: float = 2.4) -> QPen:
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    return pen


def make_icon(kind: str, dark: bool = True, size: int = 32) -> QIcon:
    c = colors(dark)
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing, True)
    s = size
    if kind == "play":
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["success"]))
        p.drawPolygon(QPolygonF([QPointF(s * 0.28, s * 0.18), QPointF(s * 0.80, s * 0.50), QPointF(s * 0.28, s * 0.82)]))
    elif kind == "stop":
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["danger"]))
        p.drawRoundedRect(QRectF(s * 0.26, s * 0.26, s * 0.48, s * 0.48), 4, 4)
    elif kind == "open":
        p.setPen(_pen(c["warning"]))
        p.setBrush(_tint(c["warning"]))
        path = QPainterPath()
        path.moveTo(s * 0.12, s * 0.30)
        path.lineTo(s * 0.40, s * 0.30)
        path.lineTo(s * 0.48, s * 0.40)
        path.lineTo(s * 0.88, s * 0.40)
        path.lineTo(s * 0.82, s * 0.78)
        path.lineTo(s * 0.16, s * 0.78)
        path.closeSubpath()
        p.drawPath(path)
    elif kind == "save":
        p.setPen(_pen(c["accent"]))
        p.setBrush(_tint(c["accent"]))
        p.drawRoundedRect(QRectF(s * 0.20, s * 0.16, s * 0.60, s * 0.68), 3, 3)
        p.setBrush(QColor(c["accent"]))
        p.drawRect(QRectF(s * 0.34, s * 0.16, s * 0.32, s * 0.22))
        p.setBrush(Qt.NoBrush)
        p.drawRect(QRectF(s * 0.32, s * 0.56, s * 0.36, s * 0.20))
    elif kind == "clear":
        p.setPen(_pen(c["muted"]))
        p.drawLine(QPointF(s * 0.28, s * 0.28), QPointF(s * 0.72, s * 0.72))
        p.drawLine(QPointF(s * 0.72, s * 0.28), QPointF(s * 0.28, s * 0.72))
    elif kind == "stats":
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["accent"]))
        p.drawRoundedRect(QRectF(s * 0.20, s * 0.52, s * 0.12, s * 0.28), 2, 2)
        p.setBrush(QColor(c["success"]))
        p.drawRoundedRect(QRectF(s * 0.44, s * 0.34, s * 0.12, s * 0.46), 2, 2)
        p.setBrush(QColor(c["purple"]))
        p.drawRoundedRect(QRectF(s * 0.68, s * 0.18, s * 0.12, s * 0.62), 2, 2)
    elif kind == "filter":
        p.setPen(_pen(c["teal"]))
        p.setBrush(_tint(c["teal"]))
        path = QPainterPath()
        path.moveTo(s * 0.16, s * 0.22)
        path.lineTo(s * 0.84, s * 0.22)
        path.lineTo(s * 0.58, s * 0.52)
        path.lineTo(s * 0.58, s * 0.80)
        path.lineTo(s * 0.42, s * 0.72)
        path.lineTo(s * 0.42, s * 0.52)
        path.closeSubpath()
        p.drawPath(path)
    elif kind == "find":
        p.setPen(_pen(c["accent"]))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QRectF(s * 0.18, s * 0.16, s * 0.44, s * 0.44))
        p.drawLine(QPointF(s * 0.58, s * 0.58), QPointF(s * 0.84, s * 0.84))
    elif kind == "stream":
        p.setPen(_pen(c["accent"]))
        path = QPainterPath()
        path.moveTo(s * 0.18, s * 0.38)
        path.cubicTo(s * 0.36, s * 0.18, s * 0.54, s * 0.58, s * 0.82, s * 0.38)
        p.drawPath(path)
        p.setPen(_pen(c["success"]))
        path2 = QPainterPath()
        path2.moveTo(s * 0.18, s * 0.64)
        path2.cubicTo(s * 0.36, s * 0.44, s * 0.54, s * 0.84, s * 0.82, s * 0.64)
        p.drawPath(path2)
    elif kind == "process":
        p.setPen(_pen(c["purple"]))
        p.setBrush(_tint(c["purple"]))
        p.drawRoundedRect(QRectF(s * 0.26, s * 0.26, s * 0.48, s * 0.48), 4, 4)
        for i in range(3):
            pos = s * (0.34 + i * 0.12)
            p.drawLine(QPointF(pos, s * 0.18), QPointF(pos, s * 0.26))
            p.drawLine(QPointF(pos, s * 0.74), QPointF(pos, s * 0.82))
            p.drawLine(QPointF(s * 0.18, pos), QPointF(s * 0.26, pos))
            p.drawLine(QPointF(s * 0.74, pos), QPointF(s * 0.82, pos))
    elif kind == "theme":
        p.setPen(_pen(c["warning"]))
        p.setBrush(QColor(c["warning"]))
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
        p.setBrush(QColor(c["bg"] if dark else c["surface"]))
        p.setPen(Qt.NoPen)
        p.drawChord(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64), 90 * 16, 180 * 16)
    elif kind == "gear":
        p.setPen(_pen(c["muted"]))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QRectF(s * 0.34, s * 0.34, s * 0.32, s * 0.32))
        for angle in range(0, 360, 45):
            p.save()
            p.translate(s / 2, s / 2)
            p.rotate(angle)
            p.drawLine(QPointF(0, -s * 0.26), QPointF(0, -s * 0.36))
            p.restore()
    elif kind == "help":
        p.setPen(_pen(c["accent"]))
        p.setBrush(Qt.NoBrush)
        p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))
        f = QFont("Segoe UI", int(s * 0.42), QFont.Bold)
        p.setFont(f)
        p.drawText(QRectF(s * 0.16, s * 0.10, s * 0.68, s * 0.68), Qt.AlignCenter, "?")
    elif kind == "refresh":
        p.setPen(_pen(c["accent"]))
        p.setBrush(Qt.NoBrush)
        p.drawArc(QRectF(s * 0.20, s * 0.20, s * 0.60, s * 0.60), 40 * 16, 280 * 16)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["accent"]))
        p.drawPolygon(QPolygonF([QPointF(s * 0.76, s * 0.18), QPointF(s * 0.86, s * 0.40), QPointF(s * 0.62, s * 0.34)]))
    elif kind == "restart":
        p.setPen(_pen(c["warning"]))
        p.setBrush(Qt.NoBrush)
        p.drawArc(QRectF(s * 0.20, s * 0.20, s * 0.60, s * 0.60), 30 * 16, 300 * 16)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["warning"]))
        p.drawPolygon(QPolygonF([QPointF(s * 0.74, s * 0.14), QPointF(s * 0.88, s * 0.36), QPointF(s * 0.64, s * 0.32)]))
    else:
        p.setPen(_pen(c["muted"]))
        p.drawEllipse(QRectF(s * 0.3, s * 0.3, s * 0.4, s * 0.4))
    p.end()
    return QIcon(pix)


def make_app_icon(size: int = 64) -> QIcon:
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing, True)
    gradient = QLinearGradient(0, 0, size, size)
    gradient.setColorAt(0.0, QColor("#2f81f7"))
    gradient.setColorAt(1.0, QColor("#1f6feb"))
    p.setPen(Qt.NoPen)
    p.setBrush(gradient)
    p.drawRoundedRect(QRectF(2, 2, size - 4, size - 4), size * 0.22, size * 0.22)
    pen = QPen(QColor("#ffffff"))
    pen.setWidthF(size * 0.055)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    path = QPainterPath()
    path.moveTo(size * 0.20, size * 0.58)
    path.cubicTo(size * 0.34, size * 0.28, size * 0.46, size * 0.75, size * 0.60, size * 0.48)
    path.cubicTo(size * 0.70, size * 0.30, size * 0.78, size * 0.44, size * 0.82, size * 0.38)
    p.drawPath(path)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#7ee787"))
    p.drawEllipse(QRectF(size * 0.18, size * 0.66, size * 0.10, size * 0.10))
    p.end()
    return QIcon(pix)
