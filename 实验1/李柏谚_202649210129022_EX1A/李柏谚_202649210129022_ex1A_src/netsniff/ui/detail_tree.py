"""Wireshark-like protocol detail tree."""

from __future__ import annotations

import html
from typing import Optional

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QAction, QApplication, QMenu, QTreeWidget, QTreeWidgetItem

from ..model import Field, Packet


class DetailTree(QTreeWidget):
    field_selected = pyqtSignal(int, int, str)   # offset, length, field key
    filter_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setColumnCount(1)
        self.setIndentation(15)
        self.setUniformRowHeights(True)
        self.setAnimated(False)
        self.setAlternatingRowColors(False)
        self.setSelectionMode(self.SingleSelection)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self.itemSelectionChanged.connect(self._selection_changed)
        self._packet: Optional[Packet] = None
        self._bold = QFont("Microsoft YaHei UI", 9)
        self._bold.setBold(True)
        self._normal = QFont("Microsoft YaHei UI", 9)
        self._mono = QFont("Consolas", 9)
        self._layer_color = QColor("#4d9fff")
        self._muted = QColor("#8b949e")

    def set_dark(self, dark: bool) -> None:
        self._layer_color = QColor("#79c0ff" if dark else "#0550ae")
        self._muted = QColor("#8b949e" if dark else "#59636e")
        if self._packet is not None:
            self.set_packet(self._packet)

    def set_packet(self, packet: Optional[Packet]) -> None:
        self._packet = packet
        self.clear()
        if packet is None:
            return
        for layer in packet.layers:
            item = QTreeWidgetItem([layer.title()])
            item.setData(0, Qt.UserRole, (-1, 0, layer.key, ""))
            item.setFont(0, self._bold)
            item.setForeground(0, self._layer_color)
            item.setToolTip(0, f"协议层: {layer.name}  字节 {layer.offset}..{layer.offset + layer.length - 1}")
            self.addTopLevelItem(item)
            for field in layer.fields:
                self._add_field(item, field, packet)
            item.setExpanded(True)
        if self.topLevelItemCount():
            self.setCurrentItem(self.topLevelItem(0))

    def _add_field(self, parent: QTreeWidgetItem, field: Field, packet: Packet) -> None:
        item = QTreeWidgetItem([field.text()])
        value_text = field.display if field.display is not None else str(field.value)
        item.setData(0, Qt.UserRole, (field.offset, field.length, field.key, value_text))
        item.setFont(0, self._normal)
        tip = f"{field.key}"
        if field.offset >= 0 and field.length > 0:
            tip += f"\n字节 {field.offset}..{field.offset + field.length - 1}（{field.length} bytes）"
        if field.key:
            tip += "\n右键可复制或作为显示过滤器"
        item.setToolTip(0, tip)
        parent.addChild(item)
        for child in field.children:
            self._add_field(item, child, packet)
        if field.children:
            item.setExpanded(False)

    def _selection_changed(self) -> None:
        item = self.currentItem()
        if item is None:
            self.field_selected.emit(-1, 0, "")
            return
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        offset, length, key, _value = data
        self.field_selected.emit(int(offset), int(length), str(key))

    def _show_menu(self, pos) -> None:
        item = self.itemAt(pos)
        if item is None:
            return
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        offset, length, key, value = data
        menu = QMenu(self)
        copy_value = QAction("复制值", self)
        copy_value.triggered.connect(lambda: QApplication.clipboard().setText("" if value is None else str(value)))
        menu.addAction(copy_value)
        copy_name = QAction("复制字段名", self)
        copy_name.triggered.connect(lambda: QApplication.clipboard().setText(str(key)))
        menu.addAction(copy_name)
        if offset is not None and self._packet is not None and int(offset) >= 0 and int(length) > 0:
            start = int(offset)
            end = start + int(length)
            raw = self._packet.raw[start:end]
            copy_hex = QAction("复制字节 (hex)", self)
            copy_hex.triggered.connect(lambda: QApplication.clipboard().setText(raw.hex(" ")))
            menu.addAction(copy_hex)
        menu.addSeparator()
        apply_action = QAction("作为显示过滤器", self)
        apply_action.setEnabled(bool(key) and value not in (None, ""))
        apply_action.triggered.connect(lambda: self.filter_requested.emit(self._expression(str(key), value)))
        menu.addAction(apply_action)
        expand = QAction("全部展开", self)
        expand.triggered.connect(self.expandAll)
        menu.addAction(expand)
        collapse = QAction("全部折叠", self)
        collapse.triggered.connect(self.collapseAll)
        menu.addAction(collapse)
        menu.exec_(self.viewport().mapToGlobal(pos))

    @staticmethod
    def _expression(key: str, value) -> str:
        if isinstance(value, bool):
            return f"{key} == {1 if value else 0}"
        text = str(value)
        if value in ("True", "False"):
            return f"{key} == {1 if value == 'True' else 0}"
        # numeric-looking values are used raw
        try:
            float(text.replace(",", ""))
            return f"{key} == {text}"
        except ValueError:
            pass
        if text.count(".") == 3 and all(part.isdigit() for part in text.split(".")):
            return f"{key} == {text}"
        if text.count(":") >= 2:
            return f"{key} == {text}"
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'{key} == "{escaped}"'
