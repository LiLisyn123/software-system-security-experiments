"""Display filter syntax reference dialog."""

from __future__ import annotations

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..filters.display import EXAMPLES, FIELD_SPECS


TYPE_NAMES = {
    "num": "数值",
    "str": "字符串",
    "ip": "IP 地址",
    "mac": "MAC 地址",
    "bool": "布尔",
    "time": "时间",
}


class FilterHelpDialog(QDialog):
    filter_requested = pyqtSignal(str)

    def __init__(self, parent=None, current: str = ""):
        super().__init__(parent)
        self.setWindowTitle("显示过滤器语法")
        self.resize(1120, 740)
        self._build(current)

    def _build(self, current: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        title = QLabel("显示过滤器：字段、运算符与逻辑表达式")
        font = QFont("Microsoft YaHei UI", 13, QFont.Bold)
        title.setFont(font)
        layout.addWidget(title)

        intro = QLabel(
            "逻辑运算：<b>and / &amp;&amp;</b>、<b>or / ||</b>、<b>not / !</b>、括号；"
            "比较：<b>== != &gt; &lt; &gt;= &lt;=</b>；"
            "文本：<b>contains</b>、<b>matches</b>（正则）。<br>"
            "协议名可直接作为谓词，例如 <code>http</code>、<code>tcp</code>、"
            "<code>ip and not icmp</code>；字段别名 <code>ip.addr</code>、"
            "<code>tcp.port</code>、<code>udp.port</code> 会同时匹配源和目的。"
            "IP 字段支持 CIDR，例如 <code>ip.addr == 192.168.1.0/24</code>。"
        )
        intro.setWordWrap(True)
        intro.setTextFormat(Qt.RichText)
        layout.addWidget(intro)

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # fields ----------------------------------------------------------
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)
        left_layout.addWidget(QLabel("可用字段（上方搜索框可过滤）"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索字段，例如 tcp / http / dns ...")
        left_layout.addWidget(self.search)
        self.field_table = QTableWidget(0, 3)
        self.field_table.setHorizontalHeaderLabels(["字段", "类型", "说明"])
        self.field_table.verticalHeader().setVisible(False)
        self.field_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.field_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.field_table.setAlternatingRowColors(False)
        header = self.field_table.horizontalHeader()
        header.setStretchLastSection(True)
        self.field_table.setColumnWidth(0, 230)
        self.field_table.setColumnWidth(1, 112)
        left_layout.addWidget(self.field_table, 1)
        splitter.addWidget(left)

        # examples --------------------------------------------------------
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        right_layout.addWidget(QLabel("常用示例（双击应用到过滤器）"))
        self.examples = QTreeWidget()
        self.examples.setHeaderLabels(["表达式", "说明"])
        self.examples.setRootIsDecorated(True)
        self.examples.setIndentation(12)
        self.examples.setColumnWidth(0, 380)
        self.examples.header().setStretchLastSection(True)
        right_layout.addWidget(self.examples, 1)
        splitter.addWidget(right)
        splitter.setSizes([500, 580])

        buttons = QDialogButtonBox()
        self.apply_button = QPushButton("应用选中的示例")
        self.apply_button.setObjectName("primary")
        buttons.addButton(self.apply_button, QDialogButtonBox.ActionRole)
        close_button = QPushButton("关闭")
        buttons.addButton(close_button, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

        self._fields = sorted(FIELD_SPECS.values(), key=lambda spec: spec.name)
        self._fill_fields("")
        self._fill_examples()
        if current:
            self.search.setText("")
        self.search.textChanged.connect(self._fill_fields)
        self.examples.itemDoubleClicked.connect(self._apply_item)
        self.apply_button.clicked.connect(lambda: self._apply_item(self.examples.currentItem()))
        close_button.clicked.connect(self.reject)

    def _fill_fields(self, text: str) -> None:
        text = text.strip().lower()
        rows = [spec for spec in self._fields if not text or text in spec.name.lower() or text in spec.description.lower()]
        self.field_table.setRowCount(len(rows))
        for row, spec in enumerate(rows):
            self.field_table.setItem(row, 0, QTableWidgetItem(spec.name))
            self.field_table.setItem(row, 1, QTableWidgetItem(TYPE_NAMES.get(spec.kind, spec.kind)))
            self.field_table.setItem(row, 2, QTableWidgetItem(spec.description))
        if rows:
            self.field_table.selectRow(0)

    def _fill_examples(self) -> None:
        categories: dict[str, QTreeWidgetItem] = {}
        for category, expression, description in EXAMPLES:
            parent = categories.get(category)
            if parent is None:
                parent = QTreeWidgetItem([category, ""])
                font = parent.font(0)
                font.setBold(True)
                parent.setFont(0, font)
                self.examples.addTopLevelItem(parent)
                categories[category] = parent
            child = QTreeWidgetItem([expression, description])
            child.setData(0, Qt.UserRole, expression)
            parent.addChild(child)
        self.examples.expandAll()

    def _apply_item(self, item) -> None:
        if item is None:
            return
        expression = item.data(0, Qt.UserRole) or item.text(0)
        if expression:
            self.filter_requested.emit(expression)
