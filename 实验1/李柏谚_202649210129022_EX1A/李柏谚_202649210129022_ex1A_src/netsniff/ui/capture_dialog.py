"""Capture options dialog (interface, BPF, buffer, promiscuous mode)."""

from __future__ import annotations

from typing import List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from ..capture.npcap import Device, NpcapError, get_npcap, npcap_status
from ..capture.worker import CaptureConfig


BPF_PRESETS = [
    ("无（捕获全部）", ""),
    ("HTTP", "tcp port 80"),
    ("HTTPS / TLS", "tcp port 443"),
    ("DNS", "port 53"),
    ("TCP", "tcp"),
    ("UDP", "udp"),
    ("ICMP", "icmp"),
    ("IPv4", "ip"),
    ("IPv6", "ipv6"),
    ("ARP", "arp"),
    ("排除 SSH", "not tcp port 22"),
    ("本机回环 HTTP", "tcp port 80 and host 127.0.0.1"),
]


class CaptureOptionsDialog(QDialog):
    def __init__(self, config: CaptureConfig, parent=None, devices: Optional[List[Device]] = None):
        super().__init__(parent)
        self.setWindowTitle("捕获选项")
        self.resize(780, 620)
        self._config = config
        self._devices = devices or []
        self._build()
        if not self._devices:
            self.refresh_devices()
        else:
            self._populate(self._config.device)

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 12)
        layout.setSpacing(10)

        form_group = QGroupBox("网卡")
        form = QFormLayout(form_group)
        device_row = QHBoxLayout()
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(460)
        device_row.addWidget(self.device_combo, 1)
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh_devices)
        device_row.addWidget(self.refresh_button)
        form.addRow("捕获接口", device_row)
        self.npcap_label = QLabel("")
        self.npcap_label.setWordWrap(True)
        available, detail = npcap_status()
        self.npcap_label.setText(detail)
        self.npcap_label.setStyleSheet("color: #3fb950;" if available else "color: #f85149;")
        form.addRow("Npcap", self.npcap_label)
        layout.addWidget(form_group)

        filter_group = QGroupBox("捕获过滤器（BPF，在内核中生效）")
        filter_layout = QVBoxLayout(filter_group)
        row = QHBoxLayout()
        self.bpf_edit = QLineEdit(self._config.bpf)
        self.bpf_edit.setPlaceholderText('例如：tcp port 80、udp port 53、host 192.168.1.1、not arp')
        self.bpf_edit.setFont(self.font())
        row.addWidget(self.bpf_edit, 1)
        self.preset_combo = QComboBox()
        for name, expression in BPF_PRESETS:
            self.preset_combo.addItem(name, expression)
        self.preset_combo.currentIndexChanged.connect(self._apply_preset)
        row.addWidget(self.preset_combo)
        filter_layout.addLayout(row)
        tip = QLabel(
            "BPF 语法由 libpcap/Npcap 编译，在数据包到达用户态前过滤，能显著降低高流量下的 CPU 开销。"
            "显示过滤器（主界面）则在解析后执行，可使用本程序提供的字段与逻辑表达式。"
        )
        tip.setWordWrap(True)
        tip.setObjectName("hint")
        filter_layout.addWidget(tip)
        layout.addWidget(filter_group)

        options_group = QGroupBox("选项")
        options_form = QFormLayout(options_group)
        self.promisc = QCheckBox("混杂模式（promiscuous）")
        self.promisc.setChecked(self._config.promisc)
        options_form.addRow(self.promisc)
        self.immediate = QCheckBox("立即模式（immediate mode，低延迟）")
        self.immediate.setChecked(self._config.immediate)
        self.immediate.setToolTip("立即模式降低延迟，但会增加 CPU 唤醒次数；默认关闭以批量收包。")
        options_form.addRow(self.immediate)
        row2 = QHBoxLayout()
        self.snaplen = QSpinBox()
        self.snaplen.setRange(64, 262144)
        self.snaplen.setValue(self._config.snaplen)
        self.snaplen.setSingleStep(1024)
        self.snaplen.setSuffix(" bytes")
        row2.addWidget(self.snaplen)
        self.buffer = QSpinBox()
        self.buffer.setRange(1, 1024)
        self.buffer.setValue(self._config.buffer_mb)
        self.buffer.setSuffix(" MiB")
        row2.addWidget(self.buffer)
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 2000)
        self.timeout.setValue(self._config.timeout_ms)
        self.timeout.setSuffix(" ms")
        row2.addWidget(self.timeout)
        row2.addStretch(1)
        options_form.addRow("快照长度 / 内核缓冲 / 读超时", row2)
        layout.addWidget(options_group)

        layout.addStretch(1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.ok_button = buttons.button(QDialogButtonBox.Ok)
        self.cancel_button = buttons.button(QDialogButtonBox.Cancel)
        self.ok_button.setText("确定")
        self.cancel_button.setText("取消")
        layout.addWidget(buttons)

    def _populate(self, selected: str = "") -> None:
        self.device_combo.clear()
        for device in self._devices:
            self.device_combo.addItem(device.label, device)
        if selected:
            for index in range(self.device_combo.count()):
                item = self.device_combo.itemData(index)
                if item is not None and item.name == selected:
                    self.device_combo.setCurrentIndex(index)
                    break
        if self.device_combo.count() == 0:
            self.device_combo.addItem("（未检测到可用网卡）", None)

    def refresh_devices(self) -> None:
        available, detail = npcap_status()
        if available:
            self.npcap_label.setText(detail)
            self.npcap_label.setStyleSheet("color: #3fb950;")
        else:
            self.npcap_label.setText(detail)
            self.npcap_label.setStyleSheet("color: #f85149;")
            self.device_combo.clear()
            self.device_combo.addItem("（未安装 Npcap，无法枚举网卡）", None)
            self.ok_button.setEnabled(False)
            return
        try:
            self._devices = get_npcap().devices()
        except NpcapError as exc:
            self.npcap_label.setText(f"枚举网卡失败：{exc}")
            self.npcap_label.setStyleSheet("color: #f85149;")
            self.ok_button.setEnabled(False)
            return
        self.ok_button.setEnabled(True)
        self._populate(self._config.device or (self.device_combo.currentData().name if self.device_combo.currentData() else ""))

    def _apply_preset(self, index: int) -> None:
        expression = self.preset_combo.itemData(index)
        if expression is not None:
            self.bpf_edit.setText(expression)

    def config(self) -> CaptureConfig:
        device = self.device_combo.currentData()
        return CaptureConfig(
            device=device.name if device else self._config.device,
            description=device.description if device else self._config.description,
            snaplen=int(self.snaplen.value()),
            promisc=bool(self.promisc.isChecked()),
            timeout_ms=int(self.timeout.value()),
            buffer_mb=int(self.buffer.value()),
            immediate=bool(self.immediate.isChecked()),
            bpf=self.bpf_edit.text().strip(),
        )
