"""Main window: three-pane packet browser, capture control and analysis tools."""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import List, Optional

from PyQt5.QtCore import QItemSelectionModel, QSettings, QSize, Qt, QTimer
from PyQt5.QtGui import QFont, QKeySequence
from PyQt5.QtWidgets import (
    QAction,
    QActionGroup,
    QApplication,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QShortcut,
    QSplitter,
    QTabWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..analysis.processes import ProcessTable
from ..analysis.streams import StreamTracker
from ..capture.npcap import Device, NpcapError, get_npcap, npcap_status
from ..capture.pcapfile import PcapFormatError, read_pcap, write_pcap
from ..capture.worker import CaptureConfig, CaptureWorker, PcapFileWorker
from ..config import (
    APP_NAME,
    APP_VERSION,
    DOCS_DIR,
    NPCAP_DOWNLOAD_URL,
    ORG_NAME,
    SAMPLES_DIR,
)
from ..dissect import dissect_packet
from ..filters.display import FilterError, compile_filter
from ..model import Packet, format_timestamp
from .capture_dialog import CaptureOptionsDialog
from .detail_tree import DetailTree
from .filter_help import FilterHelpDialog
from .hex_view import HexView
from .packet_model import PacketListModel
from .stats_dialog import StatsDialog
from .stream_dialog import TcpStreamDialog
from .theme import apply_theme, colors, make_app_icon, make_icon, packet_foreground
from .widgets import Sparkline, StatusDot


COMMON_FILTERS = [
    ("HTTP", "http"),
    ("DNS", "dns"),
    ("TLS", "tls"),
    ("TCP", "tcp"),
    ("UDP", "udp"),
    ("IPv4", "ip"),
    ("IPv6", "ipv6"),
    ("ICMP / ICMPv6", "icmp or icmpv6"),
    ("ARP", "arp"),
    ("非 HTTP 的 TCP", "tcp and not http"),
    ("错误/警告", "expert"),
]


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings(ORG_NAME, "NetSniffer1A")
        self.dark = self.settings.value("dark", True, type=bool)
        self.auto_scroll = self.settings.value("auto_scroll", True, type=bool)
        self.time_mode = self.settings.value("time_mode", "relative", type=str)
        self.config = CaptureConfig(
            snaplen=self.settings.value("snaplen", 65535, type=int),
            promisc=self.settings.value("promisc", True, type=bool),
            timeout_ms=self.settings.value("timeout_ms", 100, type=int),
            buffer_mb=self.settings.value("buffer_mb", 32, type=int),
            immediate=self.settings.value("immediate", False, type=bool),
            bpf=self.settings.value("bpf", "", type=str),
        )
        self.model = PacketListModel(max_packets=self.settings.value("max_packets", 200000, type=int))
        self.model.dark = self.dark
        self.display_filter = compile_filter("")
        self.tracker = StreamTracker()
        self.process_table = ProcessTable()
        self.process_stats: dict[int, list] = {}
        self.stream_process: dict[int, str] = {}
        self.worker = None
        self.mode = ""                 # "live" | "file" | ""
        self.linktype = 1
        self.current_packet: Optional[Packet] = None
        self.devices: List[Device] = []
        self._npcap_ok = False
        self._npcap_detail = ""
        self._driver_stats = (0, 0, 0)
        self._app_dropped = 0
        self._last_count = 0
        self._last_tick = time.monotonic()
        self._last_find = ""
        self._stream_dialogs = []
        self._stats_dialog = None
        self._help_dialog = None
        self._loading_name = ""
        self._has_process_info = False

        self._build_actions()
        self._build_ui()
        self._build_menus()
        self._build_toolbar()
        self._build_status()
        self._connect_shortcuts()
        self._restore_window()
        self._apply_theme()
        self._set_state("idle", "就绪")
        self._update_actions()
        self._update_hint()
        self._update_counts()

        self.drain_timer = QTimer(self)
        self.drain_timer.setInterval(100)
        self.drain_timer.timeout.connect(self._drain)
        self.tick_timer = QTimer(self)
        self.tick_timer.setInterval(1000)
        self.tick_timer.timeout.connect(self._tick)
        self.process_timer = QTimer(self)
        self.process_timer.setInterval(3000)
        self.process_timer.timeout.connect(self._refresh_process_table)
        self.process_timer.start()
        QTimer.singleShot(60, self._init_backend)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_actions(self) -> None:
        self.action_start = QAction("开始捕获", self)
        self.action_start.setShortcut(QKeySequence("Ctrl+R"))
        self.action_start.setToolTip("开始捕获（Ctrl+R）")
        self.action_start.triggered.connect(self.start_capture)

        self.action_stop = QAction("停止捕获", self)
        self.action_stop.setShortcut(QKeySequence("Ctrl+E"))
        self.action_stop.setToolTip("停止捕获（Ctrl+E）")
        self.action_stop.triggered.connect(self.stop_capture)

        self.action_restart = QAction("重新捕获", self)
        self.action_restart.setShortcut(QKeySequence("Ctrl+Shift+R"))
        self.action_restart.triggered.connect(self.restart_capture)

        self.action_open = QAction("打开 pcap", self)
        self.action_open.setShortcut(QKeySequence.Open)
        self.action_open.triggered.connect(lambda: self.open_pcap())

        self.action_save = QAction("保存全部", self)
        self.action_save.setShortcut(QKeySequence.Save)
        self.action_save.triggered.connect(lambda: self.save_pcap(True))

        self.action_save_visible = QAction("保存当前显示", self)
        self.action_save_visible.triggered.connect(lambda: self.save_pcap(False))

        self.action_export_csv = QAction("导出 CSV", self)
        self.action_export_csv.triggered.connect(self.export_csv)

        self.action_clear = QAction("清空", self)
        self.action_clear.setShortcut(QKeySequence("Ctrl+L"))
        self.action_clear.triggered.connect(lambda: self.clear_session(ask=True))

        self.action_options = QAction("捕获选项", self)
        self.action_options.setShortcut(QKeySequence("Ctrl+K"))
        self.action_options.triggered.connect(self.show_capture_options)

        self.action_stats = QAction("统计", self)
        self.action_stats.setShortcut(QKeySequence("Ctrl+T"))
        self.action_stats.triggered.connect(self.show_stats)

        self.action_find = QAction("查找", self)
        self.action_find.setShortcut(QKeySequence.Find)
        self.action_find.triggered.connect(self.find_packet)
        self.action_find_next = QAction("查找下一个", self)
        self.action_find_next.setShortcut(QKeySequence("Ctrl+G"))
        self.action_find_next.triggered.connect(self.find_next)

        self.action_filter_help = QAction("过滤器语法", self)
        self.action_filter_help.setShortcut(QKeySequence("F1"))
        self.action_filter_help.triggered.connect(self.show_filter_help)

        self.action_auto_scroll = QAction("自动滚动", self)
        self.action_auto_scroll.setCheckable(True)
        self.action_auto_scroll.setChecked(self.auto_scroll)
        self.action_auto_scroll.toggled.connect(self._set_auto_scroll)

        self.action_dark = QAction("深色主题", self)
        self.action_dark.setCheckable(True)
        self.action_dark.setChecked(self.dark)
        self.action_dark.setShortcut(QKeySequence("Ctrl+Shift+D"))
        self.action_dark.toggled.connect(self._set_dark)

        self.action_stream = QAction("打开选中的 TCP 流", self)
        self.action_stream.setShortcut(QKeySequence("Ctrl+Shift+O"))
        self.action_stream.triggered.connect(self.open_selected_stream)

        self.action_about = QAction("关于", self)
        self.action_about.triggered.connect(self.show_about)
        self.action_shortcuts = QAction("快捷键", self)
        self.action_shortcuts.triggered.connect(self.show_shortcuts)
        self.action_exit = QAction("退出", self)
        self.action_exit.setShortcut(QKeySequence.Quit)
        self.action_exit.triggered.connect(self.close)

        self.action_clear_filter = QAction("清除显示过滤器", self)
        self.action_clear_filter.setShortcut(QKeySequence("Ctrl+Shift+L"))
        self.action_clear_filter.triggered.connect(self._clear_filter)

        self.time_actions = QActionGroup(self)
        self.action_time_relative = QAction("相对时间", self)
        self.action_time_absolute = QAction("绝对时间", self)
        self.action_time_delta = QAction("增量时间", self)
        for action in (self.action_time_relative, self.action_time_absolute, self.action_time_delta):
            action.setCheckable(True)
        for action, mode in (
            (self.action_time_relative, "relative"),
            (self.action_time_absolute, "absolute"),
            (self.action_time_delta, "delta"),
        ):
            action.setData(mode)
            self.time_actions.addAction(action)
            action.triggered.connect(lambda checked=False, m=mode: self._set_time_mode(m))
        self._time_action_for(self.time_mode).setChecked(True)

    def _build_ui(self) -> None:
        self.setWindowTitle(f"{APP_NAME} — 带 GUI 的网络嗅探器")
        self.setWindowIcon(make_app_icon())
        self.resize(1700, 1000)
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.hint = QLabel()
        self.hint.setObjectName("hint")
        self.hint.setWordWrap(True)
        self.hint.setOpenExternalLinks(False)
        self.hint.linkActivated.connect(self._hint_link)
        layout.addWidget(self.hint)

        filter_bar = QFrame()
        filter_bar.setObjectName("filterBar")
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(10, 6, 10, 6)
        filter_layout.setSpacing(6)
        label = QLabel("显示过滤器")
        label.setStyleSheet("font-weight: 600;")
        filter_layout.addWidget(label)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('输入显示过滤器，例如：http and ip.addr == 192.168.1.0/24')
        self.filter_edit.setFont(QFont("Consolas", 10))
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.returnPressed.connect(self._apply_filter_from_edit)
        self.filter_edit.textChanged.connect(self._schedule_filter_validation)
        filter_layout.addWidget(self.filter_edit, 1)
        self.apply_filter_button = QPushButton("应用")
        self.apply_filter_button.setObjectName("primary")
        self.apply_filter_button.clicked.connect(self._apply_filter_from_edit)
        filter_layout.addWidget(self.apply_filter_button)
        self.common_button = QToolButton()
        self.common_button.setText("常用")
        self.common_button.setPopupMode(QToolButton.InstantPopup)
        self.common_button.setToolTip("常用显示过滤器")
        filter_layout.addWidget(self.common_button)
        self.filter_help_button = QToolButton()
        self.filter_help_button.setText("语法")
        self.filter_help_button.setToolTip("显示过滤器语法与字段列表（F1）")
        self.filter_help_button.clicked.connect(self.show_filter_help)
        filter_layout.addWidget(self.filter_help_button)
        self.filter_status = QLabel("")
        self.filter_status.setObjectName("filterStatus")
        self.filter_status.setMinimumWidth(150)
        filter_layout.addWidget(self.filter_status)
        layout.addWidget(filter_bar)

        self.main_splitter = QSplitter(Qt.Vertical)
        self.packet_table = QTableView()
        self.packet_table.setModel(self.model)
        self.packet_table.setSelectionBehavior(QTableView.SelectRows)
        self.packet_table.setSelectionMode(QTableView.SingleSelection)
        self.packet_table.setAlternatingRowColors(False)
        self.packet_table.setShowGrid(False)
        self.packet_table.setWordWrap(False)
        self.packet_table.setTextElideMode(Qt.ElideRight)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.verticalHeader().setDefaultSectionSize(22)
        self.packet_table.horizontalHeader().setHighlightSections(False)
        self.packet_table.horizontalHeader().setStretchLastSection(False)
        self.packet_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self._packet_menu)
        self.packet_table.doubleClicked.connect(self._on_packet_double_clicked)
        self.packet_table.selectionModel().currentRowChanged.connect(self._on_current_changed)
        for column, width in enumerate((66, 118, 158, 158, 105, 72, 420, 118)):
            self.packet_table.setColumnWidth(column, width)
        self.packet_table.setColumnHidden(7, True)
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        for column in (0, 1, 2, 3, 4, 5, 7):
            header.setSectionResizeMode(column, QHeaderView.Interactive)
        self.main_splitter.addWidget(self.packet_table)

        bottom = QSplitter(Qt.Horizontal)
        detail_box = QWidget()
        detail_layout = QVBoxLayout(detail_box)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(0)
        detail_header = QLabel("协议详情")
        detail_header.setObjectName("sectionTitle")
        detail_header.setContentsMargins(8, 4, 8, 4)
        detail_layout.addWidget(detail_header)
        self.detail_tree = DetailTree()
        self.detail_tree.field_selected.connect(self._on_field_selected)
        self.detail_tree.filter_requested.connect(self.set_filter)
        detail_layout.addWidget(self.detail_tree, 1)
        bottom.addWidget(detail_box)

        hex_box = QWidget()
        hex_layout = QVBoxLayout(hex_box)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(0)
        hex_header_row = QHBoxLayout()
        hex_header_row.setContentsMargins(8, 4, 8, 4)
        hex_header = QLabel("十六进制 / ASCII")
        hex_header.setObjectName("sectionTitle")
        hex_header_row.addWidget(hex_header)
        hex_header_row.addStretch(1)
        self.byte_label = QLabel("")
        self.byte_label.setObjectName("hint")
        hex_header_row.addWidget(self.byte_label)
        hex_layout.addLayout(hex_header_row)
        self.hex_view = HexView()
        hex_layout.addWidget(self.hex_view, 1)
        bottom.addWidget(hex_box)
        bottom.setSizes([560, 1000])
        self.main_splitter.addWidget(bottom)
        self.main_splitter.setSizes([560, 440])
        layout.addWidget(self.main_splitter, 1)
        self.setCentralWidget(central)

        self.flow_dock = QDockWidget("流与进程", self)
        self.flow_dock.setObjectName("flowDock")
        self.flow_dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        self.flow_tabs = QTabWidget()
        self.streams_table = QTableWidget(0, 7)
        self.streams_table.setHorizontalHeaderLabels(["#", "客户端", "服务器", "状态", "包", "字节", "进程"])
        self.streams_table.verticalHeader().setVisible(False)
        self.streams_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.streams_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.streams_table.setAlternatingRowColors(False)
        self.streams_table.setSortingEnabled(False)
        self.streams_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.streams_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        for column, width in ((0, 40), (3, 88), (4, 40), (5, 52), (6, 100)):
            self.streams_table.setColumnWidth(column, width)
        self.streams_table.setFont(QFont("Consolas", 8))
        self.streams_table.cellDoubleClicked.connect(self._on_stream_double_clicked)
        self.streams_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.streams_table.customContextMenuRequested.connect(self._stream_menu)
        self.flow_tabs.addTab(self.streams_table, "TCP 流")
        self.processes_table = QTableWidget(0, 5)
        self.processes_table.setHorizontalHeaderLabels(["PID", "进程", "包", "字节", "TCP 流"])
        self.processes_table.verticalHeader().setVisible(False)
        self.processes_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.processes_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.processes_table.setAlternatingRowColors(False)
        self.processes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.processes_table.setColumnWidth(0, 60)
        self.processes_table.setColumnWidth(2, 55)
        self.processes_table.setColumnWidth(3, 75)
        self.processes_table.setColumnWidth(4, 55)
        self.processes_table.setFont(QFont("Consolas", 8))
        self.processes_table.cellDoubleClicked.connect(self._on_process_double_clicked)
        self.processes_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.processes_table.customContextMenuRequested.connect(self._process_menu)
        self.flow_tabs.addTab(self.processes_table, "进程")
        self.flow_dock.setWidget(self.flow_tabs)
        self.addDockWidget(Qt.RightDockWidgetArea, self.flow_dock)
        self.flow_dock.setMinimumWidth(700)

        self._fill_common_menu()

    def _build_menus(self) -> None:
        menu_file = self.menuBar().addMenu("文件")
        menu_file.addAction(self.action_open)
        menu_file.addSeparator()
        menu_file.addAction(self.action_save)
        menu_file.addAction(self.action_save_visible)
        menu_file.addAction(self.action_export_csv)
        menu_file.addSeparator()
        menu_file.addAction(self.action_exit)

        menu_capture = self.menuBar().addMenu("捕获")
        menu_capture.addAction(self.action_start)
        menu_capture.addAction(self.action_stop)
        menu_capture.addAction(self.action_restart)
        menu_capture.addSeparator()
        menu_capture.addAction(self.action_options)
        menu_capture.addAction(self.action_clear)

        menu_view = self.menuBar().addMenu("视图")
        time_menu = menu_view.addMenu("时间格式")
        time_menu.addActions([self.action_time_relative, self.action_time_absolute, self.action_time_delta])
        menu_view.addAction(self.action_auto_scroll)
        menu_view.addAction(self.action_dark)
        menu_view.addSeparator()
        menu_view.addAction(self.flow_dock.toggleViewAction())
        reset = QAction("重置列宽", self)
        reset.triggered.connect(self._reset_columns)
        menu_view.addAction(reset)
        menu_view.addAction(self.action_clear_filter)

        menu_analysis = self.menuBar().addMenu("分析")
        menu_analysis.addAction(self.action_stats)
        menu_analysis.addAction(self.action_stream)
        menu_analysis.addAction(self.action_find)
        menu_analysis.addAction(self.action_find_next)
        menu_analysis.addAction(self.action_filter_help)

        menu_help = self.menuBar().addMenu("帮助")
        menu_help.addAction(self.action_shortcuts)
        menu_help.addAction(self.action_about)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("主工具栏")
        toolbar.setObjectName("mainToolBar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(20, 20))
        toolbar.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.addToolBar(toolbar)

        toolbar.addAction(self.action_start)
        toolbar.addAction(self.action_stop)
        toolbar.addAction(self.action_restart)
        toolbar.addSeparator()
        interface_label = QLabel("接口")
        interface_label.setContentsMargins(4, 0, 2, 0)
        toolbar.addWidget(interface_label)
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(330)
        self.device_combo.setMaximumWidth(480)
        self.device_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.device_combo.setMinimumContentsLength(28)
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        toolbar.addWidget(self.device_combo)
        bpf_label = QLabel("BPF")
        bpf_label.setContentsMargins(6, 0, 2, 0)
        toolbar.addWidget(bpf_label)
        self.bpf_edit = QLineEdit(self.config.bpf)
        self.bpf_edit.setPlaceholderText("捕获过滤器，例如 tcp port 80")
        self.bpf_edit.setFixedWidth(200)
        self.bpf_edit.editingFinished.connect(self._on_bpf_changed)
        toolbar.addWidget(self.bpf_edit)
        toolbar.addAction(self.action_options)
        toolbar.addSeparator()
        toolbar.addAction(self.action_open)
        toolbar.addAction(self.action_save)
        toolbar.addAction(self.action_clear)
        toolbar.addSeparator()
        toolbar.addAction(self.action_stats)
        toolbar.addAction(self.action_find)
        toolbar.addAction(self.action_filter_help)
        toolbar.addSeparator()
        toolbar.addAction(self.action_dark)
        self.toolbar = toolbar

    def _build_status(self) -> None:
        status = self.statusBar()
        self.status_dot = StatusDot()
        status.addWidget(self.status_dot)
        self.state_label = QLabel("就绪")
        self.state_label.setStyleSheet("padding-left: 4px; color: #8b949e;")
        status.addWidget(self.state_label)
        self.interface_label = QLabel("")
        self.interface_label.setStyleSheet("color: #8b949e; padding-left: 12px;")
        status.addWidget(self.interface_label, 1)
        self.packets_label = QLabel("包 0")
        self.displayed_label = QLabel("显示 0")
        self.dropped_label = QLabel("丢包 0")
        self.rate_label = QLabel("0 pps")
        self.sparkline = Sparkline()
        for widget in (self.packets_label, self.displayed_label, self.dropped_label, self.rate_label):
            widget.setStyleSheet("color: #8b949e; padding: 0 6px;")
            status.addPermanentWidget(widget)
        status.addPermanentWidget(self.sparkline)

    def _connect_shortcuts(self) -> None:
        QShortcut(QKeySequence.Copy, self.packet_table,
                  context=Qt.WidgetWithChildrenShortcut, activated=self._copy_summary)
        QShortcut(QKeySequence("Esc"), self.filter_edit, activated=self._clear_filter)

    def _restore_window(self) -> None:
        geometry = self.settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        state = self.settings.value("state")
        if state is not None:
            self.restoreState(state)
        self._time_action_for(self.time_mode).setChecked(True)
        self.model.set_time_mode(self.time_mode)
        self.action_auto_scroll.setChecked(self.auto_scroll)

    # ------------------------------------------------------------------
    # theme / backend initialization
    # ------------------------------------------------------------------
    def _apply_theme(self) -> None:
        apply_theme(QApplication.instance(), self.dark)
        self.model.set_dark(self.dark)
        self.detail_tree.set_dark(self.dark)
        self.sparkline.set_color("#4d9fff" if self.dark else "#0969da")
        try:
            self.packet_table.verticalHeader().setDefaultSectionSize(24)
        except Exception:
            pass
        self._set_icons()
        self.action_dark.setChecked(self.dark)
        if self.display_filter is not None:
            self._validate_filter_silent(self.filter_edit.text())
        self._restyle_filter()

    def _set_icons(self) -> None:
        mapping = {
            self.action_start: "play",
            self.action_stop: "stop",
            self.action_restart: "restart",
            self.action_open: "open",
            self.action_save: "save",
            self.action_save_visible: "save",
            self.action_clear: "clear",
            self.action_options: "gear",
            self.action_stats: "stats",
            self.action_find: "find",
            self.action_filter_help: "help",
            self.action_dark: "theme",
            self.action_stream: "stream",
        }
        for action, kind in mapping.items():
            action.setIcon(make_icon(kind, self.dark))

    def _set_dark(self, dark: bool) -> None:
        self.dark = bool(dark)
        self._apply_theme()
        self.settings.setValue("dark", self.dark)

    def _set_auto_scroll(self, enabled: bool) -> None:
        self.auto_scroll = bool(enabled)
        self.settings.setValue("auto_scroll", self.auto_scroll)

    def _set_time_mode(self, mode: str) -> None:
        self.time_mode = mode
        self.model.set_time_mode(mode)
        self.settings.setValue("time_mode", mode)

    def _time_action_for(self, mode: str) -> QAction:
        return {
            "relative": self.action_time_relative,
            "absolute": self.action_time_absolute,
            "delta": self.action_time_delta,
        }.get(mode, self.action_time_relative)

    def _init_backend(self) -> None:
        self._npcap_ok, self._npcap_detail = npcap_status()
        if self._npcap_ok:
            try:
                self.devices = get_npcap().devices()
            except NpcapError as exc:
                self._npcap_ok = False
                self._npcap_detail = str(exc)
                self.devices = []
            self._populate_devices()
        else:
            self.devices = []
            self._populate_devices()
        self._update_actions()
        self._update_hint()
        self.statusBar().setToolTip(self._npcap_detail)
        if self.process_table.available:
            try:
                self.process_table.refresh()
            except Exception:
                pass

    def _populate_devices(self) -> None:
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        for device in self.devices:
            self.device_combo.addItem(device.label, device)
        if self.devices:
            saved = self.settings.value("device", "", type=str)
            index = 0
            for i, device in enumerate(self.devices):
                if saved and device.name == saved:
                    index = i
                    break
            else:
                # prefer a physical, up, non-loopback adapter
                for i, device in enumerate(self.devices):
                    if not device.is_loopback and device.addresses and not device.name.lower().endswith("npcap_loopback"):
                        index = i
                        break
            self.device_combo.setCurrentIndex(index)
            self._on_device_changed(index)
        else:
            self.device_combo.addItem("（未发现可用网卡）", None)
        self.device_combo.blockSignals(False)

    def _on_device_changed(self, index: int) -> None:
        device = self.device_combo.currentData()
        if isinstance(device, Device):
            if self.mode in ("live", "file"):
                return
            self.config.device = device.name
            self.config.description = device.description
            self.settings.setValue("device", device.name)
            self.interface_label.setText(device.description)
        self._update_title()

    def _on_bpf_changed(self) -> None:
        text = self.bpf_edit.text().strip()
        if text != self.config.bpf:
            self.config.bpf = text
            self.settings.setValue("bpf", text)
            if self.mode == "live":
                self.statusBar().showMessage("BPF 过滤器将在下次捕获时生效", 3000)

    # ------------------------------------------------------------------
    # state / actions
    # ------------------------------------------------------------------
    def _set_state(self, state: str, text: str) -> None:
        self.status_dot.set_state(state)
        color = {
            "running": "#3fb950",
            "loading": "#d29922",
            "error": "#f85149",
        }.get(state, "#8b949e")
        self.state_label.setText(text)
        self.state_label.setStyleSheet(f"padding-left: 4px; color: {color}; font-weight: 600;")

    def _update_actions(self) -> None:
        busy = self.worker is not None
        live = self.mode == "live"
        self.action_start.setEnabled(self._npcap_ok and not live and self.mode != "file" and bool(self.devices))
        self.action_stop.setEnabled(busy)
        self.action_restart.setEnabled(self._npcap_ok and bool(self.devices) and not live)
        self.action_open.setEnabled(not live and self.mode != "file")
        self.action_clear.setEnabled(self.model.total_count > 0 or busy)
        self.action_save.setEnabled(self.model.total_count > 0)
        self.action_save_visible.setEnabled(self.model.visible_count > 0)
        self.action_export_csv.setEnabled(self.model.visible_count > 0)
        self.action_stats.setEnabled(self.model.total_count > 0)
        self.action_stream.setEnabled(self.current_packet is not None and self.current_packet.stream is not None)
        self.device_combo.setEnabled(not live and self.mode != "file")
        self.bpf_edit.setEnabled(not live)

    def _update_title(self) -> None:
        detail = ""
        if self.mode == "file" and self._loading_name:
            detail = f" — {self._loading_name}"
        elif self.config.description:
            detail = f" — {self.config.description}"
        self.setWindowTitle(f"{APP_NAME} — 带 GUI 的网络嗅探器{detail}")

    def _update_hint(self) -> None:
        if self.model.total_count > 0:
            self.hint.hide()
            return
        sample = SAMPLES_DIR / "demo.pcap"
        sample_link = (
            f' <a href="sample" style="color:#4d9fff">打开示例捕获</a>' if sample.exists() else ""
        )
        if not self._npcap_ok:
            text = (
                "<b>未检测到可用的 Npcap。</b> 仍可打开 pcap 文件进行离线分析"
                "（示例捕获已内置）；安装 Npcap 后即可实时抓包。"
                f'<a href="npcap" style="color:#4d9fff">安装说明</a>{sample_link}'
            )
        else:
            text = (
                "点击 <b>▶ 开始捕获</b>（Ctrl+R）选择网卡开始实时抓包，或按 Ctrl+O 打开 pcap 文件；"
                f"也可以直接{sample_link or '打开示例捕获'}。"
            )
        self.hint.setText(text)
        self.hint.show()

    def _hint_link(self, link: str) -> None:
        if link == "sample":
            path = SAMPLES_DIR / "demo.pcap"
            if path.exists():
                self.open_pcap(str(path))
            else:
                QMessageBox.information(self, "示例", "示例 pcap 不存在，请先运行 tools/make_demo_pcap.py。")
        elif link == "npcap":
            QMessageBox.information(
                self,
                "Npcap 安装",
                "本程序使用 Npcap 的 WinPcap 兼容 API（wpcap.dll）抓包。\n\n"
                "1. 从 https://npcap.com/#download 下载安装包；\n"
                "2. 安装时建议勾选 “Install Npcap in WinPcap API-compatible Mode”；\n"
                "3. 重新启动本程序。\n\n"
                "如果 wpcap.dll 安装在非默认目录，可设置环境变量 NETSNIFF_WPCAP "
                "指向该 DLL，或在程序目录的 config.json 中写入 {\"wpcap_path\": \"...\"}。",
            )

    # ------------------------------------------------------------------
    # capture lifecycle
    # ------------------------------------------------------------------
    def start_capture(self) -> None:
        if self.mode == "live":
            return
        if not self._npcap_ok:
            QMessageBox.warning(self, "无法开始捕获", self._npcap_detail or "未检测到 Npcap。")
            return
        device = self.device_combo.currentData()
        if not isinstance(device, Device):
            QMessageBox.warning(self, "无法开始捕获", "没有可用的捕获网卡。")
            return
        if self.model.total_count:
            answer = QMessageBox.question(
                self,
                "开始新的捕获",
                f"开始新的捕获将清空当前 {self.model.total_count} 个数据包，是否继续？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self._stop_worker()
        self._reset_session()
        self.config.device = device.name
        self.config.description = device.description
        self.config.bpf = self.bpf_edit.text().strip()
        worker = CaptureWorker(self.config, self)
        worker.opened.connect(self._on_capture_opened)
        worker.failed.connect(self._on_capture_failed)
        worker.progress.connect(self._on_capture_progress)
        worker.stats_ready.connect(self._on_driver_stats)
        worker.finished_ok.connect(self._on_capture_finished)
        self.worker = worker
        self.mode = "live"
        self.tracker = worker.tracker
        self._driver_stats = (0, 0, 0)
        self._app_dropped = 0
        self._set_state("loading", "正在打开网卡...")
        self.interface_label.setText(device.description)
        self._update_actions()
        self._update_title()
        self.drain_timer.start()
        self.tick_timer.start()
        worker.start()

    def stop_capture(self) -> None:
        if self.worker is None:
            return
        self._set_state("stopped", "正在停止...")
        self._stop_worker()
        self._set_state("stopped", "已停止")
        self._update_actions()
        self._update_counts()

    def restart_capture(self) -> None:
        if self.mode == "live":
            self._stop_worker()
        QTimer.singleShot(150, self.start_capture)

    def _stop_worker(self) -> None:
        worker = self.worker
        if worker is None:
            return
        try:
            worker.stop()
        except Exception:
            pass
        if worker.isRunning():
            worker.wait(4000)
        # drain any packets produced just before the stop
        try:
            packets = worker.drain()
            if packets:
                if self.mode == "live":
                    self._annotate_processes(packets)
                self.model.append_packets(packets)
        except Exception:
            pass
        try:
            worker.deleteLater()
        except Exception:
            pass
        self.worker = None
        self.drain_timer.stop()
        self.tick_timer.stop()
        self._update_counts()

    def _on_capture_opened(self, linktype: int) -> None:
        self.linktype = int(linktype)
        self._set_state("running", "正在捕获")
        self._update_hint()
        self._update_actions()
        self._update_title()
        self.statusBar().showMessage(f"正在从 {self.config.description or self.config.device} 捕获", 4000)

    def _on_capture_progress(self, count: int) -> None:
        if self.mode == "live":
            self.interface_label.setText(f"{self.config.description}  ·  {count} 包")

    def _on_driver_stats(self, received: int, dropped: int, if_dropped: int) -> None:
        self._driver_stats = (int(received), int(dropped), int(if_dropped))

    def _on_capture_failed(self, message: str) -> None:
        self._set_state("error", "捕获失败")
        self._update_actions()
        QMessageBox.critical(self, "捕获失败", message)
        worker = self.worker
        self.worker = None
        self.mode = ""
        self.drain_timer.stop()
        self.tick_timer.stop()
        if worker is not None:
            worker.wait(1000)
            worker.deleteLater()
        self._update_actions()
        self._update_hint()

    def _on_capture_finished(self, count: int) -> None:
        if self.worker is not None:
            try:
                packets = self.worker.drain()
                if packets:
                    if self.mode == "live":
                        self._annotate_processes(packets)
                    self.model.append_packets(packets)
            except Exception:
                pass
            try:
                self.worker.wait(1000)
                self.worker.deleteLater()
            except Exception:
                pass
        self.worker = None
        self.mode = ""
        self.drain_timer.stop()
        self.tick_timer.stop()
        self._set_state("stopped", f"已停止（共 {self.model.total_count} 包）")
        self._update_streams_table()
        self._update_process_table()
        self._update_actions()
        self._update_counts()
        self._update_hint()

    # ------------------------------------------------------------------
    # file loading
    # ------------------------------------------------------------------
    def open_pcap(self, path: Optional[str] = None) -> None:
        if path is None:
            path, _ = QFileDialog.getOpenFileName(
                self, "打开捕获文件", str(SAMPLES_DIR), "捕获文件 (*.pcap *.pcapng *.cap);;所有文件 (*.*)"
            )
        if not path:
            return
        if not Path(path).is_file():
            QMessageBox.warning(self, "打开失败", f"文件不存在：{path}")
            return
        if self.mode == "live":
            answer = QMessageBox.question(
                self, "停止捕获", "打开文件需要停止当前捕获，是否继续？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            )
            if answer != QMessageBox.Yes:
                return
            self._stop_worker()
        self._stop_worker()
        self._reset_session()
        worker = PcapFileWorker(path, self)
        worker.opened.connect(self._on_file_opened)
        worker.progress.connect(self._on_file_progress)
        worker.failed.connect(self._on_file_failed)
        worker.finished_ok.connect(self._on_file_finished)
        self.worker = worker
        self.mode = "file"
        self.tracker = worker.tracker
        self._loading_name = Path(path).name
        self._set_state("loading", f"正在加载 {self._loading_name} ...")
        self.interface_label.setText(str(path))
        self._update_title()
        self._update_actions()
        self.drain_timer.start()
        self.tick_timer.start()
        worker.start()

    def _on_file_opened(self, linktype: int) -> None:
        self.linktype = int(linktype)
        self._update_title()

    def _on_file_progress(self, count: int) -> None:
        self._set_state("loading", f"正在加载 {self._loading_name} ... {count} 包")

    def _on_file_failed(self, message: str) -> None:
        self._set_state("error", "加载失败")
        worker = self.worker
        self.worker = None
        self.mode = ""
        self.drain_timer.stop()
        self.tick_timer.stop()
        if worker is not None:
            worker.wait(1000)
            worker.deleteLater()
        self._update_actions()
        self._update_hint()
        QMessageBox.critical(self, "加载失败", message)

    def _on_file_finished(self, count: int) -> None:
        if self.worker is not None:
            try:
                packets = self.worker.drain()
                if packets:
                    self.model.append_packets(packets)
            except Exception:
                pass
            try:
                self.worker.wait(1000)
                self.worker.deleteLater()
            except Exception:
                pass
        self.worker = None
        self.mode = ""
        self.drain_timer.stop()
        self.tick_timer.stop()
        total = self.model.total_count
        if total:
            self._set_state("stopped", f"已加载 {self._loading_name}（{total} 包）")
            self.packet_table.selectRow(0)
        else:
            self._set_state("error", "文件中没有数据包")
            QMessageBox.warning(self, "加载完成", "捕获文件中没有可显示的数据包。")
        self._update_actions()
        self._update_counts()
        self._update_hint()
        self._update_streams_table()
        self._update_process_table()

    def load_pcap_sync(self, path: str) -> int:
        """Synchronous loader used by the report/screenshot tools."""
        self._stop_worker()
        self._reset_session()
        header, records = read_pcap(path)
        self.linktype = header.linktype
        tracker = StreamTracker()
        packets: List[Packet] = []
        for number, record in enumerate(records, 1):
            packet = dissect_packet(record.data, number, record.ts, record.wirelen, header.linktype)
            tracker.process(packet)
            packets.append(packet)
        self.tracker = tracker
        self.model.append_packets(packets)
        self._loading_name = Path(path).name
        self._set_state("stopped", f"已加载 {self._loading_name}（{len(packets)} 包）")
        self._update_counts()
        self._update_streams_table()
        self._update_hint()
        self._update_actions()
        if packets:
            self.packet_table.selectRow(0)
        return len(packets)

    def _reset_session(self) -> None:
        self.mode = ""
        self.model.clear()
        self.tracker = StreamTracker()
        self.process_stats.clear()
        self.stream_process.clear()
        self._has_process_info = False
        self.packet_table.setColumnHidden(7, True)
        self._driver_stats = (0, 0, 0)
        self._app_dropped = 0
        self._last_count = 0
        self._last_tick = time.monotonic()
        self.current_packet = None
        self.detail_tree.set_packet(None)
        self.hex_view.clear()
        self.byte_label.setText("")
        self.streams_table.setRowCount(0)
        self.processes_table.setRowCount(0)
        self.sparkline.clear()
        self._update_counts()
        self._update_hint()
        self.filter_edit.blockSignals(True)
        self.filter_edit.setText("")
        self.filter_edit.blockSignals(False)
        self.display_filter = compile_filter("")
        self.model.set_filter(self.display_filter)
        self._set_state("idle", "就绪")
        self.interface_label.setText(self.config.description)
        self._update_actions()

    def clear_session(self, ask: bool = True) -> None:
        if ask and self.model.total_count:
            answer = QMessageBox.question(
                self, "清空会话", "确定要清空当前捕获的所有数据包吗？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self._stop_worker()
        self._reset_session()
        self._loading_name = ""
        self._has_process_info = False
        self._update_title()
        self.statusBar().showMessage("会话已清空", 2500)

    # ------------------------------------------------------------------
    # draining / status
    # ------------------------------------------------------------------
    def _drain(self) -> None:
        worker = self.worker
        if worker is None:
            return
        try:
            packets = worker.drain()
        except Exception:
            packets = []
        if packets:
            if self.mode == "live":
                self._annotate_processes(packets)
            self.model.append_packets(packets)
            if self.auto_scroll and self.model.rowCount():
                scrollbar = self.packet_table.verticalScrollBar()
                if scrollbar.value() >= scrollbar.maximum() - 4:
                    self.packet_table.scrollToBottom()
            self._update_counts()

    def _tick(self) -> None:
        now = time.monotonic()
        elapsed = max(0.001, now - self._last_tick)
        count = self.model.total_count
        rate = max(0.0, (count - self._last_count) / elapsed)
        self._last_count = count
        self._last_tick = now
        self.rate_label.setText(f"{rate:.0f} pps")
        self.sparkline.push(rate)
        self._update_counts()
        if self.worker is not None and self.flow_dock.isVisible():
            self._update_streams_table()
            self._update_process_table()

    def _update_counts(self) -> None:
        self.packets_label.setText(f"包 {self.model.total_count}")
        self.displayed_label.setText(f"显示 {self.model.visible_count}")
        if self.model.total_count > 0:
            self.hint.hide()
        received, dropped, if_dropped = self._driver_stats
        total_dropped = dropped + if_dropped + self._app_dropped
        self.dropped_label.setText(f"丢包 {total_dropped}")
        self.dropped_label.setToolTip(
            f"驱动接收 {received}\n驱动丢弃 {dropped}\n接口丢弃 {if_dropped}\n界面队列丢弃 {self._app_dropped}"
        )
        self.filter_status.setText(f"{self.model.visible_count} / {self.model.total_count}")
        self.action_clear.setEnabled(self.model.total_count > 0 or self.worker is not None)
        self.action_save.setEnabled(self.model.total_count > 0)
        self.action_save_visible.setEnabled(self.model.visible_count > 0)
        self.action_export_csv.setEnabled(self.model.visible_count > 0)
        self.action_stats.setEnabled(self.model.total_count > 0)
        self.action_stream.setEnabled(self.current_packet is not None and self.current_packet.stream is not None)

    # ------------------------------------------------------------------
    # packet selection / detail / hex
    # ------------------------------------------------------------------
    def _on_current_changed(self, current, previous) -> None:
        if not current.isValid():
            return
        packet = self.model.packet_at(current.row())
        if packet is None:
            return
        self.current_packet = packet
        self.detail_tree.set_packet(packet)
        self.hex_view.set_data(packet.raw)
        self.detail_tree.field_selected.emit(-1, 0, "")
        self.byte_label.setText(
            f"{len(packet.raw)} bytes  ·  线上 {packet.wirelen} bytes  ·  #{packet.number}"
        )
        self._update_actions()

    def _on_field_selected(self, offset: int, length: int, key: str) -> None:
        self.hex_view.set_highlight(offset, length)
        if key and offset >= 0 and length > 0:
            self.statusBar().showMessage(f"字段 {key}  ·  字节 {offset}..{offset + length - 1}", 2000)

    def _on_packet_double_clicked(self, index) -> None:
        packet = self.model.packet_at(index.row())
        if packet is not None and packet.stream is not None:
            self.open_stream_dialog(packet.stream)

    def select_packet_number(self, number: int) -> None:
        row = self.model.row_of_packet(number)
        if row < 0:
            self.statusBar().showMessage(f"数据包 #{number} 不在当前显示结果中", 3000)
            return
        self.packet_table.setCurrentIndex(self.model.index(row, 0))
        self.packet_table.scrollTo(self.model.index(row, 0), QTableView.PositionAtCenter)
        self.raise_()
        self.activateWindow()

    # ------------------------------------------------------------------
    # filtering
    # ------------------------------------------------------------------
    def _setup_filter_validation(self) -> None:
        self._filter_validation_timer = QTimer(self)
        self._filter_validation_timer.setSingleShot(True)
        self._filter_validation_timer.setInterval(280)
        self._filter_validation_timer.timeout.connect(lambda: self._validate_filter_silent(self.filter_edit.text()))

    def _schedule_filter_validation(self) -> None:
        timer = getattr(self, "_filter_validation_timer", None)
        if timer is None:
            self._setup_filter_validation()
            timer = self._filter_validation_timer
        timer.start()

    def _validate_filter_silent(self, text: str) -> bool:
        text = (text or "").strip()
        if not text:
            self._set_filter_property(None, "")
            return True
        try:
            compile_filter(text)
        except FilterError as exc:
            self._set_filter_property(False, str(exc))
            return False
        self._set_filter_property(True, "语法正确")
        return True

    def _set_filter_property(self, valid: Optional[bool], message: str) -> None:
        self.filter_edit.setProperty("invalid", valid is False)
        self.filter_edit.setProperty("valid", valid is True)
        self.filter_edit.setToolTip(message)
        self.filter_edit.style().unpolish(self.filter_edit)
        self.filter_edit.style().polish(self.filter_edit)

    def _restyle_filter(self) -> None:
        self.filter_edit.style().unpolish(self.filter_edit)
        self.filter_edit.style().polish(self.filter_edit)

    def _apply_filter_from_edit(self) -> None:
        self.apply_filter(self.filter_edit.text())

    def apply_filter(self, text: str) -> bool:
        text = (text or "").strip()
        try:
            compiled = compile_filter(text)
        except FilterError as exc:
            self._set_filter_property(False, str(exc))
            self.filter_status.setText("过滤器错误")
            self.filter_status.setStyleSheet("color: #f85149; padding-left: 6px;")
            self.filter_status.setToolTip(str(exc))
            return False
        self.display_filter = compiled
        self.model.set_filter(compiled)
        self._set_filter_property(None, "")
        self._update_counts()
        self.filter_status.setStyleSheet("color: #8b949e; padding-left: 6px;")
        self.statusBar().showMessage(f"显示过滤器已应用：{text or '（无）'}", 3000)
        if self.model.visible_count:
            self.packet_table.selectRow(0)
        return True

    def set_filter(self, expression: str) -> None:
        self.filter_edit.setText(expression)
        self.apply_filter(expression)
        self.raise_()
        self.activateWindow()

    def _clear_filter(self) -> None:
        self.filter_edit.blockSignals(True)
        self.filter_edit.setText("")
        self.filter_edit.blockSignals(False)
        self.apply_filter("")

    def _fill_common_menu(self) -> None:
        from PyQt5.QtWidgets import QMenu
        menu = QMenu(self)
        for label, expression in COMMON_FILTERS:
            action = menu.addAction(label)
            action.triggered.connect(lambda checked=False, e=expression: self.set_filter(e))
        menu.addSeparator()
        clear_action = menu.addAction("清除过滤器")
        clear_action.triggered.connect(self._clear_filter)
        self.common_button.setMenu(menu)

    def show_filter_help(self) -> None:
        if self._help_dialog is not None:
            self._help_dialog.raise_()
            self._help_dialog.activateWindow()
            return
        self._help_dialog = FilterHelpDialog(self, self.filter_edit.text())
        self._help_dialog.filter_requested.connect(self.set_filter)
        self._help_dialog.finished.connect(self._on_help_closed)
        self._help_dialog.show()

    def _on_help_closed(self, _result: int) -> None:
        self._help_dialog = None

    # ------------------------------------------------------------------
    # streams / processes docks
    # ------------------------------------------------------------------
    def _annotate_processes(self, packets: List[Packet]) -> None:
        table = self.process_table
        for packet in packets:
            ip = packet.ip
            if ip is None:
                continue
            if packet.tcp is not None:
                proto = "tcp"
                sport, dport = packet.tcp.sport, packet.tcp.dport
            elif packet.udp is not None:
                proto = "udp"
                sport, dport = packet.udp.sport, packet.udp.dport
            else:
                continue
            result = table.lookup(proto, ip.src, sport, ip.dst, dport)
            if result is None:
                continue
            pid, name = result
            if pid <= 0:
                # TIME_WAIT rows report PID 0; that is not a usable owner.
                continue
            packet.pid = pid
            packet.process = name
            if not self._has_process_info:
                self._has_process_info = True
                self.packet_table.setColumnHidden(7, False)
            entry = self.process_stats.get(pid)
            if entry is None:
                entry = [name, 0, 0, set()]
                self.process_stats[pid] = entry
            entry[1] += 1
            entry[2] += packet.wirelen
            if packet.stream is not None:
                entry[3].add(packet.stream)
                self.stream_process[packet.stream] = name

    def _refresh_process_table(self) -> None:
        if self.process_table.available:
            try:
                self.process_table.refresh()
            except Exception:
                pass

    def _update_streams_table(self) -> None:
        if not hasattr(self, "streams_table"):
            return
        selected = None
        current = self.streams_table.currentRow()
        if current >= 0:
            item = self.streams_table.item(current, 0)
            if item is not None:
                selected = item.data(Qt.UserRole)
        infos = self.tracker.infos()
        self.streams_table.setUpdatesEnabled(False)
        self.streams_table.setRowCount(len(infos))
        for row, info in enumerate(infos):
            number_item = QTableWidgetItem(str(info.index))
            number_item.setData(Qt.UserRole, info.index)
            self.streams_table.setItem(row, 0, number_item)
            self.streams_table.setItem(row, 1, QTableWidgetItem(f"{info.client}:{info.cport}"))
            self.streams_table.setItem(row, 2, QTableWidgetItem(f"{info.server}:{info.sport}"))
            self.streams_table.setItem(row, 3, QTableWidgetItem(info.state))
            self.streams_table.setItem(row, 4, QTableWidgetItem(str(info.packets)))
            self.streams_table.setItem(row, 5, QTableWidgetItem(str(info.bytes)))
            self.streams_table.setItem(row, 6, QTableWidgetItem(self.stream_process.get(info.index, "")))
            if selected == info.index:
                self.streams_table.selectRow(row)
        self.streams_table.setUpdatesEnabled(True)

    def _update_process_table(self) -> None:
        entries = sorted(self.process_stats.items(), key=lambda item: -item[1][1])
        selected_pid = None
        row = self.processes_table.currentRow()
        if row >= 0:
            item = self.processes_table.item(row, 0)
            if item is not None:
                selected_pid = item.data(Qt.UserRole)
        self.processes_table.setUpdatesEnabled(False)
        self.processes_table.setRowCount(min(len(entries), 500))
        for row, (pid, (name, packets, bytes_count, streams)) in enumerate(entries[:500]):
            pid_item = QTableWidgetItem(str(pid))
            pid_item.setData(Qt.UserRole, pid)
            self.processes_table.setItem(row, 0, pid_item)
            self.processes_table.setItem(row, 1, QTableWidgetItem(name))
            self.processes_table.setItem(row, 2, QTableWidgetItem(str(packets)))
            self.processes_table.setItem(row, 3, QTableWidgetItem(str(bytes_count)))
            self.processes_table.setItem(row, 4, QTableWidgetItem(str(len(streams))))
            if pid == selected_pid:
                self.processes_table.selectRow(row)
        self.processes_table.setUpdatesEnabled(True)

    def _on_stream_double_clicked(self, row: int, column: int) -> None:
        item = self.streams_table.item(row, 0)
        if item is None:
            return
        index = item.data(Qt.UserRole)
        if index is not None:
            self.open_stream_dialog(int(index))

    def _on_process_double_clicked(self, row: int, column: int) -> None:
        item = self.processes_table.item(row, 0)
        if item is None:
            return
        pid = item.data(Qt.UserRole)
        if pid is not None:
            self.set_filter(f"proc.pid == {pid}")

    def open_stream_dialog(self, index: int) -> None:
        snapshot = self.tracker.snapshot(index)
        if snapshot is None:
            QMessageBox.information(self, "TCP 流", f"找不到流 #{index}。")
            return
        dialog = TcpStreamDialog(snapshot, self, self.stream_process.get(index, ""))
        dialog.filter_requested.connect(self.set_filter)
        dialog.packet_selected.connect(self.select_packet_number)
        dialog.finished.connect(lambda _result, d=dialog: self._forget_stream_dialog(d))
        self._stream_dialogs.append(dialog)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _forget_stream_dialog(self, dialog) -> None:
        if dialog in self._stream_dialogs:
            self._stream_dialogs.remove(dialog)

    def open_selected_stream(self) -> None:
        packet = self.current_packet
        if packet is not None and packet.stream is not None:
            self.open_stream_dialog(packet.stream)
        else:
            QMessageBox.information(self, "TCP 流", "请先在数据包列表中选择一个 TCP 数据包。")

    def _stream_menu(self, pos) -> None:
        from PyQt5.QtWidgets import QMenu
        item = self.streams_table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        number_item = self.streams_table.item(row, 0)
        if number_item is None:
            return
        index = number_item.data(Qt.UserRole)
        menu = QMenu(self)
        open_action = menu.addAction("打开时序图")
        open_action.triggered.connect(lambda: self.open_stream_dialog(int(index)))
        filter_action = menu.addAction("仅显示该 TCP 流")
        filter_action.triggered.connect(lambda: self.set_filter(f"tcp.stream == {index}"))
        copy_action = menu.addAction("复制摘要")
        copy_action.triggered.connect(
            lambda: QApplication.clipboard().setText(
                "\t".join(self.streams_table.item(row, c).text() if self.streams_table.item(row, c) else ""
                          for c in range(7))
            )
        )
        menu.exec_(self.streams_table.viewport().mapToGlobal(pos))

    def _process_menu(self, pos) -> None:
        from PyQt5.QtWidgets import QMenu
        item = self.processes_table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        pid_item = self.processes_table.item(row, 0)
        if pid_item is None:
            return
        pid = pid_item.data(Qt.UserRole)
        menu = QMenu(self)
        filter_action = menu.addAction("仅显示该进程的流量")
        filter_action.triggered.connect(lambda: self.set_filter(f"proc.pid == {pid}"))
        copy_action = menu.addAction("复制进程名")
        copy_action.triggered.connect(
            lambda: QApplication.clipboard().setText(self.processes_table.item(row, 1).text())
        )
        menu.exec_(self.processes_table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    # packet context menu / copy
    # ------------------------------------------------------------------
    def _packet_menu(self, pos) -> None:
        from PyQt5.QtWidgets import QMenu
        index = self.packet_table.indexAt(pos)
        if not index.isValid():
            return
        packet = self.model.packet_at(index.row())
        if packet is None:
            return
        menu = QMenu(self)
        copy_summary = menu.addAction("复制摘要")
        copy_summary.triggered.connect(self._copy_summary)
        copy_detail = menu.addAction("复制协议详情")
        copy_detail.triggered.connect(lambda: self._copy_packet_detail(packet))
        copy_hex = menu.addAction("复制全部字节 (hex)")
        copy_hex.triggered.connect(lambda: QApplication.clipboard().setText(packet.raw.hex(" ")))
        menu.addSeparator()
        filter_action = menu.addAction("按该包的 TCP 端口过滤")
        filter_action.setEnabled(packet.tcp is not None)
        filter_action.triggered.connect(self._filter_from_packet_ports)
        if packet.stream is not None:
            stream_action = menu.addAction("打开所属 TCP 流")
            stream_action.triggered.connect(lambda: self.open_stream_dialog(packet.stream))
        if packet.process:
            process_action = menu.addAction(f"仅显示进程 {packet.process}")
            process_action.triggered.connect(lambda: self.set_filter(f"proc.pid == {packet.pid}"))
        menu.exec_(self.packet_table.viewport().mapToGlobal(pos))

    def _filter_from_packet_ports(self) -> None:
        packet = self.current_packet
        if packet is None or packet.tcp is None:
            return
        ports = sorted({packet.tcp.sport, packet.tcp.dport})
        self.set_filter(f"tcp.port == {ports[0]}" + (f" and tcp.port == {ports[1]}" if len(ports) > 1 else ""))

    def _copy_summary(self) -> None:
        packet = self.current_packet
        if packet is None:
            return
        text = "\t".join([
            str(packet.number), format_timestamp(packet.ts), packet.src, packet.dst,
            packet.protocol, str(packet.wirelen), packet.info,
        ])
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("已复制数据包摘要", 2000)

    def _copy_packet_detail(self, packet: Packet) -> None:
        lines = []
        for layer in packet.layers:
            lines.append(layer.title())
            for field in layer.fields:
                for item in field.walk():
                    if item is not field:
                        lines.append("    " + item.text())
                    else:
                        lines.append("  " + item.text())
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage("已复制协议详情", 2000)

    # ------------------------------------------------------------------
    # save / export
    # ------------------------------------------------------------------
    def save_pcap(self, all_packets: bool = True) -> None:
        packets = self.model.all_packets() if all_packets else self.model.visible_packets()
        if not packets:
            QMessageBox.information(self, "保存", "没有可保存的数据包。")
            return
        default = str(Path.home() / ("netsniffer_all.pcap" if all_packets else "netsniffer_displayed.pcap"))
        path, _ = QFileDialog.getSaveFileName(self, "保存 pcap", default, "pcap 文件 (*.pcap);;所有文件 (*.*)")
        if not path:
            return
        if not path.lower().endswith(".pcap"):
            path += ".pcap"
        try:
            count = write_pcap(path, packets, self.linktype)
        except Exception as exc:
            QMessageBox.critical(self, "保存失败", str(exc))
            return
        self.statusBar().showMessage(f"已保存 {count} 个数据包到 {path}", 5000)

    def export_csv(self) -> None:
        packets = self.model.visible_packets()
        if not packets:
            QMessageBox.information(self, "导出", "没有可导出的数据包。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", str(Path.home() / "netsniffer.csv"), "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh)
                writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Process"])
                for packet in packets:
                    writer.writerow([
                        packet.number, format_timestamp(packet.ts), packet.src, packet.dst,
                        packet.protocol, packet.wirelen, packet.info, packet.process or "",
                    ])
        except OSError as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        self.statusBar().showMessage(f"已导出 {len(packets)} 行到 {path}", 5000)

    # ------------------------------------------------------------------
    # analysis dialogs
    # ------------------------------------------------------------------
    def show_stats(self) -> None:
        packets = self.model.all_packets()
        if not packets:
            QMessageBox.information(self, "统计", "没有可统计的数据包。")
            return
        if self._stats_dialog is not None:
            self._stats_dialog.raise_()
            self._stats_dialog.activateWindow()
            return
        dialog = StatsDialog(list(packets), self)
        dialog.filter_requested.connect(self.set_filter)
        dialog.finished.connect(self._on_stats_closed)
        self._stats_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def _on_stats_closed(self, _result: int) -> None:
        self._stats_dialog = None

    def find_packet(self) -> None:
        text, ok = QInputDialog.getText(self, "查找数据包", "在 Info / 协议 / 地址中查找（不区分大小写）：")
        if not ok or not text.strip():
            return
        self._last_find = text.strip()
        self.find_next()

    def find_next(self) -> None:
        if not self._last_find:
            self.find_packet()
            return
        needle = self._last_find.lower()
        start = self.packet_table.currentIndex().row() + 1
        count = self.model.rowCount()
        for offset in range(count):
            row = (start + offset) % count if count else 0
            packet = self.model.packet_at(row)
            if packet is not None and needle in packet.searchable_text():
                self.select_packet_number(packet.number)
                return
        self.statusBar().showMessage(f"未找到 “{self._last_find}”", 3000)

    def show_capture_options(self) -> None:
        dialog = CaptureOptionsDialog(self.config, self, self.devices)
        if dialog.exec_() == CaptureOptionsDialog.Accepted:
            self.config = dialog.config()
            self.bpf_edit.setText(self.config.bpf)
            self._on_bpf_changed()
            for index in range(self.device_combo.count()):
                device = self.device_combo.itemData(index)
                if isinstance(device, Device) and device.name == self.config.device:
                    self.device_combo.setCurrentIndex(index)
                    break
            self.settings.setValue("snaplen", self.config.snaplen)
            self.settings.setValue("promisc", self.config.promisc)
            self.settings.setValue("timeout_ms", self.config.timeout_ms)
            self.settings.setValue("buffer_mb", self.config.buffer_mb)
            self.settings.setValue("immediate", self.config.immediate)
            self._update_actions()

    def show_about(self) -> None:
        ok, detail = npcap_status()
        text = (
            f"<h2>{APP_NAME}</h2>"
            f"<p>版本 {APP_VERSION}　·　Python + PyQt5 + Npcap</p>"
            "<p>带 GUI 的网络嗅探器：实时抓包、协议解析、BPF/显示过滤器、"
            "TCP 流重组与时序图、进程归属、pcap 读写和统计。</p>"
            f"<p><b>Npcap</b>：{'可用' if ok else '不可用'}<br><span style='color:#8b949e'>{detail}</span></p>"
            f"<p><b>Qt</b>：{__import__('PyQt5.QtCore', fromlist=['QT_VERSION_STR']).QT_VERSION_STR}　"
            f"<b>Python</b>：{__import__('sys').version.split()[0]}</p>"
            "<p style='color:#8b949e'>《软件与系统安全》实验 1A　刘鹏老师课程</p>"
            "<p style='color:#8b949e'>作者：李柏谚（202649210129022）　Git 仓库：https://github.com/LiLisyn123/software-system-security-experiments</p>"
        )
        QMessageBox.about(self, f"关于 {APP_NAME}", text)

    def show_shortcuts(self) -> None:
        QMessageBox.information(
            self,
            "快捷键",
            "Ctrl+R　开始捕获\n"
            "Ctrl+E　停止捕获\n"
            "Ctrl+O　打开 pcap\n"
            "Ctrl+S　保存全部\n"
            "Ctrl+L　清空会话\n"
            "Ctrl+K　捕获选项\n"
            "Ctrl+T　统计\n"
            "Ctrl+F　查找　Ctrl+G 查找下一个\n"
            "Ctrl+Shift+O　打开选中的 TCP 流\n"
            "Ctrl+Shift+L　清除显示过滤器\n"
            "Ctrl+Shift+D　切换深色/浅色主题\n"
            "F1　显示过滤器语法",
        )

    def _reset_columns(self) -> None:
        for column, width in enumerate((66, 118, 158, 158, 105, 72, 420, 118)):
            self.packet_table.setColumnWidth(column, width)

    # ------------------------------------------------------------------
    # window close
    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:
        self._stop_worker()
        try:
            self.settings.setValue("geometry", self.saveGeometry())
            self.settings.setValue("state", self.saveState())
            self.settings.setValue("dark", self.dark)
            self.settings.setValue("auto_scroll", self.auto_scroll)
            self.settings.setValue("time_mode", self.time_mode)
            self.settings.setValue("device", self.config.device)
            self.settings.setValue("bpf", self.bpf_edit.text().strip())
            self.settings.setValue("snaplen", self.config.snaplen)
            self.settings.setValue("promisc", self.config.promisc)
            self.settings.setValue("timeout_ms", self.config.timeout_ms)
            self.settings.setValue("buffer_mb", self.config.buffer_mb)
            self.settings.setValue("immediate", self.config.immediate)
        except Exception:
            pass
        for dialog in list(self._stream_dialogs):
            dialog.close()
        if self._stats_dialog is not None:
            self._stats_dialog.close()
        if self._help_dialog is not None:
            self._help_dialog.close()
        event.accept()
