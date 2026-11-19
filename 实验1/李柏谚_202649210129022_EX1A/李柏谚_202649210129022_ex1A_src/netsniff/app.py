"""Application entry point and command line handling."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback
from pathlib import Path

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QMessageBox

from . import __version__
from .config import APP_NAME, ORG_NAME, log_dir
from .ui.main_window import MainWindow
from .ui.theme import apply_theme, make_app_icon


def _setup_logging() -> Path:
    path = log_dir() / "netsniff.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(path, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )
    return path


def _install_exception_hook(app: QApplication) -> None:
    def hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logging.getLogger("netsniff").error("unhandled exception:\n%s", text)
        try:
            QMessageBox.critical(
                None,
                "程序异常",
                f"发生未处理的异常：\n\n{exc_value}\n\n详细信息已写入日志。",
            )
        except Exception:
            pass

    sys.excepthook = hook


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description=f"{APP_NAME} — 带 GUI 的网络嗅探器")
    parser.add_argument("--pcap", metavar="FILE", help="启动时打开 pcap 文件")
    parser.add_argument("--filter", metavar="EXPR", default="", help="启动时应用显示过滤器")
    parser.add_argument("--capture", action="store_true", help="启动后立即开始捕获")
    parser.add_argument("--interface", metavar="NAME", help="捕获接口的设备名（\\\\Device\\\\NPF_...）")
    parser.add_argument("--bpf", metavar="EXPR", default="", help="BPF 捕获过滤器")
    parser.add_argument("--light", action="store_true", help="使用浅色主题")
    parser.add_argument("--version", action="version", version=__version__)
    args, qt_args = parser.parse_known_args(argv[1:])

    _setup_logging()
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication([argv[0]] + qt_args)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setWindowIcon(make_app_icon())
    app.setFont(QFont("Microsoft YaHei UI", 9))
    _install_exception_hook(app)

    window = MainWindow()
    if args.light:
        window.action_dark.setChecked(False)
    if args.bpf:
        window.config.bpf = args.bpf
        window.bpf_edit.setText(args.bpf)
    if args.interface:
        for index in range(window.device_combo.count()):
            device = window.device_combo.itemData(index)
            if device is not None and getattr(device, "name", "") == args.interface:
                window.device_combo.setCurrentIndex(index)
                break
    window.show()
    apply_theme(app, window.dark)

    if args.pcap:
        try:
            window.load_pcap_sync(args.pcap)
        except Exception as exc:
            QMessageBox.critical(window, "打开失败", f"{args.pcap}\n\n{exc}")
    if args.filter:
        window.set_filter(args.filter)
    if args.capture:
        QTimer.singleShot(700, window.start_capture)

    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
