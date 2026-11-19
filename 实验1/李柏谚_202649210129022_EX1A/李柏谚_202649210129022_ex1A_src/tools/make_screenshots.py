#!/usr/bin/env python3
"""Generate the screenshots used by the report (no real capture required).

Runs on the Windows QPA plugin with ``WA_DontShowOnScreen`` so text is rendered
with the real font database and no window flashes on the desktop.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from netsniff.config import SAMPLES_DIR  # noqa: E402
from netsniff.ui.capture_dialog import CaptureOptionsDialog  # noqa: E402
from netsniff.ui.filter_help import FilterHelpDialog  # noqa: E402
from netsniff.ui.main_window import MainWindow  # noqa: E402
from netsniff.ui.stats_dialog import StatsDialog  # noqa: E402
from netsniff.ui.stream_dialog import TcpStreamDialog  # noqa: E402

OUT = ROOT / "docs" / "screenshots"


def pump(app: QApplication, seconds: float = 0.3) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.015)


def save(widget, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    pix = widget.grab()
    if pix.save(str(path)):
        print(f"saved {path}  {pix.width()}x{pix.height()}")
    else:
        print(f"FAILED to save {path}")


def select_layer(window: MainWindow, prefix: str) -> None:
    tree = window.detail_tree
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item.text(0).startswith(prefix):
            tree.setCurrentItem(item)
            tree.scrollToItem(item, tree.PositionAtCenter)
            return


def select_http_layer(window: MainWindow) -> None:
    select_layer(window, "Hypertext")


def main() -> int:
    app = QApplication([])
    window = MainWindow()
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.resize(1800, 1050)
    window.show()
    pump(app, 0.6)
    window.load_pcap_sync(str(SAMPLES_DIR / "demo.pcap"))
    pump(app, 0.4)

    # 01 main window with an HTTP packet selected
    for row in range(window.model.rowCount()):
        packet = window.model.packet_at(row)
        if packet is not None and packet.protocol == "HTTP" and "GET /index.html" in packet.info:
            window.packet_table.selectRow(row)
            break
    pump(app, 0.2)
    select_http_layer(window)
    pump(app, 0.3)
    save(window, "01_main_http.png")

    # 02 display filter
    window.set_filter("dns")
    window.packet_table.selectRow(0)
    pump(app, 0.2)
    select_layer(window, "Domain Name")
    pump(app, 0.3)
    save(window, "02_filter_dns.png")

    # 03 invalid filter feedback
    window.filter_edit.setText("tcp.port ==")
    window._apply_filter_from_edit()
    pump(app, 0.3)
    save(window, "03_filter_error.png")
    window._clear_filter()
    pump(app, 0.2)

    # 04/05 TCP stream dialog
    snapshot = window.tracker.snapshot(1)
    if snapshot is not None:
        dialog = TcpStreamDialog(snapshot, window)
        dialog.setAttribute(Qt.WA_DontShowOnScreen, True)
        dialog.show()
        pump(app, 0.4)
        save(dialog, "04_stream_sequence.png")
        dialog.tabs.setCurrentIndex(5)
        pump(app, 0.3)
        save(dialog, "05_stream_http.png")
        dialog.close()

    # 06/07/08 statistics
    stats = StatsDialog(window.model.all_packets(), window)
    stats.setAttribute(Qt.WA_DontShowOnScreen, True)
    stats.show()
    pump(app, 0.4)
    save(stats, "06_stats_hierarchy.png")
    stats._tabs.setCurrentIndex(1)
    stats._conv_tabs.setCurrentIndex(2)
    pump(app, 0.4)
    save(stats, "07_stats_conversations.png")
    stats._tabs.setCurrentIndex(2)
    pump(app, 0.3)
    save(stats, "08_stats_throughput.png")
    stats.close()

    # 09 filter help
    help_dialog = FilterHelpDialog(window, "")
    help_dialog.setAttribute(Qt.WA_DontShowOnScreen, True)
    help_dialog.show()
    pump(app, 0.4)
    save(help_dialog, "09_filter_help.png")
    help_dialog.close()

    # 10 capture options
    capture = CaptureOptionsDialog(window.config, window, window.devices)
    capture.setAttribute(Qt.WA_DontShowOnScreen, True)
    capture.show()
    pump(app, 0.3)
    save(capture, "10_capture_options.png")
    capture.close()

    window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
