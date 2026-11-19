#!/usr/bin/env python3
"""Live demo: capture real loopback HTTP traffic and save a screenshot.

This starts ``python -m http.server`` on 127.0.0.1:8000, captures the loopback
adapter through Npcap with the BPF filter ``tcp port 8000``, generates a few
requests, then stops and writes ``docs/screenshots/11_live_process.png``.

Requires Npcap.  Run from the source directory:

    python tools/live_demo.py
    python tools/live_demo.py --seconds 8 --save-pcap samples/live_loopback.pcap
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402

from netsniff.capture.npcap import Device  # noqa: E402
from netsniff.capture.pcapfile import write_pcap  # noqa: E402
from netsniff.ui.main_window import MainWindow  # noqa: E402


def pump(app: QApplication, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.015)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=7.0)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--save-pcap", default="")
    parser.add_argument("--no-screenshot", action="store_true")
    args = parser.parse_args()

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(args.port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    app = QApplication([])
    window = MainWindow()
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.resize(1800, 1050)
    window.show()
    pump(app, 1.0)
    if not window._npcap_ok:
        print("Npcap unavailable:", window._npcap_detail)
        server.terminate()
        return 2
    loopback = next((d for d in window.devices if d.is_loopback), None)
    if loopback is None:
        print("no loopback device found")
        server.terminate()
        return 3
    for index in range(window.device_combo.count()):
        device = window.device_combo.itemData(index)
        if isinstance(device, Device) and device.name == loopback.name:
            window.device_combo.setCurrentIndex(index)
            break
    window.bpf_edit.setText(f"tcp port {args.port}")

    def traffic() -> None:
        time.sleep(1.2)
        for _ in range(10):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{args.port}/", timeout=5) as response:
                    response.read(64)
            except Exception as exc:  # pragma: no cover - demo only
                print("request failed:", exc)
            time.sleep(0.25)

    try:
        threading.Thread(target=traffic, daemon=True).start()
        window.start_capture()
        pump(app, args.seconds)
        window.stop_capture()
        pump(app, 1.0)
        print(f"captured {window.model.total_count} packets, "
              f"{len(window.tracker.infos())} streams, processes: "
              f"{ {pid: value[0] for pid, value in window.process_stats.items()} }")
        if args.save_pcap:
            path = Path(args.save_pcap)
            if not path.is_absolute():
                path = ROOT / path
            path.parent.mkdir(parents=True, exist_ok=True)
            write_pcap(path, window.model.all_packets(), window.linktype)
            print("saved", path)
        if not args.no_screenshot and window.model.total_count:
            for row in range(window.model.rowCount()):
                packet = window.model.packet_at(row)
                if packet is not None and packet.protocol == "HTTP":
                    window.packet_table.selectRow(row)
                    break
            pump(app, 0.2)
            tree = window.detail_tree
            for index in range(tree.topLevelItemCount()):
                item = tree.topLevelItem(index)
                if item.text(0).startswith("Hypertext"):
                    tree.setCurrentItem(item)
                    tree.scrollToItem(item, tree.PositionAtCenter)
                    break
            pump(app, 0.3)
            out = ROOT / "docs" / "screenshots" / "11_live_process.png"
            out.parent.mkdir(parents=True, exist_ok=True)
            window.grab().save(str(out))
            print("saved", out)
    finally:
        try:
            window.close()
        except Exception:
            pass
        server.terminate()
        try:
            server.wait(timeout=3)
        except Exception:
            server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
