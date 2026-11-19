#!/usr/bin/env python3
"""Record a short demo video of the GUI and encode it with ffmpeg.

The GUI is rendered with ``WA_DontShowOnScreen`` (no window flashes), driven
through a scripted offline/live session, and each frame is annotated with a
Chinese caption.  ffmpeg is only used for encoding; pass ``--ffmpeg`` if it is
not on PATH.

    python tools/make_video.py --ffmpeg "C:\\path\\to\\ffmpeg.exe"

Output: 李柏谚_202649210129022_ex1A_play.mp4 in the submission folder.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SUBMIT = ROOT.parent
FRAMES = ROOT / "docs" / "video_frames"
NAME = "李柏谚"
STUDENT_ID = "202649210129022"
OUT = SUBMIT / f"{NAME}_{STUDENT_ID}_ex1A_play.mp4"
FONT_BOLD = r"C:\Windows\Fonts\msyhbd.ttc"
FONT_REG = r"C:\Windows\Fonts\msyh.ttc"
WIDTH, HEIGHT = 1600, 900
FPS = 8


def font(size: int, bold: bool = False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REG, size)


def card(title: str, subtitle: str = "", footer: str = "") -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), (18, 22, 30))
    draw = ImageDraw.Draw(image)
    for y in range(HEIGHT):
        shade = int(18 + 18 * y / HEIGHT)
        draw.line((0, y, WIDTH, y), fill=(shade, shade + 4, shade + 12))
    draw.rounded_rectangle((90, 90, WIDTH - 90, HEIGHT - 90), radius=28,
                           outline=(47, 129, 247), width=3)
    draw.text((140, 250), title, font=font(64, True), fill=(240, 246, 255))
    if subtitle:
        draw.text((144, 350), subtitle, font=font(30), fill=(153, 170, 192))
    if footer:
        draw.text((144, HEIGHT - 190), footer, font=font(24), fill=(120, 140, 165))
    return image


def overlay(image: Image.Image, caption: str, step: str = "") -> Image.Image:
    image = image.convert("RGB")
    draw = ImageDraw.Draw(image, "RGBA")
    bar_height = 92
    draw.rectangle((0, HEIGHT - bar_height, WIDTH, HEIGHT), fill=(8, 12, 18, 220))
    draw.rectangle((0, HEIGHT - bar_height, WIDTH, HEIGHT - bar_height + 3), fill=(47, 129, 247, 255))
    draw.text((34, HEIGHT - bar_height + 18), "NetSniffer 1A", font=font(22, True), fill=(77, 159, 255))
    draw.text((34, HEIGHT - bar_height + 50), caption, font=font(24), fill=(235, 241, 250))
    if step:
        text_width = draw.textlength(step, font=font(20))
        draw.text((WIDTH - 40 - text_width, HEIGHT - bar_height + 28), step,
                  font=font(20, True), fill=(63, 185, 80))
    return image


class Recorder:
    def __init__(self, app, window, out_dir: Path):
        self.app = app
        self.window = window
        self.out_dir = out_dir
        self.index = 0
        self.frame_paths = []
        self.out_dir.mkdir(parents=True, exist_ok=True)
        for old in self.out_dir.glob("frame_*.png"):
            old.unlink()

    def pump(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.008)

    def frame(self, image: Image.Image, caption: str = "", step: str = "") -> None:
        self.index += 1
        path = self.out_dir / f"frame_{self.index:05d}.png"
        if caption:
            image = overlay(image, caption, step)
        else:
            image = image.convert("RGB")
        image.save(path)
        self.frame_paths.append(path)

    def hold(self, seconds: float, caption: str = "", step: str = "") -> None:
        count = max(1, int(round(seconds * FPS)))
        for _ in range(count):
            pix = self.window.grab()
            tmp = self.out_dir / "_grab.png"
            pix.save(str(tmp))
            image = Image.open(tmp)
            image.load()
            self.frame(image, caption, step)
        try:
            (self.out_dir / "_grab.png").unlink()
        except OSError:
            pass

    def static(self, image: Image.Image, seconds: float) -> None:
        for _ in range(max(1, int(round(seconds * FPS)))):
            self.frame(image)


def select_http_layer(window) -> None:
    tree = window.detail_tree
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        if item.text(0).startswith("Hypertext"):
            tree.setCurrentItem(item)
            tree.scrollToItem(item, tree.PositionAtCenter)
            return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", default=os.environ.get("FFMPEG", "ffmpeg"))
    parser.add_argument("--keep-frames", action="store_true")
    parser.add_argument("--skip-live", action="store_true")
    args = parser.parse_args()

    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QApplication, QMessageBox

    from netsniff.config import SAMPLES_DIR
    from netsniff.capture.npcap import Device
    from netsniff.ui.main_window import MainWindow
    from netsniff.ui.stats_dialog import StatsDialog
    from netsniff.ui.stream_dialog import TcpStreamDialog

    app = QApplication([])
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
    QMessageBox.information = staticmethod(lambda *a, **k: QMessageBox.Ok)
    QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.Ok)
    QMessageBox.critical = staticmethod(
        lambda *a, **k: print("CRITICAL:", a[1] if len(a) > 1 else a, flush=True)
    )
    window = MainWindow()
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.resize(WIDTH, HEIGHT)
    window.show()
    recorder = Recorder(app, window, FRAMES)
    recorder.pump(0.8)

    # 1. title
    recorder.static(card("NetSniffer 1A", "带 GUI 的网络嗅探器 · 实验 1A",
                         "Python 3 + PyQt5 + Npcap/libpcap · 54 个单元测试"), 2.6)

    # 2. offline demo
    window.load_pcap_sync(str(SAMPLES_DIR / "demo.pcap"))
    recorder.pump(0.2)
    recorder.hold(1.6, "加载示例 pcap：三窗格 + 协议详情 + Hex/ASCII", "1/6  总览")
    window.packet_table.selectRow(7)
    recorder.pump(0.2)
    select_http_layer(window)
    recorder.hold(1.8, "选中 HTTP GET：协议树字段联动字节高亮", "2/6  协议解析")

    # 3. filters
    window.set_filter("dns")
    window.packet_table.selectRow(0)
    recorder.pump(0.2)
    recorder.hold(1.6, "显示过滤器 dns：2/40，支持 and/or/not", "3/6  过滤")
    window.set_filter("http")
    recorder.pump(0.2)
    recorder.hold(1.4, "显示过滤器 http：逻辑演算与字段别名", "3/6  过滤")
    window._clear_filter()
    recorder.pump(0.2)

    # 4. stream dialog
    snapshot = window.tracker.snapshot(1)
    if snapshot is not None:
        dialog = TcpStreamDialog(snapshot, window)
        dialog.setAttribute(Qt.WA_DontShowOnScreen, True)
        dialog.show()
        recorder.pump(0.2)
        for _ in range(18):
            recorder.frame(_grab_pil(dialog), "TCP 流时序图：SYN / 数据 / FIN 一目了然", "4/6  流追踪")
        dialog.tabs.setCurrentIndex(5)
        recorder.pump(0.2)
        for _ in range(16):
            recorder.frame(_grab_pil(dialog), "HTTP 事务：请求头、响应头与 body 还原", "4/6  流追踪")
        dialog.close()
        recorder.pump(0.2)

    # 5. statistics
    stats = StatsDialog(window.model.all_packets(), window)
    stats.setAttribute(Qt.WA_DontShowOnScreen, True)
    stats.show()
    recorder.pump(0.2)
    for _ in range(14):
        recorder.frame(_grab_pil(stats), "协议分层统计：包数 / 字节 / 占比", "5/6  统计")
    stats._tabs.setCurrentIndex(1)
    stats._conv_tabs.setCurrentIndex(2)
    recorder.pump(0.2)
    for _ in range(14):
        recorder.frame(_grab_pil(stats), "TCP 会话：双向字节、时长、双击过滤", "5/6  统计")
    stats._tabs.setCurrentIndex(2)
    recorder.pump(0.2)
    for _ in range(12):
        recorder.frame(_grab_pil(stats), "吞吐量曲线：包/秒与字节/秒", "5/6  统计")
    stats.close()
    recorder.pump(0.2)

    # 6. live capture
    server = None
    if args.skip_live:
        print("skip live", flush=True)
    else:
        print("starting live capture", flush=True)
        server = subprocess.Popen(
            [sys.executable, "-m", "http.server", "8000", "--bind", "127.0.0.1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)
        window.clear_session(ask=False)
        window._init_backend()
        recorder.pump(0.4)
        loopback = next((device for device in window.devices if device.is_loopback), None)
        if loopback is not None:
            for index in range(window.device_combo.count()):
                device = window.device_combo.itemData(index)
                if isinstance(device, Device) and device.name == loopback.name:
                    window.device_combo.setCurrentIndex(index)
                    break
            window.bpf_edit.setText("tcp port 8000")
            window._on_bpf_changed()

            def traffic():
                time.sleep(1.0)
                for _ in range(10):
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=4) as response:
                            response.read(32)
                    except Exception:
                        pass
                    time.sleep(0.22)

            threading.Thread(target=traffic, daemon=True).start()
            window.start_capture()
            recorder.pump(1.0)
            print("live mode:", window.mode, "worker:", window.worker is not None,
                  "npcap:", window._npcap_ok, flush=True)
            if window.worker is not None and window.mode == "live":
                for _ in range(56):
                    image = _grab_pil(window)
                    recorder.frame(image, "实时回环抓包：BPF tcp port 8000，包列表实时刷新", "6/6  实时抓包")
                    app.processEvents()
                    time.sleep(0.02)
                window.stop_capture()
                recorder.pump(0.6)
                for row in range(window.model.rowCount()):
                    packet = window.model.packet_at(row)
                    if packet is not None and packet.protocol == "HTTP":
                        window.packet_table.selectRow(row)
                        break
                recorder.pump(0.2)
                select_http_layer(window)
                recorder.hold(2.2, "Process 列与 TCP 流 Dock：10 条流全部归属 python.exe", "6/6  进程归属")
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except Exception:
                server.kill()
    window.close()

    # 7. closing
    recorder.static(card("实验 1A 完成", "实时抓包 · 协议解析 · 逻辑过滤 · 流追踪 · 进程归属",
                         f"{NAME} {STUDENT_ID} · 《软件与系统安全》"), 2.4)

    print(f"recorded {recorder.index} frames")
    command = [
        args.ffmpeg, "-y", "-framerate", str(FPS),
        "-i", str(FRAMES / "frame_%05d.png"),
        "-c:v", "h264_nvenc", "-pix_fmt", "yuv420p",
        "-preset", "p4", "-cq", "20", "-movflags", "+faststart",
        "-r", str(FPS), str(OUT),
    ]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        # fall back to the software MPEG-4 encoder if NVENC is unavailable
        fallback = [
            args.ffmpeg, "-y", "-framerate", str(FPS),
            "-i", str(FRAMES / "frame_%05d.png"),
            "-c:v", "mpeg4", "-q:v", "3", "-pix_fmt", "yuv420p",
            "-movflags", "+faststart", "-r", str(FPS), str(OUT),
        ]
        result = subprocess.run(fallback, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        print(result.stderr[-2000:])
        return 1
    print("wrote", OUT, OUT.stat().st_size, "bytes")
    if not args.keep_frames:
        shutil.rmtree(FRAMES, ignore_errors=True)
    return 0


def _grab_pil(widget) -> Image.Image:
    path = FRAMES / "_dialog.png"
    widget.grab().save(str(path))
    image = Image.open(path)
    image.load()
    return image


if __name__ == "__main__":
    raise SystemExit(main())
