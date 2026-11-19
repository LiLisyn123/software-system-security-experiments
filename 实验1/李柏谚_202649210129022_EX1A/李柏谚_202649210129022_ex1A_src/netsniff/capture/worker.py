"""Background capture and file-loading threads.

Both workers dissect packets and feed the :class:`StreamTracker` in the
worker thread, then hand already-parsed ``Packet`` objects to the GUI through
a bounded queue.  Keeping parsing off the GUI thread is what makes the
window stay responsive while several thousand packets per second arrive.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from PyQt5.QtCore import QThread, pyqtSignal

from ..analysis.streams import StreamTracker
from ..dissect import dissect_packet
from .npcap import CaptureEOF, NpcapError, get_npcap
from .pcapfile import PcapFormatError, iter_pcap


@dataclass
class CaptureConfig:
    device: str = ""
    description: str = ""
    snaplen: int = 65535
    promisc: bool = True
    timeout_ms: int = 100
    buffer_mb: int = 32
    immediate: bool = False
    bpf: str = ""


class _BatchWorker(QThread):
    failed = pyqtSignal(str)
    opened = pyqtSignal(int)          # linktype
    batch_ready = pyqtSignal()        # wake the GUI (optional; queue is polled)
    progress = pyqtSignal(int)        # packets parsed so far
    finished_ok = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.queue: "queue.Queue[List]" = queue.Queue(maxsize=256)
        self.tracker = StreamTracker()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.linktype = 1
        self.packet_count = 0
        self.app_dropped = 0
        self.read_error = ""
        self._last_emit = 0.0

    # -- common -----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()
        self._break()

    def is_stopping(self) -> bool:
        return self._stop.is_set()

    def _break(self) -> None:
        pass

    def _flush(self, batch: List) -> None:
        if not batch:
            return
        try:
            self.queue.put_nowait(batch)
        except queue.Full:
            # Drop the oldest batch so the display follows the newest traffic.
            try:
                dropped = self.queue.get_nowait()
                self.app_dropped += len(dropped)
            except queue.Empty:
                pass
            try:
                self.queue.put_nowait(batch)
            except queue.Full:
                self.app_dropped += len(batch)

    def drain(self) -> List:
        packets: List = []
        while True:
            try:
                packets.extend(self.queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def clear_queue(self) -> None:
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                return


class CaptureWorker(_BatchWorker):
    """Live capture from an Npcap device."""

    stats_ready = pyqtSignal(int, int, int)  # received, dropped, if_dropped

    def __init__(self, config: CaptureConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self._handle = None
        self._driver_stats = (0, 0, 0)
        self.device_name = config.device
        self.datalink = 0
        self.started_at = 0.0

    def _break(self) -> None:
        handle = self._handle
        if handle is not None:
            handle.breakloop()

    def run(self) -> None:
        batch: List = []
        handle = None
        try:
            npcap = get_npcap()
            handle = npcap.open(
                self.config.device,
                snaplen=self.config.snaplen,
                promisc=self.config.promisc,
                timeout_ms=self.config.timeout_ms,
                buffer_mb=self.config.buffer_mb,
                immediate=self.config.immediate,
            )
            self._handle = handle
            self.linktype = handle.datalink
            self.datalink = handle.datalink
            if self.config.bpf.strip():
                handle.set_filter(self.config.bpf.strip())
            if self._stop.is_set():
                handle.close()
                return
            self.started_at = time.time()
            self.opened.emit(self.linktype)
        except Exception as exc:
            self.read_error = str(exc)
            self.failed.emit(str(exc))
            if handle is not None:
                handle.close()
            return

        last_flush = time.monotonic()
        last_stats = 0.0
        try:
            while not self._stop.is_set():
                try:
                    captured = handle.next_packet()
                except CaptureEOF:
                    break
                if captured is not None:
                    self.packet_count += 1
                    packet = dissect_packet(
                        captured.data,
                        self.packet_count,
                        captured.ts,
                        captured.wirelen,
                        self.linktype,
                    )
                    self.tracker.process(packet)
                    batch.append(packet)
                    now = time.monotonic()
                    if len(batch) >= 64 or now - last_flush >= 0.05:
                        self._flush(batch)
                        batch = []
                        last_flush = now
                now = time.monotonic()
                if now - last_stats >= 1.0:
                    try:
                        self._driver_stats = handle.stats()
                        self.stats_ready.emit(*self._driver_stats)
                    except Exception:
                        pass
                    last_stats = now
                if now - self._last_emit >= 0.5:
                    self.progress.emit(self.packet_count)
                    self._last_emit = now
        except Exception as exc:
            self.read_error = str(exc)
            self.failed.emit(str(exc))
        finally:
            self._flush(batch)
            try:
                self._driver_stats = handle.stats()
            except Exception:
                pass
            handle.close()
            self._handle = None
            self.finished_ok.emit(self.packet_count)

    def snapshot_stats(self):
        return self._driver_stats


class PcapFileWorker(_BatchWorker):
    """Load a pcap/pcapng file without blocking the GUI."""

    def __init__(self, path: str | Path, parent=None):
        super().__init__(parent)
        self.path = str(path)
        self.filename = Path(path).name
        self.total = 0

    def run(self) -> None:
        batch: List = []
        count = 0
        try:
            try:
                total = _count_records(self.path)
                self.total = total
                first = True
                for header, record in iter_pcap(self.path):
                    if first:
                        self.linktype = header.linktype
                        self.opened.emit(self.linktype)
                        first = False
                    if self._stop.is_set():
                        break
                    count += 1
                    packet = dissect_packet(
                        record.data, count, record.ts, record.wirelen, header.linktype
                    )
                    self.tracker.process(packet)
                    batch.append(packet)
                    if len(batch) >= 128:
                        self._flush(batch)
                        batch = []
                        self.progress.emit(count)
                if first:
                    self.failed.emit("pcap 文件中没有数据包")
                    return
            except PcapFormatError:
                # pcapng or an unusual variant: let Npcap open it offline.
                count = self._load_via_npcap(batch, count)
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self._flush(batch)
            self.packet_count = count
            self.finished_ok.emit(count)

    def _load_via_npcap(self, batch: List, count: int) -> int:
        npcap = get_npcap()
        handle = npcap.open_offline(self.path)
        try:
            self.linktype = handle.datalink
            self.opened.emit(self.linktype)
            while not self._stop.is_set():
                try:
                    captured = handle.next_packet()
                except CaptureEOF:
                    break
                if captured is None:
                    continue
                count += 1
                packet = dissect_packet(
                    captured.data, count, captured.ts, captured.wirelen, self.linktype
                )
                self.tracker.process(packet)
                batch.append(packet)
                if len(batch) >= 128:
                    self._flush(batch)
                    batch = []
                    self.progress.emit(count)
        finally:
            handle.close()
        return count


def _count_records(path: str) -> int:
    """Cheap record count for the progress display."""
    import struct

    from .pcapfile import MAX_RECORD, read_header

    count = 0
    try:
        with open(path, "rb") as fh:
            header = read_header(fh)
            while True:
                raw = fh.read(16)
                if len(raw) != 16:
                    break
                incl_len = struct.unpack(header.endian + "IIII", raw)[2]
                if incl_len > MAX_RECORD:
                    break
                fh.seek(incl_len, 1)
                count += 1
    except (OSError, PcapFormatError):
        return 0
    return count
