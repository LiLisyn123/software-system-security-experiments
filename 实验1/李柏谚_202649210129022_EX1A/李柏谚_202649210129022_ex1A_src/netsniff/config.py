"""Application constants and Npcap discovery helpers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

APP_NAME = "NetSniffer 1A"
APP_VERSION = "1.0.0"
ORG_NAME = "UCAS-SSS"

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
DOCS_DIR = ROOT / "docs"
CONFIG_FILE = ROOT / "config.json"

IS_WINDOWS = sys.platform.startswith("win")

NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


def _candidate_paths() -> list[Path]:
    env = os.environ.get("NETSNIFF_WPCAP") or os.environ.get("NPCAP_DLL")
    paths: list[Path] = []
    if env:
        paths.append(Path(env))

    try:
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            configured = data.get("wpcap_path")
            if configured:
                paths.append(Path(configured))
    except (OSError, ValueError):
        pass

    if IS_WINDOWS:
        windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        paths += [
            windir / "System32" / "Npcap" / "wpcap.dll",
            windir / "System32" / "wpcap.dll",
            windir / "SysWOW64" / "Npcap" / "wpcap.dll",
            windir / "SysWOW64" / "wpcap.dll",
            program_files / "Npcap" / "wpcap.dll",
            program_files_x86 / "Npcap" / "wpcap.dll",
        ]

        # Npcap stores its installation directory in the registry.  The
        # installer is 32-bit, so on 64-bit Windows the key lives under
        # WOW6432Node even when the driver is 64-bit.
        try:
            import winreg

            for hive, key_name in (
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
            ):
                try:
                    with winreg.OpenKey(hive, key_name) as key:
                        install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                        paths.append(Path(install_dir) / "wpcap.dll")
                except OSError:
                    continue
        except ImportError:
            pass

    # A copy shipped next to the application is handy for portable use.
    paths += [ROOT / "vendor" / "wpcap.dll", ROOT / "wpcap.dll"]
    return paths


def find_wpcap() -> Path | None:
    """Return the first existing wpcap.dll, or ``None``."""
    seen: set[str] = set()
    for path in _candidate_paths():
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        path = Path(base) / "NetSniffer1A"
    else:
        path = Path.home() / ".netsniffer1a"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = Path.cwd()
    return path
