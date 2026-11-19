#!/usr/bin/env python3
"""Generate the application icon (ICO/PNG) used by PyInstaller and shortcuts."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((8, 8, size - 8, size - 8), radius=54, fill=(31, 111, 235, 255))
    # wave
    points = []
    for i in range(0, 201):
        t = i / 200
        x = 44 + t * 168
        y = 150 - (40 * (0.5 + 0.5 * __import__("math").sin(t * 6.28 * 1.3 + 0.4)))
        points.append((x, y))
    draw.line(points, fill=(255, 255, 255, 255), width=16, joint="curve")
    draw.ellipse((42, 170, 66, 194), fill=(126, 231, 135, 255))
    img.save(OUT / "netsniffer.png")
    img.save(OUT / "netsniffer.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("saved", OUT / "netsniffer.ico")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
