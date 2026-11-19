#!/usr/bin/env python3
"""Generate architecture / pipeline / filter-AST diagrams for the report."""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "diagrams"
FONT_REG = r"C:\Windows\Fonts\msyh.ttc"
FONT_BOLD = r"C:\Windows\Fonts\msyhbd.ttc"

TEXT = "#1f2328"
MUTED = "#57606a"
BLUE = "#2f81f7"
BLUE_FILL = "#eaf2ff"
GREEN = "#2da44e"
GREEN_FILL = "#eaf7ee"
ORANGE = "#bf8700"
ORANGE_FILL = "#fff6e0"
PURPLE = "#8250df"
PURPLE_FILL = "#f3ecff"
BORDER = "#d0d7de"


def font(size: int, bold: bool = False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REG, size)


def box(draw, xy, title: str, lines: list[str], fill: str, border: str,
        title_color: str = TEXT, body_color: str = MUTED, title_size: int = 26,
        body_size: int = 21, radius: int = 16):
    x, y, w, h = xy
    draw.rounded_rectangle((x, y, x + w, y + h), radius=radius, fill=fill,
                           outline=border, width=3)
    draw.text((x + 22, y + 18), title, font=font(title_size, True), fill=title_color)
    cursor = y + 18 + title_size + 16
    for line in lines:
        if cursor + body_size > y + h - 12:
            break
        draw.text((x + 22, cursor), line, font=font(body_size), fill=body_color)
        cursor += body_size + 8


def _head(draw, p1, p2, color, length=17, spread=0.42):
    x1, y1 = p1
    x2, y2 = p2
    angle = math.atan2(y2 - y1, x2 - x1)
    a = (x2 - length * math.cos(angle - spread), y2 - length * math.sin(angle - spread))
    b = (x2 - length * math.cos(angle + spread), y2 - length * math.sin(angle + spread))
    draw.polygon([(x2, y2), a, b], fill=color)


def arrow(draw, start, end, color=BLUE, width=4, label: str = "", offset=(0, 0)):
    draw.line((start[0], start[1], end[0], end[1]), fill=color, width=width)
    _head(draw, start, end, color)
    if label:
        fnt = font(18)
        mx = (start[0] + end[0]) / 2 + offset[0]
        my = (start[1] + end[1]) / 2 + offset[1]
        w = draw.textlength(label, font=fnt)
        draw.rounded_rectangle((mx - w / 2 - 8, my - 14, mx + w / 2 + 8, my + 14),
                               radius=8, fill="#ffffff")
        draw.text((mx - w / 2, my - 12), label, font=fnt, fill=MUTED)


def arrow_path(draw, points, color=BLUE, width=4, label: str = "", label_pos=None):
    draw.line(points, fill=color, width=width, joint="curve")
    _head(draw, points[-2], points[-1], color)
    if label:
        fnt = font(18)
        lx, ly = label_pos or points[0]
        w = draw.textlength(label, font=fnt)
        draw.rounded_rectangle((lx - w / 2 - 8, ly - 14, lx + w / 2 + 8, ly + 14),
                               radius=8, fill="#ffffff")
        draw.text((lx - w / 2, ly - 12), label, font=fnt, fill=MUTED)


def title(draw, text: str, subtitle: str = ""):
    draw.text((60, 36), text, font=font(44, True), fill=TEXT)
    if subtitle:
        draw.text((62, 92), subtitle, font=font(22), fill=MUTED)


def architecture() -> None:
    img = Image.new("RGB", (1680, 1040), "#ffffff")
    d = ImageDraw.Draw(img)
    title(d, "NetSniffer 1A 总体架构",
          "PyQt5 三窗格 GUI + Npcap/libpcap 抓包 + 自研协议解析/流追踪")

    box(d, (60, 140, 1560, 150), "GUI 层（Qt 主线程）",
        ["MainWindow · 显示过滤器栏 · 三窗格（数据包列表 / 协议详情 / Hex+ASCII）",
         "PacketListModel · 流与进程 Dock · TCP 时序图 · 统计/吞吐图 · pcap 保存与 CSV 导出"],
        BLUE_FILL, BLUE, title_color=BLUE)
    box(d, (60, 370, 740, 190), "CaptureWorker（QThread）",
        ["来源：Npcap npf.sys + wpcap.dll（内核 BPF）",
         "pcap_create / pcap_activate → pcap_next_ex → dissect_packet",
         "StreamTracker.process → 每 64 包/50ms 批量入队",
         "驱动统计 pcap_stats（接收/丢弃）"],
        GREEN_FILL, GREEN, title_color=GREEN, body_size=20)
    box(d, (860, 370, 760, 190), "PcapFileWorker（QThread）",
        ["来源：pcap / pcapng 文件",
         "经典 pcap 纯 Python 解析；pcapng 回退 pcap_open_offline",
         "逐包解析、进度上报、可取消",
         "加载完成/失败信号"],
        GREEN_FILL, GREEN, title_color=GREEN, body_size=20)
    box(d, (60, 630, 1560, 150), "协议解析层（dissect）",
        ["Ethernet/VLAN/ARP · IPv4/IPv6（含扩展头/分片） · TCP/UDP/ICMP/ICMPv6",
         "HTTP · DNS · TLS（SNI/ALPN/版本） · DHCP · NTP · QUIC · SSH/FTP/SMTP/MQTT/Redis",
         "Packet / Field / Layer 模型：字段键、值、offset/length、子字段；校验和与专家信息"],
        PURPLE_FILL, PURPLE, title_color=PURPLE, body_size=20)
    box(d, (60, 830, 1560, 150), "分析层（analysis）",
        ["StreamTracker：TCP 四元组、方向判定、序列号重组（乱序/重传/缺口）、连接状态机",
         "ProcessTable：GetExtendedTcpTable（IPv4/IPv6，TCP/UDP）→ PID → QueryFullProcessImageNameW",
         "stats：协议分层、会话/端点、吞吐量序列；GUI 通过 QTimer 读取（内部 RLock）"],
        PURPLE_FILL, PURPLE, title_color=PURPLE, body_size=20)

    arrow(d, (300, 370), (300, 290), ORANGE, 4, "批次队列", offset=(70, -2))
    arrow(d, (1100, 370), (1100, 290), ORANGE, 4, "批次队列/信号", offset=(108, -2))
    arrow(d, (400, 560), (400, 630), GREEN, 4, "Packet", offset=(54, -2))
    arrow(d, (1200, 560), (820, 630), GREEN, 4, "Packet", offset=(36, 0))
    arrow(d, (400, 780), (400, 830), PURPLE, 4, "流/进程", offset=(62, -2))

    d.text((60, 1000),
           "注：解析在 QThread 中完成，GUI 只做模型插入、绘制和交互；"
           "StreamTracker 自带锁，统计/流对话框读取的是快照。",
           font=font(19), fill=MUTED)
    img.save(OUT / "architecture.png")
    print("saved architecture.png")

def pipeline() -> None:
    img = Image.new("RGB", (1680, 560), "#ffffff")
    d = ImageDraw.Draw(img)
    title(d, "数据包处理流水线", "从内核 BPF 到 GUI 三窗格；批量、异步、可丢批但可观测")
    boxes = [
        ("网卡 / Npcap", ["内核缓冲", "BPF 过滤"], ORANGE_FILL, ORANGE),
        ("pcap_next_ex", ["批量读取", "100ms 超时"], GREEN_FILL, GREEN),
        ("dissect_packet", ["协议解析", "校验和/专家"], PURPLE_FILL, PURPLE),
        ("StreamTracker", ["四元组", "序列号重组"], PURPLE_FILL, PURPLE),
        ("有界队列", ["256 批", "应用层丢包计数"], ORANGE_FILL, ORANGE),
        ("PacketListModel", ["批量插入", "过滤/着色"], BLUE_FILL, BLUE),
        ("三窗格 + 时序图", ["详情/字节联动", "统计/进程"], BLUE_FILL, BLUE),
    ]
    x, y, width, gap = 50, 190, 210, 24
    for index, (name, lines, fill, border) in enumerate(boxes):
        box(d, (x, y, width, 210), name, lines, fill, border, title_size=20, body_size=17)
        if index < len(boxes) - 1:
            arrow(d, (x + width + 3, y + 105), (x + width + gap - 3, y + 105), border, 4)
        x += width + gap
    d.rounded_rectangle((40, 440, 900, 500), radius=12, fill="#f6f8fa", outline=BORDER, width=2)
    d.text((60, 454), "工作线程：抓包/解析/流追踪/入队（CPU 密集）", font=font(20, True), fill=TEXT)
    d.rounded_rectangle((930, 440, 1630, 500), radius=12, fill="#f6f8fa", outline=BORDER, width=2)
    d.text((950, 454), "GUI 线程：100ms 定时 drain + 批量插入 + 绘制", font=font(20, True), fill=TEXT)
    d.text((50, 520),
           "关键设计：BPF 先在内核过滤；解析在 QThread；每 64 包或 50ms 成批入队；GUI 端每次 drain 全部批次。",
           font=font(19), fill=MUTED)
    img.save(OUT / "pipeline.png")
    print("saved pipeline.png")


def filter_ast() -> None:
    img = Image.new("RGB", (1600, 780), "#ffffff")
    d = ImageDraw.Draw(img)
    title(d, "显示过滤器的编译与求值", "表达式 → 词法/语法分析 → AST → 闭包谓词 → 逐包求值")
    stages = [
        ("表达式", ["http and not", "tcp.port == 443"], BLUE_FILL, BLUE),
        ("词法分析", ["IDENT/AND/NOT", "OP/NUMBER/STRING"], GREEN_FILL, GREEN),
        ("语法分析", ["递归下降", "not > and > or"], GREEN_FILL, GREEN),
        ("AST", ["AND", "├─ http", "└─ NOT(==)"], PURPLE_FILL, PURPLE),
        ("闭包", ["lambda pkt:", "  bool(...)"], PURPLE_FILL, PURPLE),
        ("过滤结果", ["逐包 True/False", "模型重建 visible"], ORANGE_FILL, ORANGE),
    ]
    x = 40
    for index, (name, lines, fill, border) in enumerate(stages):
        box(d, (x, 190, 220, 190), name, lines, fill, border, title_size=22, body_size=18)
        if index < len(stages) - 1:
            arrow(d, (x + 223, 285), (x + 260, 285), border, 4)
        x += 260

    d.rounded_rectangle((60, 430, 760, 710), radius=14, fill="#fbfcfd", outline=BORDER, width=2)
    d.text((80, 444), "AST 示例", font=font(22, True), fill=TEXT)

    def node(cx, cy, text, color=BLUE, fill=BLUE_FILL):
        w = max(120, int(d.textlength(text, font=font(19, True))) + 34)
        d.rounded_rectangle((cx - w / 2, cy - 24, cx + w / 2, cy + 24), radius=10,
                            fill=fill, outline=color, width=2)
        d.text((cx - d.textlength(text, font=font(19, True)) / 2, cy - 14), text,
               font=font(19, True), fill=color)

    node(410, 500, "AND")
    node(250, 590, "Proto(http)", GREEN, GREEN_FILL)
    node(570, 590, "NOT")
    node(570, 660, "Compare(tcp.port == 443)", PURPLE, PURPLE_FILL)
    d.line((410, 524, 250, 566), fill=MUTED, width=2)
    d.line((410, 524, 570, 566), fill=MUTED, width=2)
    d.line((570, 614, 570, 636), fill=MUTED, width=2)

    d.rounded_rectangle((820, 430, 1540, 710), radius=14, fill="#fbfcfd", outline=BORDER, width=2)
    d.text((840, 444), "字段别名与类型", font=font(22, True), fill=TEXT)
    rows = [
        ("tcp.port", "→ tcp.srcport, tcp.dstport"),
        ("ip.addr", "→ ip.src, ip.dst, ipv6.src, ipv6.dst"),
        ("ip.addr == 10.0.0.0/8", "CIDR 成员判断"),
        ("contains / matches", "子串 / 正则"),
        ("== / !=", "别名任一匹配 / 全部不匹配"),
    ]
    yy = 500
    for left, right in rows:
        d.text((840, yy), left, font=font(19, True), fill=BLUE)
        d.text((1070, yy), right, font=font(19), fill=MUTED)
        yy += 38
    d.text((60, 740),
           "该设计使过滤器在捕获过程中只需对每个数据包调用一次闭包，避免重复解析表达式。",
           font=font(18), fill=MUTED)
    img.save(OUT / "filter_ast.png")
    print("saved filter_ast.png")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    architecture()
    pipeline()
    filter_ast()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
