#!/usr/bin/env python3
"""Build the Word report for experiment 1A.

Run with the bundled Python (python-docx is available there):

    python tools/make_report.py

The script writes ``李柏谚_202649210129022_ex1A_report.docx`` into the
submission folder next to the source directory.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
SUBMIT = ROOT.parent
SHOTS = ROOT / "docs" / "screenshots"
DIAGRAMS = ROOT / "docs" / "diagrams"

NAME = "李柏谚"
STUDENT_ID = "202649210129022"
GIT_URL = "https://github.com/LiLisyn123/software-system-security-experiments"
REPORT_DATE = "2026 年 11 月"
OUT = SUBMIT / f"{NAME}_{STUDENT_ID}_ex1A_report.docx"

BLUE = RGBColor(0x09, 0x69, 0xDA)
DARK = RGBColor(0x1F, 0x23, 0x28)
MUTED = RGBColor(0x57, 0x60, 0x6A)
CODE_BG = "F6F8FA"
HEADER_BG = "2F81F7"
ALT_BG = "F0F6FF"


# ---------------------------------------------------------------------------
# low level helpers
# ---------------------------------------------------------------------------

def set_run_font(run, name: str = "Microsoft YaHei", size: float = 10.5,
                 bold: bool = False, color: RGBColor | None = None, italic: bool = False):
    run.font.name = name
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if color is not None:
        run.font.color.rgb = color
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:ascii"), name)
    rfonts.set(qn("w:hAnsi"), name)
    rfonts.set(qn("w:eastAsia"), name)


def shade(cell, color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), color)
    tc_pr.append(shading)


def set_cell_margins(cell, top: int = 50, bottom: int = 50, left: int = 80, right: int = 80) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for tag, value in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        node = OxmlElement(f"w:{tag}")
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")
        mar.append(node)
    tc_pr.append(mar)


def add_field(paragraph, instruction: str) -> None:
    run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    fld_sep = OxmlElement("w:fldChar")
    fld_sep.set(qn("w:fldCharType"), "separate")
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    run._r.append(fld_begin)
    run._r.append(instr)
    run._r.append(fld_sep)
    run._r.append(fld_end)


def add_toc_entry(doc, text: str, level: int = 1, page: int | None = None) -> None:
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.tab_stops.add_tab_stop(Cm(16.8), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
    paragraph.paragraph_format.space_after = Pt(1)
    paragraph.paragraph_format.left_indent = Cm(0.6 * (level - 1))
    run = paragraph.add_run(text + "\t" + (str(page) if page else ""))
    set_run_font(run, size=10 if level == 1 else 9.5, bold=(level == 1))


# ---------------------------------------------------------------------------
# document helpers
# ---------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.doc = Document()
        self.doc.core_properties.title = "实验 1A：带 GUI 的网络嗅探器设计与实现"
        self.doc.core_properties.author = NAME
        self.doc.core_properties.subject = "《软件与系统安全》实验 1A 报告"
        self._setup_page()
        self._setup_styles()

    # -- setup ------------------------------------------------------------
    def _setup_page(self) -> None:
        section = self.doc.sections[0]
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)
        section.top_margin = Cm(2.2)
        section.bottom_margin = Cm(2.0)
        section.left_margin = Cm(2.0)
        section.right_margin = Cm(2.0)
        section.header_distance = Cm(1.2)
        section.footer_distance = Cm(1.0)
        section.different_first_page_header_footer = True

        header = section.header.paragraphs[0]
        header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        run = header.add_run("《软件与系统安全》实验 1A · NetSniffer 1A")
        set_run_font(run, size=8.5, color=MUTED)
        footer = section.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = footer.add_run("第 ")
        set_run_font(run, size=9, color=MUTED)
        add_field(footer, "PAGE")
        run = footer.add_run(" 页 / 共 ")
        set_run_font(run, size=9, color=MUTED)
        add_field(footer, "NUMPAGES")
        run = footer.add_run(" 页")
        set_run_font(run, size=9, color=MUTED)

    def _setup_styles(self) -> None:
        normal = self.doc.styles["Normal"]
        normal.font.name = "Microsoft YaHei"
        normal.font.size = Pt(10.5)
        normal.font.color.rgb = DARK
        normal.paragraph_format.line_spacing = 1.32
        normal.paragraph_format.space_after = Pt(4)
        normal.paragraph_format.space_before = Pt(0)
        rpr = normal.element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            rfonts = OxmlElement("w:rFonts")
            rpr.append(rfonts)
        rfonts.set(qn("w:ascii"), "Microsoft YaHei")
        rfonts.set(qn("w:hAnsi"), "Microsoft YaHei")
        rfonts.set(qn("w:eastAsia"), "Microsoft YaHei")

        specs = {
            "Heading 1": (16, 16, 6),
            "Heading 2": (13, 10, 4),
            "Heading 3": (11.5, 8, 3),
        }
        for name, (size, before, after) in specs.items():
            style = self.doc.styles[name]
            style.font.name = "Microsoft YaHei"
            style.font.size = Pt(size)
            style.font.bold = True
            style.font.color.rgb = BLUE
            style.paragraph_format.space_before = Pt(before)
            style.paragraph_format.space_after = Pt(after)
            style.paragraph_format.keep_with_next = True
            rpr = style.element.get_or_add_rPr()
            rfonts = rpr.find(qn("w:rFonts"))
            if rfonts is None:
                rfonts = OxmlElement("w:rFonts")
                rpr.append(rfonts)
            rfonts.set(qn("w:eastAsia"), "Microsoft YaHei")

    # -- content ----------------------------------------------------------
    def title(self, text: str, size: float = 22, color: RGBColor = BLUE,
              align=WD_ALIGN_PARAGRAPH.LEFT, space_after: float = 8, bold: bool = True):
        p = self.doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_after = Pt(space_after)
        run = p.add_run(text)
        set_run_font(run, size=size, bold=bold, color=color)
        return p

    def h1(self, text: str):
        return self.doc.add_heading(text, level=1)

    def h2(self, text: str):
        return self.doc.add_heading(text, level=2)

    def h3(self, text: str):
        return self.doc.add_heading(text, level=3)

    def para(self, text: str, size: float = 10.5, align=WD_ALIGN_PARAGRAPH.JUSTIFY,
             after: float = 4, first_indent: bool = True, color: RGBColor = DARK):
        p = self.doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_after = Pt(after)
        if first_indent:
            p.paragraph_format.first_line_indent = Cm(0.74)
        self._rich(p, text, size=size, color=color)
        return p

    def _rich(self, p, text: str, size: float = 10.5, color: RGBColor = DARK):
        for token in re.split(r"(\*\*.*?\*\*|`[^`]*`)", text):
            if not token:
                continue
            if token.startswith("**") and token.endswith("**") and len(token) > 4:
                run = p.add_run(token[2:-2])
                set_run_font(run, size=size, bold=True, color=color)
            elif token.startswith("`") and token.endswith("`") and len(token) > 2:
                run = p.add_run(token[1:-1])
                set_run_font(run, "Consolas", size=max(8.0, size - 0.6),
                             color=RGBColor(0x24, 0x29, 0x2F))
            else:
                run = p.add_run(token)
                set_run_font(run, size=size, color=color)

    def bullet(self, text: str, level: int = 0):
        p = self.doc.add_paragraph(style="List Bullet" if level == 0 else "List Bullet 2")
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.left_indent = Cm(0.75 + 0.6 * level)
        self._rich(p, text)
        return p

    def numbered(self, text: str):
        p = self.doc.add_paragraph(style="List Number")
        p.paragraph_format.space_after = Pt(2)
        self._rich(p, text)
        return p

    def code(self, text: str):
        p = self.doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.35)
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.line_spacing = 1.0
        ppr = p._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:fill"), CODE_BG)
        ppr.append(shd)
        lines = text.strip("\n").split("\n")
        for index, line in enumerate(lines):
            run = p.add_run(line if line else " ")
            set_run_font(run, "Consolas", 8.4, color=RGBColor(0x24, 0x29, 0x2F))
            if index < len(lines) - 1:
                run.add_break()
        return p

    def figure(self, filename: Path, caption: str, width: float = 16.2):
        if not filename.is_file():
            self.para(f"[缺少图片：{filename}]", color=RGBColor(0xCF, 0x22, 0x2E))
            return
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run()
        run.add_picture(str(filename), width=Cm(width))
        cap = self.doc.add_paragraph()
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.space_after = Pt(10)
        r = cap.add_run(caption)
        set_run_font(r, size=9, color=MUTED)

    def table(self, headers, rows, widths=None, font_size: float = 8.8,
              header_color: str = HEADER_BG):
        table = self.doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        hdr = table.rows[0]
        for index, text in enumerate(headers):
            cell = hdr.cells[index]
            cell.text = ""
            shade(cell, header_color)
            set_cell_margins(cell)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(text)
            set_run_font(run, size=font_size, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
        for row_index, row in enumerate(rows):
            cells = table.add_row().cells
            for column, text in enumerate(row):
                cell = cells[column]
                cell.text = ""
                set_cell_margins(cell)
                if row_index % 2 == 1:
                    shade(cell, ALT_BG)
                p = cell.paragraphs[0]
                p.paragraph_format.space_after = Pt(0)
                for token in re.split(r"(`[^`]*`)", str(text)):
                    if not token:
                        continue
                    if token.startswith("`") and token.endswith("`") and len(token) > 2:
                        run = p.add_run(token[1:-1])
                        set_run_font(run, "Consolas", size=max(7.6, font_size - 0.4))
                    else:
                        run = p.add_run(token)
                        set_run_font(run, size=font_size)
        if widths:
            for index, width in enumerate(widths):
                table.columns[index].width = Cm(width)
                for cell in table.columns[index].cells:
                    cell.width = Cm(width)
        # keep rows together
        for row in table.rows:
            tr_pr = row._tr.get_or_add_trPr()
            cant = OxmlElement("w:cantSplit")
            tr_pr.append(cant)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return table

    def page_break(self):
        self.doc.add_page_break()

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(path)


# ---------------------------------------------------------------------------
# report body
# ---------------------------------------------------------------------------

def build() -> Path:
    r = Report()
    doc = r.doc

    # ---------------- cover ----------------
    for _ in range(4):
        r.para("", first_indent=False, after=0)
    r.title("《软件与系统安全》", size=17, color=MUTED, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
    r.title("实验报告", size=36, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
    r.title("实验 1A：带 GUI 的网络嗅探器设计与实现", size=20,
            align=WD_ALIGN_PARAGRAPH.CENTER, space_after=26)
    r.para("NetSniffer 1A：实时抓包 · 协议解析 · 逻辑过滤 · 流追踪 · 进程归属",
           size=11, align=WD_ALIGN_PARAGRAPH.CENTER, first_indent=False, color=MUTED)
    for _ in range(4):
        r.para("", first_indent=False, after=0)

    info = doc.add_table(rows=6, cols=2)
    info.alignment = WD_TABLE_ALIGNMENT.CENTER
    info.autofit = False
    labels = ["姓　　名", "学　　号", "课程名称", "实验项目", "日　　期", "代码仓库"]
    values = [NAME, STUDENT_ID, "软件与系统安全", "实验 1A（带 GUI 的网络嗅探器）", REPORT_DATE, GIT_URL]
    for index, (label, value) in enumerate(zip(labels, values)):
        for col in range(2):
            cell = info.cell(index, col)
            cell.width = Cm(4.0 if col == 0 else 11.5)
            set_cell_margins(cell, 90, 90, 100, 100)
            cell.text = ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(label if col == 0 else value)
            set_run_font(run, size=10.5, bold=(col == 0), color=MUTED if col == 0 else DARK)

    r.page_break()

    # ---------------- abstract ----------------
    r.h1("摘要")
    r.para(
        "本实验实现了一个带图形界面的网络嗅探器 **NetSniffer 1A**。程序使用 Python 3 与 PyQt5 构建三窗格 GUI，"
        "通过 ctypes 直接绑定 Npcap 的 wpcap.dll（libpcap 兼容 API）完成链路层抓包，并用自研解析器从原始字节开始"
        "逐层解析以太网、VLAN、ARP、IPv4/IPv6、TCP/UDP、ICMP/ICMPv6、HTTP、DNS、TLS 等协议。界面提供数据包列表、"
        "协议详情树和 Hex/ASCII 字节视图，选中字段时会在字节视图中高亮对应范围；支持 BPF 捕获过滤和带 and/or/not、"
        "比较、contains/matches、CIDR 的显示过滤器。程序还实现了 TCP 四元组流追踪、乱序/重传重组、连接状态机、"
        "时序图、HTTP 事务还原，以及基于 GetExtendedTcpTable 的本地进程归属（加分项）。"
    )
    r.para(
        "工程上用独立 QThread 完成抓包、协议解析、流追踪和批量入队，GUI 线程只负责模型插入、绘制和交互；"
        "解析器全部通过 54 个单元测试。示例 pcap 包含 40 个数据包、4 条 TCP 流；在真实的 Npcap 回环抓包测试中"
        "捕获 130 个数据包、10 条 TCP 流，并正确归属到 python.exe。报告最后给出对 Thor 抓包边界与"
        "“如何识别特定应用层报文”两个思考题的分析。"
    )
    p = doc.add_paragraph()
    run = p.add_run("关键词：")
    set_run_font(run, size=10.5, bold=True)
    run = p.add_run("网络嗅探；Npcap；libpcap；PyQt5；协议分析；TCP 流重组；显示过滤器；进程归属")
    set_run_font(run, size=10.5, color=MUTED)
    r.page_break()

    # ---------------- TOC ----------------
    r.h1("目录")
    toc = [
        ("1  实验概述", 1),
        ("1.1  实验背景与目标", 2),
        ("1.2  要求完成情况", 2),
        ("1.3  运行环境", 2),
        ("1.4  源码组织", 2),
        ("2  系统总体设计", 1),
        ("2.1  设计目标", 2),
        ("2.2  分层架构", 2),
        ("2.3  线程模型与处理流水线", 2),
        ("2.4  模块划分", 2),
        ("2.5  数据模型", 2),
        ("3  抓包层设计与实现", 1),
        ("3.1  Npcap 的 ctypes 绑定", 2),
        ("3.2  网卡枚举与选择", 2),
        ("3.3  BPF 捕获过滤", 2),
        ("3.4  抓包循环、缓冲与丢包统计", 2),
        ("3.5  pcap 文件读写", 2),
        ("4  协议分析层设计", 1),
        ("4.1  OSI 七层与实现映射", 2),
        ("4.2  Packet / Field / Layer 数据模型", 2),
        ("4.3  链路层与网络层", 2),
        ("4.4  传输层", 2),
        ("4.5  应用层", 2),
        ("4.6  校验和与专家信息", 2),
        ("4.7  抓包层次与分析层次", 2),
        ("5  协议过滤设计与实现", 1),
        ("5.1  BPF 与显示过滤器的分工", 2),
        ("5.2  显示过滤器语法", 2),
        ("5.3  词法、语法、AST 与闭包求值", 2),
        ("5.4  别名、CIDR 与语义细节", 2),
        ("5.5  过滤器的 GUI 反馈", 2),
        ("6  TCP 流追踪与进程归属", 1),
        ("6.1  四元组与方向判定", 2),
        ("6.2  序列号重组", 2),
        ("6.3  连接状态与 HTTP 事务", 2),
        ("6.4  时序图", 2),
        ("6.5  进程归属", 2),
        ("7  图形界面与交互设计", 1),
        ("7.1  三窗格主界面", 2),
        ("7.2  工具栏、过滤器栏与状态栏", 2),
        ("7.3  流与进程 Dock", 2),
        ("7.4  统计与吞吐图", 2),
        ("7.5  流对话框", 2),
        ("7.6  捕获选项与设置", 2),
        ("8  测试与结果", 1),
        ("8.1  单元测试", 2),
        ("8.2  示例 pcap", 2),
        ("8.3  真实回环抓包", 2),
        ("8.4  性能与可靠性", 2),
        ("9  思考题", 1),
        ("9.1  Thor 的抓包边界说明了什么", 2),
        ("9.2  如何识别特定应用层报文", 2),
        ("10  工程问题与解决方法", 1),
        ("11  不足与改进方向", 1),
        ("12  总结", 1),
        ("13  参考资料", 1),
    ]
    toc_pages = {}
    toc_map_path = ROOT / "docs" / "toc_pages.json"
    if toc_map_path.is_file():
        try:
            toc_pages = json.loads(toc_map_path.read_text(encoding="utf-8"))
        except ValueError:
            toc_pages = {}
    for text, level in toc:
        add_toc_entry(doc, text, level, toc_pages.get(text))
    r.page_break()

    # ---------------- 1 ----------------
    r.h1("1  实验概述")
    r.h2("1.1  实验背景与目标")
    r.para(
        "网络数据包嗅探器（Network Packet Sniffer，NPS）是专门用于侦听网络流量的基础安全工具。"
        "与 Wireshark 这类网络协议分析器（Network Protocol Analyzer，NPA）相比，NPS 负责“把包抓上来”，"
        "NPA 负责“把包讲清楚”。本次实验要求二者兼顾：既要在 Windows 上通过 Npcap/libpcap 完成真实抓包，"
        "又要实现尽可能完善的协议解析、协议过滤和图形化分析能力。"
    )
    r.para(
        "实验的硬性要求是：带 GUI；能选择网卡并开始/停止抓包；能解析 HTTP、TCP/UDP、IPv4/IPv6、ICMP "
        "等不同层次的数据包；能进行带逻辑演算的协议过滤；并建议实现基于 IP+端口的 TCP 流追踪，"
        "以及“某进程产生的所有 TCP 流”的追踪作为加分项。"
    )
    r.para(
        "本实现没有使用 Scapy、dpkt 等现成解析库，而是从字节流开始实现协议树、字段偏移和校验和；"
        "抓包层只依赖 Npcap 提供的 libpcap 兼容 API。这样做的目的，是把“抓到哪一层”和“看懂到哪一层”"
        "这两件事明确分开，也便于在报告中讲清楚 OSI 分层与真实协议栈的对应关系。"
    )

    r.h2("1.2  要求完成情况")
    r.table(
        ["实验要求 / 加分项", "实现情况", "证据"],
        [
            ["带 GUI 的网络嗅探器", "PyQt5 三窗格界面；实时/离线两种模式", "图 7-1"],
            ["选择网卡、开始/停止、状态显示", "网卡枚举、物理网卡优先排序、开始/停止/重捕获；状态栏显示速率、包数、丢包", "图 7-1"],
            ["NPS 功能（必须）", "Npcap pcap_create/activate、pcap_next_ex 实时抓包；pcap 文件保存", "3.4 节、8.3 节"],
            ["NPA 协议分析（尽量完善）", "Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP/TLS/DHCP/NTP/QUIC 等", "4.5 节"],
            ["基本协议过滤", "支持 HTTP/TCP/UDP/IPv4/IPv6/ICMP/ARP/DNS/TLS 等协议谓词", "5.2 节"],
            ["带逻辑演算的过滤器", "and/or/not、括号、比较、contains/matches、CIDR；词法/语法/AST/闭包", "5.3 节、图 5-1"],
            ["TCP 流追踪（加分）", "IP+端口四元组、方向判定、序列号重组、乱序/重传/缺口、状态机", "6 节"],
            ["按进程追踪 TCP 流（加分）", "GetExtendedTcpTable + QueryFullProcessImageNameW；可过滤 proc.pid/proc.name", "6.5 节、图 6-2"],
            ["工程与可验证性", "54 个 pytest 单元测试；40 包示例 pcap；真实回环抓包 130 包", "8 节"],
        ],
        widths=[4.0, 8.8, 3.2],
    )

    r.h2("1.3  运行环境")
    r.table(
        ["项目", "配置 / 版本"],
        [
            ["操作系统", "Windows 11（开发机；程序同样适用于 Windows 10/11）"],
            ["Python", "3.13.5（代码兼容 Python 3.10+）"],
            ["GUI", "PyQt5 5.15.10，Qt 5.15.2，Fusion 风格 + 自定义 QSS"],
            ["抓包驱动", "Npcap 1.60（基于 libpcap 1.10.2-PRE-GIT），npf 驱动运行中"],
            ["抓包 API", "wpcap.dll 的 libpcap 兼容接口；ctypes 直接调用，不依赖 python-pcap"],
            ["测试", "pytest；54 个用例；示例 pcap 与回环实时抓包"],
            ["显示", "1800×1050 窗口截图；适配 150% DPI 缩放与深/浅色主题"],
        ],
        widths=[3.4, 12.6],
    )
    r.para(
        "需要说明的是，开发机上的 wpcap.dll 并不在 Npcap 默认目录，而是随厂商软件安装在一个非标准路径。"
        "程序因此实现了“环境变量 → config.json → 注册表 InstallDir → 标准目录 → vendor 目录”的发现顺序，"
        "而不把任何机器专属路径写死。"
    )

    r.h2("1.4  源码组织")
    r.code(
        """李柏谚_202649210129022_ex1A_src/
├─ main.py                  启动入口
├─ requirements.txt         PyQt5 依赖
├─ run.bat / setup_env.bat  直接运行 / 创建虚拟环境
├─ netsniff/
│  ├─ app.py                命令行参数与 QApplication
│  ├─ model.py              Packet / Field / Layer / ParseContext
│  ├─ packetgen.py          测试与示例 pcap 的确定性构包器
│  ├─ capture/
│  │  ├─ npcap.py           wpcap.dll 的 ctypes 绑定、设备枚举
│  │  ├─ worker.py          CaptureWorker / PcapFileWorker（QThread）
│  │  └─ pcapfile.py        经典 pcap 读写（跨端序/纳秒）
│  ├─ dissect/
│  │  ├─ core.py            帧级入口、DLT 分发
│  │  ├─ ethernet.py arp.py ip.py tcp.py udp.py icmp.py
│  │  ├─ dns.py http.py tls.py app.py
│  ├─ filters/display.py    显示过滤器词法/语法/AST/求值
│  ├─ analysis/
│  │  ├─ streams.py         TCP 流追踪与重组
│  │  ├─ processes.py       Windows 进程归属
│  │  └─ stats.py           协议分层/会话/吞吐
│  └─ ui/                   MainWindow、三窗格、流对话框、统计、主题
├─ tests/                   54 个 pytest 用例
├─ tools/                   示例 pcap、截图、图表、报告生成
├─ samples/                 demo.pcap、live_loopback.pcap
└─ docs/                    报告图片、图表
"""
    )

    # ---------------- 2 ----------------
    r.h1("2  系统总体设计")
    r.h2("2.1  设计目标")
    for text in (
        "**正确性**：字节级解析必须经得起真实流量和恶意/截断报文的检验，不能让一个坏包把抓包线程打崩。",
        "**响应性**：抓包、解析、流追踪不能阻塞 GUI；高流量下宁可丢弃部分界面批次，也要保证程序可操作。",
        "**可观测性**：抓多少、丢多少、解析到哪一层、为什么没有解析，都要在状态栏或专家信息里说清楚。",
        "**可扩展性**：新增协议只需增加一个解析函数并在 `app.py` 中注册，不必改 GUI。",
        "**可验证性**：解析器、过滤器、流重组都能用确定性构包器和单元测试独立验证。",
    ):
        r.bullet(text)

    r.h2("2.2  分层架构")
    r.para(
        "程序分为 GUI 层、工作线程层、协议解析层、分析层和数据源五部分。GUI 只依赖已经解析好的 `Packet` 对象；"
        "抓包线程负责 Npcap 读取、协议解析、流追踪和批量入队；文件线程负责离线 pcap/pcapng 的加载。"
        "这样的分层让“实时抓包”和“离线分析”复用同一套解析/分析代码。"
    )
    r.figure(DIAGRAMS / "architecture.png", "图 2-1  NetSniffer 1A 总体架构", width=16.2)

    r.h2("2.3  线程模型与处理流水线")
    r.para(
        "主线程只做 Qt 事件循环、模型插入、绘制和用户交互。实时抓包时 `CaptureWorker` 在独立 QThread 中执行："
        "打开网卡 → 编译/安装 BPF → `pcap_next_ex` 读取 → `dissect_packet` 解析 → `StreamTracker.process` "
        "→ 每 64 个包或 50 ms 将一批 `Packet` 放入有界队列。GUI 每 100 ms 用 `QTimer` 排空队列，"
        "批量插入 `PacketListModel`。"
    )
    r.para(
        "离线加载使用 `PcapFileWorker`，逐包解析并上报进度；两种 worker 共用同一个 `StreamTracker` 接口和"
        "同一套 GUI 插入路径。队列上限为 256 批；队列满时优先丢弃最旧的批次，并累加“界面队列丢包”计数，"
        "避免内存无界增长。驱动层丢包则来自 `pcap_stats` 的 `ps_drop`/`ps_ifdrop`，两者在状态栏中分开显示。"
    )
    r.figure(DIAGRAMS / "pipeline.png", "图 2-2  数据包处理流水线", width=16.2)
    r.table(
        ["参数", "默认值", "理由"],
        [
            ["快照长度 snaplen", "65535", "保留完整帧，便于抓取大包和 HTTP body"],
            ["内核缓冲", "32 MiB", "吸收突发流量，降低驱动丢包"],
            ["读超时", "100 ms", "让停止标志在 100 ms 内被检查到，兼顾批量和响应"],
            ["批量阈值", "64 包 / 50 ms", "降低 Qt 模型插入和事件循环开销"],
            ["界面队列", "256 批", "内存有界；满时丢弃最旧批次并计数"],
            ["最大包数", "200000", "超出后保留最近的数据包，防止内存无限增长"],
        ],
        widths=[3.8, 3.0, 9.2],
    )

    r.h2("2.4  模块划分")
    r.table(
        ["模块", "职责", "关键类/函数"],
        [
            ["capture/npcap.py", "wpcap.dll 加载、设备枚举、打开/过滤/读包/统计", "Npcap、CaptureHandle、Device"],
            ["capture/worker.py", "实时抓包线程、文件加载线程、批量队列", "CaptureWorker、PcapFileWorker"],
            ["capture/pcapfile.py", "经典 pcap 头/记录读写，跨端序/纳秒", "PcapWriter、iter_pcap"],
            ["dissect/*", "链路/网络/传输/应用层解析", "dissect_packet、dissect_http、dissect_tls…"],
            ["model.py", "协议树、字段偏移、Packet 摘要", "Packet、Field、Layer、ParseContext"],
            ["filters/display.py", "显示过滤器词法/语法/AST/闭包", "compile_filter、Compare、TextMatch"],
            ["analysis/streams.py", "TCP 四元组、方向、序列号重组、状态机", "StreamTracker、TcpStream"],
            ["analysis/processes.py", "Windows 端点 → PID/进程名", "ProcessTable"],
            ["analysis/stats.py", "协议分层、会话、吞吐序列", "protocol_hierarchy、conversations"],
            ["ui/*", "三窗格、过滤栏、流/进程 Dock、统计、时序图", "MainWindow、TcpStreamDialog、StatsDialog"],
        ],
        widths=[4.0, 7.3, 5.2],
    )

    r.h2("2.5  数据模型")
    r.para(
        "每个字段都记录自己在原始帧中的 `offset` 和 `length`，因此协议详情树选中某个字段时，Hex 视图可以精确"
        "高亮其字节范围；字段也按 Wireshark 风格的 key（如 `ip.src`、`tcp.flags.syn`）建立索引，"
        "供显示过滤器 O(1) 查询。"
    )
    r.code(
        """@dataclass(slots=True)
class Field:
    key: str                 # ip.src / tcp.flags.syn / http.host ...
    label: str               # Source Address
    value: Any
    offset: int = -1         # 帧内字节偏移
    length: int = 0          # 字节数
    display: str | None = None
    children: list["Field"] = field(default_factory=list)

@dataclass(slots=True)
class Packet:
    number: int; ts: float; raw: bytes; wirelen: int; linktype: int
    layers: list[Layer]; protocols: list[str]
    src: str; dst: str; protocol: str; info: str; color: str
    index: dict[str, list[Field]]      # 字段索引
    tcp: TcpMeta | None; udp: UdpMeta | None; ip: IpMeta | None
    stream: int | None; process: str | None; pid: int | None
    expert: list[str]                  # 专家信息（错误/警告/提示）
"""
    )

    # ---------------- 3 ----------------
    r.h1("3  抓包层设计与实现")
    r.h2("3.1  Npcap 的 ctypes 绑定")
    r.para(
        "Npcap 在 Windows 上提供两套 DLL：`Packet.dll` 是驱动访问层，`wpcap.dll` 是 libpcap 兼容 API。"
        "本程序只依赖 `wpcap.dll` 的稳定接口，不直接 ioctl 驱动。Python 的 ctypes 需要显式声明参数和返回类型，"
        "否则 64 位指针会被截断成 32 位整数——这是开发中最早踩到的坑之一。"
    )
    r.table(
        ["libpcap 函数", "用途"],
        [
            ["pcap_findalldevs / pcap_freealldevs", "枚举网卡、描述、IPv4/IPv6 地址和 flags"],
            ["pcap_create / pcap_set_* / pcap_activate", "设置快照长度、混杂、超时、缓冲、立即模式并激活"],
            ["pcap_compile / pcap_setfilter / pcap_freecode", "编译并安装 BPF 过滤器（内核过滤）"],
            ["pcap_next_ex", "读取一个数据包；0=超时，1=成功，-1=错误，-2=EOF"],
            ["pcap_stats", "读取驱动层接收/丢弃/接口丢弃计数"],
            ["pcap_close / pcap_breakloop", "释放句柄、唤醒阻塞读"],
            ["pcap_open_offline", "打开 pcap/pcapng 文件（pcapng 的兜底路径）"],
        ],
        widths=[7.6, 8.6],
    )
    r.code(
        """lib.pcap_create.restype = c_void_p
lib.pcap_create.argtypes = [c_char_p, c_char_p]
lib.pcap_set_snaplen.argtypes = [c_void_p, c_int]
lib.pcap_set_promisc.argtypes = [c_void_p, c_int]
lib.pcap_activate.argtypes = [c_void_p]
lib.pcap_next_ex.argtypes = [
    c_void_p,
    POINTER(POINTER(pcap_pkthdr)),
    POINTER(POINTER(c_ubyte)),
]
# 注意：Windows 64 位下 timeval 的 tv_sec/tv_usec 仍是 32 位 long，
# pcap_pkthdr 为 8 + 4 + 4 = 16 字节。
"""
    )
    r.para(
        "DLL 发现顺序为：环境变量 `NETSNIFF_WPCAP` / `NPCAP_DLL` → 程序目录 `config.json` 的 `wpcap_path` → "
        "注册表 `HKLM\\SOFTWARE\\WOW6432Node\\Npcap` 的 `InstallDir` → `System32\\Npcap`、`System32`、"
        "`Program Files\\Npcap` 等标准位置 → 程序目录 `vendor`。找不到时抛出 `NpcapNotFound`，GUI 给出安装提示，"
        "但离线 pcap 分析仍然可用。"
    )

    r.h2("3.2  网卡枚举与选择")
    r.para(
        "`pcap_findalldevs` 返回 `pcap_if_t` 链表，每个节点包含设备名（`\\Device\\NPF_{GUID}`）、描述、"
        "地址链表和 flags。程序把 IPv4/IPv6 地址解析出来显示在网卡下拉框中，并按“物理网卡优先、虚拟网卡其次、"
        "回环最后”的规则排序；默认选择有地址、处于 up 状态且非回环的第一块网卡。回环设备"
        "`\\Device\\NPF_Loopback` 在 Windows 上以 `DLT_NULL` 形式交付报文，解析器会读取前 4 字节地址族后"
        "再进入 IP 层。"
    )
    r.para(
        "程序不会“猜”用户想抓哪块网卡：工具栏和“捕获选项”都显示完整描述与地址；切换网卡只在未抓包时生效，"
        "避免抓包过程中设备被替换导致统计错乱。"
    )

    r.h2("3.3  BPF 捕获过滤")
    r.para(
        "BPF 过滤器由 `pcap_compile` 编译成内核过滤器，在数据包从驱动进入用户态之前生效。对于高速链路，"
        "这比“先抓上来再在 Python 里过滤”重要得多：不匹配的包根本不会跨越内核/用户态边界。"
        "程序把用户输入原样交给 libpcap 编译，编译失败时显示 `pcap_geterr` 的具体错误，不会静默忽略。"
    )
    r.table(
        ["用途", "BPF 示例"],
        [
            ["HTTP", "tcp port 80"],
            ["HTTPS / TLS", "tcp port 443"],
            ["DNS", "port 53"],
            ["仅 TCP", "tcp"],
            ["排除 SSH", "not tcp port 22"],
            ["指定主机", "host 192.168.1.10"],
            ["回环 HTTP 测试", "tcp port 8000 and host 127.0.0.1"],
            ["IPv6", "ip6"],
        ],
        widths=[4.0, 12.2],
    )

    r.h2("3.4  抓包循环、缓冲与丢包统计")
    r.para(
        "实时抓包使用 `pcap_create` 而非更简单的 `pcap_open_live`，因为前者允许在激活前设置快照长度、混杂模式、"
        "读超时、内核缓冲和立即模式。激活后 `pcap_activate` 的负返回值是错误，正值是警告（例如网卡不支持混杂模式），"
        "程序把警告保留在 Npcap 状态里。"
    )
    r.code(
        """while not stop_event.is_set():
    pkt = handle.next_packet()          # pcap_next_ex，100ms 超时
    if pkt is not None:
        packet = dissect_packet(pkt.data, number, pkt.ts, pkt.wirelen, linktype)
        tracker.process(packet)         # 流追踪在 worker 线程完成
        batch.append(packet)
        if len(batch) >= 64 or elapsed >= 0.05:
            queue.put_nowait(batch); batch = []
    if now - last_stats >= 1.0:
        received, dropped, if_dropped = handle.stats()   # pcap_stats
"""
    )
    r.para(
        "每种链路层类型都由 `dissect/core.py` 分发：`DLT_EN10MB` 走以太网，`DLT_NULL` 读取 4 字节地址族后"
        "进入 IPv4/IPv6，`DLT_RAW` 直接看版本号，`DLT_LINUX_SLL/SLL2` 解析 cooked header；"
        "802.11/radiotap 目前只解析到 MAC 层并保留原始数据，避免在实验范围外引入无线协议复杂度。"
    )
    r.para(
        "状态栏显示三类丢包：`ps_drop`（驱动缓冲不足）、`ps_ifdrop`（网卡/接口丢弃）和界面队列丢弃。"
        "实时回环测试中三类计数均为 0；这比只显示“抓了多少包”更能反映抓包质量。"
    )

    r.h2("3.5  pcap 文件读写")
    r.para(
        "保存采用经典 pcap 格式（little-endian、微秒时间戳），Wireshark/tcpdump 可直接打开。读取端同时支持"
        "大端/小端和微秒/纳秒两种 magic；每条记录包含 ts_sec、ts_usec、incl_len、orig_len，"
        "对异常长度做上限检查并给出可读错误。pcapng 先用纯 Python 检测 magic，若失败则退回 Npcap 的"
        "`pcap_open_offline`，从而在不引入第三方库的情况下覆盖常见 pcapng 文件。"
    )
    r.code(
        """# 经典 pcap 全局头（24 字节）
struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)
# 记录头（16 字节）+ 原始字节
struct.pack("<IIII", ts_sec, ts_usec, len(data), wirelen) + data
"""
    )
    r.para(
        "“保存全部”和“保存当前显示”共享同一个写入器：后者直接把显示过滤后的 `visible_packets` 写入，"
        "适合把一次过滤结果交给同学或 Wireshark 复核。CSV 导出则输出 No./Time/Source/Destination/"
        "Protocol/Length/Info/Process 八列，编码为 UTF-8-SIG，Excel 打开不乱码。"
    )

    # ---------------- 4 ----------------
    r.h1("4  协议分析层设计")
    r.h2("4.1  OSI 七层与实现映射")
    r.para(
        "OSI 是教学模型，真实协议栈通常按 TCP/IP 四层实现。本程序在“抓包层次”上从链路层开始（Windows 回环是 "
        "NULL 伪链路层），在“分析层次”上按协议头逐层递进；应用层协议既可能直接跑在 TCP/UDP 上（HTTP/DNS），"
        "也可能被 TLS 包裹（HTTPS），后者只能看到 TLS 记录和握手元数据。"
    )
    r.table(
        ["OSI 层", "本实验中的对应", "实现/字段示例"],
        [
            ["物理层", "网卡、Npcap npf 驱动、链路介质", "不在用户态解析；由驱动完成"],
            ["数据链路层", "Ethernet II、802.1Q VLAN、ARP", "eth.src/dst、vlan.id、arp.opcode"],
            ["网络层", "IPv4、IPv6、ICMP/ICMPv6", "ip.src/dst、ip.ttl、ipv6.nxt、icmp.type"],
            ["传输层", "TCP、UDP（以及 SCTP/GRE 的基本头）", "tcp.srcport、tcp.seq、udp.length"],
            ["会话层", "TCP 连接状态机、TLS 握手会话", "tcp.stream、SYN/FIN/RST、TLS handshake"],
            ["表示层", "TLS 记录层加解密/编码、HTTP charset", "tls.record.version、Content-Type"],
            ["应用层", "HTTP、DNS、DHCP、NTP、SSH、QUIC…", "http.request.method、dns.qry.name、tls.sni"],
        ],
        widths=[3.0, 7.2, 6.4],
    )
    r.para(
        "以 HTTPS 为例：NPS 能抓到 Ethernet/IP/TCP/TLS 记录，能读出 SNI、ALPN、TLS 版本和证书长度，"
        "但看不到 HTTP 请求行和 body，因为它们在 TLS 加密载荷里。这正是“抓包层次”和“分析层次”的分界："
        "抓到了字节，不等于有密钥把它解成明文。"
    )

    r.h2("4.2  Packet / Field / Layer 数据模型")
    r.para(
        "解析器不是直接拼字符串，而是构造一棵“协议树”：`Layer` 是树的一层（Ethernet、IPv4、TCP、HTTP…），"
        "`Field` 是层内的一个字段，递归包含子字段（例如 TCP Flags 下的 SYN/ACK/FIN）。每个字段都带 key、"
        "显示值和字节范围；解析完成后，`ParseContext.finish()` 再把 Frame 层插到最前面，并生成 `Packet` 摘要。"
    )
    r.para(
        "字段索引 `Packet.index` 同时服务于显示过滤器和 GUI：过滤器按键取值，详情树按字段范围高亮字节。"
        "这种“一份解析、多处复用”的设计避免了 GUI 和过滤器各自重新解析报文。"
    )

    r.h2("4.3  链路层与网络层")
    r.bullet("**Ethernet II / VLAN / QinQ**：解析目的/源 MAC、EtherType；支持 0x8100/0x88A8/0x9100 多层 VLAN 标签，"
             "每层单独建 Layer，显示优先级、DEI、VLAN ID 和内层类型。")
    r.bullet("**ARP**：硬件类型、协议类型、opcode、Sender/Target MAC/IP；摘要显示 “Who has …? Tell …” 或 “x is at …”。")
    r.bullet("**IPv4**：版本/IHL、DSCP/ECN、总长度、ID、Flags（DF/MF）、分片偏移、TTL、协议、头校验和、"
             "源/目的地址和选项；校验和错误会进入专家信息。偏移大于 0 的分片不再解析传输层，首片会标记告警。")
    r.bullet("**IPv6**：40 字节基本头 + Hop-by-Hop/Routing/Fragment/Destination Options/AH/ESP 扩展链；"
             "Fragment Header 后若偏移非 0 则停止传输层解析；ESP 只显示 SPI/序列号并标注“加密载荷”。")
    r.bullet("**ICMP/ICMPv6**：类型/代码/校验和、Echo 的 Identifier/Sequence、错误报文的嵌入 IP 头、"
             "邻居发现与路由器通告的选项；ICMPv6 校验和按 IPv6 伪头验证。")

    r.h2("4.4  传输层")
    r.para(
        "TCP 解析包括端口、序列号/确认号、数据偏移、9 个标志位、窗口、校验和、紧急指针、选项和载荷长度。"
        "选项解析覆盖 MSS、Window Scale、SACK Permitted/SACK、Timestamps、NOP/EOL 等；这些选项在流时序图和"
        "连接分析中很有用。TCP/UDP 校验和都按伪头计算，抓包截断或分片时跳过验证并给出说明。"
    )
    r.table(
        ["协议", "解析内容", "备注"],
        [
            ["TCP", "端口、seq/ack、flags、window、options、payload", "校验和；流追踪的基础"],
            ["UDP", "端口、长度、校验和、payload", "IPv4 校验和为 0 表示未计算"],
            ["ICMP", "type/code、echo id/seq、嵌入 IP", "无伪头校验和"],
            ["ICMPv6", "type/code、ND/RA 选项、嵌入 IP", "带 IPv6 伪头校验和"],
        ],
        widths=[2.6, 9.4, 4.6],
    )

    r.h2("4.5  应用层")
    r.para(
        "应用层协议按“端口 + 载荷签名 + 结构合法性”三重判断，而不是只看端口。这样既能处理 8080 上的 HTTP、"
        "8443 上的 TLS，也能避免把 443 端口上的任意 UDP 都误标成 TLS。"
    )
    r.bullet("**HTTP/1.x**：解析请求行/响应行、头部、Content-Length、Content-Type、Host/User-Agent/Cookie 等；"
             "按包解析适合摘要，流重组后的 `parse_http_messages` 还能处理流水线请求、chunked body，"
             "“HTTP 事务”页把请求/响应成对展示。")
    r.bullet("**DNS**：事务 ID、flags、问题/回答/权威/附加区；处理名称压缩指针（带循环保护）、A/AAAA/CNAME/"
             "NS/PTR/MX/TXT/SOA/SRV/OPT 等记录，支持 UDP/TCP/mDNS(5353)/LLMNR(5355)。")
    r.bullet("**TLS**：记录层 content type/version/length，握手 ClientHello 的 SNI、ALPN、supported_versions、"
             "cipher suites、key_share，ServerHello 的选定版本/套件；不进行解密，因此只能看到元数据。")
    r.bullet("**DHCP/NTP/QUIC**：DHCP 消息类型与常用 option；NTP 版本/模式/stratum/时间戳；QUIC 长头的版本、"
             "DCID/SCID/包类型（Initial/0-RTT/Handshake/Retry），短头只做有限识别。")
    r.bullet("**SSH/FTP/SMTP/MQTT/Redis**：对明文行协议做轻量识别，显示 banner/命令行/报文类型；"
             "对加密或二进制协议保持保守，未知载荷归入 Data 层而不是强行误判。")
    r.table(
        ["协议", "层次", "解析深度"],
        [
            ["Ethernet II / VLAN", "链路", "MAC、EtherType、VLAN 标签"],
            ["ARP", "链路/网络", "opcode、Sender/Target MAC/IP"],
            ["IPv4 / IPv6", "网络", "完整首部、扩展头、分片标志、校验和"],
            ["ICMP / ICMPv6", "网络", "类型/代码、Echo、ND/RA 选项"],
            ["TCP / UDP", "传输", "首部、选项、校验和、载荷"],
            ["HTTP/1.x", "应用", "请求/响应行、头、body、流级事务"],
            ["DNS", "应用", "问题/回答/压缩名称、常用 RR"],
            ["TLS", "会话/表示", "记录、ClientHello/ServerHello、SNI/ALPN"],
            ["DHCP / NTP", "应用", "消息类型、option、时间戳/模式"],
            ["QUIC", "应用", "长头版本/连接 ID/包类型"],
            ["SSH/FTP/SMTP/MQTT/Redis", "应用", "明文行协议/报文类型"],
        ],
        widths=[6.0, 3.0, 7.6],
    )

    r.h2("4.6  校验和与专家信息")
    r.para(
        "IPv4 头、TCP、UDP、ICMP、ICMPv6 都做校验和验证，并在字段显示中标注 `[correct]` / `[incorrect]` / "
        "`[not computed]`。抓包截断、IP 分片、网卡校验和卸载（checksum offload）都可能导致“看起来错误”，"
        "因此程序把错误写入 Expert Info，但在摘要中不把它当成致命错误，避免把正常流量误报成攻击。"
    )
    r.para(
        "专家信息还记录：头部截断、长度字段非法、VLAN 标签异常、TCP 数据偏移非法、DNS 名称压缩循环、"
        "HTTP body 截断等。详情树末尾的 “Expert Info” 层按 Error/Warning/Note 分级显示，"
        "过滤器可用 `expert` 谓词筛选所有带专家信息的包。"
    )

    r.h2("4.7  抓包层次与分析层次")
    r.para(
        "抓包层次由链路类型决定：以太网从 14 字节开始，回环从 4 字节地址族开始，Raw IP 从版本号开始。"
        "分析层次则由协议头的 next header/protocol 字段递进；遇到加密（TLS Application Data、ESP、QUIC 1-RTT）"
        "或分片偏移非 0 时，分析必须止步。程序明确显示“止步”的原因（例如 “Application Data (encrypted)”），"
        "而不是假装解析出了内容。"
    )
    r.para(
        "这提醒我们：安全分析里“没看到”不等于“没有”。抓包点、权限、加密和协议封装共同决定了可见性，"
        "这与 9.1 节对 Thor 的讨论是同一个问题。"
    )

    # ---------------- 5 ----------------
    r.h1("5  协议过滤设计与实现")
    r.h2("5.1  BPF 与显示过滤器的分工")
    r.para(
        "程序提供两级过滤：**BPF 捕获过滤器**在 Npcap 内核层执行，语法由 libpcap 负责，适合按端口/主机/协议"
        "大幅削减流量；**显示过滤器**在解析后执行，支持协议名、字段、逻辑运算、CIDR 和正则，适合“已经抓上来，"
        "现在只想看某些包”的分析场景。两者是互补关系，而不是重复实现。"
    )
    r.table(
        ["维度", "BPF 捕获过滤器", "显示过滤器"],
        [
            ["执行位置", "内核（npf 驱动）", "用户态，解析后的 Packet 上"],
            ["语法来源", "libpcap pcap-filter", "本程序自研表达式语言"],
            ["典型用途", "只抓 80/443、排除 SSH、限定主机", "看 HTTP 错误、按进程/流、SNI 正则"],
            ["能否使用字段", "只能使用链路/网络/传输层少量关键字", "可使用任意解析字段和逻辑表达式"],
            ["对性能的影响", "不匹配的包不进入用户态，收益最大", "已经抓上来的包才过滤，节省 GUI 和内存"],
        ],
        widths=[2.6, 7.2, 6.8],
    )

    r.h2("5.2  显示过滤器语法")
    r.para("显示过滤器采用递归下降文法，优先级从低到高为 or、and、not：")
    r.code(
        """expr    := or_expr
or_expr := and_expr (("or" | "||") and_expr)*
and_expr:= unary (("and" | "&&") unary)*
unary   := ("not" | "!") unary | "(" expr ")" | predicate
predicate := protocol
           | field op value
           | field ("contains" | "matches") string
           | protocol "contains" string
op      := == | != | > | < | >= | <=
"""
    )
    r.para(
        "协议谓词直接写协议名，例如 `http`、`tcp`、`ip and not icmp`；字段比较支持数值、字符串、布尔、IP、MAC；"
        "`contains` 做子串匹配，`matches` 做 Python 正则匹配；IP 字段支持 CIDR 成员判断。"
    )
    r.table(
        ["类别", "可用字段（节选）", "说明"],
        [
            ["帧", "frame.number、frame.len、frame.time、frame.protocols", "帧级元数据"],
            ["链路", "eth.src/dst/addr、vlan.id、vlan.priority", "MAC/VLAN"],
            ["网络", "ip.src/dst/addr、ip.ttl、ip.proto、ipv6.src/dst/addr", "IP 地址/协议"],
            ["传输", "tcp.srcport/dstport/port、tcp.seq、tcp.flags.syn、udp.port", "端口、标志、长度"],
            ["ICMP", "icmp.type/code、icmpv6.type/code", "类型/代码"],
            ["HTTP", "http.request.method/uri、http.host、http.response.code、http.content_type", "请求/响应"],
            ["DNS", "dns.qry.name/type、dns.a、dns.aaaa、dns.flags.response", "查询/回答"],
            ["TLS", "tls.sni、tls.handshake.type、tls.handshake.version、tls.app_data_len", "握手元数据"],
            ["流/进程", "tcp.stream、proc.pid、proc.name", "加分项"],
        ],
        widths=[2.2, 9.6, 4.2],
    )

    r.h2("5.3  词法、语法、AST 与闭包求值")
    r.para(
        "过滤器首先被 tokenize 成 IDENT/STRING/NUMBER/IP/MAC/OP/AND/OR/NOT 等 token；递归下降解析器构造 AST；"
        "最后 `evaluate` 用 `Packet.index` 取值并比较。解析阶段就把非法字段、非法运算符、括号不匹配、"
        "非法正则等错误按列号报出来，不需要等到抓包时才失败。"
    )
    r.figure(DIAGRAMS / "filter_ast.png", "图 5-1  显示过滤器的编译与求值流程", width=16.0)
    r.code(
        """@dataclass(slots=True)
class Compare(Node):
    fields: tuple[FieldSpec, ...]
    op: str
    literal: str

    def evaluate(self, packet) -> bool:
        values = [(spec, v) for spec in self.fields
                  for v in _field_values(packet, spec.name)]
        if not values:
            return False
        if self.op == "!=":          # 别名语义：所有值都不等于
            return all(not _compare_one(s, v, "==", self.literal) for s, v in values)
        return any(_compare_one(s, v, self.op, self.literal) for s, v in values)
"""
    )

    r.h2("5.4  别名、CIDR 与语义细节")
    r.bullet("`ip.addr` 同时匹配 IPv4 源/目的和 IPv6 源/目的。Wireshark 的 `ip.addr` 只指 IPv4，"
             "本程序为方便教学做了扩展，并在帮助中注明。")
    r.bullet("`tcp.port`/`udp.port` 等价于源端口或目的端口；`!=` 采用“所有值都不等于”的语义，"
             "避免“源端口不等于 80”把目的端口 80 的包错误排除。")
    r.bullet("IP 字段的 `== 192.168.1.0/24` 走 CIDR 成员判断；IPv4 字面量不会匹配 IPv6 地址。")
    r.bullet("`tcp contains \"GET \"` 在 TCP 载荷中搜索字节；`http contains ...` 在 HTTP 层范围内搜索；"
             "`frame contains ...` 搜索整帧。")
    r.bullet("布尔字段可以直接写（如 `tcp.flags.syn`），表示“为真”；`tcp.flags.syn == 1` 更明确。")
    r.table(
        ["表达式", "含义"],
        [
            ["http", "只看 HTTP"],
            ["tcp.port == 443", "TCP 443"],
            ["ip.addr == 192.168.1.0/24", "网段匹配"],
            ["http.response.code >= 400", "HTTP 错误响应"],
            ['http.host contains "example"', "Host 包含 example"],
            ['http.request.uri matches "^/api/"', "URI 正则"],
            ["tcp.flags.syn == 1 and not tcp.flags.ack == 1", "SYN 请求"],
            ["tls.handshake.type == 1", "TLS Client Hello"],
            ['tls.sni contains "example"', "SNI 包含 example"],
            ['tcp contains "GET "', "TCP 载荷含 GET"],
            ["proc.name == \"python.exe\"", "按进程过滤"],
            ["tcp.stream == 3", "只看第 3 条 TCP 流"],
        ],
        widths=[8.2, 7.8],
    )

    r.h2("5.5  过滤器的 GUI 反馈")
    r.para(
        "过滤栏在输入时做 280 ms 防抖校验：合法显示绿色边框，非法显示红色边框和错误 tooltip；按 Enter 或"
        "“应用”才真正重建模型。过滤状态显示“显示数 / 总数”，状态栏显示最近一次应用结果。"
        "“常用”菜单提供 HTTP/DNS/TLS/TCP/UDP/IPv4/IPv6/ICMP/ARP 等快捷表达式，“语法”按钮打开字段与示例帮助。"
    )
    r.figure(SHOTS / "02_filter_dns.png", "图 5-2  显示过滤器 “dns” 的结果（2/40，协议详情同步）", width=16.2)
    r.figure(SHOTS / "03_filter_error.png", "图 5-3  非法过滤器 “tcp.port ==” 的红色边框与错误提示", width=16.2)

    # ---------------- 6 ----------------
    r.h1("6  TCP 流追踪与进程归属")
    r.h2("6.1  四元组与方向判定")
    r.para(
        "流键是 `("
        "tcp, min(endpointA, endpointB), max(...)"
        ")`，其中 endpoint 为 `(ip, port)`。这样无论先看到客户端还是服务端，同一连接都落到同一个 "
        "`TcpStream`。方向判定优先看 SYN：不带 ACK 的 SYN 发送者是客户端；SYN+ACK 的发送者是服务端；"
        "如果抓包从连接中途开始，则把首个发送者当作客户端，并在界面中如实显示两个端点，不强行“纠正”。"
    )
    r.para(
        "每条流分配一个递增的 `stream` 编号，写入 `Packet.stream`，于是过滤器 `tcp.stream == N`、"
        "“打开所属 TCP 流”右键菜单、时序图和 HTTP 事务都能直接定位同一条流。"
    )

    r.h2("6.2  序列号重组")
    r.para(
        "重组以 SYN 的序列号为基准：SYN 的相对序号为 0，首个数据字节为 1。对每个方向，把带载荷的段按绝对 "
        "seq 排序，维护 `next_seq` 已交付位置；遇到重传/部分重叠时只追加未覆盖的后缀，遇到乱序缺口时记录 "
        "`(输出偏移, 缺失字节数)`。这样既能处理常见的重传，也能在详情里明确告诉用户“中间有缺口”，"
        "而不是把不连续的数据静默拼在一起。"
    )
    r.code(
        """segments.sort(key=lambda s: s.seq)
base = syn_seq + 1 if syn_seq is not None else segments[0].seq
next_seq = base
for seg in segments:
    end = seg.seq + len(seg.payload)
    if end <= next_seq:            # 完全重传
        continue
    if seg.seq > next_seq:         # 缺口
        gaps.append((len(out), seg.seq - next_seq))
        next_seq = seg.seq
    out += seg.payload[max(0, next_seq - seg.seq):]
    next_seq = end
"""
    )
    r.para(
        "为避免单个长连接拖垮内存，每条流最多保留 20000 个段、8 MiB 重组数据；超过后标记 `truncated`，"
        "界面明确提示“后续内容未完整保留”。"
    )

    r.h2("6.3  连接状态与 HTTP 事务")
    r.para(
        "状态机按标志位推导：未见 SYN+ACK 时是 `SYN_SENT`；看到 SYN+ACK 后为 `ESTABLISHED`；"
        "出现 FIN 为 `FIN_WAIT`；双向 FIN 为 `CLOSED`；出现 RST 为 `RESET`。"
        "这比只显示“TCP”更能帮助判断扫描、拒绝连接和正常关闭。"
    )
    r.para(
        "“HTTP 事务”页对重组后的双向数据调用 `parse_http_messages`：按 Content-Length 或 chunked 编码"
        "切分消息，支持流水线请求；请求与响应按出现顺序配对，展示首行、头部和 body 预览。"
        "这使“抓到一个 HTTP 会话”从“看单个包”升级为“看一次完整交互”。"
    )

    r.h2("6.4  时序图")
    r.para(
        "时序图把时间画成纵向轴：左侧客户端、右侧服务器，蓝色/绿色箭头分别表示两个方向，"
        "箭头上的文字给出 flags、Len 和相对 Seq，虚线表示纯 ACK；鼠标悬停显示绝对 Seq/Ack/窗口/时间，"
        "点击箭头可跳回对应的数据包。图中同时显示 SYN、握手、请求/响应、FIN 的完整过程，"
        "比在包列表里逐条比对 seq/ack 直观得多。"
    )
    r.figure(SHOTS / "04_stream_sequence.png", "图 6-1  TCP 流 #1 的时序图（HTTP keep-alive，15 个 TCP 段）", width=15.8)

    r.h2("6.5  进程归属")
    r.para(
        "Windows 上要把一个五元组映射到进程，可用 iphlpapi 的 `GetExtendedTcpTable` / `GetExtendedUdpTable` 的 "
        "OWNER_PID 表。程序枚举 IPv4/IPv6 的 TCP 和 UDP 表，把 `(proto, local_addr, local_port)` 映射到 PID；"
        "对通配地址（0.0.0.0/::）的监听套接字做回退匹配；再通过 `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` "
        "和 `QueryFullProcessImageNameW` 取进程名。"
    )
    r.para(
        "实现中特别注意了三个细节：① `dwLocalPort` 是网络字节序，必须 `ntohs`；② TCP TIME_WAIT 行的 PID 可能为 0，"
        "不能当成 System Idle Process 显示，程序直接跳过；③ 普通权限可能打不开系统进程，程序显示“PID x（拒绝访问）”"
        "而不是崩溃。进程表每 3 秒刷新一次，抓包线程只做查询；对普通用户自己的进程（如 python.exe、浏览器）"
        "通常能正确归属。"
    )
    r.code(
        """class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState", DWORD), ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD), ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD), ("dwOwningPid", DWORD),
    ]
# GetExtendedTcpTable(..., AF_INET, TCP_TABLE_OWNER_PID_ALL)
# GetExtendedTcpTable(..., AF_INET6, TCP_TABLE_OWNER_PID_ALL)
"""
    )
    r.figure(SHOTS / "11_live_packetlist.png",
             "图 6-2  真实回环抓包：130 个包、10 条 TCP 流，Process 列显示 python.exe", width=16.2)
    r.figure(SHOTS / "11_live_streams.png",
             "图 6-3  TCP 流 Dock：10 条流全部归属 python.exe", width=10.0)
    r.para(
        "在“进程”Dock 中双击某个进程即可应用 `proc.pid == N`；也可直接在过滤器输入 `proc.name == \"python.exe\"`。"
        "这满足加分项“某进程产生的所有 TCP 流”的追踪需求。"
    )

    # ---------------- 7 ----------------
    r.h1("7  图形界面与交互设计")
    r.h2("7.1  三窗格主界面")
    r.para(
        "主界面采用 Wireshark 风格的上下 + 左右分栏：上方数据包列表显示 No./Time/Source/Destination/Protocol/"
        "Length/Info；下方左侧协议详情树，右侧 Hex+ASCII；右侧 Dock 显示 TCP 流和进程。"
        "选中数据包会同步刷新详情和字节；选中详情字段会在字节视图中高亮对应范围，并在状态栏显示字段名与字节偏移。"
    )
    r.figure(SHOTS / "01_main_panes.png",
             "图 7-1  NetSniffer 1A 主界面三窗格（示例 pcap，选中 HTTP GET 包；右侧流/进程 Dock 见图 6-3）",
             width=16.2)
    r.para(
        "数据包行按协议着色（HTTP 绿、DNS 紫、TLS 黄、TCP 蓝、UDP 青、ICMP 红、ARP 橙），协议列再用高对比色强调；"
        "深色主题下既保留信息密度，又避免整屏纯色。时间列支持相对/绝对/增量三种模式，"
        "帧号与长度用等宽字体对齐。"
    )

    r.h2("7.2  工具栏、过滤器栏与状态栏")
    r.bullet("工具栏：开始/停止/重捕获、网卡下拉框、BPF 输入、打开/保存/清空、统计/查找/语法/主题。")
    r.bullet("过滤器栏：显示过滤器输入、应用、常用表达式菜单、语法帮助、匹配计数；非法输入即时红框。")
    r.bullet("状态栏：运行状态圆点、接口/文件、总包数、显示数、丢包数、实时 pps 与迷你吞吐曲线；"
             "底部临时消息显示最近操作或字段偏移。")
    r.bullet("时间格式、自动滚动、深浅主题、列宽重置和 Dock 显隐都可通过“视图”菜单调整，并写入 QSettings。")

    r.h2("7.3  流与进程 Dock")
    r.para(
        "Dock 有两个页签：TCP 流显示流号、客户端、服务器、状态、包数、字节数和进程；进程页显示 PID、进程名、"
        "包数、字节数和涉及的 TCP 流数。双击流打开时序图，双击进程应用进程过滤器；右键菜单可复制摘要或"
        "只显示该流/该进程。Dock 每秒刷新，保留当前选中行，避免抓包时“跳来跳去”。"
    )

    r.h2("7.4  统计与吞吐图")
    r.para(
        "统计对话框提供协议分层、会话和吞吐量三个页签。协议分层按协议栈构树，统计包数与字节占比；"
        "会话按 IPv4/IPv6/TCP/UDP 分组，显示 A/B 地址、端口、包数、字节、时长和双向字节；"
        "双击会话可把对应的过滤表达式写回主界面。吞吐量页用柱状图表示每秒包数、折线表示每秒字节数，"
        "左右双轴独立缩放。"
    )
    r.figure(SHOTS / "06_stats_hierarchy.png", "图 7-2  协议分层统计", width=15.2)
    r.figure(SHOTS / "07_stats_conversations.png", "图 7-3  TCP 会话统计（可按列排序、双击过滤）", width=15.2)
    r.figure(SHOTS / "08_stats_throughput.png", "图 7-4  吞吐量曲线（包/秒与字节/秒）", width=15.2)

    r.h2("7.5  流对话框")
    r.para(
        "流对话框提供“时序图 / C→S / S→C / 双向 / 十六进制 / HTTP 事务”六个页签，"
        "覆盖从“看时序”到“看原文”的不同分析粒度。双向页用颜色区分方向，"
        "十六进制页按 16 字节分行并带 ASCII 侧栏，HTTP 页把头部和 body 排版成可读的 HTML。"
    )
    r.figure(SHOTS / "05_stream_http.png", "图 7-5  流对话框的“HTTP 事务”页（两对请求/响应）", width=15.8)

    r.h2("7.6  捕获选项与设置")
    r.para(
        "“捕获选项”对话框集中管理网卡、快照长度、内核缓冲、读超时、混杂/立即模式和 BPF 预设；"
        "Npcap 版本与状态直接显示在对话框里，找不到 wpcap.dll 时给出下载与配置说明。"
        "主窗口的几何、Dock 状态、网卡、BPF、主题、时间格式、自动滚动和每包上限都通过 QSettings 持久化。"
    )
    r.figure(SHOTS / "10_capture_options.png", "图 7-6  捕获选项对话框", width=14.6)
    r.figure(SHOTS / "09_filter_help.png", "图 7-7  显示过滤器语法与字段帮助", width=15.6)

    # ---------------- 8 ----------------
    r.h1("8  测试与结果")
    r.h2("8.1  单元测试")
    r.para(
        "测试不依赖真实网卡：使用 `packetgen.py` 构造校验和正确的以太网/IP/TCP/UDP/DNS/TLS 报文，"
        "对解析、过滤、流重组、pcap 读写和统计做确定性验证。运行 `python -m pytest`，结果为 **54 passed**，"
        "耗时约 0.25 s。"
    )
    r.table(
        ["测试文件", "用例数", "覆盖内容"],
        [
            ["test_dissect.py", "8", "Ethernet/IPv4/TCP/HTTP、ARP、DNS、TLS、ICMP、IPv6、VLAN、坏包、回环 NULL"],
            ["test_filters.py", "29", "协议谓词、逻辑运算、别名、CIDR、contains/matches、proc/stream、非法表达式"],
            ["test_streams.py", "5", "握手/重组/状态、乱序/重传、缺口、多流、非 TCP"],
            ["test_pcap_stats.py", "7", "示例 pcap、pcap 往返、写入器、坏文件、协议分层、会话、吞吐"],
            ["test_http.py", "3", "流水线 HTTP、Content-Length/chunked、分片消息"],
            ["合计", "54", "全部通过"],
        ],
        widths=[4.2, 2.0, 9.8],
    )

    r.h2("8.2  示例 pcap")
    r.para(
        "`samples/demo.pcap` 由 `tools/make_demo_pcap.py` 确定性生成，包含 ARP、DNS、HTTP keep-alive、"
        "TLS 1.3、ICMP/ICMPv6、NTP、QUIC、VLAN 和 RST，共 40 个包、4 条 TCP 流。校验和全部正确，"
        "解析时没有产生任何专家错误；生成脚本本身会回读 pcap 并打印协议统计和流信息。"
    )
    r.table(
        ["协议/最高层", "包数", "说明"],
        [
            ["ARP", "2", "请求/应答"],
            ["DNS", "2", "A + AAAA 查询/响应"],
            ["TCP", "22", "HTTP/TLS 握手、ACK、FIN"],
            ["HTTP", "4", "两次 keep-alive 请求/响应"],
            ["TLSv1.3", "2", "ClientHello / ServerHello"],
            ["TLS", "1", "应用数据/CCS"],
            ["ICMP / ICMPv6", "2 + 2", "Echo request/reply"],
            ["NTP", "2", "客户端/服务器"],
            ["QUIC", "1", "Initial 头"],
        ],
        widths=[3.6, 2.2, 9.6],
    )

    r.h2("8.3  真实回环抓包")
    r.para(
        "`tools/live_demo.py` 启动本机 `python -m http.server 8000`，用 Npcap 抓取回环适配器，"
        "BPF 为 `tcp port 8000`，生成 10 次 HTTP 请求。实测捕获 **130 个数据包、13760 字节、10 条 TCP 流**，"
        "其中 TCP 100 个、HTTP 30 个，0 个专家错误、0 个驱动/界面丢包；Process 列全部为 python.exe，"
        "流 Dock 中 10 条流均归属到 python.exe。图 6-2、图 6-3 即该次抓包的界面截图。"
    )
    r.para(
        "在 Intel Wi-Fi 网卡上也做了 Npcap 实时打开与读包验证（抓到管理/数据帧 5 个），确认程序不只能处理回环；"
        "报告中的截图使用回环流量，避免暴露个人网络数据。"
    )

    r.h2("8.4  性能与可靠性")
    r.bullet("抓包/解析/流追踪在 QThread 中执行，GUI 只做模型插入；100 ms 定时排空队列，避免每包一次事件循环。")
    r.bullet("队列上限 256 批（每批最多 64 包）；满时丢最旧批次并计数，状态栏区分驱动丢包和界面丢包。")
    r.bullet("包列表默认最多 20 万包；超出后保留最近数据，防止长时间抓包耗尽内存。")
    r.bullet("所有解析函数都由 `dissect_packet` 的异常保护包裹；单个坏包只会产生 Expert Info，不会终止线程。")
    r.bullet("停止抓包时先置停止标志，再 `pcap_breakloop`/等待 100 ms 超时，最后 `wait` 线程，避免 QThread 被销毁时仍在运行。")
    r.bullet("54 个测试覆盖解析、过滤、流重组、pcap 和统计；示例回读与真实回环均无解析异常。")

    # ---------------- 9 ----------------
    r.h1("9  思考题")
    r.h2("9.1  Thor 的抓包边界说明了什么")
    r.para(
        "iOS 的 Thor 在安装系统描述文件（本质上是把 Thor 的根证书加入系统信任链）后，可以代理/解密 HTTP/HTTPS，"
        "从而看到应用层请求和响应；但它对某些传输控制协议的内容无能为力。这个现象说明："
        "**抓包能力首先取决于观测点和权限边界，而不是工具名字**。"
    )
    for text in (
        "**分层决定可见性**：Thor 工作在应用层代理/中间人位置，能看懂它代理的 HTTP；"
        "TCP 的 SYN/ACK/RST、窗口、重传、拥塞控制等行为发生在传输层，应用层代理并不天然暴露这些信息。",
        "**解密需要信任与密钥**：安装根证书后 Thor 才能对 TLS 做中间人解密；一旦应用使用证书固定（pinning）、"
        "双向认证或端到端加密，代理就看不到明文。能抓到包不等于能解出内容。",
        "**权限与沙箱限制**：iOS 应用沙箱、系统网络扩展权限、VPN/代理的接管范围都会限制可见流量；"
        "未经过代理的流量、其他 App 的流量、系统底层协议可能完全不可见。",
        "**安全分析必须声明威胁模型**：说“我抓到了全部流量”之前，必须先说明抓包点、是否有解密密钥、"
        "覆盖哪些协议和进程。否则结论可能只是“在我能看见的范围内是这样”。",
        "**NPS 与 NPA 互补**：Npcap 能拿到链路层到传输层的原始字节，即使 TLS 加密也能看到五元组、SNI、"
        "包长、时序和 TCP 行为；但要还原 HTTP 语义，仍需要应用层解析或解密。两者结合才是完整的分析链路。",
    ):
        r.bullet(text)
    r.para(
        "对本实验的启示是：程序必须明确标出“解析止步”的位置（TLS Application Data、ESP、分片后续、"
        "非 IP 载荷），并在 GUI 中把抓包层次、协议栈和专家信息放在一起展示；不能因为看不到明文，"
        "就假装某个应用协议不存在。"
    )

    r.h2("9.2  如何识别特定应用层报文")
    r.para(
        "识别应用层协议通常从弱到强有几类手段，实际系统往往组合使用："
    )
    r.numbered("**端口映射**：80→HTTP、443→TLS、53→DNS。简单快速，但非标准端口、隧道和端口复用会导致误判。")
    r.numbered("**载荷签名/魔数**：HTTP 方法或 `HTTP/` 开头，TLS 记录头 `0x16 0x03 0x0x`，SSH banner `SSH-`，"
               "DNS 头部的计数/名称结构，QUIC 长头的固定位和版本号。签名比端口可靠，但可能被分片/加密打断。")
    r.numbered("**结构合法性校验**：不仅看开头，还验证长度字段、名称压缩指针、校验和、状态机。"
               "本程序对 TLS 记录长度、DNS 指针循环、HTTP 头部终止、QUIC 固定位都做了边界检查，"
               "避免“看到 443 就当 TLS”的误判。")
    r.numbered("**状态机与上下文**：HTTP 请求/响应、TCP 握手后的首个载荷、TLS 握手顺序、"
               "DNS 事务 ID 配对；单包看不出时，要靠流重组后的上下文。")
    r.numbered("**元数据线索**：TLS 的 SNI/ALPN、DNS 的查询名、HTTP 的 Host/User-Agent、"
               "QUIC 的版本和连接 ID。这些即使加密也常常可见。")
    r.numbered("**统计/机器学习/主动探测**：包长分布、时序、字节熵、已知指纹库、主动发送探测包；"
               "适用于未知协议或规避场景，但需要标注误报率和对抗风险。")
    r.para(
        "本程序的实现策略是“端口先验 + 签名 + 结构校验 + 流上下文”：`app.py` 先按端口缩小候选，"
        "再用载荷签名和解析结果确认；解析失败时回退到 Data 层，而不是强行套一个错误协议。"
        "例如 QUIC 短头必须满足 fixed bit，TLS 必须通过记录长度检查，HTTP 必须出现合法的方法/状态行。"
        "这体现了安全工程中的一个原则：**宁可少标，不可错标**——错误的协议标签会误导后续的过滤和判断。"
    )

    # ---------------- 10 ----------------
    r.h1("10  工程问题与解决方法")
    r.table(
        ["问题", "现象", "解决方法"],
        [
            ["ctypes 指针截断", "调用 pcap_datalink 后访问违例", "为每个函数声明 argtypes/restype，句柄用 c_void_p"],
            ["wpcap.dll 不在默认路径", "Npcap 驱动在运行，但程序找不到 DLL", "环境变量/config.json/注册表/标准目录/vendor 多级发现"],
            ["回环链路类型", "回环包没有以太网头，直接按 Ethernet 解析会错位", "识别 DLT_NULL，读取 4 字节地址族后再进 IP 层"],
            ["QThread 生命周期", "关闭窗口时报 “Destroyed while thread is still running”", "停止标志 + pcap 超时/breakloop + wait + deleteLater"],
            ["校验和“错误”", "本机发出的包 TCP 校验和不正确", "标注可能是 checksum offload/截断，不当作致命错误"],
            ["进程归属 PID 0", "TIME_WAIT 行把包归到 System Idle Process", "跳过 PID≤0；只对真实进程显示"],
            ["系统进程拒绝访问", "OpenProcess 失败", "显示 PID（拒绝访问），继续处理其他进程"],
            ["pcapng 读取", "纯 Python 只支持经典 pcap", "检测 magic 后回退到 Npcap pcap_open_offline"],
            ["高 DPI 下 Hex 对齐", "ASCII 列被挤出视图", "按逻辑 DPI 动态调整 Hex 字体，按字符宽度布局"],
            ["大流量界面卡顿", "每包一次信号/插入导致事件循环过载", "worker 批量入队，GUI 100ms 批量插入，队列有界"],
        ],
        widths=[3.6, 6.2, 6.6],
    )

    # ---------------- 11 ----------------
    r.h1("11  不足与改进方向")
    for text in (
        "**TLS 解密**：目前只解析握手元数据（SNI/ALPN/版本）。可支持 SSLKEYLOGFILE 或用户导入私钥，"
        "在合法授权场景下解密 HTTP/2；这也需要明确隐私与合规边界。",
        "**HTTP/2 与 QUIC**：当前把 HTTP/2 作为 HTTP 标记，未解析二进制帧；QUIC 只解析长头。"
        "后续可增加 HTTP/2 frame、QPACK 和 QUIC Initial 解密。",
        "**IP 分片重组**：目前首片解析传输层、后续片归入 Data；完整重组可还原超大 UDP/TCP 载荷。",
        "**TCP 分析**：可增加重传、乱序、零窗口、Keep-Alive、RST 原因等 `tcp.analysis.*` 字段，"
        "并在时序图上用不同颜色标记。",
        "**协议插件化**：把 dissector 注册表做成 entry point，让新增协议无需改 `app.py`；"
        "对工业协议/工控安全课程尤其有用。",
        "**性能**：Python 解析在 1 Gbps 以上会成为瓶颈；可引入 C 扩展、PF_RING/eBPF/XDP 或把解析下沉到内核。"
        "当前实现定位是教学与中小流量分析。",
        "**pcapng 写入、HTTP 对象导出、GeoIP、TLS 证书解析**：都是低风险、高价值的增量功能。",
        "**安全与隐私**：抓包可能包含密码、Cookie、个人信息；程序应在首次启动时提示授权，"
        "并提供“脱敏显示/保存”选项。",
    ):
        r.bullet(text)

    # ---------------- 12 ----------------
    r.h1("12  总结")
    r.para(
        "本实验从零实现了一个可用的带 GUI 网络嗅探器：底层用 ctypes 绑定 Npcap，完成网卡枚举、BPF、"
        "实时抓包和 pcap 读写；中间层用自研解析器构造协议树，覆盖链路、网络、传输和常见应用层协议；"
        "上层用 PyQt5 实现三窗格、协议过滤、流追踪、时序图和统计。工程上通过工作线程、有界队列、批量插入、"
        "异常保护和单元测试，保证了程序在真实流量下的可用性与可验证性。"
    )
    r.para(
        "更重要的是，实验把“抓包层次”和“分析层次”真正拆开了：我能在同一个界面里看到 Ethernet/IP/TCP 的"
        "原始字节、HTTP 的请求行、TLS 的 SNI，也能明确知道哪些内容因为加密或权限而不可见。"
        "对 Thor 思考题的回答、对应用层协议识别方法的整理，以及进程归属的实现，都让我更清楚地理解了"
        "网络安全的观测边界：工具能看到什么，取决于它站在哪一层、拥有什么权限、是否掌握密钥。"
    )

    # ---------------- 13 ----------------
    r.page_break()
    r.h1("13  参考资料")
    refs = [
        "libpcap 官方仓库与文档：https://github.com/the-tcpdump-group/libpcap",
        "Npcap 官方站点与 API 文档：https://npcap.com/",
        "Wireshark Display Filter Reference：https://www.wireshark.org/docs/dfref/",
        "RFC 9110 / RFC 9112：HTTP Semantics / HTTP/1.1",
        "RFC 1035：Domain Names — Implementation and Specification",
        "RFC 9293：Transmission Control Protocol (TCP)",
        "RFC 8446：The Transport Layer Security (TLS) Protocol Version 1.3",
        "RFC 8200：Internet Protocol, Version 6 (IPv6) Specification",
        "Microsoft Learn：GetExtendedTcpTable / GetExtendedUdpTable / QueryFullProcessImageNameW",
        "BPF 官方站点：https://ebpf.io/；BPF 中文教程：https://github.com/eunomia-bpf/bpf-developer-tutorial",
        "deepwiki / arthurchiao 网络协议栈文章：http://arthurchiao.art/articles-zh/",
        "PyQt5 文档：https://www.riverbankcomputing.com/static/Docs/PyQt5/",
    ]
    for index, ref in enumerate(refs, 1):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.8)
        p.paragraph_format.first_line_indent = Cm(-0.8)
        p.paragraph_format.space_after = Pt(1)
        run = p.add_run(f"[{index}] ")
        set_run_font(run, size=9.5, bold=True, color=MUTED)
        run = p.add_run(ref)
        set_run_font(run, size=9.5)

    # ---------------- appendix A ----------------
    r.page_break()
    r.h1("附录 A  运行、测试与提交")
    r.h2("A.1  安装与运行")
    r.code(
        """# 1) 安装 Npcap（https://npcap.com/#download），建议勾选 WinPcap 兼容模式
# 2) 安装 Python 依赖
python -m pip install -r requirements.txt

# 3) 启动主程序
python main.py

# 4) 直接打开示例 pcap
python main.py --pcap samples\\demo.pcap

# 5) 实时回环演示（自动启动 http.server 并抓包/截图）
python tools\\live_demo.py

# 6) 运行单元测试
python -m pytest
"""
    )
    r.para(
        "如果 wpcap.dll 不在默认位置，可设置环境变量 `NETSNIFF_WPCAP`，或在源码目录创建 "
        "`config.json`：`{\"wpcap_path\": \"C:\\path\\to\\wpcap.dll\"}`。"
        "程序也支持从 Windows 注册表的 Npcap InstallDir 自动发现。"
    )
    r.h2("A.2  快捷键")
    r.table(
        ["快捷键", "功能"],
        [
            ["Ctrl+R / Ctrl+E", "开始 / 停止捕获"],
            ["Ctrl+O / Ctrl+S", "打开 pcap / 保存全部"],
            ["Ctrl+L", "清空会话"],
            ["Ctrl+K", "捕获选项"],
            ["Ctrl+T", "统计"],
            ["Ctrl+F / Ctrl+G", "查找 / 查找下一个"],
            ["Ctrl+Shift+O", "打开选中的 TCP 流"],
            ["Ctrl+Shift+L", "清除显示过滤器"],
            ["Ctrl+Shift+D", "切换深/浅色主题"],
            ["F1", "显示过滤器语法"],
        ],
        widths=[4.0, 12.2],
    )
    r.h2("A.3  Git 仓库与提交目录")
    r.para(
        f"代码仓库：{GIT_URL}。仓库中包含本实验的完整源码、报告和演示视频。"
        "推荐提交信息：`feat: initial packet sniffer`、`feat: protocol dissectors and display filters`、"
        "`feat: PyQt5 three-pane GUI and stream view`、`test: add 54 unit tests and demo capture`、"
        "`docs: add report and screenshots`。"
    )
    r.para(
        f"提交目录结构：`{NAME}_{STUDENT_ID}_EX1A/` 下包含 `{NAME}_{STUDENT_ID}_ex1A_src/`、"
        f"`{NAME}_{STUDENT_ID}_ex1A_play.mp4`、`{NAME}_{STUDENT_ID}_ex1A_report.docx`（或 PDF）。"
        "按课程要求提交 ZIP，不要使用 rar/7zip，也不要加密。"
    )

    # ---------------- appendix B ----------------
    r.h1("附录 B  代码统计与文件清单")
    py_files = sorted(ROOT.glob("netsniff/**/*.py"))
    test_files = sorted(ROOT.glob("tests/**/*.py"))
    tool_files = sorted(ROOT.glob("tools/**/*.py"))

    def line_count(files):
        total = 0
        for path in files:
            try:
                total += sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
            except OSError:
                pass
        return total

    r.table(
        ["范围", "Python 文件数", "代码行数（含空行）"],
        [
            ["netsniff/（产品代码）", str(len(py_files)), str(line_count(py_files))],
            ["tests/（单元测试）", str(len(test_files)), str(line_count(test_files))],
            ["tools/（构包/截图/报告）", str(len(tool_files)), str(line_count(tool_files))],
        ],
        widths=[6.4, 4.4, 5.4],
    )
    r.para(
        "完整文件清单见源码目录；示例捕获 `samples/demo.pcap`（40 包）与 `samples/live_loopback.pcap`"
        "（130 包，回环真实流量）随源码提供，便于评审在没有 Npcap 或没有网络的情况下复现界面与统计结果。"
    )

    r.save(OUT)
    return OUT


if __name__ == "__main__":
    path = build()
    print("wrote", path, path.stat().st_size, "bytes")
