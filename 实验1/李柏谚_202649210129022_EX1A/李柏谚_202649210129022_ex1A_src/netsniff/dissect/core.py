"""Top-level frame dissection entry point."""

from __future__ import annotations

import struct
from typing import Optional

from ..model import ParseContext, Packet
from . import arp, ethernet, icmp, ip, tcp, udp
from .utils import ETHERTYPES, IP_PROTOS, ipv4_str, ipv6_str, mac_str


def add_data_layer(ctx: ParseContext, offset: int, length: int, title: str = "Data") -> None:
    if offset < 0 or length <= 0 or offset >= len(ctx.raw):
        return
    length = min(length, len(ctx.raw) - offset)
    ctx.begin_layer(title, "data", offset, length, summary=f"{length} bytes")
    ctx.add("data.data", "Data", length, offset, length, display=f"{length} bytes")
    ctx.add("data.len", "Length", length, offset, length)
    ctx.end_layer()


def dissect_packet(
    raw: bytes,
    number: int,
    ts: float,
    wirelen: Optional[int] = None,
    linktype: int = 1,
) -> Packet:
    if wirelen is None:
        wirelen = len(raw)
    ctx = ParseContext(raw, number, ts, int(wirelen), int(linktype))
    try:
        _dissect_link(ctx, int(linktype))
    except Exception as exc:  # never let a malformed frame kill the capture
        while ctx._current is not None:
            ctx.end_layer()
        ctx.error(f"解析异常: {type(exc).__name__}: {exc}")
        if not ctx.layers:
            add_data_layer(ctx, 0, len(raw), "Raw Data")
    if not ctx.layers:
        add_data_layer(ctx, 0, len(raw), "Raw Data")
        ctx.protocol = "Data"
        ctx.info = f"{len(raw)} bytes"
    return ctx.finish()


def _dissect_link(ctx: ParseContext, linktype: int) -> None:
    data = ctx.raw
    if linktype == 1:  # DLT_EN10MB
        ethernet.dissect_ethernet(ctx, 0)
    elif linktype == 0:  # DLT_NULL / loopback
        if len(data) >= 4:
            family = struct.unpack("<I", data[:4])[0]
            family_name = {2: "AF_INET", 23: "AF_INET6", 24: "AF_INET6",
                           28: "AF_INET6", 30: "AF_INET6"}.get(family, str(family))
            ctx.begin_layer("Null/Loopback", "null", 0, 4, summary=family_name)
            ctx.add("null.family", "Family", family, 0, 4, display=family_name)
            ctx.end_layer()
            if family == 2:
                ip.dissect_ipv4(ctx, 4)
            elif family in (23, 24, 28, 30):
                ip.dissect_ipv6(ctx, 4)
            else:
                add_data_layer(ctx, 4, len(data) - 4, "Loopback Data")
                ctx.protocol = "Loopback"
                ctx.info = f"Loopback family {family_name}"
        else:
            add_data_layer(ctx, 0, len(data), "Loopback Data")
    elif linktype == 12:  # DLT_RAW
        if data:
            if data[0] >> 4 == 6:
                ip.dissect_ipv6(ctx, 0)
            elif data[0] >> 4 == 4:
                ip.dissect_ipv4(ctx, 0)
            else:
                add_data_layer(ctx, 0, len(data), "Raw IP Data")
    elif linktype == 113:  # DLT_LINUX_SLL
        if len(data) >= 16:
            pkt_type = (data[0] << 8) | data[1]
            arphrd = (data[2] << 8) | data[3]
            addr_len = (data[4] << 8) | data[5]
            addr = data[6:14]
            proto = (data[14] << 8) | data[15]
            ctx.begin_layer("Linux cooked capture", "sll", 0, 16, summary=f"Protocol: {ETHERTYPES.get(proto, hex(proto))}")
            ctx.add("sll.pkttype", "Packet Type", pkt_type, 0, 2)
            ctx.add("sll.hatype", "Link-layer Address Type", arphrd, 2, 2)
            ctx.add("sll.halen", "Link-layer Address Length", addr_len, 4, 2)
            ctx.add("sll.src", "Source", mac_str(addr), 6, 8)
            ctx.add("sll.protocol", "Protocol", proto, 14, 2,
                    display=f"{ETHERTYPES.get(proto, 'Unknown')} (0x{proto:04x})")
            ctx.end_layer()
            ethernet._dispatch_ethertype(ctx, proto, 16)
        else:
            add_data_layer(ctx, 0, len(data), "Linux cooked capture")
    elif linktype == 276:  # DLT_LINUX_SLL2
        if len(data) >= 20:
            proto = (data[0] << 8) | data[1]
            ctx.begin_layer("Linux cooked capture v2", "sll2", 0, 20,
                            summary=f"Protocol: {ETHERTYPES.get(proto, hex(proto))}")
            ctx.add("sll2.protocol", "Protocol", proto, 0, 2,
                    display=f"{ETHERTYPES.get(proto, 'Unknown')} (0x{proto:04x})")
            ctx.add("sll2.ifindex", "Interface Index", int.from_bytes(data[4:8], "big"), 4, 4)
            ctx.add("sll2.hatype", "Link-layer Address Type", (data[8] << 8) | data[9], 8, 2)
            ctx.end_layer()
            ethernet._dispatch_ethertype(ctx, proto, 20)
        else:
            add_data_layer(ctx, 0, len(data), "Linux cooked capture v2")
    elif linktype in (105, 127):  # 802.11 / radiotap
        offset = 0
        if linktype == 127 and len(data) >= 8:
            radiotap_len = struct.unpack_from("<H", data, 2)[0]
            ctx.begin_layer("Radiotap", "radiotap", 0, radiotap_len)
            ctx.add("radiotap.version", "Version", data[0], 0, 1)
            ctx.add("radiotap.length", "Header Length", radiotap_len, 2, 2)
            ctx.add("radiotap.present", "Present Flags", int.from_bytes(data[4:8], "little"), 4, 4,
                    display=f"0x{int.from_bytes(data[4:8], 'little'):08x}")
            ctx.end_layer()
            offset = radiotap_len
        add_data_layer(ctx, offset, len(data) - offset, "IEEE 802.11 frame")
        ctx.protocol = "802.11"
        ctx.info = "IEEE 802.11 frame (只需解析到 MAC 层即可)"
    else:
        add_data_layer(ctx, 0, len(data), f"Link type {linktype} data")
        ctx.protocol = "Unknown"
        ctx.info = f"Unsupported link type {linktype} ({len(data)} bytes)"
