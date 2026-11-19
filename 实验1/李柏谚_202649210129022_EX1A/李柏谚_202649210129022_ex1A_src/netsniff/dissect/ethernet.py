"""Ethernet II / VLAN dissection."""

from __future__ import annotations

from ..model import ParseContext
from .utils import ETHERTYPES, mac_str


VLAN_TPIDS = {0x8100, 0x88A8, 0x9100}


def dissect_ethernet(ctx: ParseContext, off: int = 0) -> None:
    data = ctx.raw
    if len(data) < off + 14:
        ctx.begin_layer("Ethernet II", "eth", off, max(0, len(data) - off))
        ctx.add("eth.dst", "Destination", "", off, 0, display="[truncated]")
        ctx.add("eth.src", "Source", "", off + 6, 0, display="[truncated]")
        ctx.add("eth.type", "Type", 0, off + 12, 0, display="[truncated]")
        ctx.end_layer()
        ctx.error("Ethernet 帧头被截断")
        ctx.protocol = "Ethernet"
        return

    dst = data[off:off + 6]
    src = data[off + 6:off + 12]
    ethertype = (data[off + 12] << 8) | data[off + 13]
    type_name = ETHERTYPES.get(ethertype, f"Unknown (0x{ethertype:04x})")

    layer = ctx.begin_layer(
        "Ethernet II",
        "eth",
        off,
        14,
        summary=f"Src: {mac_str(src)}, Dst: {mac_str(dst)}, Type: {type_name}",
    )
    ctx.add("eth.dst", "Destination", mac_str(dst), off, 6)
    ctx.add("eth.src", "Source", mac_str(src), off + 6, 6)
    ctx.add("eth.type", "Type", ethertype, off + 12, 2, display=f"{type_name} (0x{ethertype:04x})")
    ctx.end_layer()

    ctx.src = mac_str(src)
    ctx.dst = mac_str(dst)
    if ctx.protocol in ("", "Ethernet"):
        ctx.protocol = "Ethernet"

    next_off = off + 14
    # 802.1Q / QinQ tags: each tag is four bytes and repeats before the type.
    while ethertype in VLAN_TPIDS and len(data) >= next_off + 4:
        tci = (data[next_off] << 8) | data[next_off + 1]
        inner = (data[next_off + 2] << 8) | data[next_off + 3]
        vlan_id = tci & 0x0FFF
        prio = (tci >> 13) & 0x7
        dei = (tci >> 12) & 0x1
        vlan_name = "802.1Q Virtual LAN" if ethertype == 0x8100 else "802.1ad Service VLAN"
        ctx.begin_layer(vlan_name, "vlan", next_off, 4, summary=f"ID: {vlan_id}")
        ctx.add("vlan.priority", "Priority", prio, next_off, 1)
        ctx.add("vlan.dei", "DEI", dei, next_off, 1)
        ctx.add("vlan.id", "VLAN ID", vlan_id, next_off, 2)
        inner_name = ETHERTYPES.get(inner, f"Unknown (0x{inner:04x})")
        ctx.add("vlan.etype", "Type", inner, next_off + 2, 2,
                display=f"{inner_name} (0x{inner:04x})")
        ctx.end_layer()
        next_off += 4
        ethertype = inner

    _dispatch_ethertype(ctx, ethertype, next_off)


def _dispatch_ethertype(ctx: ParseContext, ethertype: int, off: int) -> None:
    from . import arp, ip

    if ethertype == 0x0800:
        ip.dissect_ipv4(ctx, off)
    elif ethertype == 0x86DD:
        ip.dissect_ipv6(ctx, off)
    elif ethertype == 0x0806:
        arp.dissect_arp(ctx, off)
    elif ethertype == 0x8863:
        ctx.begin_layer("PPPoE Discovery", "pppoed", off, 6)
        if len(ctx.raw) >= off + 6:
            ctx.add("pppoed.version_type", "Version and Type", ctx.raw[off])
            ctx.add("pppoed.code", "Code", ctx.raw[off + 1])
            ctx.add("pppoed.session_id", "Session ID", (ctx.raw[off + 2] << 8) | ctx.raw[off + 3])
            ctx.add("pppoed.length", "Payload Length", (ctx.raw[off + 4] << 8) | ctx.raw[off + 5])
        ctx.end_layer()
        ctx.protocol = "PPPoE"
        ctx.info = "PPPoE Discovery"
    else:
        # Unknown EtherType: keep the bytes visible as a Data layer.
        if off < len(ctx.raw):
            from .core import add_data_layer

            add_data_layer(ctx, off, len(ctx.raw) - off, f"Data ({len(ctx.raw) - off} bytes)")
            ctx.protocol = "Ethernet"
            ctx.info = f"EtherType 0x{ethertype:04x}"
