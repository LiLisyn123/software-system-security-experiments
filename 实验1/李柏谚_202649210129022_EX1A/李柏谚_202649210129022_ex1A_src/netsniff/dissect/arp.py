"""ARP / RARP dissection."""

from __future__ import annotations

from ..model import COLOR_ARP, ParseContext
from .utils import ipv4_str, mac_str


ARP_OPCODES = {
    1: "request",
    2: "reply",
    3: "RARP request",
    4: "RARP reply",
    8: "InARP request",
    9: "InARP reply",
}


def dissect_arp(ctx: ParseContext, off: int) -> None:
    data = ctx.raw
    if len(data) < off + 8:
        ctx.begin_layer("Address Resolution Protocol", "arp", off, max(0, len(data) - off))
        ctx.error("ARP 头部被截断")
        ctx.protocol = "ARP"
        return

    htype = (data[off] << 8) | data[off + 1]
    ptype = (data[off + 2] << 8) | data[off + 3]
    hlen = data[off + 4]
    plen = data[off + 5]
    opcode = (data[off + 6] << 8) | data[off + 7]
    fixed = 8
    need = fixed + 2 * hlen + 2 * plen
    if len(data) < off + need:
        ctx.begin_layer("Address Resolution Protocol", "arp", off, len(data) - off)
        ctx.add("arp.opcode", "Opcode", opcode, off + 6, 2)
        ctx.end_layer()
        ctx.error("ARP 地址字段被截断")
        ctx.protocol = "ARP"
        return

    sha = data[off + 8:off + 8 + hlen]
    spa = data[off + 8 + hlen:off + 8 + hlen + plen]
    tha = data[off + 8 + hlen + plen:off + 8 + 2 * hlen + plen]
    tpa = data[off + 8 + 2 * hlen + plen:off + need]
    sha_s = mac_str(sha)
    tha_s = mac_str(tha)
    spa_s = ipv4_str(spa)
    tpa_s = ipv4_str(tpa)
    op_name = ARP_OPCODES.get(opcode, str(opcode))

    ctx.begin_layer(
        "Address Resolution Protocol",
        "arp",
        off,
        need,
        summary=f"{op_name} {spa_s} → {tpa_s}",
    )
    ctx.add("arp.hw.type", "Hardware Type", htype, off, 2,
            display={1: "Ethernet (1)"}.get(htype, str(htype)))
    ctx.add("arp.proto.type", "Protocol Type", ptype, off + 2, 2,
            display={0x0800: "IPv4 (0x0800)"}.get(ptype, f"0x{ptype:04x}"))
    ctx.add("arp.hw.size", "Hardware Size", hlen, off + 4, 1)
    ctx.add("arp.proto.size", "Protocol Size", plen, off + 5, 1)
    ctx.add("arp.opcode", "Opcode", opcode, off + 6, 2, display=f"{op_name} ({opcode})")
    ctx.add("arp.src.hw_mac", "Sender MAC Address", sha_s, off + 8, hlen)
    ctx.add("arp.src.proto_ipv4", "Sender IP Address", spa_s, off + 8 + hlen, plen)
    ctx.add("arp.dst.hw_mac", "Target MAC Address", tha_s, off + 8 + hlen + plen, hlen)
    ctx.add("arp.dst.proto_ipv4", "Target IP Address", tpa_s, off + 8 + 2 * hlen + plen, plen)
    ctx.end_layer()

    ctx.src = sha_s
    ctx.dst = tha_s
    ctx.protocol = "ARP"
    ctx.color = COLOR_ARP
    if opcode == 1:
        ctx.info = f"Who has {tpa_s}? Tell {spa_s}"
    elif opcode == 2:
        ctx.info = f"{spa_s} is at {sha_s}"
    else:
        ctx.info = f"{op_name}: {spa_s} → {tpa_s}"
