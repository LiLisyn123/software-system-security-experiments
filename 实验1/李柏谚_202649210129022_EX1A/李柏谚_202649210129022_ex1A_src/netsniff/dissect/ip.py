"""IPv4 / IPv6 dissection (including extension headers and fragmentation)."""

from __future__ import annotations

import struct

from ..model import COLOR_IPV6, COLOR_OTHER, IpMeta, ParseContext
from .utils import (
    ETHERTYPES,
    IP_PROTOS,
    checksum16,
    ipv4_str,
    ipv6_str,
    verify_checksum,
)


def _add_data(ctx: ParseContext, offset: int, length: int, title: str = "Data") -> None:
    from .core import add_data_layer

    add_data_layer(ctx, offset, length, title)


def dissect_ipv4(ctx: ParseContext, off: int) -> None:
    data = ctx.raw
    if len(data) < off + 20:
        ctx.begin_layer("Internet Protocol Version 4", "ip", off, max(0, len(data) - off))
        ctx.add("ip.version", "Version", 4, off, 0, display="[truncated]")
        ctx.end_layer()
        ctx.error("IPv4 头部被截断")
        ctx.protocol = "IPv4"
        return

    version_ihl = data[off]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4:
        ctx.warn(f"IPv4 版本字段为 {version}")
    if ihl < 20 or off + ihl > len(data):
        ctx.error(f"IPv4 头长度非法: {ihl}")
        ihl = 20

    tos = data[off + 1]
    dscp = tos >> 2
    ecn = tos & 0x03
    total_len = (data[off + 2] << 8) | data[off + 3]
    ident = (data[off + 4] << 8) | data[off + 5]
    flags_frag = (data[off + 6] << 8) | data[off + 7]
    flags = (flags_frag >> 13) & 0x07
    frag_offset = flags_frag & 0x1FFF
    ttl = data[off + 8]
    proto = data[off + 9]
    checksum = (data[off + 10] << 8) | data[off + 11]
    src_raw = data[off + 12:off + 16]
    dst_raw = data[off + 16:off + 20]
    src = ipv4_str(src_raw)
    dst = ipv4_str(dst_raw)
    proto_name = IP_PROTOS.get(proto, f"Unknown ({proto})")

    header = data[off:off + ihl]
    checksum_ok = verify_checksum(header) if len(header) == ihl else None

    layer = ctx.begin_layer(
        "Internet Protocol Version 4",
        "ip",
        off,
        ihl,
        summary=f"Src: {src}, Dst: {dst}",
    )
    ctx.add("ip.version", "Version", version, off, 1)
    ctx.add("ip.hdr_len", "Header Length", ihl, off, 1, display=f"{ihl} bytes")
    ctx.add("ip.dsfield.dscp", "Differentiated Services Codepoint", dscp, off + 1, 1)
    ctx.add("ip.dsfield.ecn", "Explicit Congestion Notification", ecn, off + 1, 1)
    ctx.add("ip.len", "Total Length", total_len, off + 2, 2)
    ctx.add("ip.id", "Identification", ident, off + 4, 2, display=f"0x{ident:04x}")
    flags_item = ctx.group("ip.flags", "Flags", flags, off + 6, 1, display=f"0x{flags:02x}")
    ctx.child(flags_item, "ip.flags.rb", "Reserved bit", bool(flags & 0x4), off + 6, 1)
    ctx.child(flags_item, "ip.flags.df", "Don't fragment", bool(flags & 0x2), off + 6, 1)
    ctx.child(flags_item, "ip.flags.mf", "More fragments", bool(flags & 0x1), off + 6, 1)
    ctx.add("ip.frag_offset", "Fragment Offset", frag_offset * 8, off + 7, 2,
            display=f"{frag_offset * 8} bytes")
    ctx.add("ip.ttl", "Time to Live", ttl, off + 8, 1)
    ctx.add("ip.proto", "Protocol", proto, off + 9, 1, display=f"{proto_name} ({proto})")
    ctx.add("ip.checksum", "Header Checksum", checksum, off + 10, 2,
            display=f"0x{checksum:04x} " + ("[correct]" if checksum_ok else "[incorrect]"))
    ctx.add("ip.src", "Source Address", src, off + 12, 4)
    ctx.add("ip.dst", "Destination Address", dst, off + 16, 4)

    if ihl > 20:
        opt = data[off + 20:off + ihl]
        ctx.add("ip.options", "Options", opt, off + 20, len(opt), display=opt.hex(" "))

    ctx.end_layer()

    if checksum_ok is False:
        ctx.warn(f"IPv4 头校验和错误 (0x{checksum:04x})")

    available = len(data) - off
    if total_len == 0:
        total_len = available
        ctx.note("IPv4 total length 为 0，按实际捕获长度处理")
    elif total_len < ihl:
        ctx.error(f"IPv4 total length ({total_len}) 小于头部长度 ({ihl})")
        total_len = available
    elif total_len > available:
        ctx.warn(f"IPv4 数据包被截断：声明 {total_len} 字节，实际 {available} 字节")

    end = min(off + total_len, len(data))
    if end <= off + ihl:
        ctx.protocol = "IPv4"
        ctx.info = f"IPv4 {src} → {dst} (无载荷)"
        ctx.src, ctx.dst = src, dst
        ctx.ip = IpMeta(4, src, dst, proto, ttl, ident, ihl, total_len, bool(flags & 0x1) or frag_offset > 0)
        return

    l4 = off + ihl
    fragmented = bool(flags & 0x1) or frag_offset > 0
    ctx.ip = IpMeta(
        version=4,
        src=src,
        dst=dst,
        proto=proto,
        ttl=ttl,
        ident=ident,
        header_len=ihl,
        total_len=total_len,
        fragmented=fragmented,
    )
    ctx.src, ctx.dst = src, dst
    ctx.protocol = "IPv4"
    if not ctx.info:
        ctx.info = f"IPv4 {src} → {dst}  {proto_name}"

    if frag_offset > 0:
        ctx.info = f"IPv4 fragment (offset={frag_offset * 8}, id=0x{ident:04x})"
        ctx.protocol = "IPv4"
        _add_data(ctx, l4, end - l4, "IPv4 Fragment Data")
        return

    if flags & 0x1:
        ctx.warn(f"IPv4 分片：首片，后续数据可能不完整 (id=0x{ident:04x})")

    _dispatch_ip(ctx, proto, l4, end, version=4, src_raw=src_raw, dst_raw=dst_raw,
                 fragmented=fragmented)


def dissect_ipv6(ctx: ParseContext, off: int) -> None:
    data = ctx.raw
    if len(data) < off + 40:
        ctx.begin_layer("Internet Protocol Version 6", "ipv6", off, max(0, len(data) - off))
        ctx.add("ipv6.version", "Version", 6, off, 0, display="[truncated]")
        ctx.end_layer()
        ctx.error("IPv6 头部被截断")
        ctx.protocol = "IPv6"
        return

    first = (data[off] << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3]
    version = (first >> 28) & 0x0F
    traffic_class = (first >> 20) & 0xFF
    flow_label = first & 0xFFFFF
    payload_len = (data[off + 4] << 8) | data[off + 5]
    next_header = data[off + 6]
    hop_limit = data[off + 7]
    src_raw = data[off + 8:off + 24]
    dst_raw = data[off + 24:off + 40]
    src = ipv6_str(src_raw)
    dst = ipv6_str(dst_raw)

    layer = ctx.begin_layer(
        "Internet Protocol Version 6",
        "ipv6",
        off,
        40,
        summary=f"Src: {src}, Dst: {dst}",
    )
    ctx.add("ipv6.version", "Version", version, off, 1)
    ctx.add("ipv6.tclass", "Traffic Class", traffic_class, off, 2,
            display=f"0x{traffic_class:02x}")
    ctx.add("ipv6.flow", "Flow Label", flow_label, off + 1, 3, display=f"0x{flow_label:05x}")
    ctx.add("ipv6.plen", "Payload Length", payload_len, off + 4, 2)
    ctx.add("ipv6.nxt", "Next Header", next_header, off + 6, 1,
            display=f"{IP_PROTOS.get(next_header, 'Unknown')} ({next_header})")
    ctx.add("ipv6.hlim", "Hop Limit", hop_limit, off + 7, 1)
    ctx.add("ipv6.src", "Source Address", src, off + 8, 16)
    ctx.add("ipv6.dst", "Destination Address", dst, off + 24, 16)
    ctx.end_layer()

    ctx.src, ctx.dst = src, dst
    ctx.protocol = "IPv6"
    ctx.color = COLOR_IPV6
    ctx.info = f"IPv6 {src} → {dst}  {IP_PROTOS.get(next_header, 'Unknown')}"

    available = len(data) - (off + 40)
    if payload_len == 0:
        payload_len = available
    elif payload_len > available:
        ctx.warn(f"IPv6 数据包被截断：声明 {payload_len} 字节，实际 {available} 字节")
    end = min(off + 40 + payload_len, len(data))

    nh = next_header
    cur = off + 40
    fragmented = False
    while nh in (0, 43, 44, 51, 60):
        if cur + 8 > end:
            ctx.error("IPv6 扩展头被截断")
            break
        nh_next = data[cur]
        if nh == 44:  # fragment header
            frag_word = (data[cur + 2] << 8) | data[cur + 3]
            frag_offset = (frag_word >> 3) & 0x1FFF
            more = frag_word & 0x1
            ident = (data[cur + 4] << 24) | (data[cur + 5] << 16) | (data[cur + 6] << 8) | data[cur + 7]
            lb = ctx.begin_layer("IPv6 Fragment Header", "ipv6.fragment", cur, 8,
                                 summary=f"Offset: {frag_offset * 8}")
            ctx.add("ipv6.frag.offset", "Offset", frag_offset * 8, cur + 2, 2)
            ctx.add("ipv6.frag.more", "More Fragments", bool(more), cur + 3, 1)
            ctx.add("ipv6.frag.id", "Identification", ident, cur + 4, 4, display=f"0x{ident:08x}")
            ctx.end_layer()
            fragmented = True
            cur += 8
            nh = nh_next
            if frag_offset > 0:
                ctx.info = f"IPv6 fragment (offset={frag_offset * 8})"
                _add_data(ctx, cur, end - cur, "IPv6 Fragment Data")
                ctx.ip = IpMeta(6, src, dst, nh_next, hop_limit, ident, 40, payload_len, True)
                return
            continue
        if nh == 51:  # Authentication Header
            hdr_len = (data[cur + 1] + 2) * 4
            spi = int.from_bytes(data[cur + 4:cur + 8], "big")
            seq = int.from_bytes(data[cur + 8:cur + 12], "big") if hdr_len >= 12 else 0
            lb = ctx.begin_layer("Authentication Header", "ipv6.ah", cur, hdr_len)
            ctx.add("ipv6.ah.nxt", "Next Header", nh_next, cur, 1)
            ctx.add("ipv6.ah.len", "Payload Length", hdr_len, cur + 1, 1, display=f"{hdr_len} bytes")
            ctx.add("ipv6.ah.spi", "SPI", spi, cur + 4, 4, display=f"0x{spi:08x}")
            ctx.add("ipv6.ah.seq", "Sequence", seq, cur + 8, 4)
            ctx.end_layer()
            cur += hdr_len
            nh = nh_next
            continue
        if nh == 50:  # ESP: encrypted beyond the first eight bytes
            spi = int.from_bytes(data[cur:cur + 4], "big")
            seq = int.from_bytes(data[cur + 4:cur + 8], "big")
            lb = ctx.begin_layer("Encapsulating Security Payload", "ipv6.esp", cur, end - cur,
                                 summary="encrypted")
            ctx.add("ipv6.esp.spi", "SPI", spi, cur, 4, display=f"0x{spi:08x}")
            ctx.add("ipv6.esp.seq", "Sequence", seq, cur + 4, 4)
            ctx.end_layer()
            ctx.protocol = "ESP"
            ctx.info = f"ESP SPI=0x{spi:08x} Seq={seq} (加密载荷)"
            _add_data(ctx, min(cur + 8, end), max(0, end - cur - 8), "Encrypted Data")
            ctx.ip = IpMeta(6, src, dst, nh, hop_limit, 0, 40, payload_len, True)
            return
        # Hop-by-Hop (0), Routing (43), Destination Options (60)
        hdr_len = (data[cur + 1] + 1) * 4
        names = {0: ("Hop-by-Hop Options", "ipv6.hop"), 43: ("Routing Header", "ipv6.routing"),
                 60: ("Destination Options", "ipv6.dstopts")}
        name, key = names.get(nh, ("IPv6 Extension Header", "ipv6.ext"))
        lb = ctx.begin_layer(name, key, cur, hdr_len)
        ctx.add(key + ".nxt", "Next Header", nh_next, cur, 1)
        ctx.add(key + ".len", "Header Length", hdr_len, cur + 1, 1, display=f"{hdr_len} bytes")
        if nh == 43 and hdr_len >= 4:
            ctx.add("ipv6.routing.type", "Routing Type", data[cur + 2], cur + 2, 1)
            ctx.add("ipv6.routing.segleft", "Segments Left", data[cur + 3], cur + 3, 1)
        ctx.end_layer()
        cur += hdr_len
        nh = nh_next

    if cur >= end:
        ctx.protocol = "IPv6"
        ctx.info = f"IPv6 {src} → {dst} (无载荷)"
        ctx.ip = IpMeta(6, src, dst, nh, hop_limit, 0, 40, payload_len, fragmented)
        return

    ctx.ip = IpMeta(6, src, dst, nh, hop_limit, 0, 40, payload_len, fragmented)
    _dispatch_ip(ctx, nh, cur, end, version=6, src_raw=src_raw, dst_raw=dst_raw,
                 fragmented=fragmented)


def _dispatch_ip(
    ctx: ParseContext,
    proto: int,
    off: int,
    end: int,
    version: int,
    src_raw: bytes,
    dst_raw: bytes,
    fragmented: bool,
) -> None:
    from . import icmp, tcp, udp

    if proto == 6:
        tcp.dissect_tcp(ctx, off, end, version, src_raw, dst_raw, fragmented)
    elif proto == 17:
        udp.dissect_udp(ctx, off, end, version, src_raw, dst_raw, fragmented)
    elif proto == 1:
        icmp.dissect_icmp(ctx, off, end, version=4, src_raw=src_raw, dst_raw=dst_raw)
    elif proto == 58:
        icmp.dissect_icmp(ctx, off, end, version=6, src_raw=src_raw, dst_raw=dst_raw)
    elif proto == 2:
        _dissect_igmp(ctx, off, end)
    elif proto == 47:
        _dissect_gre(ctx, off, end)
    elif proto == 50:
        spi = int.from_bytes(ctx.raw[off:off + 4], "big") if off + 4 <= end else 0
        ctx.begin_layer("Encapsulating Security Payload", "esp", off, end - off,
                        summary=f"SPI: 0x{spi:08x}")
        ctx.add("esp.spi", "SPI", spi, off, 4, display=f"0x{spi:08x}")
        ctx.end_layer()
        ctx.protocol = "ESP"
        ctx.info = f"ESP SPI=0x{spi:08x} (加密载荷)"
        _add_data(ctx, min(off + 8, end), max(0, end - off - 8), "Encrypted Data")
    elif proto == 132:
        _dissect_sctp(ctx, off, end)
    else:
        name = IP_PROTOS.get(proto, f"Unknown ({proto})")
        ctx.protocol = "IPv4" if version == 4 else "IPv6"
        ctx.info = f"IPv{version} {ctx.src} → {ctx.dst}  {name}"
        _add_data(ctx, off, end - off, f"{name} Data")


def _dissect_igmp(ctx: ParseContext, off: int, end: int) -> None:
    data = ctx.raw
    length = min(8, end - off)
    lb = ctx.begin_layer("Internet Group Management Protocol", "igmp", off, length)
    if length >= 8:
        igmp_type = data[off]
        ctx.add("igmp.type", "Type", igmp_type, off, 1,
                display={0x11: "Membership Query", 0x12: "Membership Report v1",
                         0x16: "Membership Report v2", 0x17: "Leave Group",
                         0x22: "Membership Report v3"}.get(igmp_type, str(igmp_type)))
        ctx.add("igmp.max_resp", "Max Response Time", data[off + 1], off + 1, 1)
        ctx.add("igmp.checksum", "Checksum", (data[off + 2] << 8) | data[off + 3], off + 2, 2)
        ctx.add("igmp.group", "Group Address", ipv4_str(data[off + 4:off + 8]), off + 4, 4)
        ctx.protocol = "IGMP"
        ctx.info = "IGMP"
    ctx.end_layer()


def _dissect_gre(ctx: ParseContext, off: int, end: int) -> None:
    data = ctx.raw
    if end - off < 4:
        return
    flags_version = (data[off] << 8) | data[off + 1]
    proto = (data[off + 2] << 8) | data[off + 3]
    version = flags_version & 0x7
    has_checksum = bool(flags_version & 0x8000)
    has_key = bool(flags_version & 0x2000)
    has_seq = bool(flags_version & 0x1000)
    header_len = 4 + (4 if (has_checksum or has_key or has_seq) else 0)
    if has_seq:
        header_len += 4
    if has_checksum and has_key:
        header_len += 4
    lb = ctx.begin_layer("Generic Routing Encapsulation", "gre", off, min(header_len, end - off),
                         summary=f"Proto: {ETHERTYPES.get(proto, hex(proto))}")
    ctx.add("gre.flags", "Flags and Version", flags_version, off, 2, display=f"0x{flags_version:04x}")
    ctx.add("gre.proto", "Protocol Type", proto, off + 2, 2,
            display=f"{ETHERTYPES.get(proto, 'Unknown')} (0x{proto:04x})")
    pos = off + 4
    if has_checksum and pos + 4 <= end:
        ctx.add("gre.checksum", "Checksum", (data[pos] << 8) | data[pos + 1], pos, 2)
        ctx.add("gre.offset", "Reserved / Offset", (data[pos + 2] << 8) | data[pos + 3], pos + 2, 2)
        pos += 4
    if has_key and pos + 4 <= end:
        ctx.add("gre.key", "Key", int.from_bytes(data[pos:pos + 4], "big"), pos, 4)
        pos += 4
    if has_seq and pos + 4 <= end:
        ctx.add("gre.seq", "Sequence Number", int.from_bytes(data[pos:pos + 4], "big"), pos, 4)
        pos += 4
    ctx.end_layer()
    ctx.protocol = "GRE"
    ctx.info = f"GRE {ETHERTYPES.get(proto, hex(proto))}"
    if version != 0:
        _add_data(ctx, pos, end - pos, "GRE Payload")
        return
    from . import ethernet

    ethernet._dispatch_ethertype(ctx, proto, pos)


def _dissect_sctp(ctx: ParseContext, off: int, end: int) -> None:
    data = ctx.raw
    if end - off < 12:
        return
    sport = (data[off] << 8) | data[off + 1]
    dport = (data[off + 2] << 8) | data[off + 3]
    vtag = int.from_bytes(data[off + 4:off + 8], "big")
    checksum = int.from_bytes(data[off + 8:off + 12], "big")
    lb = ctx.begin_layer("Stream Control Transmission Protocol", "sctp", off, end - off,
                         summary=f"{sport} → {dport}")
    ctx.add("sctp.srcport", "Source Port", sport, off, 2)
    ctx.add("sctp.dstport", "Destination Port", dport, off + 2, 2)
    ctx.add("sctp.vtag", "Verification Tag", vtag, off + 4, 4, display=f"0x{vtag:08x}")
    ctx.add("sctp.checksum", "Checksum", checksum, off + 8, 4, display=f"0x{checksum:08x}")
    ctx.end_layer()
    ctx.protocol = "SCTP"
    ctx.info = f"SCTP {sport} → {dport}"
