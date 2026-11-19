"""TCP dissection and application protocol dispatch."""

from __future__ import annotations

from ..model import COLOR_TCP, ParseContext, TcpMeta
from .utils import (
    TCP_FLAG_NAMES,
    service_name,
    tcp_flags_bracket,
    tcp_flags_text,
    verify_transport_checksum,
)


def dissect_tcp(
    ctx: ParseContext,
    off: int,
    end: int,
    version: int,
    src_raw: bytes,
    dst_raw: bytes,
    fragmented: bool = False,
) -> None:
    data = ctx.raw
    if end - off < 20:
        ctx.begin_layer("Transmission Control Protocol", "tcp", off, max(0, end - off))
        ctx.add("tcp.srcport", "Source Port", 0, off, 0, display="[truncated]")
        ctx.end_layer()
        ctx.error("TCP 头部被截断")
        ctx.protocol = "TCP"
        return

    sport = (data[off] << 8) | data[off + 1]
    dport = (data[off + 2] << 8) | data[off + 3]
    seq = int.from_bytes(data[off + 4:off + 8], "big")
    ack = int.from_bytes(data[off + 8:off + 12], "big")
    offset_flags = (data[off + 12] << 8) | data[off + 13]
    header_len = ((offset_flags >> 12) & 0x0F) * 4
    flags = offset_flags & 0x01FF
    window = (data[off + 14] << 8) | data[off + 15]
    checksum = (data[off + 16] << 8) | data[off + 17]
    urgent = (data[off + 18] << 8) | data[off + 19]

    if header_len < 20 or off + header_len > end:
        ctx.error(f"TCP 数据偏移非法: {header_len}")
        header_len = 20
    payload_off = off + header_len
    payload = data[payload_off:end] if payload_off < end else b""
    payload_len = len(payload)
    src_name = service_name(sport)
    dst_name = service_name(dport)

    layer = ctx.begin_layer(
        "Transmission Control Protocol",
        "tcp",
        off,
        header_len,
        summary=f"Src Port: {sport}, Dst Port: {dport}, Seq: {seq}, Ack: {ack}, Len: {payload_len}",
    )
    ctx.add("tcp.srcport", "Source Port", sport, off, 2,
            display=f"{sport} ({src_name})" if src_name else str(sport))
    ctx.add("tcp.dstport", "Destination Port", dport, off + 2, 2,
            display=f"{dport} ({dst_name})" if dst_name else str(dport))
    ctx.add("tcp.seq", "Sequence Number", seq, off + 4, 4)
    ctx.add("tcp.ack", "Acknowledgment Number", ack, off + 8, 4)
    ctx.add("tcp.hdr_len", "Header Length", header_len, off + 12, 1, display=f"{header_len} bytes")
    flags_item = ctx.group("tcp.flags", "Flags", flags, off + 12, 2,
                           display=f"0x{flags:03x} ({tcp_flags_text(flags)})")
    for bit, name in TCP_FLAG_NAMES:
        key = "tcp.flags." + name.lower()
        ctx.child(flags_item, key, name, bool(flags & bit), off + 12, 2)
    ctx.add("tcp.window_size_value", "Window", window, off + 14, 2)
    checksum_field = ctx.add("tcp.checksum", "Checksum", checksum, off + 16, 2,
                             display=f"0x{checksum:04x}")
    ctx.add("tcp.urgent_pointer", "Urgent Pointer", urgent, off + 18, 2)
    ctx.add("tcp.len", "TCP Segment Len", payload_len, payload_off, payload_len)

    options = _dissect_options(ctx, data, off, header_len)
    ctx.end_layer()

    checksum_ok = None
    truncated = end >= len(data) and ctx.wirelen > len(data)
    if not fragmented and not truncated and end - off >= header_len:
        segment = data[off:end]
        checksum_ok = verify_transport_checksum(version, src_raw, dst_raw, 6, segment)
        checksum_field.display = f"0x{checksum:04x} " + (
            "[correct]" if checksum_ok else "[incorrect]"
        )
        if checksum_ok is False:
            ctx.warn("TCP 校验和错误（可能是网卡校验和卸载或抓包截断）")

    ctx.protocol = "TCP"
    ctx.color = COLOR_TCP
    ctx.info = (
        f"{sport} → {dport} {tcp_flags_bracket(flags)} "
        f"Seq={seq} Ack={ack} Win={window} Len={payload_len}"
    )
    ctx.tcp = TcpMeta(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        header_len=header_len,
        payload=payload,
        payload_offset=payload_off,
        options=options,
        checksum_ok=checksum_ok,
    )

    if payload_len <= 0:
        return

    from . import app

    handled = app.dissect_tcp_payload(ctx, payload, payload_off, sport, dport)
    if not handled:
        from .core import add_data_layer

        add_data_layer(ctx, payload_off, payload_len, f"TCP payload ({payload_len} bytes)")


def _dissect_options(ctx: ParseContext, data: bytes, off: int, header_len: int) -> dict:
    """Parse TCP options; returns the few values the stream analysis needs."""
    result: dict = {}
    if header_len <= 20 or off + header_len > len(data):
        return result
    start = off + 20
    end = off + header_len
    group = ctx.group("tcp.options", "Options", "", start, header_len - 20)
    i = start
    while i < end:
        kind = data[i]
        if kind == 0:
            ctx.child(group, "tcp.options.eol", "End of Option List", True, i, 1)
            break
        if kind == 1:
            ctx.child(group, "tcp.options.nop", "No-Operation", True, i, 1)
            i += 1
            continue
        if i + 1 >= end:
            ctx.child(group, "tcp.options.malformed", "Malformed Option", kind, i, 1)
            break
        length = data[i + 1]
        if length < 2 or i + length > end:
            ctx.child(group, "tcp.options.malformed", "Malformed Option", kind, i, min(2, end - i))
            break
        value = data[i + 2:i + length]
        if kind == 2 and length == 4:
            mss = int.from_bytes(value, "big")
            ctx.child(group, "tcp.options.mss_val", "Maximum Segment Size", mss, i, length)
            result["mss"] = mss
        elif kind == 3 and length == 3:
            shift = value[0]
            ctx.child(group, "tcp.options.wscale", "Window Scale", shift, i, length)
            result["wscale"] = shift
        elif kind == 4 and length == 2:
            ctx.child(group, "tcp.options.sack_perm", "SACK Permitted", True, i, length)
            result["sack_perm"] = True
        elif kind == 5:
            ctx.child(group, "tcp.options.sack", "SACK", value.hex(), i, length)
            result["sack"] = value
        elif kind == 8 and length == 10:
            tsval = int.from_bytes(value[0:4], "big")
            tsecr = int.from_bytes(value[4:8], "big")
            child = ctx.child(group, "tcp.options.timestamp", "Timestamps", "", i, length)
            ctx.child(child, "tcp.options.timestamp.tsval", "Timestamp value", tsval, i + 2, 4)
            ctx.child(child, "tcp.options.timestamp.tsecr", "Timestamp echo reply", tsecr, i + 6, 4)
            result["tsval"] = tsval
            result["tsecr"] = tsecr
        elif kind == 30 and length == 4:
            ctx.child(group, "tcp.options.mptcp", "Multipath TCP", value.hex(), i, length)
        else:
            ctx.child(group, "tcp.options.unknown", f"Option {kind}", value.hex(), i, length)
        i += length
    return result
