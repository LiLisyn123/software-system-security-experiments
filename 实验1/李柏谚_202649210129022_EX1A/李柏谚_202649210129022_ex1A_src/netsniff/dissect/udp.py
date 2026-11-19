"""UDP dissection."""

from __future__ import annotations

from ..model import COLOR_UDP, ParseContext, UdpMeta
from .utils import service_name, verify_transport_checksum


def dissect_udp(
    ctx: ParseContext,
    off: int,
    end: int,
    version: int,
    src_raw: bytes,
    dst_raw: bytes,
    fragmented: bool = False,
) -> None:
    data = ctx.raw
    if end - off < 8:
        ctx.begin_layer("User Datagram Protocol", "udp", off, max(0, end - off))
        ctx.add("udp.srcport", "Source Port", 0, off, 0, display="[truncated]")
        ctx.end_layer()
        ctx.error("UDP 头部被截断")
        ctx.protocol = "UDP"
        return

    sport = (data[off] << 8) | data[off + 1]
    dport = (data[off + 2] << 8) | data[off + 3]
    length = (data[off + 4] << 8) | data[off + 5]
    checksum = (data[off + 6] << 8) | data[off + 7]
    payload_off = off + 8
    if length == 0:
        payload_end = end
        length = end - off
    else:
        payload_end = min(off + length, end)
    payload = data[payload_off:payload_end] if payload_off < payload_end else b""
    payload_len = len(payload)
    src_name = service_name(sport)
    dst_name = service_name(dport)

    layer = ctx.begin_layer(
        "User Datagram Protocol",
        "udp",
        off,
        8,
        summary=f"Source Port: {sport}, Destination Port: {dport}, Length: {length}",
    )
    ctx.add("udp.srcport", "Source Port", sport, off, 2,
            display=f"{sport} ({src_name})" if src_name else str(sport))
    ctx.add("udp.dstport", "Destination Port", dport, off + 2, 2,
            display=f"{dport} ({dst_name})" if dst_name else str(dport))
    ctx.add("udp.length", "Length", length, off + 4, 2)
    checksum_field = ctx.add("udp.checksum", "Checksum", checksum, off + 6, 2,
                             display=f"0x{checksum:04x}")
    ctx.add("udp.payload", "Payload Length", payload_len, payload_off, payload_len)
    ctx.end_layer()

    if length < 8:
        ctx.error(f"UDP 长度字段非法: {length}")
    elif length > end - off:
        ctx.warn(f"UDP 数据包被截断：声明 {length} 字节，实际 {end - off} 字节")

    truncated = end >= len(data) and ctx.wirelen > len(data)
    if fragmented or truncated or payload_end - off < 8:
        pass
    elif checksum == 0 and version == 4:
        checksum_field.display = "0x0000 [not computed]"
    else:
        ok = verify_transport_checksum(version, src_raw, dst_raw, 17, data[off:payload_end])
        checksum_field.display = f"0x{checksum:04x} " + ("[correct]" if ok else "[incorrect]")
        if not ok:
            ctx.warn("UDP 校验和错误（可能是网卡校验和卸载或抓包截断）")

    ctx.protocol = "UDP"
    ctx.color = COLOR_UDP
    ctx.info = f"{sport} → {dport} Len={payload_len}"
    ctx.udp = UdpMeta(
        sport=sport,
        dport=dport,
        length=length,
        payload=payload,
        payload_offset=payload_off,
    )

    if not payload:
        return

    from . import app

    handled = app.dissect_udp_payload(ctx, payload, payload_off, sport, dport)
    if not handled:
        from .core import add_data_layer

        add_data_layer(ctx, payload_off, payload_len, f"UDP payload ({payload_len} bytes)")
