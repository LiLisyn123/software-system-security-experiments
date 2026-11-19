"""ICMP and ICMPv6 dissection."""

from __future__ import annotations

from ..model import COLOR_ICMP, ParseContext
from .utils import checksum16, ipv4_str, ipv6_str, mac_str, verify_checksum, verify_transport_checksum


ICMPV4_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    4: "Source quench",
    5: "Redirect",
    8: "Echo (ping) request",
    9: "Router advertisement",
    10: "Router solicitation",
    11: "Time-to-live exceeded",
    12: "Parameter problem",
    13: "Timestamp request",
    14: "Timestamp reply",
    15: "Information request",
    16: "Information reply",
    17: "Address mask request",
    18: "Address mask reply",
    30: "Traceroute",
}

ICMPV4_CODES = {
    3: {
        0: "Network unreachable",
        1: "Host unreachable",
        2: "Protocol unreachable",
        3: "Port unreachable",
        4: "Fragmentation needed but DF set",
        5: "Source route failed",
        6: "Destination network unknown",
        7: "Destination host unknown",
        9: "Network administratively prohibited",
        10: "Host administratively prohibited",
        13: "Communication administratively prohibited",
    },
    11: {0: "Time to live exceeded in transit", 1: "Fragment reassembly time exceeded"},
    12: {0: "Pointer indicates the error", 1: "Missing a required option", 2: "Bad length"},
}

ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    4: "Parameter problem",
    128: "Echo (ping) request",
    129: "Echo (ping) reply",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbor solicitation",
    136: "Neighbor advertisement",
    137: "Redirect",
    143: "MLDv2 report",
    155: "Home Agent address discovery request",
    156: "Home Agent address discovery reply",
    157: "Mobile prefix solicitation",
    158: "Mobile prefix advertisement",
}

ICMPV6_CODES = {
    1: {
        0: "No route to destination",
        1: "Communication with destination administratively prohibited",
        2: "Beyond scope of source address",
        3: "Address unreachable",
        4: "Port unreachable",
        5: "Source address failed ingress/egress policy",
        6: "Reject route to destination",
    },
    3: {0: "Hop limit exceeded in transit", 1: "Fragment reassembly time exceeded"},
    4: {0: "Erroneous header field", 1: "Unrecognized Next Header", 2: "Unrecognized Option"},
}


def dissect_icmp(
    ctx: ParseContext,
    off: int,
    end: int,
    version: int = 4,
    src_raw: bytes = b"",
    dst_raw: bytes = b"",
) -> None:
    data = ctx.raw
    if end - off < 4:
        ctx.begin_layer("Internet Control Message Protocol", "icmp" if version == 4 else "icmpv6",
                        off, max(0, end - off))
        ctx.error("ICMP 头部被截断")
        ctx.protocol = "ICMP" if version == 4 else "ICMPv6"
        return

    icmp_type = data[off]
    code = data[off + 1]
    checksum = (data[off + 2] << 8) | data[off + 3]
    prefix = "icmp" if version == 4 else "icmpv6"
    type_name = (ICMPV4_TYPES if version == 4 else ICMPV6_TYPES).get(
        icmp_type, f"Unknown ({icmp_type})"
    )
    code_name = (ICMPV4_CODES if version == 4 else ICMPV6_CODES).get(icmp_type, {}).get(code)

    layer = ctx.begin_layer(
        "Internet Control Message Protocol" if version == 4 else "Internet Control Message Protocol v6",
        prefix,
        off,
        min(end - off, 8),
        summary=f"Type: {type_name}, Code: {code}",
    )
    ctx.add(prefix + ".type", "Type", icmp_type, off, 1, display=f"{type_name} ({icmp_type})")
    ctx.add(prefix + ".code", "Code", code, off + 1, 1,
            display=f"{code_name} ({code})" if code_name else str(code))
    checksum_field = ctx.add(prefix + ".checksum", "Checksum", checksum, off + 2, 2,
                             display=f"0x{checksum:04x}")

    if version == 4:
        checksum_ok = _verify_icmp_checksum(data[off:end])
    else:
        checksum_ok = _verify_icmpv6_checksum(src_raw, dst_raw, data[off:end]) if src_raw else None
    if checksum_ok is not None:
        checksum_field.display += " " + ("[correct]" if checksum_ok else "[incorrect]")
        if not checksum_ok:
            ctx.warn(f"{prefix.upper()} 校验和错误（可能是校验和卸载或抓包截断）")

    if version == 4:
        _dissect_icmpv4_body(ctx, off, end, icmp_type, code, type_name, code_name, prefix)
    else:
        _dissect_icmpv6_body(ctx, off, end, icmp_type, code, type_name, code_name, prefix)

    ctx.end_layer()
    ctx.protocol = "ICMP" if version == 4 else "ICMPv6"
    ctx.color = COLOR_ICMP


def _dissect_icmpv4_body(ctx, off, end, icmp_type, code, type_name, code_name, prefix) -> None:
    data = ctx.raw
    if icmp_type in (0, 8, 13, 14, 15, 16, 17, 18):
        ident = (data[off + 4] << 8) | data[off + 5] if end - off >= 8 else 0
        seq = (data[off + 6] << 8) | data[off + 7] if end - off >= 8 else 0
        ctx.add(prefix + ".ident", "Identifier", ident, off + 4, 2, display=f"0x{ident:04x}")
        ctx.add(prefix + ".seq", "Sequence Number", seq, off + 6, 2,
                display=f"{seq} ({seq >> 8}*256+{seq & 0xFF})")
        if icmp_type in (0, 8):
            ctx.info = f"{type_name}  id=0x{ident:04x}, seq={seq}, ttl={ctx.ip.ttl if ctx.ip else '?'}"
        else:
            ctx.info = f"{type_name}  id=0x{ident:04x}, seq={seq}"
        return

    if icmp_type in (3, 4, 5, 11, 12):
        ctx.add(prefix + ".unused", "Unused", int.from_bytes(data[off + 4:off + 8], "big"),
                off + 4, max(0, min(4, end - off - 4)))
        if code_name:
            ctx.info = f"{type_name} ({code_name})"
        else:
            ctx.info = type_name
        # Parse the embedded original IP header so the user can see the flow
        # that triggered the error.
        emb = off + 8
        if emb + 20 <= end:
            ver = data[emb] >> 4
            if ver == 4:
                emb_src = ipv4_str(data[emb + 12:emb + 16])
                emb_dst = ipv4_str(data[emb + 16:emb + 20])
                ctx.add(prefix + ".embedded.ip.src", "Embedded Source Address", emb_src, emb + 12, 4)
                ctx.add(prefix + ".embedded.ip.dst", "Embedded Destination Address", emb_dst, emb + 16, 4)
                ctx.info += f"  [{emb_src} → {emb_dst}]"
        return

    ctx.info = type_name
    ctx.add(prefix + ".rest", "Rest of Header", data[off + 4:off + 8].hex(), off + 4,
            max(0, min(4, end - off - 4)))


def _dissect_icmpv6_body(ctx, off, end, icmp_type, code, type_name, code_name, prefix) -> None:
    data = ctx.raw
    if icmp_type in (128, 129):
        ident = (data[off + 4] << 8) | data[off + 5] if end - off >= 8 else 0
        seq = (data[off + 6] << 8) | data[off + 7] if end - off >= 8 else 0
        ctx.add(prefix + ".ident", "Identifier", ident, off + 4, 2, display=f"0x{ident:04x}")
        ctx.add(prefix + ".seq", "Sequence Number", seq, off + 6, 2)
        ctx.info = f"{type_name}  id=0x{ident:04x}, seq={seq}"
        return

    if icmp_type == 2:  # packet too big
        mtu = int.from_bytes(data[off + 4:off + 8], "big") if end - off >= 8 else 0
        ctx.add(prefix + ".mtu", "MTU", mtu, off + 4, 4)
        ctx.info = f"Packet too big (MTU={mtu})"
        return

    if icmp_type in (1, 3, 4):
        ctx.add(prefix + ".unused", "Unused", int.from_bytes(data[off + 4:off + 8], "big"),
                off + 4, max(0, min(4, end - off - 4)))
        ctx.info = f"{type_name}" + (f" ({code_name})" if code_name else "")
        return

    if icmp_type in (135, 136):  # neighbor solicitation / advertisement
        target = ipv6_str(data[off + 8:off + 24]) if end - off >= 24 else "::"
        ctx.add(prefix + ".target", "Target Address", target, off + 8, 16)
        if icmp_type == 136 and end - off >= 8:
            flags = data[off + 4]
            ctx.add(prefix + ".flags.router", "Router", bool(flags & 0x80), off + 4, 1)
            ctx.add(prefix + ".flags.solicited", "Solicited", bool(flags & 0x40), off + 4, 1)
            ctx.add(prefix + ".flags.override", "Override", bool(flags & 0x20), off + 4, 1)
            ctx.info = f"Neighbor Advertisement  {target}"
        else:
            ctx.info = f"Neighbor Solicitation  {target}"
        _add_options(ctx, off + 24, end, prefix)
        return

    if icmp_type == 134:  # router advertisement
        cur_hop = data[off + 4]
        flags = data[off + 5]
        lifetime = (data[off + 6] << 8) | data[off + 7]
        ctx.add(prefix + ".cur_hop_limit", "Cur Hop Limit", cur_hop, off + 4, 1)
        ctx.add(prefix + ".flags.managed", "Managed Address Configuration", bool(flags & 0x80), off + 5, 1)
        ctx.add(prefix + ".flags.other", "Other Configuration", bool(flags & 0x40), off + 5, 1)
        ctx.add(prefix + ".router_lifetime", "Router Lifetime", lifetime, off + 6, 2)
        if end - off >= 16:
            ctx.add(prefix + ".reachable_time", "Reachable Time",
                    int.from_bytes(data[off + 8:off + 12], "big"), off + 8, 4)
            ctx.add(prefix + ".retrans_timer", "Retrans Timer",
                    int.from_bytes(data[off + 12:off + 16], "big"), off + 12, 4)
        ctx.info = f"Router Advertisement  (lifetime={lifetime}s)"
        _add_options(ctx, off + 16, end, prefix)
        return

    if icmp_type == 133:
        ctx.info = "Router Solicitation"
        _add_options(ctx, off + 8, end, prefix)
        return

    ctx.info = type_name
    ctx.add(prefix + ".rest", "Rest of Header", data[off + 4:off + 8].hex(), off + 4,
            max(0, min(4, end - off - 4)))


def _add_options(ctx, off, end, prefix) -> None:
    """Parse ND/RA options (type, length in 8-byte units)."""
    data = ctx.raw
    pos = off
    group = None
    while pos + 2 <= end:
        opt_type = data[pos]
        length = data[pos + 1] * 8
        if length <= 0 or pos + length > end:
            break
        if group is None:
            group = ctx.group(prefix + ".options", "Options", "", pos, 0)
        names = {1: "Source Link-Layer Address", 2: "Target Link-Layer Address",
                 3: "Prefix Information", 5: "MTU"}
        child = ctx.child(group, prefix + f".option.{opt_type}", names.get(opt_type, f"Option {opt_type}"),
                          data[pos + 2:pos + length].hex(), pos, length)
        if opt_type in (1, 2) and length >= 8:
            mac = mac_str(data[pos + 2:pos + 8])
            child.value = mac
        elif opt_type == 5 and length >= 8:
            child.value = int.from_bytes(data[pos + 4:pos + 8], "big")
        elif opt_type == 3 and length >= 32:
            child.value = ipv6_str(data[pos + 16:pos + 32])
        pos += length


def _verify_icmp_checksum(data: bytes) -> bool:
    return ones_complement_ok(data)


def _verify_icmpv6_checksum(src_raw: bytes, dst_raw: bytes, data: bytes) -> bool:
    return verify_transport_checksum(6, src_raw, dst_raw, 58, data)


def ones_complement_ok(data: bytes) -> bool:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF
