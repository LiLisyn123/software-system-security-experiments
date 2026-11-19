"""DNS dissection (UDP, TCP and mDNS/LLMNR)."""

from __future__ import annotations

import struct
from typing import Optional

from ..model import COLOR_DNS, ParseContext
from .utils import ipv4_str, ipv6_str


DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX",
    16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA",
    33: "SRV", 35: "NAPTR", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS",
    44: "SSHFP", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    51: "NSEC3PARAM", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF",
    251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}

DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

DNS_OPCODES = {0: "Standard query", 1: "Inverse query", 2: "Server status request",
               4: "Notify", 5: "Update"}

DNS_RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name",
              4: "Not implemented", 5: "Refused", 6: "Name exists", 7: "RRset exists",
              8: "RRset does not exist", 9: "Not authoritative", 10: "Not zone"}


def dissect_dns(ctx: ParseContext, payload: bytes, offset: int, tcp: bool = False) -> bool:
    """Parse a DNS message.  ``tcp`` means the two-byte length prefix is present."""
    data = payload
    base = offset
    if tcp:
        if len(data) < 2:
            return False
        length = (data[0] << 8) | data[1]
        data = data[2:2 + length]
        base += 2
    if len(data) < 12:
        return False

    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    ad = (flags >> 5) & 1
    cd = (flags >> 4) & 1
    rcode = flags & 0xF
    opcode_name = DNS_OPCODES.get(opcode, f"Opcode {opcode}")
    query_kind = "response" if qr else "query"
    rcode_name = DNS_RCODES.get(rcode, f"Rcode {rcode}")

    layer = ctx.begin_layer(
        "Domain Name System",
        "dns",
        base,
        len(data),
        summary="response" if qr else "query",
    )
    ctx.add("dns.id", "Transaction ID", ident, base, 2, display=f"0x{ident:04x}")
    ctx.add("dns.flags", "Flags", flags, base + 2, 2, display=f"0x{flags:04x}")
    ctx.add("dns.flags.response", "Response", bool(qr), base + 2, 2)
    ctx.add("dns.flags.opcode", "Opcode", opcode, base + 2, 2, display=f"{opcode_name} ({opcode})")
    ctx.add("dns.flags.authoritative", "Authoritative", bool(aa), base + 2, 2)
    ctx.add("dns.flags.truncated", "Truncated", bool(tc), base + 2, 2)
    ctx.add("dns.flags.recursion_desired", "Recursion desired", bool(rd), base + 2, 2)
    ctx.add("dns.flags.recursion_available", "Recursion available", bool(ra), base + 2, 2)
    ctx.add("dns.flags.authenticated", "Authentic data", bool(ad), base + 2, 2)
    ctx.add("dns.flags.checking_disabled", "Checking disabled", bool(cd), base + 2, 2)
    ctx.add("dns.flags.rcode", "Reply code", rcode, base + 3, 1,
            display=f"{rcode_name} ({rcode})")
    ctx.add("dns.count.queries", "Questions", qd, base + 4, 2)
    ctx.add("dns.count.answers", "Answer RRs", an, base + 6, 2)
    ctx.add("dns.count.auth_rr", "Authority RRs", ns, base + 8, 2)
    ctx.add("dns.count.add_rr", "Additional RRs", ar, base + 10, 2)

    pos = 12
    qname = ""
    qtype = 0
    qnames: list[str] = []
    answer_texts: list[str] = []
    try:
        for index in range(qd):
            q_start = pos
            name, pos2 = _read_name(data, pos)
            if pos2 + 4 > len(data):
                break
            rtype, rclass = struct.unpack("!HH", data[pos2:pos2 + 4])
            pos = pos2 + 4
            qname = qname or name
            qnames.append(name)
            field = ctx.add("dns.qry", f"Queries ({index + 1})", name, base + q_start,
                            pos - q_start, display=name)
            ctx.child(field, "dns.qry.name", "Name", name, base + q_start, 0)
            ctx.child(field, "dns.qry.type", "Type", rtype, base + pos2, 2,
                      display=f"{DNS_TYPES.get(rtype, 'Unknown')} ({rtype})")
            ctx.child(field, "dns.qry.class", "Class", rclass, base + pos2 + 2, 2,
                      display=f"{DNS_CLASSES.get(rclass, 'Unknown')} ({rclass})")
            if index == 0:
                qtype = rtype
    except ValueError:
        ctx.warn("DNS 问题区名称解析失败")
        ctx.end_layer()
        ctx.protocol = "DNS"
        ctx.color = COLOR_DNS
        ctx.info = "DNS malformed message"
        return True

    for section, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for index in range(count):
            try:
                name, pos2 = _read_name(data, pos)
                if pos2 + 10 > len(data):
                    raise ValueError
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[pos2:pos2 + 10])
                rdata_off = pos2 + 10
                rdata = data[rdata_off:rdata_off + rdlength]
                if len(rdata) != rdlength:
                    raise ValueError
            except (ValueError, struct.error):
                ctx.warn(f"DNS {section} 区解析被截断")
                pos = len(data)
                break
            pos = rdata_off + rdlength
            text = _rdata_text(data, rdata_off, rdata, rtype)
            label = {"answers": "Answers", "authority": "Authoritative nameservers",
                     "additional": "Additional records"}[section]
            if section == "answers":
                answer_texts.append(f"{DNS_TYPES.get(rtype, rtype)} {text}" if rtype != 1 and rtype != 28
                                    else f"{DNS_TYPES.get(rtype, rtype)} {text}")
            group = ctx.add("dns.resp", f"{label} ({index + 1})", name, base + pos2, 10 + rdlength,
                            display=name)
            ctx.child(group, "dns.resp.name", "Name", name, base + pos2, 0)
            ctx.child(group, "dns.resp.type", "Type", rtype, base + rdata_off - 10, 2,
                      display=f"{DNS_TYPES.get(rtype, 'Unknown')} ({rtype})")
            ctx.child(group, "dns.resp.class", "Class", rclass, base + rdata_off - 8, 2,
                      display=f"{DNS_CLASSES.get(rclass, 'Unknown')} ({rclass})")
            ctx.child(group, "dns.resp.ttl", "Time to live", ttl, base + rdata_off - 6, 4,
                      display=f"{ttl} seconds")
            ctx.child(group, "dns.resp.len", "Data length", rdlength, base + rdata_off - 2, 2)
            if rtype == 1 and len(rdata) == 4:
                ip = ipv4_str(rdata)
                ctx.child(group, "dns.a", "Address", ip, base + rdata_off, 4)
            elif rtype == 28 and len(rdata) == 16:
                ip = ipv6_str(rdata)
                ctx.child(group, "dns.aaaa", "Address", ip, base + rdata_off, 16)
            elif rtype in (2, 5, 12, 39):
                target, _ = _read_name(data, rdata_off)
                key = "dns.cname" if rtype == 5 else ("dns.ptr" if rtype == 12 else "dns.resp.name")
                ctx.child(group, key, "Name", target, base + rdata_off, rdlength)
            if rtype == 16 and rdata:
                ctx.child(group, "dns.txt", "Text", _txt_text(rdata), base + rdata_off, rdlength)
            elif rtype == 15 and len(rdata) >= 3:
                pref = (rdata[0] << 8) | rdata[1]
                target, _ = _read_name(data, rdata_off + 2)
                ctx.child(group, "dns.mx.preference", "Preference", pref, base + rdata_off, 2)
                ctx.child(group, "dns.mx.exchange", "Mail Exchange", target, base + rdata_off + 2, rdlength - 2)
            elif rtype == 33 and len(rdata) >= 7:
                prio, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = _read_name(data, rdata_off + 6)
                ctx.child(group, "dns.srv.priority", "Priority", prio, base + rdata_off, 2)
                ctx.child(group, "dns.srv.weight", "Weight", weight, base + rdata_off + 2, 2)
                ctx.child(group, "dns.srv.port", "Port", port, base + rdata_off + 4, 2)
                ctx.child(group, "dns.srv.target", "Target", target, base + rdata_off + 6, rdlength - 6)
            elif rtype == 6:
                text = _soa_text(data, rdata_off, rdlength)
                ctx.child(group, "dns.soa", "SOA", text, base + rdata_off, rdlength)

    ctx.end_layer()
    ctx.protocol = "DNS"
    ctx.color = COLOR_DNS
    if qr:
        suffix = "" if rcode == 0 else f" {rcode_name}"
        answer = (" " + ", ".join(answer_texts[:3])) if answer_texts else ""
        ctx.info = f"Standard query response 0x{ident:04x} {DNS_TYPES.get(qtype, qtype)} {qname}{answer}{suffix}"
    else:
        ctx.info = f"Standard query 0x{ident:04x} {DNS_TYPES.get(qtype, qtype)} {qname}"
    ctx.info = ctx.info.replace("  0x", " 0x")
    return True


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    if depth > 24:
        raise ValueError("DNS compression pointer loop")
    labels: list[str] = []
    start = pos
    jumped = False
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            return ".".join(labels) or ".", pos
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if pointer >= len(data):
                raise ValueError("bad DNS pointer")
            if not jumped:
                start = pos + 2
                jumped = True
            suffix, _ = _read_name(data, pointer, depth + 1)
            if suffix and suffix != ".":
                labels.extend(suffix.split("."))
            return ".".join(labels) or ".", start
        if length & 0xC0:
            raise ValueError("bad DNS label")
        if pos + 1 + length > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[pos + 1:pos + 1 + length].decode("latin-1"))
        pos += 1 + length
    raise ValueError("unterminated DNS name")


def _rdata_text(data: bytes, off: int, rdata: bytes, rtype: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:
            return ipv4_str(rdata)
        if rtype == 28 and len(rdata) == 16:
            return ipv6_str(rdata)
        if rtype in (2, 5, 12, 39):
            return _read_name(data, off)[0]
        if rtype == 15 and len(rdata) >= 3:
            return _read_name(data, off + 2)[0]
        if rtype == 16:
            return _txt_text(rdata)
        if rtype == 6:
            return _soa_text(data, off, len(rdata))
        if rtype == 65 or rtype == 64:
            if len(rdata) >= 3:
                return _read_name(data, off + 2)[0]
        return rdata.hex()
    except (ValueError, IndexError):
        return rdata.hex()


def _txt_text(rdata: bytes) -> str:
    parts: list[str] = []
    pos = 0
    while pos < len(rdata):
        length = rdata[pos]
        pos += 1
        parts.append(rdata[pos:pos + length].decode("utf-8", "replace"))
        pos += length
    return " ".join(parts)


def _soa_text(data: bytes, off: int, length: int) -> str:
    try:
        mname, pos = _read_name(data, off)
        rname, pos = _read_name(data, pos)
        if pos + 20 <= len(data):
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos:pos + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    except (ValueError, IndexError):
        pass
    return data[off:off + length].hex()
