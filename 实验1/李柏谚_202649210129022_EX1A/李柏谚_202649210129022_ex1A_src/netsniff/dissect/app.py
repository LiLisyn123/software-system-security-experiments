"""Application layer dispatch for TCP/UDP payloads.

Implemented protocols: HTTP/1.x, TLS (metadata + SNI), DNS (UDP/TCP/mDNS/
LLMNR), DHCP, NTP, QUIC (header only), SSDP, SSH, FTP, SMTP, MQTT and Redis.
Unknown payloads are left to the caller, which adds a generic Data layer.
"""

from __future__ import annotations

import struct

from ..model import COLOR_DNS, COLOR_HTTP, COLOR_TLS, ParseContext
from . import dns, http, tls
from .utils import ipv4_str, ipv6_str, mac_str, safe_text


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

def dissect_tcp_payload(
    ctx: ParseContext, payload: bytes, offset: int, sport: int, dport: int
) -> bool:
    if not payload:
        return False

    if tls.looks_like_tls(payload, sport, dport):
        if tls.dissect_tls(ctx, payload, offset, sport, dport):
            return True
    if http.looks_like_http(payload, sport, dport):
        if http.dissect_http(ctx, payload, offset, sport, dport):
            return True
    if sport == 53 or dport == 53 or sport == 5353 or dport == 5353:
        if dns.dissect_dns(ctx, payload, offset, tcp=True):
            return True
    if sport == 22 or dport == 22:
        return _dissect_ssh(ctx, payload, offset)
    if sport == 21 or dport == 21:
        return _dissect_ftp(ctx, payload, offset)
    if sport in (25, 465, 587) or dport in (25, 465, 587):
        return _dissect_smtp(ctx, payload, offset)
    if sport == 1883 or dport == 1883:
        return _dissect_mqtt(ctx, payload, offset)
    if sport == 6379 or dport == 6379:
        return _dissect_redis(ctx, payload, offset)
    return False


def _dissect_ssh(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    if not payload.startswith(b"SSH-"):
        return False
    line = payload.split(b"\r\n", 1)[0]
    text = line.decode("latin-1", "replace")
    parts = text.split("-", 2)
    proto = parts[1] if len(parts) > 1 else ""
    software = parts[2] if len(parts) > 2 else ""
    lb = ctx.begin_layer("SSH Protocol", "ssh", offset, len(payload), summary=text)
    ctx.add("ssh.protocol", "Protocol Version", proto, offset, len(line))
    ctx.add("ssh.software", "Software Version", software, offset, 0)
    ctx.add("ssh.banner", "Banner", text, offset, len(line))
    ctx.end_layer()
    ctx.protocol = "SSH"
    ctx.info = f"Server Protocol: {text}"
    return True


def _dissect_ftp(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    first = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if not first or not (first[:3].isdigit() or first[:4].upper() in (
            "USER", "PASS", "LIST", "RETR", "STOR", "QUIT", "TYPE", "PWD", "CWD", "PORT", "PASV")):
        return False
    lb = ctx.begin_layer("File Transfer Protocol", "ftp", offset, len(payload), summary=first)
    ctx.add("ftp.line", "Line", first, offset, len(first))
    if first[:3].isdigit():
        ctx.add("ftp.response.code", "Response Code", int(first[:3]), offset, 3)
        ctx.add("ftp.response.arg", "Response Arg", first[4:], offset, 0)
    else:
        ctx.add("ftp.request.command", "Request Command", first.split(" ", 1)[0], offset, 0)
        ctx.add("ftp.request.arg", "Request Arg", first.split(" ", 1)[1] if " " in first else "", offset, 0)
    ctx.end_layer()
    ctx.protocol = "FTP"
    ctx.info = first
    return True


def _dissect_smtp(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    first = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if not first or not (first[:3].isdigit() or first[:4].upper() in (
            "EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "AUTH", "STARTTLS")):
        return False
    lb = ctx.begin_layer("Simple Mail Transfer Protocol", "smtp", offset, len(payload), summary=first)
    ctx.add("smtp.line", "Line", first, offset, len(first))
    if first[:3].isdigit():
        ctx.add("smtp.response.code", "Response Code", int(first[:3]), offset, 3)
    else:
        ctx.add("smtp.request.command", "Command", first.split(" ", 1)[0], offset, 0)
    ctx.end_layer()
    ctx.protocol = "SMTP"
    ctx.info = first
    return True


def _dissect_mqtt(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    if len(payload) < 2:
        return False
    first = payload[0]
    packet_type = first >> 4
    names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE",
             9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
             13: "PINGRESP", 14: "DISCONNECT"}
    name = names.get(packet_type, f"Type {packet_type}")
    remaining = 0
    multiplier = 1
    p = 1
    for _ in range(4):
        if p >= len(payload):
            break
        byte = payload[p]
        p += 1
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
    lb = ctx.begin_layer("MQTT", "mqtt", offset, len(payload), summary=name)
    ctx.add("mqtt.type", "Packet Type", packet_type, offset, 1, display=f"{name} ({packet_type})")
    ctx.add("mqtt.flags", "Flags", first & 0x0F, offset, 1)
    ctx.add("mqtt.len", "Remaining Length", remaining, offset + 1, p - 1)
    if packet_type == 1 and len(payload) >= p + 6:
        proto_len = (payload[p] << 8) | payload[p + 1]
        proto = payload[p + 2:p + 2 + proto_len].decode("latin-1", "replace")
        ctx.add("mqtt.convert.protocol_name", "Protocol Name", proto, offset + p, 2 + proto_len)
        if p + 2 + proto_len < len(payload):
            ctx.add("mqtt.convert.protocol_version", "Protocol Version",
                    payload[p + 2 + proto_len], offset + p + 2 + proto_len, 1)
    if packet_type == 3 and len(payload) >= p + 2:
        topic_len = (payload[p] << 8) | payload[p + 1]
        topic = payload[p + 2:p + 2 + topic_len].decode("utf-8", "replace")
        ctx.add("mqtt.topic", "Topic", topic, offset + p, 2 + topic_len)
    ctx.end_layer()
    ctx.protocol = "MQTT"
    ctx.info = f"MQTT {name}"
    return True


def _dissect_redis(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    first = payload[:64].decode("latin-1", "replace").split("\r\n", 1)[0]
    if not first or first[0] not in "*$+-:":
        return False
    lb = ctx.begin_layer("Redis Protocol", "redis", offset, len(payload), summary=first)
    ctx.add("redis.response", "RESP", first, offset, len(first))
    ctx.end_layer()
    ctx.protocol = "Redis"
    ctx.info = first
    return True


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

def dissect_udp_payload(
    ctx: ParseContext, payload: bytes, offset: int, sport: int, dport: int
) -> bool:
    if not payload:
        return False
    if sport in (53, 5353, 5355) or dport in (53, 5353, 5355):
        if dns.dissect_dns(ctx, payload, offset):
            return True
    if sport in (67, 68) or dport in (67, 68):
        return _dissect_dhcp(ctx, payload, offset)
    if sport == 123 or dport == 123:
        return _dissect_ntp(ctx, payload, offset)
    if sport in (443, 80, 8080) or dport in (443, 80, 8080):
        if _dissect_quic(ctx, payload, offset):
            return True
    if sport == 1900 or dport == 1900:
        if http.dissect_http(ctx, payload, offset, sport, dport):
            return True
    return False


def _dissect_dhcp(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return False
    op = payload[0]
    htype = payload[1]
    hlen = payload[2]
    hops = payload[3]
    xid = int.from_bytes(payload[4:8], "big")
    secs = (payload[8] << 8) | payload[9]
    flags = (payload[10] << 8) | payload[11]
    ciaddr = ipv4_str(payload[12:16])
    yiaddr = ipv4_str(payload[16:20])
    siaddr = ipv4_str(payload[20:24])
    giaddr = ipv4_str(payload[24:28])
    chaddr = mac_str(payload[28:34])
    lb = ctx.begin_layer("Dynamic Host Configuration Protocol", "dhcp", offset, len(payload),
                         summary="DHCP")
    ctx.add("dhcp.op", "Message type", "BOOTREQUEST" if op == 1 else "BOOTREPLY", offset, 1)
    ctx.add("dhcp.htype", "Hardware type", htype, offset + 1, 1)
    ctx.add("dhcp.hlen", "Hardware address length", hlen, offset + 2, 1)
    ctx.add("dhcp.hops", "Hops", hops, offset + 3, 1)
    ctx.add("dhcp.id", "Transaction ID", xid, offset + 4, 4, display=f"0x{xid:08x}")
    ctx.add("dhcp.secs", "Seconds elapsed", secs, offset + 8, 2)
    ctx.add("dhcp.flags", "Flags", flags, offset + 10, 2, display=f"0x{flags:04x}")
    ctx.add("dhcp.ciaddr", "Client IP address", ciaddr, offset + 12, 4)
    ctx.add("dhcp.yiaddr", "Your (client) IP address", yiaddr, offset + 16, 4)
    ctx.add("dhcp.siaddr", "Next server IP address", siaddr, offset + 20, 4)
    ctx.add("dhcp.giaddr", "Relay agent IP address", giaddr, offset + 24, 4)
    ctx.add("dhcp.hw.mac_addr", "Client MAC address", chaddr, offset + 28, hlen)
    options = _parse_dhcp_options(ctx, payload, 240, offset)
    msg_type = options.get(53, 0)
    type_names = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK",
                  6: "NAK", 7: "Release", 8: "Inform"}
    type_name = type_names.get(msg_type, "DHCP")
    ctx.add("dhcp.option.dhcp", "Message Type", msg_type, offset + 240, 0,
            display=f"{type_name} ({msg_type})")
    lb.summary = f"Message type: {type_name}"
    ctx.end_layer()
    ctx.protocol = "DHCP"
    ctx.color = COLOR_DNS
    ctx.info = f"DHCP {type_name}  Transaction ID 0x{xid:08x}  Client MAC {chaddr}"
    return True


def _parse_dhcp_options(ctx: ParseContext, payload: bytes, start: int, base: int) -> dict:
    values: dict = {}
    p = start
    group = None
    names = {
        1: "Subnet Mask", 3: "Router", 6: "Domain Name Server", 12: "Host Name",
        15: "Domain Name", 28: "Broadcast Address", 42: "NTP Servers",
        50: "Requested IP Address", 51: "IP Address Lease Time", 52: "Option Overload",
        53: "DHCP Message Type", 54: "Server Identifier", 55: "Parameter Request List",
        56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal Time Value",
        59: "Rebinding Time Value", 60: "Vendor Class Identifier", 61: "Client Identifier",
        66: "TFTP Server Name", 67: "Bootfile Name", 81: "Client FQDN",
        82: "Relay Agent Information", 121: "Classless Static Route", 249: "MS Classless Static Route",
    }
    while p < len(payload):
        code = payload[p]
        if code == 0:
            p += 1
            continue
        if code == 255:
            break
        if p + 1 >= len(payload):
            break
        length = payload[p + 1]
        if p + 2 + length > len(payload):
            break
        data = payload[p + 2:p + 2 + length]
        if group is None:
            group = ctx.group("dhcp.options", "Options", "", base + p, 0)
        label = names.get(code, f"Option {code}")
        display = _dhcp_option_value(code, data)
        ctx.child(group, f"dhcp.option.{code}", label, display, base + p, 2 + length)
        if code in (1, 3, 6, 28, 42, 50, 54):
            ips = [ipv4_str(data[i:i + 4]) for i in range(0, len(data) - 3, 4)]
            if code in (3, 6, 28, 42):
                display = ", ".join(ips)
            elif ips:
                display = ips[0]
            values[code] = display
        elif code == 51 and length == 4:
            values[code] = int.from_bytes(data, "big")
        elif code == 53 and length >= 1:
            values[code] = data[0]
        elif code in (12, 15, 56, 60, 61, 66, 67):
            values[code] = safe_text(data)
        p += 2 + length
    return values


def _dhcp_option_value(code: int, data: bytes) -> str:
    if code in (1, 3, 6, 28, 42, 50, 54) and len(data) >= 4:
        return ", ".join(ipv4_str(data[i:i + 4]) for i in range(0, len(data) - 3, 4))
    if code == 12:
        return safe_text(data)
    if code == 53 and data:
        return str(data[0])
    if code == 55:
        return ", ".join(str(b) for b in data)
    if code == 121 and len(data) >= 5:
        return data.hex()
    if len(data) <= 8:
        return data.hex(" ") + f" ({safe_text(data)})" if all(32 <= b < 127 for b in data) else data.hex(" ")
    return data.hex(" ")


def _dissect_ntp(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    if len(payload) < 48:
        return False
    first = payload[0]
    leap = (first >> 6) & 0x3
    version = (first >> 3) & 0x7
    mode = first & 0x7
    stratum = payload[1]
    poll = payload[2]
    precision = payload[3]
    root_delay = struct.unpack("!I", payload[4:8])[0] / 65536.0
    root_disp = struct.unpack("!I", payload[8:12])[0] / 65536.0
    ref_id = payload[12:16]
    mode_name = {1: "symmetric active", 2: "symmetric passive", 3: "client",
                 4: "server", 5: "broadcast", 6: "control", 7: "private"}.get(mode, str(mode))
    lb = ctx.begin_layer("Network Time Protocol", "ntp", offset, len(payload),
                         summary=f"Mode: {mode_name}")
    ctx.add("ntp.flags.leap", "Leap Indicator", leap, offset, 1)
    ctx.add("ntp.flags.version", "Version", version, offset, 1)
    ctx.add("ntp.flags.mode", "Mode", mode, offset, 1, display=f"{mode_name} ({mode})")
    ctx.add("ntp.stratum", "Stratum", stratum, offset + 1, 1)
    ctx.add("ntp.poll", "Poll", poll, offset + 2, 1)
    ctx.add("ntp.precision", "Precision", precision, offset + 3, 1)
    ctx.add("ntp.rootdelay", "Root Delay", root_delay, offset + 4, 4)
    ctx.add("ntp.rootdisp", "Root Dispersion", root_disp, offset + 8, 4)
    ctx.add("ntp.refid", "Reference ID", ref_id.hex(), offset + 12, 4)
    for name, pos in (("reference", 16), ("origin", 24), ("receive", 32), ("transmit", 40)):
        raw = payload[pos:pos + 8]
        if len(raw) == 8:
            seconds = int.from_bytes(raw[:4], "big")
            fraction = int.from_bytes(raw[4:8], "big")
            ctx.add(f"ntp.{name}_timestamp", f"{name.title()} Timestamp", seconds, offset + pos, 8,
                    display=f"{seconds}.{fraction:010d}")
    ctx.end_layer()
    ctx.protocol = "NTP"
    ctx.info = f"NTP version {version}, {mode_name}  stratum={stratum}"
    return True


def _dissect_quic(ctx: ParseContext, payload: bytes, offset: int) -> bool:
    if len(payload) < 7:
        return False
    first = payload[0]
    if not (first & 0x80):
        # Short header; QUIC is only a guess on port 443 without decryption.
        if not (first & 0x40):
            return False
        lb = ctx.begin_layer("QUIC", "quic", offset, len(payload), summary="1-RTT")
        ctx.add("quic.header_form", "Header Form", 0, offset, 1, display="Short Header")
        ctx.add("quic.spin_bit", "Spin Bit", (first >> 5) & 1, offset, 1)
        ctx.end_layer()
        ctx.protocol = "QUIC"
        ctx.info = f"QUIC 1-RTT ({len(payload)} bytes, encrypted)"
        return True
    if not (first & 0x40):
        return False
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return False
    p = 5
    dcid_len = payload[p]
    p += 1
    dcid = payload[p:p + dcid_len]
    p += dcid_len
    if p >= len(payload):
        return False
    scid_len = payload[p]
    p += 1
    scid = payload[p:p + scid_len]
    p += scid_len
    if len(scid) != scid_len:
        return False
    packet_type = (first >> 4) & 0x3
    type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
    type_name = type_names.get(packet_type, str(packet_type))
    lb = ctx.begin_layer("QUIC", "quic", offset, len(payload), summary=type_name)
    ctx.add("quic.header_form", "Header Form", 1, offset, 1, display="Long Header")
    ctx.add("quic.version", "Version", version, offset + 1, 4, display=f"0x{version:08x}")
    ctx.add("quic.dcid", "Destination Connection ID", dcid.hex(), offset + 6, dcid_len)
    ctx.add("quic.scid", "Source Connection ID", scid.hex(), offset + 6 + dcid_len + 1, scid_len)
    ctx.add("quic.packet_type", "Packet Type", packet_type, offset, 1, display=f"{type_name} ({packet_type})")
    ctx.end_layer()
    ctx.protocol = "QUIC"
    ctx.color = COLOR_HTTP
    ctx.info = f"QUIC {type_name}  DCID={dcid.hex()}  Version=0x{version:08x}"
    return True
