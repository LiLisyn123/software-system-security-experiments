"""TLS record / handshake dissection (metadata only, no decryption)."""

from __future__ import annotations

from ..model import COLOR_TLS, ParseContext


TLS_PORTS = {443, 8443, 9443, 993, 995, 465, 636, 5061, 853}

CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
}

HANDSHAKE_TYPES = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
    24: "Key Update",
    254: "Message Hash",
}

VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
    0x7F00: "TLSv1.3 (draft 0x7f00)",
}

ALERT_DESCRIPTIONS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 30: "decompression_failure",
    40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 60: "export_restriction", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    90: "user_canceled", 100: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name", 116: "certificate_required",
    120: "no_application_protocol",
}

GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072",
}

SIG_ALGS = {
    0x0401: "rsa_pkcs1_sha256", 0x0403: "rsa_pkcs1_sha384", 0x0405: "rsa_pkcs1_sha512",
    0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0402: "ecdsa_secp256r1_sha256", 0x0502: "ecdsa_secp384r1_sha384",
    0x0602: "ecdsa_secp521r1_sha512", 0x0807: "ed25519", 0x0808: "ed448",
}


def looks_like_tls(payload: bytes, sport: int = 0, dport: int = 0) -> bool:
    if len(payload) >= 5:
        if payload[0] in CONTENT_TYPES and payload[1] == 0x03 and payload[2] <= 0x04:
            return True
    return sport in TLS_PORTS or dport in TLS_PORTS


def dissect_tls(ctx: ParseContext, payload: bytes, offset: int, sport: int, dport: int) -> bool:
    if not payload:
        return False
    if not looks_like_tls(payload, sport, dport):
        return False

    layer = ctx.begin_layer("Transport Layer Security", "tls", offset, len(payload),
                            summary=f"Src Port: {sport}, Dst Port: {dport}")
    records = 0
    pos = 0
    negotiated = ""
    sni = ""
    handshake_name = ""
    app_len = 0
    while pos + 5 <= len(payload) and records < 12:
        content_type = payload[pos]
        version = (payload[pos + 1] << 8) | payload[pos + 2]
        length = (payload[pos + 3] << 8) | payload[pos + 4]
        if content_type not in CONTENT_TYPES or version < 0x0300 or length > len(payload) - pos - 5:
            if records == 0:
                # Probably a continuation of a record whose header was in the
                # previous segment.
                ctx.add("tls.record", "TLS Record", "continuation", offset, len(payload),
                        display="Record continuation")
                break
            break
        record = payload[pos + 5:pos + 5 + length]
        ctx.add("tls.record.content_type", "Content Type", content_type, offset + pos, 1,
                display=f"{CONTENT_TYPES.get(content_type, 'Unknown')} ({content_type})")
        ctx.add("tls.record.version", "Version", version, offset + pos + 1, 2,
                display=f"{VERSIONS.get(version, hex(version))} (0x{version:04x})")
        ctx.add("tls.record.length", "Length", length, offset + pos + 3, 2)
        if content_type == 22:
            htype, hlen, hdata_off, hdata = _first_handshake(record, offset + pos + 5)
            if htype is not None:
                handshake_name = HANDSHAKE_TYPES.get(htype, f"Handshake {htype}")
                ctx.add("tls.handshake.type", "Handshake Type", htype, hdata_off - 4, 1,
                        display=f"{handshake_name} ({htype})")
                ctx.add("tls.handshake.length", "Handshake Length", hlen, hdata_off - 3, 3)
                if htype == 1:
                    version, sni, alpn, group = _parse_client_hello(ctx, payload, hdata_off, hdata)
                    if version:
                        negotiated = VERSIONS.get(version, negotiated)
                        ctx.add("tls.handshake.version", "Client Version", version, hdata_off, 2,
                                display=f"{VERSIONS.get(version, hex(version))} (0x{version:04x})")
                elif htype == 2:
                    version, chosen, alpn, group = _parse_server_hello(ctx, payload, hdata_off, hdata)
                    if version:
                        negotiated = VERSIONS.get(version, negotiated)
                        ctx.add("tls.handshake.version", "Server Version", version, hdata_off, 2,
                                display=f"{VERSIONS.get(version, hex(version))} (0x{version:04x})")
                elif htype == 11:
                    _parse_certificates(ctx, hdata)
                elif htype == 20:
                    ctx.add("tls.handshake.finished", "Finished", len(hdata), hdata_off, len(hdata),
                            display=f"{len(hdata)} bytes (encrypted)")
            elif len(record) >= 4:
                ctx.add("tls.handshake", "Handshake", "fragment", offset + pos + 5, len(record),
                        display="Handshake fragment")
        elif content_type == 21:
            if len(record) >= 2:
                level, desc = record[0], record[1]
                ctx.add("tls.alert_message.level", "Alert Level", level, offset + pos + 5, 1,
                        display="Fatal" if level == 2 else "Warning")
                ctx.add("tls.alert_message.desc", "Alert Description", desc, offset + pos + 6, 1,
                        display=f"{ALERT_DESCRIPTIONS.get(desc, 'Unknown')} ({desc})")
                if not ctx.info or ctx.info.startswith("TCP"):
                    ctx.info = f"Alert ({'Fatal' if level == 2 else 'Warning'}, {ALERT_DESCRIPTIONS.get(desc, desc)})"
        elif content_type == 20:
            ctx.add("tls.change_cipher_spec", "Change Cipher Spec", record.hex(), offset + pos + 5,
                    len(record))
        elif content_type == 23:
            app_len += len(record)
            ctx.add("tls.app_data_len", "Application Data Length", len(record), offset + pos + 5,
                    len(record), display=f"{len(record)} bytes (encrypted)")
        pos += 5 + length
        records += 1

    ctx.end_layer()
    ctx.color = COLOR_TLS
    ctx.protocol = negotiated or "TLS"
    if not ctx.protocol.startswith("TLS") and not ctx.protocol.startswith("SSL"):
        ctx.protocol = "TLS"
    if handshake_name == "Client Hello":
        ctx.info = "Client Hello" + (f" (SNI={sni})" if sni else "")
    elif handshake_name == "Server Hello":
        ctx.info = "Server Hello" + (f" ({negotiated})" if negotiated else "")
    elif app_len:
        ctx.info = f"Application Data ({app_len} bytes, encrypted)"
    elif handshake_name:
        ctx.info = handshake_name
    else:
        ctx.info = "TLS Record"
    return True


def _is_grease(value: int) -> bool:
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


def _first_handshake(record: bytes, abs_offset: int):
    if len(record) < 4:
        return None, 0, abs_offset, b""
    htype = record[0]
    hlen = (record[1] << 16) | (record[2] << 8) | record[3]
    data = record[4:4 + hlen]
    return htype, hlen, abs_offset + 4, data


def _u16(data: bytes, pos: int) -> int:
    if pos + 2 > len(data):
        raise IndexError
    return (data[pos] << 8) | data[pos + 1]


def _parse_client_hello(ctx: ParseContext, frame: bytes, pos: int, data: bytes):
    try:
        version = _u16(data, 0)
        # legacy_version, random(32), session id
        p = 34
        session_len = data[p]
        p += 1 + session_len
        cipher_len = _u16(data, p)
        p += 2
        cipher_count = cipher_len // 2
        ctx.add("tls.handshake.cipher_suites.count", "Cipher Suites", cipher_count,
                pos + p, cipher_len, display=f"{cipher_count} suites")
        p += cipher_len
        comp_len = data[p]
        p += 1 + comp_len
        alpn = ""
        sni = ""
        selected_group = None
        supported_versions = None
        if p + 2 <= len(data):
            ext_total = _u16(data, p)
            p += 2
            end = min(len(data), p + ext_total)
            while p + 4 <= end:
                ext_type = _u16(data, p)
                ext_len = _u16(data, p + 2)
                body_off = p + 4
                body = data[body_off:body_off + ext_len]
                if len(body) != ext_len:
                    break
                if ext_type == 0:  # server_name
                    sni, name_off = _parse_sni(body)
                    if sni:
                        ctx.add("tls.handshake.extensions_server_name",
                                "Server Name Indication", sni, pos + body_off + name_off, len(sni))
                        ctx.add("tls.sni", "SNI", sni, pos + body_off + name_off, len(sni))
                elif ext_type == 16:  # ALPN
                    alpn = _parse_alpn(body)
                    if alpn:
                        ctx.add("tls.handshake.extensions_alpn", "ALPN", alpn, pos + body_off, ext_len)
                elif ext_type == 43:  # supported_versions
                    if len(body) >= 3:
                        count = body[0] // 2
                        versions = []
                        for i in range(count):
                            if 1 + i * 2 + 2 > len(body):
                                break
                            v = _u16(body, 1 + i * 2)
                            if not _is_grease(v):
                                versions.append(v)
                        supported_versions = max(versions) if versions else None
                        if supported_versions:
                            ctx.add("tls.handshake.supported_versions", "Supported Versions",
                                    VERSIONS.get(supported_versions, hex(supported_versions)),
                                    pos + body_off, ext_len,
                                    display=", ".join(VERSIONS.get(v, hex(v)) for v in versions))
                elif ext_type == 51:  # key_share
                    if len(body) >= 4:
                        selected_group = _u16(body, 2)
                        ctx.add("tls.handshake.extensions_key_share_group", "Key Share Group",
                                GROUPS.get(selected_group, selected_group), pos + body_off, ext_len)
                elif ext_type == 10:  # supported groups
                    names = []
                    if len(body) >= 2:
                        for i in range(body[0] // 2):
                            if 1 + i * 2 + 2 > len(body):
                                break
                            g = _u16(body, 1 + i * 2)
                            names.append(GROUPS.get(g, str(g)))
                    if names:
                        ctx.add("tls.handshake.extensions_supported_groups", "Supported Groups",
                                ", ".join(names), pos + body_off, ext_len)
                p = body_off + ext_len
        return supported_versions or version, sni, alpn, selected_group
    except (IndexError, ValueError):
        ctx.warn("TLS ClientHello 解析被截断")
        return 0, "", "", None


def _parse_server_hello(ctx: ParseContext, frame: bytes, pos: int, data: bytes):
    try:
        version = _u16(data, 0)
        p = 34
        session_len = data[p]
        p += 1 + session_len
        cipher = _u16(data, p)
        p += 2
        ctx.add("tls.handshake.cipher_suite", "Cipher Suite", cipher, pos + p - 2, 2,
                display=f"0x{cipher:04x}")
        p += 1  # compression
        negotiated = version
        alpn = ""
        selected_group = None
        if p + 2 <= len(data):
            ext_total = _u16(data, p)
            p += 2
            end = min(len(data), p + ext_total)
            while p + 4 <= end:
                ext_type = _u16(data, p)
                ext_len = _u16(data, p + 2)
                body_off = p + 4
                body = data[body_off:body_off + ext_len]
                if ext_type == 43 and len(body) >= 2:
                    negotiated = _u16(body, 0)
                    ctx.add("tls.handshake.supported_versions", "Selected Version",
                            VERSIONS.get(negotiated, hex(negotiated)), pos + body_off, 2)
                elif ext_type == 16:
                    alpn = _parse_alpn(body)
                    if alpn:
                        ctx.add("tls.handshake.extensions_alpn", "ALPN", alpn, pos + body_off, ext_len)
                elif ext_type == 51 and len(body) >= 2:
                    selected_group = _u16(body, 0)
                    ctx.add("tls.handshake.extensions_key_share_group", "Key Share Group",
                            GROUPS.get(selected_group, selected_group), pos + body_off, 2)
                p = body_off + ext_len
        return negotiated, cipher, alpn, selected_group
    except (IndexError, ValueError):
        ctx.warn("TLS ServerHello 解析被截断")
        return 0, 0, "", None


def _parse_sni(body: bytes) -> tuple[str, int]:
    try:
        if len(body) < 5:
            return "", 0
        list_len = _u16(body, 0)
        end = min(len(body), 2 + list_len)
        p = 2
        while p + 3 <= end:
            name_type = body[p]
            name_len = _u16(body, p + 1)
            p += 3
            if name_type == 0 and p + name_len <= len(body):
                return body[p:p + name_len].decode("ascii", "replace"), p
            p += name_len
    except (IndexError, ValueError):
        pass
    return "", 0


def _parse_alpn(body: bytes) -> str:
    try:
        if len(body) < 2:
            return ""
        end = min(len(body), 2 + _u16(body, 0))
        p = 2
        names = []
        while p < end:
            n = body[p]
            p += 1
            names.append(body[p:p + n].decode("ascii", "replace"))
            p += n
        return ", ".join(names)
    except (IndexError, ValueError):
        return ""


def _parse_certificates(ctx: ParseContext, data: bytes) -> None:
    try:
        if len(data) < 3:
            return
        total = (data[0] << 16) | (data[1] << 8) | data[2]
        p = 3
        end = min(len(data), 3 + total)
        count = 0
        while p + 3 <= end and count < 32:
            length = (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]
            p += 3 + length
            count += 1
        ctx.add("tls.handshake.certificates", "Certificates", count, -1, 0,
                display=f"{count} certificate(s)")
    except (IndexError, ValueError):
        pass
