"""HTTP/1.x message dissection.

The per-packet parser is deliberately tolerant: a message may be split over
several TCP segments, in which case only the available header lines are shown.
The stream dialog uses the reassembled byte stream for the full picture.
"""

from __future__ import annotations

from ..model import COLOR_HTTP, ParseContext
from .utils import safe_text


HTTP_METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH",
    b"TRACE", b"CONNECT", b"PRI",
)

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8888, 3128, 9090}

HEADER_FIELDS = {
    "host": ("http.host", "Host"),
    "user-agent": ("http.user_agent", "User-Agent"),
    "accept": ("http.accept", "Accept"),
    "accept-encoding": ("http.accept_encoding", "Accept-Encoding"),
    "accept-language": ("http.accept_language", "Accept-Language"),
    "content-type": ("http.content_type", "Content-Type"),
    "content-length": ("http.content_length", "Content-Length"),
    "content-encoding": ("http.content_encoding", "Content-Encoding"),
    "connection": ("http.connection", "Connection"),
    "cookie": ("http.cookie", "Cookie"),
    "set-cookie": ("http.set_cookie", "Set-Cookie"),
    "referer": ("http.referer", "Referer"),
    "server": ("http.server", "Server"),
    "location": ("http.location", "Location"),
    "cache-control": ("http.cache_control", "Cache-Control"),
    "authorization": ("http.authorization", "Authorization"),
    "x-forwarded-for": ("http.x_forwarded_for", "X-Forwarded-For"),
    "transfer-encoding": ("http.transfer_encoding", "Transfer-Encoding"),
    "via": ("http.via", "Via"),
}


def looks_like_http(payload: bytes, sport: int = 0, dport: int = 0) -> bool:
    if not payload:
        return False
    head = payload[:16]
    if head.startswith(HTTP_METHODS) or head.startswith(b"HTTP/"):
        return True
    return sport in HTTP_PORTS or dport in HTTP_PORTS


def dissect_http(ctx: ParseContext, payload: bytes, offset: int, sport: int, dport: int) -> bool:
    if not payload:
        return False
    head = payload[:24]
    is_request = head.startswith(HTTP_METHODS)
    is_response = head.startswith(b"HTTP/")
    if not (is_request or is_response):
        # Port-based fallback: still label the data as HTTP so the stream can
        # be followed even when the first segment only holds body bytes.
        if sport in HTTP_PORTS or dport in HTTP_PORTS:
            layer = ctx.begin_layer("Hypertext Transfer Protocol", "http", offset, len(payload),
                                    summary="data")
            ctx.add("http.data", "HTTP Data", len(payload), offset, len(payload),
                    display=f"{len(payload)} bytes (continuation)")
            ctx.end_layer()
            ctx.protocol = "HTTP"
            ctx.color = COLOR_HTTP
            ctx.info = "HTTP Continuation"
            return True
        return False

    header_end = payload.find(b"\r\n\r\n")
    sep_len = 4
    if header_end < 0:
        header_end = payload.find(b"\n\n")
        sep_len = 2
    truncated = header_end < 0
    head_bytes = payload if truncated else payload[:header_end]
    body_off = len(payload) if truncated else header_end + sep_len
    body = payload[body_off:]
    text = safe_text(head_bytes, 65536)
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        return False
    first_line = lines[0]

    layer = ctx.begin_layer(
        "Hypertext Transfer Protocol",
        "http",
        offset,
        len(payload),
        summary="request" if is_request else "response",
    )
    ctx.add("http.first_line", "First Line", first_line, offset, len(first_line.encode("latin-1", "replace")))

    method = ""
    uri = ""
    version = ""
    code = None
    phrase = ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and headers:
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip())
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))

    header_field = None
    if is_request:
        parts = first_line.split(" ")
        if len(parts) >= 2:
            method = parts[0]
            uri = parts[1]
            version = parts[2] if len(parts) >= 3 else "HTTP/1.0"
        ctx.add("http.request.method", "Request Method", method, offset, len(method))
        ctx.add("http.request.uri", "Request URI", uri, offset, 0)
        ctx.add("http.request.version", "Request Version", version, offset, 0)
        scheme = "http"
        host = ""
        for name, value in headers:
            if name.lower() == "host":
                host = value
                break
        full_uri = f"{scheme}://{host}{uri}" if host else uri
        ctx.add("http.request.full_uri", "Full request URI", full_uri, offset, 0)
        ctx.info = first_line
    else:
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            version = parts[0]
            try:
                code = int(parts[1])
            except ValueError:
                code = 0
            phrase = parts[2] if len(parts) >= 3 else ""
        ctx.add("http.response.version", "Response Version", version, offset, 0)
        ctx.add("http.response.code", "Status Code", code if code is not None else 0, offset, 0,
                display=f"{code} " if code is not None else "")
        ctx.add("http.response.phrase", "Response Phrase", phrase, offset, 0)
        ctx.info = first_line

    if headers:
        header_field = ctx.group("http.headers", "Headers", len(headers), offset, 0,
                                 display=f"{len(headers)} headers")
        for name, value in headers:
            child = ctx.child(header_field, "http.header", name, value, -1, 0)
            ctx.child(child, "http.header.name", "Name", name, -1, 0)
            ctx.child(child, "http.header.value", "Value", value, -1, 0)
            key = name.lower()
            if key in HEADER_FIELDS:
                field_key, label = HEADER_FIELDS[key]
                ctx.add(field_key, label, value, -1, 0)

    content_length = None
    for name, value in headers:
        if name.lower() == "content-length":
            try:
                content_length = int(value)
            except ValueError:
                pass
    if body:
        if content_length is not None and len(body) < content_length:
            ctx.warn(f"HTTP body 被截断：声明 {content_length} 字节，实际 {len(body)} 字节")
        ctx.add("http.file_data", "File Data", len(body), offset + body_off, len(body),
                display=_body_preview(body, content_length))
    ctx.end_layer()

    ctx.protocol = "HTTP" if not head.startswith(b"PRI ") else "HTTP/2"
    ctx.color = COLOR_HTTP
    if is_response and code is not None:
        ctype = ""
        for name, value in headers:
            if name.lower() == "content-type":
                ctype = value.split(";", 1)[0].strip()
                break
        ctx.info = first_line + (f"  ({ctype})" if ctype else "")
    return True


def _body_preview(body: bytes, content_length: int | None) -> str:
    size = f"{len(body)} bytes" if content_length is None else f"{len(body)}/{content_length} bytes"
    text = body[:200]
    try:
        decoded = text.decode("utf-8")
        printable = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else "·" for ch in decoded)
        if printable.strip():
            first = printable.replace("\r", "").split("\n")[0][:100]
            return f"{size}: {first}"
    except UnicodeDecodeError:
        pass
    return size


def parse_http_messages(data: bytes) -> list[dict]:
    """Parse a reassembled HTTP byte stream into request/response records.

    Used by the stream dialog.  Handles Content-Length and chunked bodies,
    pipelining, and stops gracefully on partial messages.
    """
    messages: list[dict] = []
    pos = 0
    total = len(data)
    while pos < total:
        # skip inter-message CRLF
        while pos < total and data[pos:pos + 2] in (b"\r\n", b"\n"):
            pos += 2 if data[pos:pos + 2] == b"\r\n" else 1
        if pos >= total:
            break
        head_end = data.find(b"\r\n\r\n", pos)
        sep = 4
        if head_end < 0:
            head_end = data.find(b"\n\n", pos)
            sep = 2
        if head_end < 0:
            break
        head = data[pos:head_end].decode("latin-1", "replace")
        lines = head.replace("\r\n", "\n").split("\n")
        if not lines:
            break
        first = lines[0]
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers.append((name.strip(), value.strip()))
        content_length = 0
        chunked = False
        for name, value in headers:
            lname = name.lower()
            if lname == "content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = 0
            elif lname == "transfer-encoding" and "chunked" in value.lower():
                chunked = True
        body_start = head_end + sep
        if chunked:
            body, body_end = _decode_chunked(data, body_start)
        else:
            body = data[body_start:body_start + content_length]
            body_end = body_start + content_length
        if body_end > total:
            body = data[body_start:total]
            body_end = total
        messages.append({
            "start": pos,
            "end": min(body_end, total),
            "first_line": first,
            "headers": headers,
            "body": body,
            "request": first.startswith(tuple(m.decode("ascii") for m in HTTP_METHODS)),
            "response": first.startswith("HTTP/"),
            "complete": body_end <= total,
        })
        if body_end <= pos:
            break
        pos = body_end
    return messages


def _decode_chunked(data: bytes, pos: int) -> tuple[bytes, int]:
    out = bytearray()
    total = len(data)
    while pos < total:
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            break
        try:
            size = int(data[pos:line_end].split(b";", 1)[0], 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", pos)
            if trailer_end >= 0:
                pos = trailer_end + 4
            else:
                pos = min(total, pos + 2)
            break
        out += data[pos:pos + size]
        pos += size
        if data[pos:pos + 2] == b"\r\n":
            pos += 2
    return bytes(out), pos
