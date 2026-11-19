"""HTTP stream parser and application helper tests."""

from __future__ import annotations

from netsniff.dissect.http import _decode_chunked, parse_http_messages
from netsniff.packetgen import http_request, http_response


def test_parse_pipelined_http():
    data = (
        http_request("GET", "/a", "example.com")
        + http_response(200, "OK", b"hello", content_type="text/plain")
        + http_request("POST", "/b", "example.com", body=b"x" * 10)
        + http_response(201, "Created", b"ok", content_type="text/plain")
    )
    # c2s and s2c are separate streams, but the parser also copes with a
    # concatenation of both directions.
    messages = parse_http_messages(data)
    assert len(messages) == 4
    assert messages[0]["request"] is True
    assert messages[0]["first_line"].startswith("GET /a")
    assert messages[1]["response"] is True
    assert messages[1]["body"] == b"hello"
    assert messages[2]["request"] is True
    assert messages[2]["body"] == b"x" * 10
    assert messages[3]["first_line"].startswith("HTTP/1.1 201")


def test_content_length_and_chunked():
    chunked = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    )
    messages = parse_http_messages(chunked)
    assert len(messages) == 1
    assert messages[0]["body"] == b"hello world"
    body, end = _decode_chunked(chunked, chunked.find(b"\r\n\r\n") + 4)
    assert body == b"hello world"
    assert end == len(chunked)


def test_partial_http_does_not_crash():
    assert parse_http_messages(b"GET / HTTP/1.1\r\nHost: exa") == []
    assert parse_http_messages(b"") == []
