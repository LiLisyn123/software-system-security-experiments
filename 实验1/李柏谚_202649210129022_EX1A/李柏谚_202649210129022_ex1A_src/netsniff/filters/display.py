"""Wireshark-style display filter engine.

Supports:

* protocol predicates: ``http``, ``tcp``, ``udp``, ``ip``, ``ipv6``,
  ``icmp``, ``icmpv6``, ``arp``, ``dns``, ``tls``, ``dhcp``, ``ntp``,
  ``quic``, ``ssh``, ``data`` ...
* boolean logic with ``and``/``&&``, ``or``/``||``, ``not``/``!`` and
  parentheses;
* comparisons ``== != > < >= <=``;
* string operators ``contains`` / ``matches`` (regular expression);
* field aliases such as ``ip.addr``, ``tcp.port``, ``udp.port``,
  ``eth.addr``, ``dns.qname`` and ``tls.sni``;
* CIDR matching: ``ip.addr == 192.168.1.0/24``.

The expression is tokenised, parsed into an AST and compiled into a Python
closure, so evaluating it for every packet is cheap.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple


class FilterError(ValueError):
    """Raised for an invalid display filter."""


# ---------------------------------------------------------------------------
# field registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str  # num | str | ip | mac | bool | time
    description: str = ""


_SPECS: list[FieldSpec] = [
    FieldSpec("frame.number", "num", "帧序号"),
    FieldSpec("frame.len", "num", "帧长度（线上字节数）"),
    FieldSpec("frame.cap_len", "num", "捕获到的字节数"),
    FieldSpec("frame.time", "time", "帧时间戳（epoch 秒）"),
    FieldSpec("frame.time_epoch", "time", "帧时间戳（epoch 秒）"),
    FieldSpec("frame.protocols", "str", "协议栈，如 eth:ip:tcp:http"),
    FieldSpec("frame.linktype", "num", "链路层类型"),
    FieldSpec("eth.src", "mac", "源 MAC"),
    FieldSpec("eth.dst", "mac", "目的 MAC"),
    FieldSpec("eth.type", "num", "以太网类型"),
    FieldSpec("vlan.id", "num", "VLAN ID"),
    FieldSpec("vlan.priority", "num", "VLAN 优先级"),
    FieldSpec("ip.src", "ip", "IPv4 源地址"),
    FieldSpec("ip.dst", "ip", "IPv4 目的地址"),
    FieldSpec("ip.proto", "num", "IPv4 协议号"),
    FieldSpec("ip.ttl", "num", "IPv4 TTL"),
    FieldSpec("ip.id", "num", "IPv4 Identification"),
    FieldSpec("ip.len", "num", "IPv4 总长度"),
    FieldSpec("ip.checksum", "num", "IPv4 头校验和"),
    FieldSpec("ip.flags.df", "bool", "IPv4 Don't Fragment"),
    FieldSpec("ip.flags.mf", "bool", "IPv4 More Fragments"),
    FieldSpec("ip.frag_offset", "num", "IPv4 分片偏移"),
    FieldSpec("ipv6.src", "ip", "IPv6 源地址"),
    FieldSpec("ipv6.dst", "ip", "IPv6 目的地址"),
    FieldSpec("ipv6.nxt", "num", "IPv6 Next Header"),
    FieldSpec("ipv6.hlim", "num", "IPv6 Hop Limit"),
    FieldSpec("ipv6.plen", "num", "IPv6 Payload Length"),
    FieldSpec("ipv6.frag.offset", "num", "IPv6 分片偏移"),
    FieldSpec("tcp.srcport", "num", "TCP 源端口"),
    FieldSpec("tcp.dstport", "num", "TCP 目的端口"),
    FieldSpec("tcp.seq", "num", "TCP 序列号"),
    FieldSpec("tcp.ack", "num", "TCP 确认号"),
    FieldSpec("tcp.len", "num", "TCP 载荷长度"),
    FieldSpec("tcp.window_size_value", "num", "TCP 窗口大小"),
    FieldSpec("tcp.hdr_len", "num", "TCP 头部长度"),
    FieldSpec("tcp.checksum", "num", "TCP 校验和"),
    FieldSpec("tcp.flags", "num", "TCP 标志位（数值）"),
    FieldSpec("tcp.flags.syn", "bool", "TCP SYN"),
    FieldSpec("tcp.flags.ack", "bool", "TCP ACK"),
    FieldSpec("tcp.flags.fin", "bool", "TCP FIN"),
    FieldSpec("tcp.flags.rst", "bool", "TCP RST"),
    FieldSpec("tcp.flags.psh", "bool", "TCP PSH"),
    FieldSpec("tcp.flags.urg", "bool", "TCP URG"),
    FieldSpec("tcp.options.mss_val", "num", "TCP MSS"),
    FieldSpec("tcp.options.wscale", "num", "TCP Window Scale"),
    FieldSpec("tcp.stream", "num", "TCP 流编号（由流追踪器分配）"),
    FieldSpec("udp.srcport", "num", "UDP 源端口"),
    FieldSpec("udp.dstport", "num", "UDP 目的端口"),
    FieldSpec("udp.length", "num", "UDP 长度"),
    FieldSpec("udp.checksum", "num", "UDP 校验和"),
    FieldSpec("icmp.type", "num", "ICMP 类型"),
    FieldSpec("icmp.code", "num", "ICMP 代码"),
    FieldSpec("icmp.ident", "num", "ICMP Identifier"),
    FieldSpec("icmp.seq", "num", "ICMP 序列号"),
    FieldSpec("icmpv6.type", "num", "ICMPv6 类型"),
    FieldSpec("icmpv6.code", "num", "ICMPv6 代码"),
    FieldSpec("arp.opcode", "num", "ARP 操作码"),
    FieldSpec("arp.src.proto_ipv4", "ip", "ARP 发送方 IP"),
    FieldSpec("arp.dst.proto_ipv4", "ip", "ARP 目标 IP"),
    FieldSpec("arp.src.hw_mac", "mac", "ARP 发送方 MAC"),
    FieldSpec("arp.dst.hw_mac", "mac", "ARP 目标 MAC"),
    FieldSpec("http.request.method", "str", "HTTP 请求方法"),
    FieldSpec("http.request.uri", "str", "HTTP 请求 URI"),
    FieldSpec("http.request.version", "str", "HTTP 请求版本"),
    FieldSpec("http.request.full_uri", "str", "HTTP 完整请求 URI"),
    FieldSpec("http.response.code", "num", "HTTP 响应码"),
    FieldSpec("http.response.phrase", "str", "HTTP 响应短语"),
    FieldSpec("http.host", "str", "HTTP Host"),
    FieldSpec("http.user_agent", "str", "HTTP User-Agent"),
    FieldSpec("http.content_type", "str", "HTTP Content-Type"),
    FieldSpec("http.content_length", "str", "HTTP Content-Length"),
    FieldSpec("http.server", "str", "HTTP Server 响应头"),
    FieldSpec("http.location", "str", "HTTP Location 响应头"),
    FieldSpec("http.cookie", "str", "HTTP Cookie"),
    FieldSpec("dns.id", "num", "DNS 事务 ID"),
    FieldSpec("dns.flags.response", "bool", "DNS 响应标志"),
    FieldSpec("dns.flags.rcode", "num", "DNS 返回码"),
    FieldSpec("dns.qry.name", "str", "DNS 查询名"),
    FieldSpec("dns.qry.type", "num", "DNS 查询类型"),
    FieldSpec("dns.a", "ip", "DNS A 记录"),
    FieldSpec("dns.aaaa", "ip", "DNS AAAA 记录"),
    FieldSpec("dns.cname", "str", "DNS CNAME 记录"),
    FieldSpec("tls.record.content_type", "num", "TLS 记录类型"),
    FieldSpec("tls.record.version", "num", "TLS 记录版本"),
    FieldSpec("tls.handshake.type", "num", "TLS 握手类型"),
    FieldSpec("tls.handshake.extensions_server_name", "str", "TLS SNI"),
    FieldSpec("tls.handshake.version", "num", "TLS 协商版本"),
    FieldSpec("tls.handshake.extensions_alpn", "str", "TLS ALPN"),
    FieldSpec("tls.app_data_len", "num", "TLS 应用数据长度"),
    FieldSpec("dhcp.option.dhcp", "num", "DHCP 消息类型"),
    FieldSpec("ntp.stratum", "num", "NTP Stratum"),
    FieldSpec("quic.version", "num", "QUIC 版本"),
    FieldSpec("mqtt.type", "num", "MQTT 报文类型"),
    FieldSpec("data.len", "num", "未解析数据长度"),
    FieldSpec("proc.pid", "num", "产生该包的本地进程 PID"),
    FieldSpec("proc.name", "str", "产生该包的本地进程名"),
]

FIELD_SPECS: dict[str, FieldSpec] = {spec.name: spec for spec in _SPECS}

ALIASES: dict[str, Tuple[str, ...]] = {
    "ip.addr": ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"),
    "ipv6.addr": ("ipv6.src", "ipv6.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
    "eth.addr": ("eth.src", "eth.dst"),
    "dns.qname": ("dns.qry.name",),
    "tls.sni": ("tls.handshake.extensions_server_name",),
    "http.request.uri": ("http.request.uri",),
}

# protocol atom -> list of values that appear in Packet.protocols
PROTOCOLS: dict[str, Tuple[str, ...]] = {
    "frame": ("frame",),
    "eth": ("eth",),
    "vlan": ("vlan",),
    "ip": ("ip",),
    "ipv6": ("ipv6",),
    "tcp": ("tcp",),
    "udp": ("udp",),
    "icmp": ("icmp",),
    "icmpv6": ("icmpv6",),
    "arp": ("arp",),
    "dns": ("dns",),
    "http": ("http",),
    "http2": ("http",),
    "tls": ("tls", "ssl"),
    "ssl": ("tls", "ssl"),
    "dhcp": ("dhcp",),
    "ntp": ("ntp",),
    "quic": ("quic",),
    "ssh": ("ssh",),
    "ftp": ("ftp",),
    "smtp": ("smtp",),
    "mqtt": ("mqtt",),
    "redis": ("redis",),
    "sctp": ("sctp",),
    "gre": ("gre",),
    "data": ("data",),
    "expert": ("expert",),
}

EXAMPLES: list[tuple[str, str, str]] = [
    ("协议", "http", "只看 HTTP"),
    ("协议", "tcp or udp", "TCP 或 UDP"),
    ("协议", "ip and not http", "IPv4 中排除 HTTP"),
    ("协议", "icmp or icmpv6", "ICMP / ICMPv6"),
    ("端口", "tcp.port == 80", "TCP 80 端口"),
    ("端口", "udp.port == 53 or tcp.port == 53", "DNS 端口"),
    ("地址", "ip.addr == 192.168.1.0/24", "网段匹配"),
    ("地址", "ip.src == 10.0.0.5 and tcp.dstport == 443", "源地址 + 目的端口"),
    ("TCP", "tcp.flags.syn == 1 and not tcp.flags.ack == 1", "SYN 扫描/连接请求"),
    ("TCP", "tcp.len > 0 and tcp.port == 80", "HTTP 数据"),
    ("HTTP", 'http.request.method == "POST"', "POST 请求"),
    ("HTTP", "http.response.code >= 400", "HTTP 错误响应"),
    ("HTTP", 'http.host contains "example"', "Host 包含 example"),
    ("HTTP", 'http.request.uri matches "^/api/"', "URI 正则匹配"),
    ("DNS", "dns.flags.response == 0 and dns.qry.type == 1", "A 查询"),
    ("DNS", 'dns.qry.name == "example.com"', "指定域名"),
    ("TLS", "tls.handshake.type == 1", "TLS Client Hello"),
    ("TLS", 'tls.sni contains "example"', "SNI 包含 example"),
    ("载荷", 'tcp contains "GET "', "TCP 载荷包含 GET"),
    ("进程", "proc.name == \"chrome.exe\"", "按进程过滤"),
    ("流", "tcp.stream == 3", "第 3 条 TCP 流"),
]


# ---------------------------------------------------------------------------
# tokenizer
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Token:
    kind: str
    text: str
    pos: int


_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_MAC_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![\w:])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?(?![\w:])")
_NUMBER_RE = re.compile(r"0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append(Token("LPAREN" if ch == "(" else "RPAREN", ch, i))
            i += 1
            continue
        two = text[i:i + 2]
        if two in ("==", "!=", ">=", "<=", "&&", "||"):
            kind = {"&&": "AND", "||": "OR"}.get(two, "OP")
            tokens.append(Token(kind, two, i))
            i += 2
            continue
        if ch in "><~":
            tokens.append(Token("OP", ch, i))
            i += 1
            continue
        if ch == "!":
            tokens.append(Token("NOT", ch, i))
            i += 1
            continue
        match = _STRING_RE.match(text, i)
        if match:
            raw = match.group(0)
            tokens.append(Token("STRING", _unquote(raw), i))
            i = match.end()
            continue
        match = _IPV4_RE.match(text, i)
        if match:
            tokens.append(Token("IP", match.group(0), i))
            i = match.end()
            continue
        match = _MAC_RE.match(text, i)
        if match:
            tokens.append(Token("MAC", match.group(0), i))
            i = match.end()
            continue
        match = _IPV6_RE.match(text, i)
        if match:
            tokens.append(Token("IP", match.group(0), i))
            i = match.end()
            continue
        match = _NUMBER_RE.match(text, i)
        if match:
            tokens.append(Token("NUMBER", match.group(0), i))
            i = match.end()
            continue
        match = _IDENT_RE.match(text, i)
        if match:
            word = match.group(0)
            lower = word.lower()
            if lower in ("and", "or", "not", "contains", "matches"):
                tokens.append(Token(lower.upper(), word, i))
            elif lower in ("true", "false"):
                tokens.append(Token("BOOL", lower, i))
            else:
                tokens.append(Token("IDENT", word, i))
            i = match.end()
            continue
        raise FilterError(f"第 {i + 1} 列出现无法识别的字符: {ch!r}")
    tokens.append(Token("EOF", "", n))
    return tokens


def _unquote(raw: str) -> str:
    body = raw[1:-1]
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            mapping = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\"}
            out.append(mapping.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

class Node:
    def evaluate(self, packet) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(slots=True)
class Const(Node):
    value: bool

    def evaluate(self, packet) -> bool:
        return self.value


@dataclass(slots=True)
class And(Node):
    left: Node
    right: Node

    def evaluate(self, packet) -> bool:
        return self.left.evaluate(packet) and self.right.evaluate(packet)


@dataclass(slots=True)
class Or(Node):
    left: Node
    right: Node

    def evaluate(self, packet) -> bool:
        return self.left.evaluate(packet) or self.right.evaluate(packet)


@dataclass(slots=True)
class Not(Node):
    node: Node

    def evaluate(self, packet) -> bool:
        return not self.node.evaluate(packet)


@dataclass(slots=True)
class Proto(Node):
    names: Tuple[str, ...]

    def evaluate(self, packet) -> bool:
        name = self.names[0] if self.names else ""
        if name == "frame":
            return True
        if name == "expert":
            return bool(packet.expert)
        protocols = packet.protocols
        return any(item in protocols for item in self.names)


@dataclass(slots=True)
class ProtoContains(Node):
    proto: str
    needle: bytes

    def evaluate(self, packet) -> bool:
        haystack = _protocol_bytes(packet, self.proto)
        return self.needle in haystack


@dataclass(slots=True)
class Compare(Node):
    fields: Tuple[FieldSpec, ...]
    op: str
    literal: str
    token_kind: str

    def evaluate(self, packet) -> bool:
        values: list[tuple[FieldSpec, Any]] = []
        for spec in self.fields:
            for value in _field_values(packet, spec.name):
                values.append((spec, value))
        if not values:
            return False
        if self.op == "!=":
            return all(not _compare_one(spec, value, "==", self.literal, self.token_kind)
                       for spec, value in values)
        if self.op == "==":
            return any(_compare_one(spec, value, "==", self.literal, self.token_kind)
                       for spec, value in values)
        return any(_compare_one(spec, value, self.op, self.literal, self.token_kind)
                   for spec, value in values)


@dataclass(slots=True)
class TextMatch(Node):
    fields: Tuple[FieldSpec, ...]
    op: str  # contains | matches
    text: str
    pattern: Optional[re.Pattern] = None

    def evaluate(self, packet) -> bool:
        for spec in self.fields:
            for value in _field_values(packet, spec.name):
                hay = _as_text(value)
                if self.op == "contains":
                    if self.text in hay:
                        return True
                else:
                    if self.pattern is not None and self.pattern.search(hay):
                        return True
        return False


@dataclass(slots=True)
class Exists(Node):
    fields: Tuple[FieldSpec, ...]

    def evaluate(self, packet) -> bool:
        for spec in self.fields:
            values = _field_values(packet, spec.name)
            if not values:
                continue
            if spec.kind == "bool":
                if any(bool(value) for value in values):
                    return True
            else:
                return True
        return False


# ---------------------------------------------------------------------------
# field access and comparison
# ---------------------------------------------------------------------------

def _protocol_bytes(packet, proto: str) -> bytes:
    if proto == "tcp" and packet.tcp is not None:
        return packet.tcp.payload
    if proto == "udp" and packet.udp is not None:
        return packet.udp.payload
    if proto in ("http", "dns", "tls", "ssh", "ftp", "smtp", "mqtt", "redis"):
        chunks = []
        for layer in packet.layers:
            if layer.key == proto or (proto == "tls" and layer.key == "tls"):
                chunks.append(packet.raw[layer.offset:layer.offset + layer.length])
        if chunks:
            return b"".join(chunks)
    return packet.raw


def _field_values(packet, name: str) -> list[Any]:
    if name == "tcp.stream":
        return [] if packet.stream is None else [packet.stream]
    if name == "proc.pid":
        return [] if packet.pid is None else [packet.pid]
    if name == "proc.name":
        return [] if not packet.process else [packet.process]
    return [field.value for field in packet.index.get(name, ())]


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _coerce_number(value: Any) -> Optional[float]:
    try:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(text: str) -> Optional[bool]:
    low = text.strip().lower()
    if low in ("1", "true", "yes", "on"):
        return True
    if low in ("0", "false", "no", "off"):
        return False
    return None


def _parse_ip_target(text: str):
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_address(text)
    except ValueError:
        raise FilterError(f"不是合法的 IP 地址或网段: {text}")


def _compare_one(spec: FieldSpec, value: Any, op: str, literal: str, token_kind: str) -> bool:
    kind = spec.kind
    if kind in ("num", "time"):
        left = _coerce_number(value)
        try:
            right = float(int(literal, 0)) if literal.lower().startswith("0x") else float(literal)
        except ValueError:
            raise FilterError(f"字段 {spec.name} 需要数值，得到 {literal!r}")
        if left is None:
            return False
        return _apply_op(left, right, op)
    if kind == "bool":
        left = _coerce_bool(_as_text(value).lower()) if isinstance(value, bool) else _coerce_bool(str(value))
        right = _coerce_bool(literal)
        if right is None:
            raise FilterError(f"字段 {spec.name} 需要 true/false，得到 {literal!r}")
        if op not in ("==", "!="):
            raise FilterError(f"布尔字段 {spec.name} 只支持 == 与 !=")
        left = bool(value) if isinstance(value, bool) else bool(left)
        return (left == right) if op == "==" else (left != right)
    if kind == "ip":
        target = _parse_ip_target(literal)
        text = _as_text(value).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return False
        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if target.version != addr.version:
                return False
            inside = addr in target
            if op == "==":
                return inside
            if op == "!=":
                return not inside
            raise FilterError("IP 网段只支持 == 与 !=")
        if op == "==":
            return addr == target
        if op == "!=":
            return addr != target
        raise FilterError("IP 字段只支持 == 与 !=")
    if kind == "mac":
        if op not in ("==", "!="):
            raise FilterError("MAC 字段只支持 == 与 !=")
        left = _as_text(value).lower().replace("-", ":")
        right = literal.lower().replace("-", ":")
        return (left == right) if op == "==" else (left != right)
    # string
    left = _as_text(value)
    if op == "==":
        return left == literal
    if op == "!=":
        return left != literal
    if op == "contains":
        return literal in left
    if op == "matches":
        try:
            return re.search(literal, left) is not None
        except re.error as exc:
            raise FilterError(f"正则表达式错误: {exc}")
    if op in (">", "<", ">=", "<="):
        return _apply_op(left, literal, op)
    raise FilterError(f"不支持的比较运算符: {op}")


def _apply_op(left, right, op: str) -> bool:
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == ">":
        return left > right
    if op == "<":
        return left < right
    if op == ">=":
        return left >= right
    if op == "<=":
        return left <= right
    raise FilterError(f"不支持的运算符: {op}")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens: List[Token], text: str):
        self.tokens = tokens
        self.text = text
        self.pos = 0

    def peek(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[self.pos]

    def next(self) -> Token:
        token = self.peek()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return token

    def error(self, message: str, token: Optional[Token] = None):
        token = token or self.peek()
        raise FilterError(f"第 {token.pos + 1} 列: {message}")

    def parse(self) -> Node:
        if self.peek().kind == "EOF":
            return Const(True)
        node = self.parse_or()
        if self.peek().kind != "EOF":
            self.error(f"多余的内容 {self.peek().text!r}")
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek().kind == "OR":
            self.next()
            node = Or(node, self.parse_and())
        return node

    def parse_and(self) -> Node:
        node = self.parse_unary()
        while self.peek().kind == "AND":
            self.next()
            node = And(node, self.parse_unary())
        return node

    def parse_unary(self) -> Node:
        if self.peek().kind == "NOT":
            self.next()
            return Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Node:
        token = self.peek()
        if token.kind == "LPAREN":
            self.next()
            node = self.parse_or()
            if self.peek().kind != "RPAREN":
                self.error("缺少右括号")
            self.next()
            return node
        if token.kind == "BOOL":
            self.next()
            return Const(token.text == "true")
        if token.kind != "IDENT":
            self.error(f"这里需要协议名或字段名，得到 {token.text!r}")
        self.next()
        word = token.text
        low = word.lower()

        if low in PROTOCOLS:
            if self.peek().kind in ("CONTAINS", "MATCHES"):
                op = self.next().kind.lower()
                if op != "contains":
                    self.error("协议名只支持 contains 运算符")
                value = self.next()
                if value.kind not in ("STRING", "IDENT", "NUMBER", "IP", "MAC"):
                    self.error("contains 后面需要字符串")
                return ProtoContains(low, value.text.encode("utf-8", "replace"))
            return Proto(PROTOCOLS[low])

        specs = _resolve_field(word)
        if specs is None:
            import difflib

            suggestions = difflib.get_close_matches(word, list(FIELD_SPECS) + list(PROTOCOLS), n=2)
            hint = f"，你是不是想输入 {', '.join(suggestions)}?" if suggestions else ""
            self.error(f"未知的协议或字段 {word!r}{hint}", token)

        nxt = self.peek()
        if nxt.kind == "OP":
            self.next()
            op = nxt.text
            value = self.next()
            if value.kind not in ("STRING", "NUMBER", "IP", "MAC", "IDENT", "BOOL"):
                self.error("比较运算符后面需要值")
            return Compare(tuple(specs), op, value.text, value.kind)
        if nxt.kind in ("CONTAINS", "MATCHES"):
            self.next()
            value = self.next()
            if value.kind not in ("STRING", "IDENT", "NUMBER", "IP", "MAC"):
                self.error(f"{nxt.text} 后面需要字符串")
            pattern = None
            if nxt.kind == "MATCHES":
                try:
                    pattern = re.compile(value.text)
                except re.error as exc:
                    self.error(f"正则表达式错误: {exc}", value)
            return TextMatch(tuple(specs), nxt.kind.lower(), value.text, pattern)
        return Exists(tuple(specs))


def _resolve_field(name: str) -> Optional[List[FieldSpec]]:
    if name in ALIASES:
        return [FIELD_SPECS[item] for item in ALIASES[name] if item in FIELD_SPECS]
    if name in FIELD_SPECS:
        return [FIELD_SPECS[name]]
    return None


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

class DisplayFilter:
    def __init__(self, expression: str, root: Node):
        self.expression = expression
        self.root = root

    def matches(self, packet) -> bool:
        return self.root.evaluate(packet)

    def __call__(self, packet) -> bool:
        return self.root.evaluate(packet)


def compile_filter(expression: str) -> DisplayFilter:
    expression = (expression or "").strip()
    if len(expression) > 4096:
        raise FilterError("过滤器过长（最多 4096 字符）")
    tokens = tokenize(expression)
    root = _Parser(tokens, expression).parse()
    return DisplayFilter(expression, root)


ALL_OF: Callable[[Any], bool] = lambda packet: True
