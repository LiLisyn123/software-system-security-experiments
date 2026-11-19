"""Packet / protocol field data model shared by the dissectors and the GUI.

The model is intentionally close to Wireshark's notion of a *protocol tree*:

* :class:`Field` is one displayable item, e.g. ``Source Address: 10.0.0.1``.
  It knows the byte range it came from so the hex view can highlight it.
* :class:`Layer` groups the fields of one protocol header.
* :class:`Packet` is a fully dissected frame plus the handful of attributes
  the packet list needs (summary columns, colour, TCP stream id, process
  attribution...).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# value formatting helpers
# ---------------------------------------------------------------------------

def format_timestamp(ts: float) -> str:
    """Format an epoch timestamp in local time, microsecond resolution."""
    try:
        dt = _dt.datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return str(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}"


def format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    if isinstance(value, (bytes, bytearray)):
        if not value:
            return ""
        try:
            text = bytes(value).decode("utf-8")
            if all(32 <= ord(ch) < 127 or ch in "\r\n\t" for ch in text):
                return text.replace("\r", "\\r").replace("\n", "\\n")
        except UnicodeDecodeError:
            pass
        return bytes(value).hex(" ")
    if value is None:
        return ""
    return str(value)


# ---------------------------------------------------------------------------
# protocol tree
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Field:
    key: str
    label: str
    value: Any = ""
    offset: int = -1          # byte offset relative to the start of the frame
    length: int = 0           # number of bytes covered by this field
    display: Optional[str] = None
    raw: Optional[bytes] = None
    children: List["Field"] = field(default_factory=list)

    def text(self) -> str:
        shown = self.display if self.display is not None else format_value(self.value)
        if self.label:
            return f"{self.label}: {shown}"
        return shown

    def walk(self) -> Iterable["Field"]:
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass(slots=True)
class Layer:
    name: str
    key: str
    offset: int = 0
    length: int = 0
    summary: str = ""
    fields: List[Field] = field(default_factory=list)

    def title(self) -> str:
        if self.summary:
            return f"{self.name} ({self.summary})"
        return self.name


# ---------------------------------------------------------------------------
# transport protocol metadata used by the stream tracker
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TcpMeta:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    header_len: int
    payload: bytes
    payload_offset: int
    options: Dict[str, Any] = field(default_factory=dict)
    checksum_ok: Optional[bool] = None


@dataclass(slots=True)
class UdpMeta:
    sport: int
    dport: int
    length: int
    payload: bytes
    payload_offset: int


@dataclass(slots=True)
class IpMeta:
    version: int
    src: str
    dst: str
    proto: int
    ttl: int
    ident: int = 0
    header_len: int = 0
    total_len: int = 0
    fragmented: bool = False


# ---------------------------------------------------------------------------
# packet
# ---------------------------------------------------------------------------

# colour keys understood by the GUI
COLOR_HTTP = "http"
COLOR_DNS = "dns"
COLOR_TLS = "tls"
COLOR_TCP = "tcp"
COLOR_UDP = "udp"
COLOR_ICMP = "icmp"
COLOR_ARP = "arp"
COLOR_IPV6 = "ipv6"
COLOR_OTHER = "other"
COLOR_ERROR = "error"


@dataclass(slots=True)
class Packet:
    number: int
    ts: float
    raw: bytes
    wirelen: int
    linktype: int
    layers: List[Layer] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    src: str = ""
    dst: str = ""
    protocol: str = ""
    info: str = ""
    color: str = COLOR_OTHER
    index: Dict[str, List[Field]] = field(default_factory=dict)
    tcp: Optional[TcpMeta] = None
    udp: Optional[UdpMeta] = None
    ip: Optional[IpMeta] = None
    stream: Optional[int] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    expert: List[str] = field(default_factory=list)
    # private caches (not part of the public model)
    _flat: Optional[Tuple[Field, ...]] = None

    # -- convenience ------------------------------------------------------
    @property
    def caplen(self) -> int:
        return len(self.raw)

    @property
    def has_error(self) -> bool:
        return any(msg.startswith("Error") for msg in self.expert)

    def fields_for(self, key: str) -> List[Field]:
        return self.index.get(key, [])

    def first_field(self, key: str) -> Optional[Field]:
        vals = self.index.get(key)
        return vals[0] if vals else None

    def first_value(self, key: str, default: Any = None) -> Any:
        f = self.first_field(key)
        return f.value if f is not None else default

    def text_value(self, key: str, default: str = "") -> str:
        f = self.first_field(key)
        if f is None:
            return default
        return f.display if f.display is not None else format_value(f.value)

    def has_protocol(self, name: str) -> bool:
        return name in self.protocols

    def all_layers(self) -> List[Layer]:
        return self.layers

    def flattened_fields(self) -> Tuple[Field, ...]:
        if self._flat is None:
            out: List[Field] = []
            for layer in self.layers:
                for f in layer.fields:
                    out.extend(f.walk())
            self._flat = tuple(out)
        return self._flat

    def searchable_text(self) -> str:
        """Text used by the quick-find function."""
        parts = [self.info, self.protocol, self.src, self.dst, self.process or ""]
        return " ".join(parts).lower()

    def protocols_string(self) -> str:
        return ":".join(self.protocols)

    def summary_line(self) -> str:
        return f"{self.number}\t{format_timestamp(self.ts)}\t{self.src}\t{self.dst}\t{self.protocol}\t{self.wirelen}\t{self.info}"


# ---------------------------------------------------------------------------
# dissection context
# ---------------------------------------------------------------------------

class ParseContext:
    """Accumulates layers and fields while walking a frame.

    Dissectors call :meth:`begin_layer`, add fields with :meth:`add`, and
    finally :meth:`end_layer`.  Every field is also inserted into ``index`` so
    display filters can look it up in O(1).
    """

    __slots__ = (
        "raw", "number", "ts", "wirelen", "linktype", "layers", "protocols",
        "index", "src", "dst", "protocol", "info", "color", "expert",
        "tcp", "udp", "ip", "payload_offset", "payload_handled",
        "_current", "_layer_protocols",
    )

    def __init__(self, raw: bytes, number: int, ts: float, wirelen: int, linktype: int):
        self.raw = raw
        self.number = number
        self.ts = ts
        self.wirelen = wirelen
        self.linktype = linktype
        self.layers: List[Layer] = []
        self.protocols: List[str] = []
        self.index: Dict[str, List[Field]] = {}
        self.src = ""
        self.dst = ""
        self.protocol = ""
        self.info = ""
        self.color = COLOR_OTHER
        self.expert: List[str] = []
        self.tcp: Optional[TcpMeta] = None
        self.udp: Optional[UdpMeta] = None
        self.ip: Optional[IpMeta] = None
        self.payload_offset = -1
        self.payload_handled = False
        self._current: Optional[Layer] = None
        self._layer_protocols: set[str] = set()

    # -- layer/field construction ----------------------------------------
    def begin_layer(self, name: str, key: str, offset: int, length: int = 0,
                    summary: str = "") -> Layer:
        layer = Layer(name=name, key=key, offset=offset, length=length, summary=summary)
        self.layers.append(layer)
        self._current = layer
        if key and key not in self._layer_protocols:
            self._layer_protocols.add(key)
            self.protocols.append(key)
        return layer

    def end_layer(self) -> None:
        self._current = None

    def _index(self, f: Field) -> None:
        for item in f.walk():
            if item.key:
                self.index.setdefault(item.key, []).append(item)

    def add(self, key: str, label: str, value: Any = "", offset: int = -1,
            length: int = 0, display: Any = None, raw: Optional[bytes] = None,
            children: Optional[List[Field]] = None) -> Field:
        if self._current is None:
            raise RuntimeError("add() called outside a layer")
        f = Field(
            key=key,
            label=label,
            value=value,
            offset=offset,
            length=length,
            display=None if display is None else str(display),
            raw=raw,
            children=children or [],
        )
        self._current.fields.append(f)
        self._index(f)
        return f

    def child(self, parent: Field, key: str, label: str, value: Any = "",
              offset: int = -1, length: int = 0, display: Any = None,
              raw: Optional[bytes] = None) -> Field:
        f = Field(
            key=key,
            label=label,
            value=value,
            offset=offset,
            length=length,
            display=None if display is None else str(display),
            raw=raw,
        )
        parent.children.append(f)
        self._index(f)
        return f

    def group(self, key: str, label: str, value: Any = "", offset: int = -1,
              length: int = 0, display: Any = None) -> Field:
        """Add a field that is a container for :meth:`child` items."""
        return self.add(key, label, value, offset=offset, length=length, display=display)

    # -- diagnostics ------------------------------------------------------
    def warn(self, message: str) -> None:
        self.expert.append("Warning: " + message)

    def error(self, message: str) -> None:
        self.expert.append("Error: " + message)

    def note(self, message: str) -> None:
        self.expert.append("Note: " + message)

    # -- finalisation -----------------------------------------------------
    def finish(self) -> Packet:
        # Frame layer is created last (it needs the protocol stack) but must
        # be displayed first.
        frame = Layer(name="Frame", key="frame", offset=0, length=len(self.raw))
        frame_fields = [
            Field("frame.number", "Number", self.number),
            Field("frame.time", "Time", self.ts, display=format_timestamp(self.ts)),
            Field("frame.time_epoch", "Epoch Time", self.ts, display=f"{self.ts:.6f}"),
            Field("frame.len", "Frame Length", self.wirelen),
            Field("frame.cap_len", "Captured Length", len(self.raw)),
            Field("frame.protocols", "Protocols", ":".join(self.protocols)),
            Field("frame.linktype", "Link Type", self.linktype),
        ]
        frame.fields = frame_fields
        for f in frame_fields:
            self.index.setdefault(f.key, []).append(f)
        self.layers.insert(0, frame)

        if self.expert:
            layer = Layer(name="Expert Info", key="expert", offset=0, length=len(self.raw))
            for msg in self.expert:
                key = "expert.error" if msg.startswith("Error") else (
                    "expert.warn" if msg.startswith("Warning") else "expert.note")
                layer.fields.append(Field(key, "Expert", msg))
            self.layers.append(layer)
            # index expert fields as well
            for f in layer.fields:
                self.index.setdefault(f.key, []).append(f)

        if not self.protocol:
            self.protocol = (self.protocols[-1].upper() if self.protocols else "Unknown")
        if not self.info:
            self.info = self.protocol
        if not self.src:
            self.src = "?"
        if not self.dst:
            self.dst = "?"

        return Packet(
            number=self.number,
            ts=self.ts,
            raw=self.raw,
            wirelen=self.wirelen,
            linktype=self.linktype,
            layers=self.layers,
            protocols=self.protocols,
            src=self.src,
            dst=self.dst,
            protocol=self.protocol,
            info=self.info,
            color=self.color,
            index=self.index,
            tcp=self.tcp,
            udp=self.udp,
            ip=self.ip,
            expert=self.expert,
        )
