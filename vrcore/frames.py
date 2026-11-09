"""Composable byte builders, after Beer's RT()/WIFI()/AWDL() style.

A Frame is a list of parts. A part is bytes, another Frame, or a callable that
receives the already-built *inner* bytes (for length prefixes). Frames build
lazily so a field can depend on the size of what follows it.
"""
from __future__ import annotations
import struct
from typing import Callable, Union

Part = Union[bytes, "Frame", Callable[[bytes], bytes]]


class Unknown:
    """Marker for a wire-format field not yet recovered. Builders that hit an
    UNKNOWN with no explicit override raise, so no one sends a guess by accident."""
    def __repr__(self) -> str:
        return "UNKNOWN"

UNKNOWN = Unknown()


class Frame:
    """A list of parts, built lazily. A part is bytes, another Frame, or a
    callable receiving the already-built inner bytes (for length prefixes)."""

    def __init__(self, *parts: Part, name: str = ""):
        self.parts: list = list(parts)
        self.name = name

    def __add__(self, other: Part) -> "Frame":
        return Frame(*self.parts, other, name=self.name)

    def append(self, part: Part) -> "Frame":
        self.parts.append(part)
        return self

    def build(self) -> bytes:
        return b"".join(_build_part(p) for p in self.parts)

    def __bytes__(self) -> bytes:
        return self.build()

    def __len__(self) -> int:
        return len(self.build())

    def hexdump(self) -> str:
        data = self.build()
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08x}  {hx:<48}  {asc}")
        return "\n".join(lines)


def _build_part(p: Part) -> bytes:
    if isinstance(p, Unknown):
        raise ValueError("frame contains an UNKNOWN field; pass an explicit value")
    if isinstance(p, (bytes, bytearray)):
        return bytes(p)
    if isinstance(p, Frame):
        return p.build()
    if isinstance(p, str):
        return p.encode()
    if callable(p):
        raise TypeError("bare callables are only valid inside lenprefix()")
    raise TypeError(f"unsupported frame part: {type(p)!r}")


# --- scalar fields -----------------------------------------------------------
def u8(v: int) -> bytes:  return struct.pack("<B", v & 0xFF)
def u16le(v: int) -> bytes: return struct.pack("<H", v & 0xFFFF)
def u16be(v: int) -> bytes: return struct.pack(">H", v & 0xFFFF)
def u32le(v: int) -> bytes: return struct.pack("<I", v & 0xFFFFFFFF)
def u32be(v: int) -> bytes: return struct.pack(">I", v & 0xFFFFFFFF)
def u64le(v: int) -> bytes: return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
def ascii_bytes(s: str) -> bytes: return s.encode("ascii")
def raw(b: bytes) -> bytes: return bytes(b)
def pad(n: int, fill: int = 0) -> bytes: return bytes([fill]) * n


def lenprefix(fmt: str, body: Part, *, includes_prefix: bool = False, adjust: int = 0) -> Frame:
    """Length-prefixed body. fmt is a struct format like '<I' or '>H'.
    includes_prefix=True counts the prefix itself. adjust is added to the value
    (useful for off-by-one experiments)."""
    inner = _build_part(body)
    n = len(inner) + (struct.calcsize(fmt) if includes_prefix else 0) + adjust
    return Frame(struct.pack(fmt, n), inner)
