"""Minimal ISO-BMFF (MP4) construction with vrcore.Frame, for turning a CodeQL
hypothesis about a suspected unchecked field into a targeted demuxer input.

Two ways to produce a crafted input (see hypotheses.py):
  A) build a container from scratch with box()/container()/ftyp();
  B) locate a box in a validated 'reach template' (a PoC you know reaches the
     element) with find_box() and overwrite one field with splice().
"""
from __future__ import annotations
from vrcore import Frame, u32be, u16be, u8, raw

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf",
              b"udta", b"mvex", b"moof", b"traf"}


def box(type4: str, payload: bytes = b"") -> bytes:
    """A 32-bit ISO box: size(u32be, whole box) + 4cc type + payload."""
    assert len(type4) == 4, type4
    return Frame(u32be(8 + len(payload)), raw(type4.encode("ascii")), raw(payload),
                 name=f"box:{type4}").build()


def container(type4: str, *children: bytes) -> bytes:
    return box(type4, b"".join(children))


def full_box(type4: str, version: int, flags: int, payload: bytes) -> bytes:
    return box(type4, u8(version) + bytes([(flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF]) + payload)


def ftyp(major: str = "isom", minor: int = 0, *brands: str) -> bytes:
    brands = brands or ("isom", "mp41")
    return box("ftyp", major.encode("ascii") + u32be(minor) + b"".join(b.encode("ascii") for b in brands))


def find_box(data: bytes, type4: str):
    """Best-effort locate the first box of type4. Returns (box_start, box_size,
    payload_start) or None. Tries a structured walk (descending into known
    container boxes), then falls back to a raw scan for the 4cc with a plausible
    preceding size. For full-boxes (stsd/meta) you may prefer an explicit offset."""
    want = type4.encode("ascii")

    def walk(off: int, end: int):
        i = off
        while i + 8 <= end:
            size = int.from_bytes(data[i:i+4], "big")
            typ = data[i+4:i+8]
            hdr = 8
            if size == 1 and i + 16 <= end:
                size = int.from_bytes(data[i+8:i+16], "big"); hdr = 16
            elif size == 0:
                size = end - i
            if typ == want:
                return (i, size, i + hdr)
            if size < hdr or i + size > end:
                break
            if typ in CONTAINERS:
                r = walk(i + hdr, i + size)
                if r:
                    return r
            i += size
        return None

    r = walk(0, len(data))
    if r:
        return r
    # raw fallback: scan for the 4cc, validate preceding size
    pos = data.find(want)
    while pos >= 4:
        start = pos - 4
        size = int.from_bytes(data[start:start+4], "big")
        if 8 <= size <= len(data) - start:
            return (start, size, start + 8)
        pos = data.find(want, pos + 1)
    return None


def splice(data: bytes, offset: int, newbytes: bytes) -> bytes:
    """Overwrite len(newbytes) bytes at offset (same length in/out)."""
    return data[:offset] + newbytes + data[offset + len(newbytes):]
