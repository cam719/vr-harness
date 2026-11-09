"""Example hypotheses -- each turns a CodeQL/audit finding into a probe spec.

These are GENERIC SKELETONS to illustrate the two shapes, not real findings:
  A) build the container from scratch with mp4.py (full control of the field);
  B) splice one field inside a 'reach template' file you provide.

Add your own: a dict with name/codeql_ref/element/sink/build/values, registered
in REGISTRY. `build(value)` must place `value` in the suspected field; `values`
are the attacker extremes your hypothesis says are unchecked. Keep real targets
and template files in your own private corpus, not in a public checkout.
"""
from __future__ import annotations
import os
from pathlib import Path
from vrcore import u32be
from . import mp4

# Your private 'reach template' files (kept out of git). Override with the
# GST_POC_DIR env var; defaults to ./pocs next to the repo.
POC = Path(os.environ.get("GST_POC_DIR", "./pocs")).expanduser()


# --- Example A: a made-up 'exbx' box whose count field sizes an allocation -----
#   Illustrative only: 'exbx' is a fictional box, not a real element/field.
def _build_example_count(count: int) -> bytes:
    exbx = mp4.box("exbx", u32be(count) + b"\x00" * 8)   # count, then (truncated) entries
    return mp4.ftyp() + mp4.container("moov", mp4.container("trak", exbx))

HYP_A = dict(
    name="example_count_field",
    codeql_ref="example-unchecked-count",
    element="demux",
    sink="a count field sizes an allocation/loop without a bound check",
    build=_build_example_count,
    values=[0xFFFFFFFF, 0x7FFFFFFF, 0x40000000, 0x00010000],
    note="SKELETON -- replace the box/field/element with your own finding",
)


# --- Example B: splice one field inside a reach template you provide ----------
def _splice_factory(template_file: str, box_type: str, field_off: int, width: int = 4):
    def build(value: int) -> bytes:
        base = (POC / template_file).read_bytes()
        loc = mp4.find_box(base, box_type)
        if not loc:
            raise ValueError(f"box {box_type!r} not found in {template_file}")
        _, _, payload = loc
        return mp4.splice(base, payload + field_off, value.to_bytes(width, "big"))
    return build

HYP_B = dict(
    name="example_field_splice",
    codeql_ref="example-unchecked-field",
    element="demux",
    sink="a size/count field in a box is used unchecked",
    build=_splice_factory("YOUR_TEMPLATE.mp4", "exbx", field_off=4, width=4),
    values=[0xFFFFFFFF, 0x7FFFFFFF, 0x0],
    note="SKELETON -- set template/box/offset from your own finding",
)


REGISTRY = {h["name"]: h for h in (HYP_A, HYP_B)}
