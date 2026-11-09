"""CodeQL -> hypothesis -> Frame -> confirm, recorded through vrcore.

A Hypothesis encodes a suspected unchecked field a CodeQL query (or a manual
read) flagged in a parser. probe() builds one targeted input per candidate
value, fires each into the ASAN pipeline, and records -- control-case first,
then one N-of-N 'fault' record per value -- which values actually fault.

The *reading* produces the hypothesis; the harness turns it into a trustworthy
experiment. Discovery, not just replay.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from vrcore import RunStore, LabPolicy
from .runner import GstRunner
from ._pipeline import RUNS, load_cfg, fire


@dataclass
class Hypothesis:
    name: str
    codeql_ref: str                       # the query/finding id that flagged the sink
    element: str                          # element expected to parse it (demux, ...)
    sink: str                             # human description of the suspected unchecked op
    build: Callable[[int], bytes]         # value -> crafted container bytes
    values: Sequence[int]                 # attacker values to probe (the hypothesis)
    control: bytes | None = None          # benign container that reaches `element`
    note: str = ""


def probe(h: Hypothesis, lab_toml: Path, trials: int = 3,
          runner_override: str | None = None, transport_factory=GstRunner) -> int:
    cfg = load_cfg(lab_toml); t = cfg["target"]
    runner_cmd = runner_override or t["runner"]
    policy = LabPolicy.from_toml(lab_toml)
    store = RunStore(RUNS)
    run = store.create_run("gstreamer", t.get("build", "?"),
                           notes=f"hypothesis {h.name} <- {h.codeql_ref}")
    node = store.open_node(run.id, f"gstcodeql/hypothesis/{h.name}",
                           prereq=f"reaches {h.element}", notes=h.sink)

    def shot(rec_id, data, expect_fault, label):
        return fire(store, run.id, rec_id, data, expect_fault, label,
                    policy=policy, runner_cmd=runner_cmd, transport_factory=transport_factory)

    if h.control is not None:
        rec = store.add_record(run.id, node.id, "observation", "reach template parses clean",
                               hypothesis=f"a benign {h.element} input parses without fault", min_trials=trials)
        for i in range(trials):
            o = shot(rec.id, h.control, False, f"control-{i}")
            print(f"[control {i+1}/{trials}] {o.get('verdict')} ({o.get('detail','')[:60]})")
        if store.get_record(run.id, rec.id).status != "confirmed":
            print("WARNING: reach template did not parse clean -- runner wrong, or the benign file already faults.")

    faulting = []
    for v in h.values:
        try:
            data = h.build(v)
        except Exception as e:
            print(f"[build {hex(v)}] SKIP ({e})"); continue
        rec = store.add_record(run.id, node.id, "fault", f"{h.name} @ {hex(v)}",
                               hypothesis=h.sink, min_trials=trials)
        for i in range(trials):
            o = shot(rec.id, data, True, f"{h.name}-{hex(v)}-{i}")
            print(f"[{h.name} {hex(v)} {i+1}/{trials}] {o.get('verdict')} ({o.get('detail','')[:60]})")
        if store.get_record(run.id, rec.id).status == "confirmed":
            faulting.append(hex(v))

    store.close_node(run.id, node.id, "success" if faulting else "exhausted", evidence=node.id)
    print(store.render_timeline(run.id))
    print(f"\nhypothesis {h.name}: values that faulted {trials}/{trials} -> {faulting or '(none confirmed)'}")
    return 0 if faulting else 1
