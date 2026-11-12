"""verify: run ONE lead through the harness and let the harness -- not the
person or agent who proposed the lead -- decide whether it is real.

Given a known-good CONTROL file and a MUTANT that changes only the field the
lead names, it:
  1. records the byte diff between them (exactly what was changed),
  2. requires the control to parse CLEAN N/N under ASAN, or stops without
     mutating anything (a "fault" on a broken runner/control means nothing),
  3. fires the mutant N times, judged by GstFaultOracle (hard memory-safety
     fault vs soft GLib diagnostic) and, with `site`, GstSiteOracle (is the
     fault in the lead's code?),
  4. optionally fires VARIANTS (boundary values, a revert, ...) with their own
     expected outcome, as supporting causality evidence,
  5. takes the verdict from the record statuses, which RunStore derives purely
     from the trials:
       CONFIRMED    control clean N/N and mutant faulted (at the site) N/N
       REFUTED      mutant produced no memory-safety fault in N/N trials
       INCONCLUSIVE anything else (control broken, flaky, timeouts, wrong site)
     and writes verdict.json next to the run.

Everything is recorded through RunStore (node, records, N-of-N trials,
timeline). Non-destructive: it parses files under a sanitizer and records what
happened.
"""
from __future__ import annotations
import functools
import hashlib
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from vrcore import RunStore, LabPolicy
from .runner import GstRunner
from .oracle import GstSiteOracle, hard_fault
from ._pipeline import RUNS, ORACLE, fire

LAB = Path(__file__).resolve().parents[1] / "lab.toml"

CONFIRMED, REFUTED, INCONCLUSIVE = "CONFIRMED", "REFUTED", "INCONCLUSIVE"
EXIT = {CONFIRMED: 0, REFUTED: 1, INCONCLUSIVE: 2}


@dataclass
class Variant:
    path: Path
    expect: str                           # "fault" | "clean"

    @classmethod
    def parse(cls, spec: str) -> "Variant":
        path, sep, expect = spec.rpartition("=")
        if not sep or not path or expect not in ("fault", "clean"):
            raise ValueError(f"variant must be FILE=fault or FILE=clean, got {spec!r}")
        return cls(Path(path), expect)


def byte_diff(a: bytes, b: bytes, max_ranges: int = 16) -> dict:
    """Which bytes the mutant changed: (offset, length) ranges over the common
    prefix, plus any change in length."""
    ranges, start, n = [], None, min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i - start))
            start = None
    if start is not None:
        ranges.append((start, n - start))
    return {"control_len": len(a), "mutant_len": len(b),
            "bytes_changed": sum(k for _, k in ranges),
            "ranges": [{"offset": o, "length": k, "old": a[o:o + k][:16].hex(), "new": b[o:o + k][:16].hex()}
                       for o, k in ranges[:max_ranges]],
            "more_ranges": max(0, len(ranges) - max_ranges)}


def gst_runner_template(element: str, gst_src, builddir) -> str:
    """The uninstalled-ASAN-build runner: filesrc -> <element> -> fakesink."""
    env_py = shlex.quote(str(Path(gst_src).expanduser() / "gst-env.py"))
    bdir = shlex.quote(str(Path(builddir).expanduser()))
    return (f"python3 {env_py} --builddir {bdir} "
            f"gst-launch-1.0 -q filesrc location={{input}} ! {element} ! fakesink")


_ASAN_TYPE = re.compile(rb"ERROR: AddressSanitizer: ([\w-]+)")
_ACCESS = re.compile(rb"\b(READ|WRITE) of size (\d+)")
_UBSAN = re.compile(rb"runtime error: ([^\n]+)")


def summarize_fault(reply: bytes) -> dict:
    """Bug type, access kind/size and a report excerpt from one faulting reply."""
    m = hard_fault(reply)
    if not m:
        return {}
    start = reply.rfind(b"\n", 0, m.start()) + 1
    excerpt = b"\n".join(reply[start:].splitlines()[:60]).decode("utf-8", "replace")
    t, a, u = _ASAN_TYPE.search(reply), _ACCESS.search(reply), _UBSAN.search(reply)
    if t:
        kind = t.group(1).decode()
    elif u:
        kind = "ubsan: " + u.group(1).decode("utf-8", "replace")[:100]
    else:
        kind = m.group(0).decode("utf-8", "replace")
    return {"type": kind, "access": a.group(1).decode() if a else None,
            "size": int(a.group(2)) if a else None, "excerpt": excerpt}


def _rev(gst_src) -> str:
    try:
        return subprocess.run(["git", "-C", str(Path(gst_src).expanduser()), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _status(store: RunStore, run_id: str, rec_id: str) -> dict:
    rec = store.get_record(run_id, rec_id)
    ts = [store.get_trial(run_id, t) for t in rec.trials]
    count = lambda v: sum(1 for t in ts if t.verdict == v)
    return {"status": rec.status, "n": len(ts), "passes": count("PASS"),
            "fails": count("FAIL"), "inconclusive": count("INCONCLUSIVE")}


def verify(control, mutant, *, element: str, trials: int = 3, site: str | None = None,
           variants: Sequence[Variant] = (), gst_src=None, builddir=None,
           runner: str | None = None, run_root=None, lab_toml=LAB, lead: str = "",
           build_label: str | None = None, timeout: float = 90,
           transport_factory: Callable | None = None) -> dict:
    control, mutant = Path(control), Path(mutant)
    ctl, mut = control.read_bytes(), mutant.read_bytes()
    if runner is None:
        if not (gst_src and builddir):
            raise ValueError("need a runner template, or gst_src + builddir "
                             "(--gst-src/--builddir or GST_ASAN_SRC/GST_ASAN_BUILD)")
        runner = gst_runner_template(element, gst_src, builddir)
    if "{input}" not in runner:
        raise ValueError("runner template must contain '{input}'")
    root = Path(run_root).expanduser() if run_root else RUNS
    store = RunStore(root)
    if transport_factory is None:
        transport_factory = functools.partial(
            GstRunner, env={"GST_REGISTRY_FORK": "no", "GST_REGISTRY": str(root / "registry.bin")})
    policy = LabPolicy.from_toml(lab_toml)
    if build_label is None:
        rev = _rev(gst_src) if gst_src else ""
        build_label = f"gstreamer {rev} ASAN build" if rev else "gstreamer ASAN build"

    diff = byte_diff(ctl, mut)
    run = store.create_run("gstreamer", build_label, notes=f"verify {lead or mutant.name} via {element}")
    node = store.open_node(run.id, f"gstcodeql/verify/{lead or mutant.stem}",
                           prereq=f"a crafted file reaches {element}",
                           notes=(f"{diff['bytes_changed']} byte(s) changed in {len(diff['ranges'])} range(s); "
                                  f"length {diff['control_len']} -> {diff['mutant_len']}"))
    result = {"lead": lead, "element": element, "trials": trials, "site": site,
              "run_id": run.id, "run_dir": str(root / run.id), "build": build_label,
              "runner": runner,
              "control": {"path": str(control), "sha256": hashlib.sha256(ctl).hexdigest()},
              "mutant": {"path": str(mutant), "sha256": hashlib.sha256(mut).hexdigest()},
              "diff": diff, "records": {}, "variants": [], "fault": None}

    def shot(rec, data, expect_fault, label, extra=()):
        return fire(store, run.id, rec.id, data, expect_fault, label, policy=policy,
                    runner_cmd=runner, transport_factory=transport_factory,
                    timeout=timeout, extra_oracles=extra)

    def finish(verdict, reason, close, evidence):
        store.close_node(run.id, node.id, close, evidence=evidence)
        result.update(verdict=verdict, reason=reason)
        (root / run.id / "verdict.json").write_text(json.dumps(result, indent=2))
        result["timeline"] = store.render_timeline(run.id)
        return result

    if ctl == mut:
        return finish(INCONCLUSIVE, "mutant is byte-identical to the control", "blocked", node.id)

    # 1) control: must parse clean N/N before anything is mutated
    rc = store.add_record(run.id, node.id, "observation", f"control {control.name} parses clean",
                          hypothesis=f"a benign file parses through {element} with no memory-safety fault",
                          min_trials=trials)
    for i in range(trials):
        shot(rc, ctl, False, f"control-{i}")
    sc = result["records"]["control"] = _status(store, run.id, rc.id)
    if sc["status"] != "confirmed":
        return finish(INCONCLUSIVE,
                      f"control not clean ({sc['passes']}/{sc['n']} clean) -- the runner or control is "
                      f"broken, not the target; the mutant was not fired", "blocked", rc.id)

    # 2) mutant: must hard-fault N/N (at the site, if one is given)
    extra = [GstSiteOracle(site)] if site else []
    rm = store.add_record(run.id, node.id, "fault",
                          f"mutant {mutant.name} faults in {element}" + (f" at /{site}/" if site else ""),
                          hypothesis=lead or f"the mutated field drives {element} into a memory-safety fault",
                          min_trials=trials)
    for i in range(trials):
        shot(rm, mut, True, f"mutant-{i}", extra)
    sm = result["records"]["mutant"] = _status(store, run.id, rm.id)

    mtrials = [store.get_trial(run.id, t) for t in store.get_record(run.id, rm.id).trials]
    wrong_site = 0
    for t in mtrials:
        faulted = t.oracles.get(ORACLE, {}).get("verdict") == "PASS"
        if faulted and t.oracles.get("site", {}).get("verdict") == "INCONCLUSIVE":
            wrong_site += 1
        if faulted and result["fault"] is None:
            reply = next((Path(p) for p in t.artifacts if p.endswith(".reply")), None)
            if reply and reply.exists():
                result["fault"] = {**summarize_fault(reply.read_bytes()), "report": str(reply),
                                   "site": t.oracles.get("site", {}).get("detail")}

    # 3) variants: supporting causality evidence, each with its own expectation
    for k, v in enumerate(variants):
        want = v.expect == "fault"
        rv = store.add_record(run.id, node.id, "fault" if want else "observation",
                              f"variant {v.path.name} expected {v.expect}", min_trials=trials)
        data = Path(v.path).read_bytes()
        for i in range(trials):
            shot(rv, data, want, f"variant{k}-{i}", extra if want else ())
        sv = _status(store, run.id, rv.id)
        result["variants"].append({"path": str(v.path), "expect": v.expect, **sv,
                                   "as_predicted": sv["status"] == "confirmed"})

    # 4) verdict = a function of the record statuses
    vtxt = ""
    if variants:
        ok = sum(1 for v in result["variants"] if v["as_predicted"])
        vtxt = f"; variants as predicted {ok}/{len(variants)}"
    at = f" at /{site}/" if site else ""
    if sm["status"] == "confirmed":
        return finish(CONFIRMED, f"control clean {trials}/{trials}; mutant hard-faulted{at} "
                                 f"{sm['passes']}/{sm['n']}{vtxt}", "success", rm.id)
    if sm["status"] == "refuted":
        return finish(REFUTED, f"control clean {trials}/{trials}; mutant produced no memory-safety "
                               f"fault in {sm['fails']}/{sm['n']} trials{vtxt}", "exhausted", rm.id)
    why = (f"mutant: {sm['passes']} faulted{at}, {sm['fails']} clean, "
           f"{sm['inconclusive']} inconclusive of {sm['n']}")
    if wrong_site:
        why += f" -- {wrong_site} fault(s) were NOT at /{site}/ (possibly a different bug)"
    return finish(INCONCLUSIVE, why + vtxt, "blocked", rm.id)
