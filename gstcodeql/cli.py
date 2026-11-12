"""gstcodeql CLI.

  python -m gstcodeql reproduce  [--trials N] [--runner "...{input}..."]
  python -m gstcodeql hypothesis --list
  python -m gstcodeql hypothesis --run NAME [--trials N] [--runner "...{input}..."]
  python -m gstcodeql verify --control C --mutant M --element E [--site REGEX]
                             [--variant FILE=fault|clean ...] [--trials N] [--run-dir D]
                             (--gst-src S --builddir B | --runner "...{input}...")

reproduce  : replay the known PoC files under ASAN (confirmation).
hypothesis : CodeQL-driven discovery -- build targeted inputs for a suspected
             sink (see gstcodeql/hypotheses.py) and record which values fault.
verify     : run ONE lead through the harness: control clean N/N, then the
             mutant must hard-fault N/N (at --site) -> CONFIRMED / REFUTED /
             INCONCLUSIVE. Exit code 0 / 1 / 2. Writes <run>/verdict.json.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

LAB = Path(__file__).resolve().parents[1] / "lab.toml"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gstcodeql", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)

    rep = sp.add_parser("reproduce", help="replay known PoC files under ASAN (N-of-N)")
    rep.add_argument("--trials", type=int, default=3)
    rep.add_argument("--runner", default=None, help="override the runner template from lab.toml")

    hyp = sp.add_parser("hypothesis", help="CodeQL-driven targeted probing")
    g = hyp.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="list registered hypotheses")
    g.add_argument("--run", metavar="NAME", help="run one hypothesis by name")
    hyp.add_argument("--trials", type=int, default=3)
    hyp.add_argument("--runner", default=None, help="override the runner template from lab.toml")

    ver = sp.add_parser("verify", help="run one lead through the harness -> CONFIRMED/REFUTED/INCONCLUSIVE")
    ver.add_argument("--control", required=True, type=Path, help="known-good file (must parse clean N/N)")
    ver.add_argument("--mutant", required=True, type=Path, help="the control with only the lead's field changed")
    ver.add_argument("--element", required=True, help="element under test: a demuxer/parser element name, or parsebin")
    ver.add_argument("--site", default=None, help="regex the sanitizer report must contain (lead's function/file)")
    ver.add_argument("--variant", action="append", default=[], metavar="FILE=fault|clean",
                     help="extra input with its expected outcome (boundary value, revert, ...); repeatable")
    ver.add_argument("--trials", type=int, default=3)
    ver.add_argument("--gst-src", default=os.environ.get("GST_ASAN_SRC"), help="GStreamer source dir (has gst-env.py)")
    ver.add_argument("--builddir", default=os.environ.get("GST_ASAN_BUILD"), help="ASAN meson build dir")
    ver.add_argument("--runner", default=None, help="full runner template with {input} (overrides --gst-src/--builddir)")
    ver.add_argument("--run-dir", type=Path, default=None, help="where to store the run (default: ./runs)")
    ver.add_argument("--lead", default="", help="lead id, e.g. area-L1")
    ver.add_argument("--build-label", default=None, help="build string to record (default: git rev of --gst-src)")
    ver.add_argument("--timeout", type=float, default=90, help="per-trial timeout, seconds")
    ver.add_argument("--json", action="store_true", help="print verdict.json instead of the report")

    a = p.parse_args(argv)
    if a.cmd == "reproduce":
        from .campaign import run
        return run(LAB, trials=a.trials, runner_override=a.runner)
    if a.cmd == "hypothesis":
        from .hypotheses import REGISTRY
        if a.list:
            print(f"{'name':24} {'element':12} codeql_ref")
            for name, h in REGISTRY.items():
                print(f"{name:24} {h['element']:12} {h['codeql_ref']}\n{'':24} └ {h['sink']}")
            return 0
        from .hypothesis import Hypothesis, probe
        spec = REGISTRY.get(a.run)
        if not spec:
            print(f"unknown hypothesis {a.run!r}; use --list"); return 2
        return probe(Hypothesis(**spec), LAB, trials=a.trials, runner_override=a.runner)
    if a.cmd == "verify":
        from .verify import Variant, verify, EXIT
        try:
            res = verify(a.control, a.mutant, element=a.element, trials=a.trials, site=a.site,
                         variants=[Variant.parse(v) for v in a.variant], gst_src=a.gst_src,
                         builddir=a.builddir, runner=a.runner, run_root=a.run_dir, lead=a.lead,
                         build_label=a.build_label, timeout=a.timeout)
        except (ValueError, FileNotFoundError) as e:
            print(f"verify: {e}"); return 2
        if a.json:
            print(json.dumps({k: v for k, v in res.items() if k != "timeline"}, indent=2))
            return EXIT[res["verdict"]]
        print(res["timeline"])
        d = res["diff"]
        print(f"\nmutation: {d['bytes_changed']} byte(s) in {len(d['ranges'])} range(s), "
              f"length {d['control_len']} -> {d['mutant_len']}")
        for r in d["ranges"][:6]:
            print(f"  @{r['offset']:#x} len {r['length']}: {r['old']} -> {r['new']}")
        for name, s in res["records"].items():
            print(f"{name:8} {s['status']:10} pass {s['passes']} / fail {s['fails']} / inconcl {s['inconclusive']} of {s['n']}")
        for v in res["variants"]:
            print(f"variant  {Path(v['path']).name} expect {v['expect']}: {v['status']} "
                  f"({'as predicted' if v['as_predicted'] else 'NOT as predicted'})")
        f = res["fault"]
        if f:
            acc = f" {f['access']} of size {f['size']}" if f.get("access") else ""
            print(f"fault    {f.get('type')}{acc}\n         report: {f['report']}")
            if f.get("site"):
                print(f"         {f['site']}")
        print(f"\nVERDICT: {res['verdict']} -- {res['reason']}")
        print(f"run: {res['run_dir']}  (verdict.json, run.jsonl, records/, trials/, artifacts/)")
        return EXIT[res["verdict"]]
    return 2
