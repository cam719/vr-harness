"""gstcodeql CLI.

  python -m gstcodeql reproduce  [--trials N] [--runner "...{input}..."]
  python -m gstcodeql hypothesis --list
  python -m gstcodeql hypothesis --run NAME [--trials N] [--runner "...{input}..."]

reproduce  : replay the known PoC files under ASAN (confirmation).
hypothesis : CodeQL-driven discovery -- build targeted inputs for a suspected
             sink (see gstcodeql/hypotheses.py) and record which values fault.
"""
from __future__ import annotations
import argparse
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
    return 2
