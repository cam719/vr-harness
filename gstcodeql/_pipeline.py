"""Shared pipeline helpers for the gstcodeql campaigns.

Keeps the run-storage root, the lab.toml loader, and the one-trial
start -> inject -> finish step in one place, so campaign.py and hypothesis.py
don't duplicate them (and can't drift).
"""
from __future__ import annotations
import tomllib
from pathlib import Path

from vrcore import Injector
from .runner import GstRunner
from .oracle import GstFaultOracle

RUNS = Path(__file__).resolve().parents[1] / "runs"
ORACLE = GstFaultOracle.name          # the oracle's dict key in a trial's results


def load_cfg(lab_toml) -> dict:
    return tomllib.loads(Path(lab_toml).read_text())


def fire(store, run_id: str, rec_id: str, data: bytes, expect_fault: bool, label: str,
         *, policy, runner_cmd: str, transport_factory=GstRunner,
         host: str = "127.0.0.1", timeout: float = 90, extra_oracles=()) -> dict:
    """Run one trial: start it, inject `data` under the fault oracle, finish it.
    `extra_oracles` are judged alongside it (the trial PASSes only if all do).
    Returns the fault oracle's result dict ({'verdict', 'detail'})."""
    trial = store.start_trial(run_id, rec_id)
    adir = store.artifact_dir(run_id, trial.id)
    inj = Injector(transport_factory(runner_cmd), policy, host, artifact_dir=adir)
    oracles = [GstFaultOracle(expect_fault=expect_fault), *extra_oracles]
    res = inj.inject(data, oracles, timeout=timeout, label=label)
    store.finish_trial(run_id, trial, res.oracles,
                       artifacts=[str(p) for p in adir.glob("*")],
                       notes=res.oracles.get(ORACLE, {}).get("detail", "")[:200])
    return res.oracles.get(ORACLE, {})
