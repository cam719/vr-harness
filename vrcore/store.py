"""Run / Node / Record / Trial store (Lorenc model).

A run is a timeline (run.jsonl). Nodes are attack-surface leaves the run opens
and closes. Records are typed claims (observation | bypass | fault | rce). A
record's status is a PURE function of its trials, recomputed after each one:
`confirmed` only when at least min_trials trials have run and EVERY trial PASSed,
so a later failing or inconclusive trial un-confirms it; `refuted` when it has
run min_trials and every trial FAILed; otherwise `candidate`.
"""
from __future__ import annotations
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Iterator

RECORD_KINDS = ("observation", "bypass", "fault", "rce")
NODE_CLOSE_REASONS = ("exhausted", "blocked", "success", "out-of-scope", "deferred")


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


def _now() -> float:
    return time.time()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@dataclass
class Trial:
    id: str
    record_id: str
    started: float
    ended: float | None = None
    verdict: str = Verdict.INCONCLUSIVE.value
    oracles: dict = field(default_factory=dict)     # oracle name -> {verdict, detail}
    artifacts: list = field(default_factory=list)   # paths relative to run dir
    frame_sha256: str | None = None
    notes: str = ""


@dataclass
class Record:
    id: str
    node_id: str
    kind: str
    title: str
    created: float
    status: str = "candidate"                       # candidate | confirmed | refuted
    hypothesis: str = ""
    evidence: str = ""
    trials: list = field(default_factory=list)      # trial ids
    min_trials: int = 3

    def validate(self) -> None:
        if self.kind not in RECORD_KINDS:
            raise ValueError(f"record kind must be one of {RECORD_KINDS}")


@dataclass
class Node:
    id: str
    path: str                                       # e.g. demux/mp4/box-field
    opened: float | None = None
    closed: float | None = None
    close_reason: str | None = None
    close_evidence: str = ""
    prereq: str = ""                                # who can reach it: remote peer, local file, ...
    notes: str = ""


@dataclass
class Run:
    id: str
    target: str
    build: str                                      # exact product version under test
    created: float
    lab_snapshot: str = ""
    operator: str = ""
    notes: str = ""


class RunStore:
    """Append-only JSONL timeline plus materialised JSON objects per run."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # --- run ---------------------------------------------------------------
    def create_run(self, target: str, build: str, **kw) -> Run:
        run = Run(id=_id("run"), target=target, build=build, created=_now(), **kw)
        d = self._run_dir(run.id)
        for sub in ("records", "trials", "nodes", "artifacts"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        self._write(d / "run.json", run)
        self._event(run.id, "run.launch", {"target": target, "build": build, **kw})
        return run

    def load_run(self, run_id: str) -> Run:
        return Run(**json.loads((self._run_dir(run_id) / "run.json").read_text()))

    def list_runs(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if (p / "run.json").exists())

    # --- nodes -------------------------------------------------------------
    def open_node(self, run_id: str, path: str, prereq: str = "", notes: str = "") -> Node:
        node = Node(id=_id("node"), path=path, opened=_now(), prereq=prereq, notes=notes)
        self._write(self._run_dir(run_id) / "nodes" / f"{node.id}.json", node)
        self._event(run_id, "node.open", {"node": node.id, "path": path, "prereq": prereq})
        return node

    def close_node(self, run_id: str, node_id: str, reason: str, evidence: str = "") -> Node:
        if reason not in NODE_CLOSE_REASONS:
            raise ValueError(f"close reason must be one of {NODE_CLOSE_REASONS}")
        node = self.get_node(run_id, node_id)
        node.closed, node.close_reason, node.close_evidence = _now(), reason, evidence
        self._write(self._run_dir(run_id) / "nodes" / f"{node.id}.json", node)
        self._event(run_id, "node.close", {"node": node_id, "reason": reason, "evidence": evidence})
        return node

    def get_node(self, run_id: str, node_id: str) -> Node:
        return Node(**json.loads((self._run_dir(run_id) / "nodes" / f"{node_id}.json").read_text()))

    # --- records -----------------------------------------------------------
    def add_record(self, run_id: str, node_id: str, kind: str, title: str,
                   hypothesis: str = "", min_trials: int = 3) -> Record:
        rec = Record(id=_id("rec"), node_id=node_id, kind=kind, title=title, created=_now(),
                     hypothesis=hypothesis, min_trials=min_trials)
        rec.validate()
        self._write(self._run_dir(run_id) / "records" / f"{rec.id}.json", rec)
        self._event(run_id, "record.candidate", {"record": rec.id, "kind": kind, "title": title})
        return rec

    def get_record(self, run_id: str, rec_id: str) -> Record:
        return Record(**json.loads((self._run_dir(run_id) / "records" / f"{rec_id}.json").read_text()))

    def records(self, run_id: str) -> Iterator[Record]:
        for p in sorted((self._run_dir(run_id) / "records").glob("*.json")):
            yield Record(**json.loads(p.read_text()))

    # --- trials ------------------------------------------------------------
    def start_trial(self, run_id: str, rec_id: str, frame_sha256: str | None = None) -> Trial:
        t = Trial(id=_id("trial"), record_id=rec_id, started=_now(), frame_sha256=frame_sha256)
        (self._run_dir(run_id) / "artifacts" / t.id).mkdir(parents=True, exist_ok=True)
        self._write(self._run_dir(run_id) / "trials" / f"{t.id}.json", t)
        self._event(run_id, "trial.start", {"trial": t.id, "record": rec_id})
        return t

    def artifact_dir(self, run_id: str, trial_id: str) -> Path:
        return self._run_dir(run_id) / "artifacts" / trial_id

    def finish_trial(self, run_id: str, trial: Trial, oracles: dict, artifacts: list | None = None,
                     notes: str = "") -> Trial:
        """oracles: {name: {"verdict": "PASS|FAIL|INCONCLUSIVE", "detail": str}}.
        Trial verdict = PASS only if every oracle PASSed."""
        verdicts = {v["verdict"] for v in oracles.values()} or {Verdict.INCONCLUSIVE.value}
        if verdicts == {Verdict.PASS.value}:
            trial.verdict = Verdict.PASS.value
        elif Verdict.FAIL.value in verdicts:
            trial.verdict = Verdict.FAIL.value
        else:
            trial.verdict = Verdict.INCONCLUSIVE.value
        trial.ended, trial.oracles, trial.notes = _now(), oracles, notes
        trial.artifacts = artifacts or []
        self._write(self._run_dir(run_id) / "trials" / f"{trial.id}.json", trial)
        rec = self.get_record(run_id, trial.record_id)
        rec.trials.append(trial.id)
        self._write(self._run_dir(run_id) / "records" / f"{rec.id}.json", rec)
        self._event(run_id, "trial.end", {"trial": trial.id, "record": rec.id, "verdict": trial.verdict,
                                          "oracles": {k: v["verdict"] for k, v in oracles.items()}})
        self._reevaluate(run_id, rec)
        return trial

    def _reevaluate(self, run_id: str, rec: Record) -> None:
        # Status is a PURE function of all trials so far -- never sticky. A record
        # is confirmed only if every trial PASSed (N-of-N) and at least min_trials
        # ran; a later failing/inconclusive trial moves it back to candidate.
        trials = [self.get_trial(run_id, t) for t in rec.trials]
        n = len(trials)
        passes = sum(1 for t in trials if t.verdict == Verdict.PASS.value)
        fails = sum(1 for t in trials if t.verdict == Verdict.FAIL.value)
        if n >= rec.min_trials and passes == n:
            new = "confirmed"
        elif n >= rec.min_trials and fails == n:
            new = "refuted"
        else:
            new = "candidate"
        if new != rec.status:
            rec.status = new
            self._write(self._run_dir(run_id) / "records" / f"{rec.id}.json", rec)
            self._event(run_id, f"record.{new}", {"record": rec.id, "kind": rec.kind, "title": rec.title,
                                                 "trials": f"{passes}/{len(trials)}"})

    def get_trial(self, run_id: str, trial_id: str) -> Trial:
        return Trial(**json.loads((self._run_dir(run_id) / "trials" / f"{trial_id}.json").read_text()))

    # --- timeline ----------------------------------------------------------
    def timeline(self, run_id: str) -> list[dict]:
        p = self._run_dir(run_id) / "run.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def render_timeline(self, run_id: str) -> str:
        """Lorenc-style 'T+ | what it did' table."""
        evs = self.timeline(run_id)
        if not evs:
            return "(empty)"
        t0 = evs[0]["ts"]
        rows = ["| T+ | what it did |", "|---|---|"]
        for e in evs:
            dt = e["ts"] - t0
            h, rem = divmod(int(dt), 3600); m, s = divmod(rem, 60)
            stamp = f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"
            rows.append(f"| {stamp} | {_describe(e)} |")
        return "\n".join(rows)

    # --- internals ---------------------------------------------------------
    def _run_dir(self, run_id: str) -> Path:
        return self.root / run_id

    def _write(self, path: Path, obj) -> None:
        path.write_text(json.dumps(asdict(obj), indent=2))

    def _event(self, run_id: str, kind: str, data: dict) -> None:
        with open(self._run_dir(run_id) / "run.jsonl", "a") as f:
            f.write(json.dumps({"ts": _now(), "event": kind, **data}) + "\n")


def _describe(e: dict) -> str:
    k = e["event"]
    if k == "run.launch":      return f"run launches ({e.get('target')} {e.get('build')})"
    if k == "node.open":       return f"opened {e['path']} [{e.get('prereq') or 'prereq unset'}]"
    if k == "node.close":      return f"closed {e['node']} — {e['reason']}"
    if k == "record.candidate":return f"candidate {e['kind']}: {e['title']}"
    if k == "record.confirmed":return f"**confirmed {e['kind']}: {e['title']}, {e['trials']}**"
    if k == "record.refuted":  return f"refuted {e['kind']}: {e['title']}, {e['trials']}"
    if k == "trial.start":     return f"trial {e['trial']} for {e['record']}"
    if k == "trial.end":       return f"trial {e['trial']} {e['verdict']} ({', '.join(f'{a}={b}' for a, b in e['oracles'].items())})"
    return k
