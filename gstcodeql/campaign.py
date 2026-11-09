"""Control-case-first, N-of-N reproduction of local parsing PoCs, recorded
through vrcore (nodes, records, trials, oracles, timeline).

Flow:
  1. control node: a known-good file must parse CLEAN under ASAN, N/N, or we stop
     (a 'crash' on a broken runner would be meaningless).
  2. one fault node per PoC: the crafted file must FAULT under ASAN, N/N.
Nothing here weaponizes anything: it parses files under a sanitizer and records
whether a parser faulted.

The PoC corpus lives OUTSIDE this repo (keep crash files private, out of git).
Point `[target].poc_dir` at it and list entries under `[[target.pocs]]` in
lab.toml:

  [[target.pocs]]
  file = "sample01.mp4"
  element = "demux"
  desc = "example parser fault"
"""
from __future__ import annotations
from pathlib import Path

from vrcore import RunStore, LabPolicy
from ._pipeline import RUNS, load_cfg, fire

# Placeholder; real entries belong in lab.toml [[target.pocs]] (names are examples).
EXAMPLE_POCS = [
    {"file": "sample01.mp4", "element": "demux", "desc": "example parser fault"},
]


def run(lab_toml: Path, trials: int = 3, runner_override: str | None = None) -> int:
    cfg = load_cfg(lab_toml)
    t = cfg["target"]
    poc_dir = Path(t.get("poc_dir", "./pocs")).expanduser()
    runner_cmd = runner_override or t["runner"]
    pocs = t.get("pocs", EXAMPLE_POCS)
    control_name = t.get("control", "normal.mkv")
    policy = LabPolicy.from_toml(lab_toml)
    store = RunStore(RUNS)
    run = store.create_run("gstreamer", t.get("build", "?"),
                           notes="parsing-PoC reproduction (control + fault nodes)")

    # 1) CONTROL CASE
    node = store.open_node(run.id, "gstreamer/control", prereq="ASAN pipeline runs")
    rec = store.add_record(run.id, node.id, "observation", f"{control_name} parses clean",
                           hypothesis="benign media produces no sanitizer report", min_trials=trials)
    ctrl = poc_dir / control_name
    if not ctrl.exists():
        raise SystemExit(f"control input missing: {ctrl}\n"
                         f"Put a known-good file there, or set [target].control in lab.toml.")
    data = ctrl.read_bytes()
    for i in range(trials):
        o = fire(store, run.id, rec.id, data, False, f"control-{i}",
                 policy=policy, runner_cmd=runner_cmd)
        print(f"[control {i+1}/{trials}] {o.get('verdict')} ({o.get('detail','')[:70]})")
    if store.get_record(run.id, rec.id).status != "confirmed":
        store.close_node(run.id, node.id, "blocked", evidence=rec.id)
        print(store.render_timeline(run.id))
        print("\nCONTROL FAILED -- the runner is wrong or the ASAN build can't parse a normal file.")
        print("Fix the runner in lab.toml (see its comments) and retry.")
        return 2
    store.close_node(run.id, node.id, "success", evidence=rec.id)

    # 2) FAULT NODES
    confirmed = 0
    total = 0
    for poc in pocs:
        fname = poc["file"]; elem = poc.get("element", "demux"); desc = poc.get("desc", "")
        f = poc_dir / fname
        if not f.exists():
            print(f"[skip] missing PoC {f}")
            continue
        total += 1
        node = store.open_node(run.id, f"gstreamer/{elem}/{Path(fname).stem}",
                               prereq="control passed")
        rec = store.add_record(run.id, node.id, "fault", f"{fname}: {desc}",
                               hypothesis=f"crafted {f.suffix} reaches a {elem} fault under ASAN",
                               min_trials=trials)
        data = f.read_bytes()
        for i in range(trials):
            o = fire(store, run.id, rec.id, data, True, f"{Path(fname).stem}-{i}",
                     policy=policy, runner_cmd=runner_cmd)
            print(f"[{Path(fname).stem} {i+1}/{trials}] {o.get('verdict')} ({o.get('detail','')[:70]})")
        st = store.get_record(run.id, rec.id).status
        if st == "confirmed":
            confirmed += 1
        store.close_node(run.id, node.id, "success" if st == "confirmed" else "exhausted", evidence=rec.id)

    print(store.render_timeline(run.id))
    print(f"\nreproduced {confirmed}/{total} configured PoCs as confirmed faults on {t.get('build')}")
    return 0
