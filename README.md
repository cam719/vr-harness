# vr-harness

A small, standalone **vulnerability-research harness**: a target-agnostic engine
plus a worked GStreamer example that turns CodeQL/audit findings into disciplined,
reproducible experiments. It follows two ideas:

- **Frame + inject + oracle** (parse/protocol side): composable byte builders, a
  delivery-confirming injector guarded by a loopback allowlist, and independent
  oracles that judge each trial.
- **Run / node / record / trial** (campaign side): the attack surface is a tree of
  *nodes*; a run opens a node and emits typed *records* (observation / fault / …),
  each backed by N-of-N *trials* judged by oracles, and closes the node with a
  reason. The control case must pass before any mutation, and nothing is
  "confirmed" without N/N passing trials.

## Layout
- `vrcore/` — the engine: the `Frame` builder, the run/record/trial `RunStore`,
  the `Oracle` framework, and TCP/UDP transports + the allowlisted `Injector`.
  Nothing target-specific.
- `gstcodeql/` — a worked example target: a GStreamer **CodeQL-hypothesis +
  PoC-reproduction** harness that imports `vrcore`.
- `lab.toml`, `tests/`, `runs/`.

## Install / run
No install needed — run from the repo root (both packages import from here):
```
python -m pytest tests/ -q          # offline tests, no GStreamer required
python -m gstcodeql --help
```
(Optionally `pip install -e .` to put `vrcore` on your path.)

## gstcodeql — two modes

### reproduce — replay your local PoCs under ASAN (confirmation)
Point `lab.toml` at an AddressSanitizer build of GStreamer and your private PoC
corpus (`[target].poc_dir`, `[[target.pocs]]`), then:
```
python -m gstcodeql reproduce --trials 3
```
The control file (`[target].control`) must parse clean, then each configured PoC
must fault, N-of-N. Crash files stay in your own corpus, out of this repo.

### hypothesis — CodeQL-driven targeted probing (discovery)
```
python -m gstcodeql hypothesis --list
python -m gstcodeql hypothesis --run example_count_field --trials 3
```
A **Hypothesis** encodes a suspected unchecked field (from a CodeQL query or a
manual read) plus the attacker `values` to probe. `probe()` builds one targeted
input per value (via `gstcodeql/mp4.py`'s `Frame`-based ISO-BMFF builders, or by
splicing a field inside a reach-template you provide), fires each into the ASAN
pipeline, and records a control-first run plus one N-of-N `fault` record per
value, printing which values crashed. The *reading* produces the hypothesis; the
harness confirms it.

#### Add your own
Edit `gstcodeql/hypotheses.py`: add a dict with `name`, `codeql_ref`, `element`,
`sink` (what's unchecked), `build(value) -> bytes`, and `values`. Two shapes are
shown:
- **A (from scratch):** build the container with `mp4.box / container / ftyp` so
  the suspected field carries `value`.
- **B (splice a template):** `mp4.find_box` + `mp4.splice` to overwrite one field
  inside a file you already know reaches the element.

The two shipped entries (`example_count_field`, `example_field_splice`) are
**generic skeletons** — replace the fictional box/field/element/template with your
own finding. This repo intentionally ships no real target details or crash inputs.

## How a fault is judged
The oracle counts only a **memory-safety** fault — AddressSanitizer / UBSan / a
fatal signal. A `GLib-CRITICAL`, assertion, or glib warning (which GStreamer
emits freely on malformed-but-safe input) is recorded as an *observation*, never
a confirmed fault. And a record is `confirmed` only when **every one of its ≥N
trials passed** — the status is recomputed from all trials, so a later failing or
inconclusive trial un-confirms it. Trustworthy fault claims are the whole point.

## Scope & ethics
Research tooling for **authorized** work on software you own or are permitted to
test. It is non-destructive: it feeds inputs to a parser under a sanitizer and
records whether the parser faulted — no exploitation, persistence, or payloads.
The injector refuses any destination outside the loopback allowlist in `lab.toml`.
Follow coordinated disclosure for anything you find, and keep details of unfixed
bugs and your crash corpora private. See `SECURITY.md`.

## License
MIT — see `LICENSE`.
