"""Oracles: independent judges of what a trial did.

Each oracle answers one question with PASS / FAIL / INCONCLUSIVE and a detail
string. A trial is PASS only when every attached oracle passes, so a claim
like "fault" must be supported by e.g. ProcessOracle(expect_alive=False) AND
DumpOracle(expect_new_dump=True), not by a single signal.
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass
class OracleResult:
    verdict: str          # PASS | FAIL | INCONCLUSIVE
    detail: str = ""

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "detail": self.detail}


class Oracle:
    name = "oracle"

    def before(self) -> None:
        """Snapshot state before the frame is sent."""

    def after(self, ctx: dict) -> OracleResult:
        """Judge after the frame is sent. ctx carries reply bytes, trace events, etc."""
        raise NotImplementedError


class ReplyOracle(Oracle):
    """Expect (or expect not) a reply matching a predicate within the timeout."""
    name = "reply"

    def __init__(self, expect: Callable[[bytes], bool] | None = None, expect_reply: bool = True, label: str = ""):
        self.expect, self.expect_reply, self.label = expect, expect_reply, label

    def after(self, ctx: dict) -> OracleResult:
        reply = ctx.get("reply")
        if not self.expect_reply:
            return OracleResult("PASS" if not reply else "FAIL", f"reply={reply[:32]!r}" if reply else "no reply")
        if not reply:
            return OracleResult("FAIL", "no reply")
        if self.expect and not self.expect(reply):
            return OracleResult("FAIL", f"reply did not match {self.label}: {reply[:64]!r}")
        return OracleResult("PASS", f"reply {len(reply)}B {reply[:32]!r}")


class LogOracle(Oracle):
    """Watch a log file for a regex appearing after `before()`. The log may be a
    local path or a path on a mounted guest share."""
    name = "log"

    def __init__(self, path: Path | str, pattern: str, expect_match: bool = True, settle: float = 1.0):
        self.path, self.rx, self.expect_match, self.settle = Path(path), re.compile(pattern), expect_match, settle
        self._offset = 0

    def before(self) -> None:
        self._offset = self.path.stat().st_size if self.path.exists() else 0

    def after(self, ctx: dict) -> OracleResult:
        time.sleep(self.settle)
        if not self.path.exists():
            return OracleResult("INCONCLUSIVE", f"log missing: {self.path}")
        with open(self.path, "rb") as f:
            f.seek(self._offset)
            new = f.read().decode("utf-8", "replace")
        hit = self.rx.search(new)
        if self.expect_match:
            return OracleResult("PASS", hit.group(0)[:120]) if hit else OracleResult("FAIL", f"no match for {self.rx.pattern!r} in {len(new)}B new log")
        return OracleResult("FAIL", hit.group(0)[:120]) if hit else OracleResult("PASS", "pattern absent")


class TraceOracle(Oracle):
    """Expect the trace collector (frida) to have seen the given function names
    (in order if `ordered`). Reachability proof in the Beer sense."""
    name = "trace"

    def __init__(self, expect_hits: Iterable[str], ordered: bool = False, forbid: Iterable[str] = ()):
        self.expect, self.ordered, self.forbid = list(expect_hits), ordered, set(forbid)

    def after(self, ctx: dict) -> OracleResult:
        events = ctx.get("trace", [])
        names = [e.get("fn") for e in events]
        missing = [n for n in self.expect if n not in names]
        if missing:
            return OracleResult("FAIL", f"not reached: {missing}; saw {names[:12]}")
        bad = [n for n in names if n in self.forbid]
        if bad:
            return OracleResult("FAIL", f"forbidden path hit: {bad}")
        if self.ordered:
            idx = [names.index(n) for n in self.expect]
            if idx != sorted(idx):
                return OracleResult("FAIL", f"order mismatch: {names}")
        return OracleResult("PASS", f"reached {self.expect} ({len(events)} events)")


class ProcessOracle(Oracle):
    """Is the target process still alive after the frame? `probe` returns the
    PID or None (e.g. via frida-ps, a guest agent, or `sc query` over WinRM)."""
    name = "process"

    def __init__(self, probe: Callable[[], int | None], expect_alive: bool = True, settle: float = 2.0):
        self.probe, self.expect_alive, self.settle = probe, expect_alive, settle
        self._pid_before = None

    def before(self) -> None:
        self._pid_before = self.probe()

    def after(self, ctx: dict) -> OracleResult:
        time.sleep(self.settle)
        pid = self.probe()
        alive_same = pid is not None and pid == self._pid_before
        if self.expect_alive:
            return OracleResult("PASS", f"pid {pid} unchanged") if alive_same else OracleResult("FAIL", f"pid before={self._pid_before} after={pid}")
        return OracleResult("PASS", f"process died/restarted: before={self._pid_before} after={pid}") if not alive_same else OracleResult("FAIL", f"pid {pid} still alive")


class DumpOracle(Oracle):
    """A new crash dump (WER .dmp / procdump output) appeared in `dump_dir`."""
    name = "dump"

    def __init__(self, dump_dir: Path | str, expect_new_dump: bool, settle: float = 5.0, glob: str = "*.dmp"):
        self.dir, self.expect, self.settle, self.glob = Path(dump_dir), expect_new_dump, settle, glob
        self._before: set[str] = set()

    def before(self) -> None:
        self._before = {p.name for p in self.dir.glob(self.glob)} if self.dir.exists() else set()

    def after(self, ctx: dict) -> OracleResult:
        time.sleep(self.settle)
        now = {p.name for p in self.dir.glob(self.glob)} if self.dir.exists() else set()
        new = sorted(now - self._before)
        ctx.setdefault("new_dumps", []).extend(str(self.dir / n) for n in new)
        if self.expect:
            return OracleResult("PASS", f"new dumps: {new}") if new else OracleResult("FAIL", "no new dump")
        return OracleResult("FAIL", f"unexpected dumps: {new}") if new else OracleResult("PASS", "no new dump")
