"""Fault oracle for the GStreamer repro.

It distinguishes a real memory-safety fault (AddressSanitizer / UBSan / a fatal
signal) from a *soft* diagnostic (a GLib-CRITICAL / assertion / glib warning),
which GStreamer emits on all kinds of benign-but-malformed input. Only a hard
memory-safety fault is ever counted as a fault -- the point of the harness is
trustworthy fault claims, so a GLib critical is surfaced in the detail as an
observation but never flips a record to a confirmed 'fault'.

Two directions: expect_fault=False for the control case (a benign file must show
no memory-safety fault) and expect_fault=True for a PoC / hypothesis value (the
crafted input must produce one). A None reply (transport timeout) is INCONCLUSIVE.
"""
from __future__ import annotations
import re
from vrcore import Oracle, OracleResult

# Hard: a genuine memory-safety fault or a fatal crash signal.
MEMSAFETY = re.compile(
    rb"AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|"
    rb"UndefinedBehaviorSanitizer|runtime error:|SUMMARY:\s+\w*Sanitizer|"
    rb"SIGSEGV|SIGABRT|SIGBUS|SIGFPE|SIGILL|__SIGNAL__", re.I)

# Soft: real but NOT memory-safety. Recorded as an observation, never a fault
# (GStreamer emits these freely on malformed-but-safe input).
SOFT = re.compile(
    rb"[A-Za-z][\w-]*-(?:CRITICAL|WARNING)\b|\bassertion\b[^\n]*\bfailed\b", re.I)


class GstFaultOracle(Oracle):
    name = "fault"

    def __init__(self, expect_fault: bool):
        self.expect = expect_fault

    def after(self, ctx: dict) -> OracleResult:
        out = ctx.get("reply")
        if out is None:                       # transport timed out / no reply
            return OracleResult("INCONCLUSIVE", "runner timed out (no reply)")
        hard = MEMSAFETY.search(out)
        soft = SOFT.search(out)
        hsig = hard.group(0).decode("ascii", "replace")[:80] if hard else ""
        ssig = soft.group(0).decode("ascii", "replace")[:80] if soft else ""
        obs = f"; observed non-fatal {ssig}" if ssig else ""
        if self.expect:                       # expecting a memory-safety fault
            if hard:
                return OracleResult("PASS", f"memory-safety fault: {hsig}{obs}")
            if soft:
                return OracleResult("FAIL", f"no memory-safety fault (only non-fatal {ssig}; observation, not a fault)")
            return OracleResult("FAIL", f"no fault ({len(out)} B output)")
        # control: expecting a clean parse (no memory-safety fault)
        if hard:
            return OracleResult("FAIL", f"unexpected memory-safety fault: {hsig}{obs}")
        return OracleResult("PASS", f"clean parse{obs}")
