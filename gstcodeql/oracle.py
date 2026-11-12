"""Fault oracle for the GStreamer repro.

It distinguishes a real memory-safety fault (AddressSanitizer / UBSan / a fatal
signal) from a *soft* diagnostic (a GLib-CRITICAL / assertion / glib warning),
which GStreamer emits on all kinds of benign-but-malformed input. Only a hard
memory-safety fault is ever counted as a fault -- the point of the harness is
trustworthy fault claims, so a GLib critical is surfaced in the detail as an
observation but never flips a record to a confirmed 'fault'.

UBSan *alignment* reports are treated the same way (see MISALIGNED).

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

# UBSan alignment reports are not memory-safety faults on the x86 builds this
# targets: GStreamer's GST_READ_*/GST_WRITE_* fast paths (gstutils.h) do
# unaligned access on purpose. Observations, like GLib criticals.
MISALIGNED = re.compile(
    rb"runtime error: (?:load of|store to|member access within|reference binding to)"
    rb"[^\n]*misaligned address[^\n]*|SUMMARY: UndefinedBehaviorSanitizer: misaligned-pointer-use[^\n]*")


def hard_fault(out: bytes):
    """First genuine memory-safety marker in `out` (a re.Match), ignoring UBSan
    alignment reports; None if there is none."""
    spans = [m.span() for m in MISALIGNED.finditer(out)]
    for m in MEMSAFETY.finditer(out):
        if not any(a <= m.start() < b for a, b in spans):
            return m
    return None


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
        hard = hard_fault(out)
        soft = SOFT.search(out) or MISALIGNED.search(out)
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


class GstSiteOracle(Oracle):
    """Is the memory-safety fault where the lead says it is?

    Searches the sanitizer report (from the first hard-fault marker onward) for
    `site`, a regex naming the lead's function and/or file. A fault whose report
    never mentions the site is a *different* bug: INCONCLUSIVE for this lead --
    neither a confirmation nor a refutation. With no hard fault there is nothing
    to locate (INCONCLUSIVE); GstFaultOracle already fails that trial.
    """
    name = "site"

    def __init__(self, site: str):
        self.site = site
        self.rx = re.compile(site.encode(), re.I)

    def after(self, ctx: dict) -> OracleResult:
        out = ctx.get("reply")
        if out is None:
            return OracleResult("INCONCLUSIVE", "runner timed out (no reply)")
        hard = hard_fault(out)
        if not hard:
            return OracleResult("INCONCLUSIVE", "no sanitizer report to locate")
        m = self.rx.search(out, hard.start())
        if not m:
            return OracleResult("INCONCLUSIVE",
                                f"fault, but the report never mentions /{self.site}/ (different site)")
        end = out.find(b"\n", m.end())
        line = out[out.rfind(b"\n", 0, m.start()) + 1: end if end != -1 else len(out)].strip()
        return OracleResult("PASS", f"fault located at /{self.site}/: {line.decode('utf-8', 'replace')[:120]}")
