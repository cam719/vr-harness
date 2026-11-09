"""vrcore: target-agnostic vulnerability-research harness engine.

A small, reusable engine for running disciplined repro/discovery campaigns
against any target. Nothing target-specific lives here:

- frames  : the composable byte `Frame` builder + scalar helpers
- store   : the run / node / record / trial store with N-of-N trial gating
- oracles : independent trial judges (reply/log/trace/process/dump)
- inject  : TCP/UDP transports + an allowlist-guarded Injector

Target-specific builders, tracers, and lab config live in a target package that
imports this one (see gstcodeql/ for a worked GStreamer example).
"""
from .frames import (Frame, u8, u16le, u16be, u32le, u32be, u64le, ascii_bytes, pad, raw,
                     lenprefix, UNKNOWN)
from .store import Run, Node, Record, Trial, Verdict, RunStore
from .oracles import (Oracle, OracleResult, ReplyOracle, LogOracle, TraceOracle,
                      ProcessOracle, DumpOracle)
from .inject import Injector, LabPolicy, Transport, UdpTransport, TcpTransport

__version__ = "0.1.0"
__all__ = ["Frame", "u8", "u16le", "u16be", "u32le", "u32be", "u64le", "ascii_bytes", "pad",
           "raw", "lenprefix", "UNKNOWN", "Run", "Node", "Record", "Trial", "Verdict",
           "RunStore", "Oracle", "OracleResult", "ReplyOracle", "LogOracle", "TraceOracle",
           "ProcessOracle", "DumpOracle", "Injector", "LabPolicy", "Transport",
           "UdpTransport", "TcpTransport"]
