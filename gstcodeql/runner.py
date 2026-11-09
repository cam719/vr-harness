"""GstRunner: a vrcore Transport that feeds crafted media bytes into a
GStreamer pipeline (built with AddressSanitizer) as a one-shot subprocess and
returns its combined stderr+stdout. A parser crash shows up there as an ASAN /
UBSan report or a fatal signal.
"""
from __future__ import annotations
import os
import shlex
import subprocess
import tempfile
from vrcore.inject import Transport


class GstRunner(Transport):
    """`cmd_template` must contain '{input}', replaced by the crafted file path.
    The command is run WITHOUT a shell, so '!' / spaces are literal args."""

    def __init__(self, cmd_template: str):
        if "{input}" not in cmd_template:
            raise ValueError("runner template must contain '{input}'")
        self.tmpl = cmd_template
        self.env = {**os.environ,
                    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:exitcode=0",
                    "UBSAN_OPTIONS": "print_stacktrace=1",
                    "GST_DEBUG": "0", "GST_DEBUG_NO_COLOR": "1"}
        self.last_returncode: int | None = None

    def send(self, data: bytes, timeout: float) -> bytes | None:
        with tempfile.NamedTemporaryFile(prefix="gstpoc_", suffix=".media", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            cmd = [a.replace("{input}", path) for a in shlex.split(self.tmpl)]
            p = subprocess.run(cmd, env=self.env, capture_output=True, timeout=timeout)
            self.last_returncode = p.returncode
            tail = b""
            if p.returncode and p.returncode < 0:          # killed by signal
                tail = b"\n__SIGNAL__ %d\n" % (-p.returncode)
            return (p.stderr or b"") + (p.stdout or b"") + tail
        except subprocess.TimeoutExpired:
            self.last_returncode = None
            return None          # None = timed out / no reply (handled by the oracle)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def close(self) -> None:
        pass
