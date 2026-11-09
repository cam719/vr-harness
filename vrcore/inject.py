"""Injector: send a frame to a lab host, confirm delivery, run oracles, capture
artifacts. Mirrors Beer's inject()/try_inject() + ACK-sniffer pairing, with the
oracles playing the role of the sniffer thread.
"""
from __future__ import annotations
import hashlib
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .frames import Frame
from .oracles import Oracle


@dataclass
class LabPolicy:
    """Destinations the injector may talk to. Loaded from lab/lab.toml."""
    allowed_hosts: set = field(default_factory=set)
    allowed_nets: list = field(default_factory=list)   # ipaddress networks
    min_interval: float = 0.05                          # seconds between sends

    def check(self, host: str) -> None:
        if host in self.allowed_hosts:
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise PermissionError(f"refusing non-lab destination {host!r}: not in allowed_hosts")
        if any(ip in n for n in self.allowed_nets):
            return
        raise PermissionError(f"refusing non-lab destination {host!r}")

    @classmethod
    def from_toml(cls, path: Path | str) -> "LabPolicy":
        import tomllib
        cfg = tomllib.loads(Path(path).read_text())
        lab = cfg.get("lab", {})
        hosts = set(lab.get("allowed_hosts", []))
        # optional generic [hosts] table (name -> ip) of lab hosts you allow
        for ip in cfg.get("hosts", {}).values():
            if isinstance(ip, str) and ip:
                hosts.add(ip)
        nets = [ipaddress.ip_network(n) for n in lab.get("allowed_nets", [])]
        return cls(hosts, nets, float(lab.get("min_interval", 0.05)))


class Transport:
    def send(self, data: bytes, timeout: float) -> bytes | None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class UdpTransport(Transport):
    def __init__(self, host: str, port: int, bind: tuple[str, int] | None = None):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind:
            self.sock.bind(bind)

    def send(self, data: bytes, timeout: float) -> bytes | None:
        self.sock.sendto(data, self.addr)
        self.sock.settimeout(timeout)
        try:
            reply, _ = self.sock.recvfrom(65535)
            return reply
        except socket.timeout:
            return None

    def close(self) -> None:
        self.sock.close()


class TcpTransport(Transport):
    """One persistent stream. `reconnect_each=True` opens a fresh connection per
    send (state-free experiments); otherwise the stream persists so a
    multi-message exchange stays on one connection."""
    def __init__(self, host: str, port: int, reconnect_each: bool = False, connect_timeout: float = 3.0):
        self.addr, self.reconnect_each, self.ct = (host, port), reconnect_each, connect_timeout
        self.sock: socket.socket | None = None

    def _ensure(self) -> socket.socket:
        if self.sock is None:
            self.sock = socket.create_connection(self.addr, timeout=self.ct)
        return self.sock

    def send(self, data: bytes, timeout: float) -> bytes | None:
        s = self._ensure()
        s.sendall(data)
        s.settimeout(timeout)
        try:
            reply = s.recv(65535)
        except socket.timeout:
            reply = None
        except ConnectionError as e:
            reply = None
        if self.reconnect_each:
            self.close()
        return reply

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None


@dataclass
class SendResult:
    frame_sha256: str
    sent_bytes: int
    reply: bytes | None
    elapsed: float
    oracles: dict
    trace: list
    verdict: str


class Injector:
    def __init__(self, transport: Transport, policy: LabPolicy, host: str,
                 tracer=None, artifact_dir: Path | None = None):
        policy.check(host)
        self.transport, self.policy, self.host = transport, policy, host
        self.tracer = tracer                       # object with .drain() -> list[dict], optional
        self.artifact_dir = artifact_dir
        self._last_send = 0.0

    def inject(self, frame: Frame | bytes, oracles: Iterable[Oracle] = (), timeout: float = 2.0,
               label: str = "") -> SendResult:
        data = frame.build() if isinstance(frame, Frame) else bytes(frame)
        sha = hashlib.sha256(data).hexdigest()
        oracles = list(oracles)
        # rate limit
        gap = time.time() - self._last_send
        if gap < self.policy.min_interval:
            time.sleep(self.policy.min_interval - gap)
        if self.tracer:
            self.tracer.drain()
        for o in oracles:
            o.before()
        t0 = time.time()
        reply = self.transport.send(data, timeout)
        elapsed = time.time() - t0
        self._last_send = time.time()
        trace = self.tracer.drain() if self.tracer else []
        ctx = {"reply": reply, "trace": trace, "frame": data, "label": label}
        results = {o.name: o.after(ctx).as_dict() for o in oracles}
        if self.artifact_dir:
            self.artifact_dir.mkdir(parents=True, exist_ok=True)
            (self.artifact_dir / f"{label or sha[:12]}.bin").write_bytes(data)
            if reply:
                (self.artifact_dir / f"{label or sha[:12]}.reply").write_bytes(reply)
            if trace:
                import json
                (self.artifact_dir / f"{label or sha[:12]}.trace.json").write_text(json.dumps(trace, indent=1))
        verdicts = {r["verdict"] for r in results.values()}
        verdict = "PASS" if verdicts == {"PASS"} else ("FAIL" if "FAIL" in verdicts else "INCONCLUSIVE")
        return SendResult(sha, len(data), reply, elapsed, results, trace, verdict)
