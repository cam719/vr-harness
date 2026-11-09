import sys, pathlib, tomllib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from gstcodeql import mp4
from gstcodeql.oracle import GstFaultOracle
from gstcodeql.runner import GstRunner
from gstcodeql.hypothesis import Hypothesis, probe
from gstcodeql import hypotheses

LAB = pathlib.Path(__file__).resolve().parents[1] / "lab.toml"


def test_mp4_box_size_and_nesting():
    b = mp4.box("abcd", b"\x00\x00\x00\x05")
    assert int.from_bytes(b[:4], "big") == len(b) == 12 and b[4:8] == b"abcd"
    moov = mp4.container("moov", mp4.box("trak", b"ab"))
    assert moov[4:8] == b"moov" and int.from_bytes(moov[:4], "big") == len(moov)


def test_find_box_and_splice():
    f = mp4.ftyp() + mp4.container("moov", mp4.container("trak", mp4.box("abcd", b"\xAA" * 8)))
    loc = mp4.find_box(f, "abcd")
    assert loc is not None
    _, _, payload = loc
    g = mp4.splice(f, payload, (0xFFFFFFFF).to_bytes(4, "big"))
    assert len(g) == len(f) and g[payload:payload+4] == b"\xff\xff\xff\xff"
    assert mp4.find_box(f, "zzzz") is None


def test_example_hypothesis_builds_distinct_inputs():
    build = hypotheses.HYP_A["build"]
    a, b = build(0x10000), build(0xFFFFFFFF)
    assert a != b and b[4:8] == b"ftyp" and b"exbx" in a
    assert set(hypotheses.REGISTRY) >= {"example_count_field", "example_field_splice"}


def test_oracle_directions():
    asan = b"==1==ERROR: AddressSanitizer: heap-buffer-overflow"
    assert GstFaultOracle(expect_fault=True).after({"reply": asan}).verdict == "PASS"
    assert GstFaultOracle(expect_fault=True).after({"reply": b"Got EOS"}).verdict == "FAIL"
    # a fatal signal is a memory-safety fault
    assert GstFaultOracle(expect_fault=True).after({"reply": b"out\n__SIGNAL__ 11\n"}).verdict == "PASS"
    # a timeout (None reply) is inconclusive, never a fault
    assert GstFaultOracle(expect_fault=True).after({"reply": None}).verdict == "INCONCLUSIVE"


def test_glib_critical_is_an_observation_not_a_fault():
    glib = (b"(gst-launch-1.0:12): GLib-GObject-CRITICAL **: g_object_unref: "
            b"assertion 'G_IS_OBJECT (object)' failed\nGot EOS\n")
    # expecting a fault: a GLib critical alone does NOT count as one
    assert GstFaultOracle(expect_fault=True).after({"reply": glib}).verdict == "FAIL"
    # control: a GLib critical must NOT fail the control (it is not memory-unsafe)
    assert GstFaultOracle(expect_fault=False).after({"reply": glib}).verdict == "PASS"
    # but a real ASan report alongside a GLib line still faults
    both = b"GLib-GObject-CRITICAL **: foo\n==1==ERROR: AddressSanitizer: heap-use-after-free"
    assert GstFaultOracle(expect_fault=True).after({"reply": both}).verdict == "PASS"


class _StubRunner(GstRunner):
    """Offline stand-in: faults only for the 0xFFFFFFFF input, no GStreamer."""
    def __init__(self, cmd): self._cmd = cmd
    def send(self, data, timeout):
        return (b"==9==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                if b"\xff\xff\xff\xff" in data else b"Setting pipeline to PLAYING\nGot EOS\n")
    def close(self): pass


def test_probe_loop_records_faults_without_gstreamer(tmp_path, monkeypatch):
    # drive the full hypothesis loop with a stub transport -> proves the N-of-N
    # recording works end to end, no GStreamer involved.
    import gstcodeql.hypothesis as H
    monkeypatch.setattr(H, "RUNS", tmp_path / "runs")
    h = Hypothesis(name="t", codeql_ref="x", element="demux", sink="unchecked",
                   build=lambda v: b"ftyp" + v.to_bytes(4, "big"),
                   values=[0x1, 0xFFFFFFFF])
    rc = probe(h, LAB, trials=3, transport_factory=_StubRunner)
    assert rc == 0  # 0xFFFFFFFF faulted 3/3 -> at least one value confirmed


def test_lab_toml_and_policy():
    cfg = tomllib.loads(LAB.read_text())
    assert "{input}" in cfg["target"]["runner"]
    from vrcore import LabPolicy
    pol = LabPolicy.from_toml(LAB); pol.check("127.0.0.1")
    with pytest.raises(PermissionError):
        pol.check("8.8.8.8")
