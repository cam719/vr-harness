import sys, pathlib, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from gstcodeql.oracle import GstSiteOracle
from gstcodeql.runner import GstRunner
from gstcodeql.verify import verify, Variant, byte_diff, summarize_fault, CONFIRMED, REFUTED, INCONCLUSIVE
from gstcodeql import cli

MARK = b"\xff\xff\xff\xff"
CLEAN = b"Setting pipeline to PLAYING ...\nGot EOS from element \"pipeline0\".\n"
REPORT = (b"=================================================================\n"
          b"==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014\n"
          b"WRITE of size 4 at 0x602000000014 thread T0\n"
          b"    #0 0x7f01 in parse_widget ../gst/widget/widget-demux.c:123\n"
          b"    #1 0x7f02 in gst_widget_demux_chain ../gst/widget/widget-demux.c:456\n"
          b"SUMMARY: AddressSanitizer: heap-buffer-overflow ../gst/widget/widget-demux.c:123 in parse_widget\n")
OTHER_SITE = REPORT.replace(b"widget-demux.c", b"other-lib.c").replace(b"parse_widget", b"other_fn")
GLIB = b"(gst-launch-1.0:1): GStreamer-CRITICAL **: gst_buffer_map: assertion 'GST_IS_BUFFER (buffer)' failed\n"


def stub(reply_for):
    """A transport class whose reply depends only on the input bytes."""
    class Stub(GstRunner):
        def __init__(self, cmd): pass
        def send(self, data, timeout): return reply_for(data)
        def close(self): pass
    return Stub


def files(tmp_path, mutate=True):
    ctl = b"HEAD" + b"\x00\x00\x00\x10" + b"payload-bytes"
    mut = ctl.replace(b"\x00\x00\x00\x10", MARK) if mutate else ctl
    c, m = tmp_path / "control.bin", tmp_path / "mutant.bin"
    c.write_bytes(ctl); m.write_bytes(mut)
    return c, m


def run(tmp_path, reply_for, **kw):
    c, m = files(tmp_path, kw.pop("mutate", True))
    return verify(c, m, element="widgetdemux", runner="stub {input}", run_root=tmp_path / "runs",
                  transport_factory=stub(reply_for), **kw)


def test_confirmed_when_control_clean_and_mutant_faults_at_site(tmp_path):
    res = run(tmp_path, lambda d: REPORT if MARK in d else CLEAN, site="widget-demux\\.c|parse_widget")
    assert res["verdict"] == CONFIRMED
    assert res["records"]["control"]["status"] == "confirmed"
    assert res["records"]["mutant"] == {"status": "confirmed", "n": 3, "passes": 3, "fails": 0, "inconclusive": 0}
    assert res["fault"]["type"] == "heap-buffer-overflow"
    assert (res["fault"]["access"], res["fault"]["size"]) == ("WRITE", 4)
    assert "parse_widget" in res["fault"]["site"]
    saved = json.loads((pathlib.Path(res["run_dir"]) / "verdict.json").read_text())
    assert saved["verdict"] == CONFIRMED and saved["diff"]["bytes_changed"] == 4


def test_refuted_when_mutant_parses_clean(tmp_path):
    res = run(tmp_path, lambda d: CLEAN)
    assert res["verdict"] == REFUTED and res["records"]["mutant"]["fails"] == 3


def test_glib_critical_alone_never_confirms(tmp_path):
    # GStreamer emits CRITICALs on malformed-but-safe input: an observation, not a fault
    res = run(tmp_path, lambda d: GLIB if MARK in d else CLEAN)
    assert res["verdict"] == REFUTED


def test_broken_control_stops_before_the_mutant_is_fired(tmp_path):
    res = run(tmp_path, lambda d: REPORT)          # everything "faults": the runner is wrong
    assert res["verdict"] == INCONCLUSIVE and "control not clean" in res["reason"]
    assert "mutant" not in res["records"]


def test_fault_at_a_different_site_is_inconclusive_not_confirmed(tmp_path):
    res = run(tmp_path, lambda d: OTHER_SITE if MARK in d else CLEAN, site="widget-demux\\.c")
    assert res["verdict"] == INCONCLUSIVE and "NOT at" in res["reason"]


def test_flaky_mutant_is_inconclusive(tmp_path):
    calls = {"n": 0}
    def flaky(d):
        if MARK not in d:
            return CLEAN
        calls["n"] += 1
        return REPORT if calls["n"] % 2 else CLEAN
    res = run(tmp_path, flaky)
    assert res["verdict"] == INCONCLUSIVE


def test_timeouts_are_inconclusive(tmp_path):
    res = run(tmp_path, lambda d: None if MARK in d else CLEAN)
    assert res["verdict"] == INCONCLUSIVE and res["records"]["mutant"]["inconclusive"] == 3


def test_identical_mutant_is_rejected(tmp_path):
    res = run(tmp_path, lambda d: CLEAN, mutate=False)
    assert res["verdict"] == INCONCLUSIVE and "byte-identical" in res["reason"]


def test_variants_record_their_own_expectation(tmp_path):
    near = tmp_path / "boundary.bin"; near.write_bytes(b"HEAD\x00\x00\x00\x11payload-bytes")
    res = run(tmp_path, lambda d: REPORT if MARK in d else CLEAN,
              variants=[Variant(near, "clean")])
    assert res["verdict"] == CONFIRMED
    assert res["variants"][0]["as_predicted"] and "variants as predicted 1/1" in res["reason"]


def test_byte_diff_and_variant_parsing():
    d = byte_diff(b"abcdef", b"abXdeY!")
    assert d["bytes_changed"] == 2 and [r["offset"] for r in d["ranges"]] == [2, 5]
    assert (d["control_len"], d["mutant_len"]) == (6, 7)
    assert Variant.parse("a=b.mkv=fault").path.name == "a=b.mkv"
    with pytest.raises(ValueError):
        Variant.parse("x.mkv=maybe")


def test_site_oracle_directions():
    o = GstSiteOracle("parse_widget")
    assert o.after({"reply": REPORT}).verdict == "PASS"
    assert o.after({"reply": OTHER_SITE}).verdict == "INCONCLUSIVE"
    assert o.after({"reply": CLEAN}).verdict == "INCONCLUSIVE"
    assert o.after({"reply": None}).verdict == "INCONCLUSIVE"
    # the site must appear in the report itself, not in output printed before it
    assert o.after({"reply": b"loading parse_widget plugin\n" + OTHER_SITE}).verdict == "INCONCLUSIVE"


def test_summarize_fault_ubsan():
    s = summarize_fault(b"x.c:9:5: runtime error: signed integer overflow: 2147483647 + 1\n")
    assert s["type"].startswith("ubsan: signed integer overflow") and s["access"] is None


def test_runner_env_overrides():
    r = GstRunner("echo {input}", env={"GST_REGISTRY_FORK": "no", "ASAN_OPTIONS": "x=1"})
    assert r.env["GST_REGISTRY_FORK"] == "no" and r.env["ASAN_OPTIONS"] == "x=1"


def test_cli_verify_requires_a_runner(tmp_path, capsys):
    c, m = files(tmp_path)
    rc = cli.main(["verify", "--control", str(c), "--mutant", str(m), "--element", "x",
                   "--gst-src", "", "--builddir", ""])
    assert rc == 2 and "need a runner" in capsys.readouterr().out


MISALIGN = (b"../gst/gstutils.h:204:25: runtime error: store to misaligned address 0x5020 for type "
            b"'guint16', which requires 2 byte alignment\n"
            b"    #0 0x1 in __gst_fast_write_swap16 ../gst/gstutils.h:204\n")


def test_ubsan_alignment_report_is_an_observation_not_a_fault():
    from gstcodeql.oracle import GstFaultOracle
    assert GstFaultOracle(expect_fault=True).after({"reply": MISALIGN}).verdict == "FAIL"
    assert GstFaultOracle(expect_fault=False).after({"reply": MISALIGN}).verdict == "PASS"
    # a real ASan report after an alignment nit still faults, and is located correctly
    both = MISALIGN + REPORT
    assert GstFaultOracle(expect_fault=True).after({"reply": both}).verdict == "PASS"
    assert GstSiteOracle("parse_widget").after({"reply": both}).verdict == "PASS"
    # a genuine UBSan check (not alignment) is still a hard fault
    ovf = b"x.c:9:5: runtime error: index 40 out of bounds for type 'int [8]'\n"
    assert GstFaultOracle(expect_fault=True).after({"reply": ovf}).verdict == "PASS"


def test_alignment_noise_cannot_confirm_a_lead(tmp_path):
    res = run(tmp_path, lambda d: MISALIGN if MARK in d else MISALIGN + CLEAN)
    assert res["verdict"] == REFUTED and res["records"]["control"]["status"] == "confirmed"


def test_runner_ships_alignment_suppression():
    from gstcodeql.runner import UBSAN_SUPP
    r = GstRunner("echo {input}")
    assert UBSAN_SUPP.exists() and f"suppressions={UBSAN_SUPP}" in r.env["UBSAN_OPTIONS"]
    assert "alignment:gstutils.h" in UBSAN_SUPP.read_text()
