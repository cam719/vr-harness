"""Tests for the target-agnostic engine (frames, store, injector policy)."""
import struct
import pytest
from vrcore import Frame, lenprefix, UNKNOWN, RunStore, LabPolicy


# --- frames ------------------------------------------------------------------
def test_frame_compose_and_lenprefix():
    assert Frame(b"AB", Frame(b"CD"), "E").build() == b"ABCDE"
    assert lenprefix("<I", b"hello").build() == struct.pack("<I", 5) + b"hello"
    assert lenprefix("<H", b"hello", includes_prefix=True).build() == struct.pack("<H", 7) + b"hello"
    assert lenprefix("<H", b"hello", adjust=-1).build()[:2] == struct.pack("<H", 4)


def test_unknown_field_refuses_to_build():
    with pytest.raises(ValueError):
        Frame(b"x", UNKNOWN).build()


# --- store -------------------------------------------------------------------
def _oracles(*verdicts):
    return {f"o{i}": {"verdict": v, "detail": ""} for i, v in enumerate(verdicts)}


def test_record_confirms_only_after_min_trials_all_pass(tmp_path):
    st = RunStore(tmp_path)
    run = st.create_run("target", "1.0")
    node = st.open_node(run.id, "a/b/c", prereq="peer")
    rec = st.add_record(run.id, node.id, "fault", "x", min_trials=3)
    for _ in range(2):
        st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS", "PASS"))
    assert st.get_record(run.id, rec.id).status == "candidate"
    st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS"))
    assert st.get_record(run.id, rec.id).status == "confirmed"
    assert "confirmed fault: x, 3/3" in st.render_timeline(run.id)


def test_single_failing_oracle_refutes(tmp_path):
    st = RunStore(tmp_path)
    run = st.create_run("target", "1.0")
    node = st.open_node(run.id, "a/b")
    rec = st.add_record(run.id, node.id, "bypass", "x", min_trials=2)
    for _ in range(2):
        st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS", "FAIL"))
    assert st.get_record(run.id, rec.id).status == "refuted"


def test_invalid_kind_and_reason_rejected(tmp_path):
    st = RunStore(tmp_path)
    run = st.create_run("target", "x")
    node = st.open_node(run.id, "a/b")
    with pytest.raises(ValueError):
        st.add_record(run.id, node.id, "crash", "nope")
    with pytest.raises(ValueError):
        st.close_node(run.id, node.id, "done")


# --- inject policy -----------------------------------------------------------
def test_policy_allows_generic_hosts_and_nets_only(tmp_path):
    p = tmp_path / "lab.toml"
    # generic [hosts] table (name -> ip) + an allowed net; no target-specific roles
    p.write_text('[lab]\nallowed_nets=["172.16.213.0/24"]\n[hosts]\nnode_a="10.9.9.9"\n')
    pol = LabPolicy.from_toml(p)
    pol.check("10.9.9.9")        # allowed via [hosts]
    pol.check("172.16.213.7")    # allowed via net
    for bad in ("8.8.8.8", "192.168.238.5", "example.com", "157.180.61.21"):
        with pytest.raises(PermissionError):
            pol.check(bad)


def test_confirmed_is_not_sticky_regresses_on_later_failure(tmp_path):
    st = RunStore(tmp_path)
    run = st.create_run("target", "1.0")
    node = st.open_node(run.id, "a/b/c")
    rec = st.add_record(run.id, node.id, "fault", "x", min_trials=3)
    for _ in range(3):
        st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS"))
    assert st.get_record(run.id, rec.id).status == "confirmed"
    # a later FAIL must un-confirm: status is a pure function of ALL trials
    st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("FAIL"))
    assert st.get_record(run.id, rec.id).status == "candidate"


def test_inconclusive_trial_blocks_confirmation(tmp_path):
    st = RunStore(tmp_path)
    run = st.create_run("target", "1.0")
    node = st.open_node(run.id, "a/b")
    rec = st.add_record(run.id, node.id, "fault", "x", min_trials=3)
    st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS"))
    st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("PASS"))
    st.finish_trial(run.id, st.start_trial(run.id, rec.id), _oracles("INCONCLUSIVE"))
    # 2 pass + 1 inconclusive is NOT N-of-N passing
    assert st.get_record(run.id, rec.id).status == "candidate"
