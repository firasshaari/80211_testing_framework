"""
Offline tests for ``benchd.store`` — run storage and result reading.

The store is what every other console feature stands on: comparisons key on
what ``cases()`` returns, and the run list is only as trustworthy as
``meta.json``. These tests pin the cross-run case key, tolerance of damaged
files, and that the AP identity a run was against survives a round trip.
"""
from __future__ import annotations

import json

import pytest

from benchd import paths, store
from benchd.store import Meta
from tests.unit.conftest import make_run, write_environment, write_result


# ── isolation ────────────────────────────────────────────────────────────────

def test_the_store_never_touches_the_real_runs_directory(tmp_path):
    """
    The autouse fixture is the only thing standing between these tests and
    the bench's real history. If it ever stops applying, this fails first.
    """
    assert paths.RUNS == tmp_path / "runs"
    assert str(store.run_dir("anything")).startswith(str(tmp_path))
    store.write_meta(Meta(id="probe"))
    assert (tmp_path / "runs" / "probe" / "meta.json").exists()


# ── cases(): the cross-run key ───────────────────────────────────────────────

def test_cases_are_keyed_by_example_and_band_from_the_parameters():
    write_result("r1", "crypto-psk", "5G", "passed")
    write_result("r1", "crypto-psk", "2G", "failed", message="boom")
    write_result("r1", "radius", "5G", "skipped")

    keys = set(store.cases("r1"))
    assert keys == {("crypto-psk", "5G"), ("crypto-psk", "2G"), ("radius", "5G")}


def test_repr_quoted_parameter_values_are_unquoted():
    """
    allure-pytest stores parametrize values as Python reprs, so the key would
    otherwise be ``("'crypto-psk'", "'5G'")`` and never match a run recorded
    any other way.
    """
    write_result("r1", "crypto-psk", "5G", "passed", quoted=True)
    assert ("crypto-psk", "5G") in store.cases("r1")


def test_unquoted_parameter_values_are_accepted_as_they_are():
    write_result("r1", "crypto-psk", "5G", "passed", quoted=False)
    assert ("crypto-psk", "5G") in store.cases("r1")


@pytest.mark.parametrize("raw, clean", [
    ("'crypto-psk'", "crypto-psk"),
    ('"crypto-psk"', "crypto-psk"),
    ("crypto-psk", "crypto-psk"),
    ("'", "'"),                     # a lone quote is not a quoted empty string
    ("'mismatched\"", "'mismatched\""),
    (5, "5"),                       # non-strings are stringified, not rejected
])
def test_unquote_only_strips_a_matching_pair_of_quotes(raw, clean):
    assert store._unquote(raw) == clean


def test_a_case_carries_status_message_trace_labels_and_duration():
    write_result("r1", "radius", "5G", "failed", message="Did not associate",
                 trace="Traceback...", feature="security", story="RADIUS",
                 title="Enterprise RADIUS · 5G", start=100, stop=2600)
    case = store.cases("r1")[("radius", "5G")]
    assert case == {
        "status": "failed",
        "title": "Enterprise RADIUS · 5G",
        "feature": "security",
        "story": "RADIUS",
        "message": "Did not associate",
        "trace": "Traceback...",
        "ms": 2500,
    }


def test_a_result_with_no_status_details_reads_as_empty_strings():
    """A passing case has ``statusDetails: null``; that must not become None."""
    f = write_result("r1", "psk", "5G", "passed")
    doc = json.loads(f.read_text())
    doc["statusDetails"] = None
    del doc["stop"]
    f.write_text(json.dumps(doc))

    case = store.cases("r1")[("psk", "5G")]
    assert case["message"] == "" and case["trace"] == ""
    assert case["ms"] == 0        # a missing stop never yields a negative duration


def test_malformed_result_files_are_skipped_not_fatal():
    """
    A run interrupted mid-write leaves a truncated result behind. One bad file
    must not hide the hundreds of good ones next to it.
    """
    write_result("r1", "psk", "5G", "passed")
    rdir = store.results_dir("r1")
    (rdir / "truncated-result.json").write_text('{"name": "half', encoding="utf-8")
    (rdir / "empty-result.json").write_text("")

    assert set(store.cases("r1")) == {("psk", "5G")}


def test_results_without_the_identifying_parameters_are_skipped():
    """Container or fixture results have no example/band and are not cases."""
    f = write_result("r1", "psk", "5G", "passed")
    doc = json.loads(f.read_text())
    doc["parameters"] = [{"name": "something_else", "value": "'x'"}]
    f.write_text(json.dumps(doc))
    write_result("r1", "psk", "2G", "passed")

    assert set(store.cases("r1")) == {("psk", "2G")}


def test_only_result_files_are_read():
    """Allure writes containers and attachments alongside; they are not cases."""
    write_result("r1", "psk", "5G", "passed")
    rdir = store.results_dir("r1")
    (rdir / "abc-container.json").write_text('{"children": []}')
    (rdir / "abc-attachment.txt").write_text("not json at all")
    assert len(store.cases("r1")) == 1


def test_a_run_with_no_results_directory_has_no_cases():
    assert store.cases("never-ran") == {}


# ── totals() ─────────────────────────────────────────────────────────────────

def test_totals_count_every_status_and_sum_to_total():
    make_run("r1", {
        ("a", "2G"): "passed", ("a", "5G"): "passed",
        ("b", "2G"): ("failed", "x"), ("c", "2G"): ("broken", "y"),
        ("d", "2G"): "skipped",
    })
    assert store.totals("r1") == {
        "passed": 2, "failed": 1, "broken": 1, "skipped": 1, "unknown": 0,
        "total": 5,
    }


def test_an_unrecognised_status_is_counted_as_unknown_not_dropped():
    write_result("r1", "a", "2G", "something-new")
    totals = store.totals("r1")
    assert totals["unknown"] == 1 and totals["total"] == 1


def test_totals_of_an_empty_run_are_all_zero():
    assert store.totals("none")["total"] == 0


# ── environment() / ap_from_environment() ────────────────────────────────────

def test_environment_reads_the_suites_own_record_of_the_ap():
    write_environment("r1", **{
        "AP.Model": "EAP102", "AP.Firmware": "3.0.1-rc2",
        "AP.Serial": "0011223344", "Station.Host": "10.0.125.190",
    })
    env = store.environment("r1")
    assert env["AP.Model"] == "EAP102"
    assert env["Station.Host"] == "10.0.125.190"


def test_environment_tolerates_comments_blank_lines_and_values_with_equals():
    rdir = store.results_dir("r1")
    rdir.mkdir(parents=True)
    (rdir / "environment.properties").write_text(
        "# written by conftest\n\nAP.Kernel = 5.15.137\nAP.Note=a=b\n")
    env = store.environment("r1")
    assert env == {"AP.Kernel": "5.15.137", "AP.Note": "a=b"}


def test_a_run_without_environment_properties_has_an_empty_environment():
    """
    Older sweeps predate the environment file. Importing them must still work,
    just with an AP identity the operator has to supply.
    """
    write_result("r1", "a", "2G", "passed")
    assert store.environment("r1") == {}
    assert store.ap_from_environment({}) == {
        "host": "", "model": "", "firmware": "", "serial": "", "kernel": "", "platform": "",
    }


def test_ap_from_environment_maps_every_identity_field():
    env = {"AP.Host": "10.0.127.220", "AP.Model": "EAP102", "AP.Firmware": "3.0.1",
           "AP.Serial": "s", "AP.Kernel": "k", "AP.Platform": "mt7621",
           "Station.Host": "ignored"}
    assert store.ap_from_environment(env) == {
        "host": "10.0.127.220", "model": "EAP102", "firmware": "3.0.1",
        "serial": "s", "kernel": "k", "platform": "mt7621",
    }


# ── meta.json ────────────────────────────────────────────────────────────────

def test_meta_round_trips_through_json():
    meta = Meta(id="20260101-000000-eap102", status="failed", label="nightly",
                scope_kind="area", scope_value="security", mode="nat",
                started="2026-01-01T00:00:00+00:00", finished="2026-01-01T02:00:00+00:00",
                ap={"host": "10.0.127.220", "model": "EAP102", "firmware": "3.0.1"},
                station={"host": "10.0.125.190"},
                preflight={"ok": True, "lines": ["radio up"]},
                totals={"passed": 10, "failed": 1, "total": 11},
                pid=4242, exit_code=1, imported=False, note="first run on new fw")
    store.write_meta(meta)
    assert store.read_meta(meta.id) == meta


def test_write_meta_leaves_no_temporary_file_behind():
    """The write is tmp-then-rename so a crash cannot leave a half-written meta."""
    store.write_meta(Meta(id="r1"))
    assert sorted(p.name for p in store.run_dir("r1").iterdir()) == ["meta.json"]


def test_read_meta_returns_none_for_a_missing_run():
    assert store.read_meta("nope") is None


def test_read_meta_returns_none_for_corrupt_json_rather_than_raising():
    d = store.run_dir("r1")
    d.mkdir(parents=True)
    (d / "meta.json").write_text('{"id": "r1", "status": ')
    assert store.read_meta("r1") is None


def test_read_meta_returns_none_when_the_json_does_not_fit_the_schema():
    """A field from a future version, or the wrong shape entirely, is unreadable."""
    d = store.run_dir("r1")
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"id": "r1", "no_such_field": 1}))
    assert store.read_meta("r1") is None
    (d / "meta.json").write_text("[]")
    assert store.read_meta("r1") is None


def test_ap_label_prefers_model_then_host_then_a_placeholder():
    assert Meta(id="x", ap={"model": "EAP102", "host": "10.0.0.1"}).ap_label == "EAP102"
    assert Meta(id="x", ap={"host": "10.0.0.1"}).ap_label == "10.0.0.1"
    assert Meta(id="x", ap={"model": ""}).ap_label == "unknown AP"
    assert Meta(id="x").ap_label == "unknown AP"


def test_fw_falls_back_to_unknown():
    assert Meta(id="x", ap={"firmware": "3.0.1"}).fw == "3.0.1"
    assert Meta(id="x").fw == "unknown"


def test_scope_label_names_a_partial_sweep():
    assert Meta(id="x").scope_label == "full sweep"
    assert Meta(id="x", scope_kind="area", scope_value="vlan").scope_label == "area: vlan"
    assert Meta(id="x", scope_kind="example", scope_value="radius").scope_label == "example: radius"


@pytest.mark.parametrize("status, live", [
    ("queued", True), ("preflight", True), ("running", True),
    ("passed", False), ("failed", False), ("stopped", False),
    ("interrupted", False), ("error", False), ("imported", False),
])
def test_is_live_covers_exactly_the_in_progress_states(status, live):
    """The console polls live runs and offers to stop them; nothing else."""
    assert Meta(id="x", status=status).is_live is live


# ── run ids and listing ──────────────────────────────────────────────────────

def test_new_id_is_timestamp_then_a_slug_of_the_ap():
    rid = store.new_id("EAP102 (Edgecore)")
    stamp, _, slug = rid.partition("-")
    assert len(stamp) == 8 and stamp.isdigit()
    assert slug.endswith("-eap102-edgecore")


def test_new_id_slug_falls_back_when_the_hint_is_unusable():
    assert store.new_id("").endswith("-ap")
    assert store.new_id("!!!").endswith("-ap")


def test_slug_is_lowercase_hyphenated_and_bounded():
    assert store._slug("Edgecore EAP102 v3.0") == "edgecore-eap102-v3-0"
    assert len(store._slug("x" * 100)) == 24


def test_list_runs_is_newest_first_and_skips_unreadable_entries():
    make_run("older", {}, started="2026-01-01T00:00:00+00:00")
    make_run("newer", {}, started="2026-02-01T00:00:00+00:00")
    (paths.RUNS / "no-meta").mkdir()
    (paths.RUNS / "stray-file").write_text("not a run")
    d = paths.RUNS / "corrupt"
    d.mkdir()
    (d / "meta.json").write_text("{")

    assert [m.id for m in store.list_runs()] == ["newer", "older"]


def test_list_runs_creates_the_runs_directory_when_it_is_missing():
    assert not paths.RUNS.exists()
    assert store.list_runs() == []
    assert paths.RUNS.is_dir()


def test_delete_run_removes_the_whole_directory_and_reports_whether_it_existed():
    make_run("r1", {("a", "2G"): "passed"})
    assert store.delete_run("r1") is True
    assert not store.run_dir("r1").exists()
    assert store.delete_run("r1") is False
