"""
Offline tests for ``benchd.compare`` — summarising one run, diffing two.

The comparison page produces the single most quotable number the console has:
"N regressed". Most of what is pinned here is about that number not lying —
a case skipped on one bench is a capability gap, and a case that failed
because SSH dropped is a bench fault; neither is the AP getting worse.
"""
from __future__ import annotations

import pytest

from benchd import compare, store
from tests.unit.conftest import make_run, write_result

SSH_LOST = "station: Cannot SSH to 10.0.125.190 (transport failed)"
STRICT_REJECT = "AP rejected 'wifi-6e': Rejecting config due to strict mode"
NO_ASSOC = "Did not associate with 'ap-psk2' after 45s (last wpa_state=SCANNING)"
WPA1 = ("Beacon for 'ap-wpa' carries neither a WPA nor an RSN information element "
        "although proto=wpa was configured")


# ── _verdict(): every transition ─────────────────────────────────────────────

@pytest.mark.parametrize("a, b, verdict", [
    ("passed", "failed", "regressed"),
    ("passed", "broken", "regressed"),
    ("failed", "passed", "fixed"),
    ("broken", "passed", "fixed"),
    ("failed", "failed", "both_failed"),
    ("failed", "broken", "both_failed"),
    ("broken", "broken", "both_failed"),
    ("passed", "passed", "both_passed"),
])
def test_verdict_for_each_pass_fail_transition(a, b, verdict):
    assert compare._verdict({"status": a}, {"status": b}) == verdict


@pytest.mark.parametrize("a, b", [
    ("passed", "skipped"), ("skipped", "passed"),
    ("failed", "skipped"), ("skipped", "failed"),
    ("broken", "skipped"), ("skipped", "broken"),
])
def test_a_skip_on_either_side_is_a_capability_difference_not_a_regression(a, b):
    """
    A case that ran on one bench and skipped on the other says the benches
    differ (a RADIUS container down, no 6 GHz radio), not that the AP did.
    Calling it a regression would blame the AP for hardware it was never given.
    """
    assert compare._verdict({"status": a}, {"status": b}) == "skip_diff"


def test_skipped_on_both_sides_is_treated_as_unchanged():
    assert compare._verdict({"status": "skipped"}, {"status": "skipped"}) == "both_passed"


def test_a_case_missing_from_one_run_is_only_in_the_other():
    assert compare._verdict(None, {"status": "passed"}) == "only_b"
    assert compare._verdict({"status": "failed"}, None) == "only_a"


def test_an_unknown_status_never_reads_as_a_regression():
    """Something the store could not classify is not evidence either way."""
    assert compare._verdict({"status": "passed"}, {"status": "unknown"}) == "both_passed"
    assert compare._verdict({"status": "unknown"}, {"status": "failed"}) == "both_passed"


def test_every_verdict_has_a_label():
    assert set(compare._LABEL) == set(compare.VERDICTS)


# ── _first_line() ────────────────────────────────────────────────────────────

def test_first_line_of_an_empty_message_is_empty_not_an_index_error():
    """
    A passing case has no message, so ``splitlines()`` is ``[]`` and indexing
    it raised. That IndexError took the whole comparison page down for any pair
    of runs with a passing case in it — which is all of them.
    """
    assert compare._first_line({"message": ""}) == ""
    assert compare._first_line({}) == ""
    assert compare._first_line(None) == ""


def test_first_line_keeps_only_the_first_line_and_bounds_its_length():
    assert compare._first_line({"message": "first\nsecond\nthird"}) == "first"
    assert compare._first_line({"message": "x" * 500}) == "x" * 180
    assert compare._first_line({"message": "x" * 500}, limit=10) == "x" * 10


# ── categorise(): the bench's own buckets ────────────────────────────────────

def test_the_real_categories_file_is_in_use():
    """Guards against the tests silently passing against an empty category list."""
    assert len(compare._categories()) >= 8


def test_wpa1_without_an_information_element_is_encryption_the_ap_never_describes():
    assert compare.categorise("failed", WPA1) == "AP advertised encryption it never describes"


def test_losing_ssh_is_the_harness_losing_the_ap_or_station():
    assert compare.categorise("failed", SSH_LOST) == "Harness lost the AP or the station"
    assert compare.categorise("broken", "paramiko: Socket is closed") == \
        "Harness lost the AP or the station"


def test_a_skip_for_missing_hardware_is_the_testbed_lacking_it():
    assert compare.categorise("skipped", "testbed lacks: radius server") == \
        "Testbed lacks the hardware"


def test_a_category_that_only_matches_skipped_does_not_fire_for_a_failure():
    """
    Allure honours ``matchedStatuses``; so must we, or a failure whose message
    happens to say "testbed lacks" would be filed as a harmless skip.
    """
    assert compare.categorise("failed", "testbed lacks: radius server") == ""
    assert compare.categorise("broken", "testbed lacks: radius server") == ""


def test_a_category_restricted_to_failed_does_not_fire_for_broken():
    assert compare.categorise("failed", NO_ASSOC) == "Client could not connect"
    assert compare.categorise("broken", NO_ASSOC) == ""


def test_the_trace_is_searched_as_well_as_the_message():
    """An SSH loss often surfaces in the traceback with a bare AssertionError on top."""
    assert compare.categorise("failed", "AssertionError", trace="paramiko EOFError") == \
        "Harness lost the AP or the station"


def test_matching_is_case_insensitive_and_spans_lines():
    assert compare.categorise("failed", "the AP said:\nVALUE MUST BE an integer") == \
        "AP rejected the config"


def test_an_unrecognised_failure_has_no_category():
    assert compare.categorise("failed", "something nobody has seen before") == ""


def test_first_matching_category_wins_in_file_order():
    """The file is ordered cause-first; a rejection with SSH noise is a rejection."""
    assert compare.categorise("failed", f"{SSH_LOST}; also: {STRICT_REJECT}") == \
        "AP rejected the config"


# ── compare(): two runs side by side ─────────────────────────────────────────

def test_compare_lines_cases_up_by_example_and_band_across_different_aps():
    make_run("a", {("psk", "5G"): "passed", ("psk", "2G"): "passed"},
             model="EAP102", host="10.0.127.220")
    make_run("b", {("psk", "5G"): "passed", ("psk", "2G"): ("failed", STRICT_REJECT)},
             model="SPW2AC1200", host="10.0.127.221")

    result = compare.compare("a", "b")
    by_key = {(r["example"], r["band"]): r for r in result["rows"]}
    assert by_key[("psk", "5G")]["verdict"] == "both_passed"
    assert by_key[("psk", "2G")]["verdict"] == "regressed"
    assert by_key[("psk", "2G")]["a"] == "passed"
    assert by_key[("psk", "2G")]["b"] == "failed"
    assert by_key[("psk", "2G")]["b_message"].startswith("AP rejected")
    assert result["kind"] == "ap"


def test_a_bench_fault_is_counted_as_an_artefact_and_the_headline_says_so():
    """
    The one that matters. Three EAP102 sweeps were destroyed by a station that
    fell over; every case "regressed". A comparison that reports those as the
    AP getting worse is worse than no comparison at all.
    """
    make_run("a", {("psk", "5G"): "passed", ("radius", "5G"): "passed",
                   ("wpa", "2G"): "passed"})
    make_run("b", {("psk", "5G"): ("failed", SSH_LOST),
                   ("radius", "5G"): ("broken", "paramiko: Socket is closed"),
                   ("wpa", "2G"): ("failed", STRICT_REJECT)})

    result = compare.compare("a", "b")
    counts = result["counts"]
    assert counts["regressed"] == 3
    assert counts["regressed_artefact"] == 2
    assert counts["regressed_defect"] == 1
    assert "3 regressed (1 worth looking at, 2 bench artefacts)" in result["headline"]

    rows = {(r["example"], r["band"]): r for r in result["rows"]}
    assert rows[("psk", "5G")]["blame"] == "artefact"
    assert rows[("psk", "5G")]["cause"] == "Harness lost the AP or the station"
    assert rows[("wpa", "2G")]["blame"] == "defect"


def test_a_transport_failure_the_reporter_alone_would_not_recognise_is_still_an_artefact():
    """
    ``classify_failure`` has its own shorter list of transport patterns.
    "Socket is closed" is only in the categories file, so this proves the
    category override is what sets the blame, not the reporter's list.
    """
    from framework.reporting.html_report import classify_failure
    assert classify_failure("paramiko: Socket is closed") != "artefact"

    make_run("a", {("psk", "5G"): "passed"})
    make_run("b", {("psk", "5G"): ("failed", "paramiko: Socket is closed")})
    assert compare.compare("a", "b")["counts"]["regressed_artefact"] == 1


def test_headline_with_no_artefacts_does_not_mention_them():
    make_run("a", {("psk", "5G"): "passed", ("wpa", "2G"): ("failed", WPA1)})
    make_run("b", {("psk", "5G"): ("failed", STRICT_REJECT), ("wpa", "2G"): "passed"})

    headline = compare.compare("a", "b")["headline"]
    assert headline.endswith("— 1 regressed, 1 fixed")
    assert "artefact" not in headline


def test_headline_reports_no_change_when_nothing_moved():
    make_run("a", {("psk", "5G"): "passed", ("x", "2G"): ("failed", WPA1)})
    make_run("b", {("psk", "5G"): "passed", ("x", "2G"): ("failed", WPA1)})
    assert compare.compare("a", "b")["headline"].endswith("— no change in pass/fail")


def test_same_model_compares_firmware_and_names_the_versions():
    make_run("a", {("psk", "5G"): "passed"}, model="EAP102", firmware="3.0.1")
    make_run("b", {("psk", "5G"): "passed"}, model="EAP102", firmware="3.1.0")
    result = compare.compare("a", "b")
    assert result["kind"] == "firmware"
    assert result["headline"].startswith("3.0.1 → 3.1.0")


def test_different_models_compare_aps_and_name_them():
    make_run("a", {("psk", "5G"): "passed"}, model="EAP102")
    make_run("b", {("psk", "5G"): "passed"}, model="SPW2AC1200")
    assert compare.compare("a", "b")["headline"].startswith("EAP102 → SPW2AC1200")


def test_runs_with_no_model_are_not_mistaken_for_the_same_model():
    """Two imports with empty identity must not be labelled a firmware diff."""
    make_run("a", {("psk", "5G"): "passed"}, model="")
    make_run("b", {("psk", "5G"): "passed"}, model="")
    assert compare.compare("a", "b")["kind"] == "ap"


def test_a_skipped_case_is_a_skip_diff_and_never_blamed():
    make_run("a", {("radius", "5G"): "passed"})
    make_run("b", {("radius", "5G"): ("skipped", "testbed lacks: radius server")})
    result = compare.compare("a", "b")
    (row,) = result["rows"]
    assert row["verdict"] == "skip_diff"
    assert row["blame"] == ""
    assert result["counts"]["regressed"] == 0
    assert "regressed" not in result["headline"]


def test_cases_present_in_only_one_run_are_reported_as_such():
    make_run("a", {("old", "5G"): "passed"})
    make_run("b", {("new", "5G"): "passed"})
    rows = {r["example"]: r for r in compare.compare("a", "b")["rows"]}
    assert rows["old"]["verdict"] == "only_a" and rows["old"]["b"] == "—"
    assert rows["new"]["verdict"] == "only_b" and rows["new"]["a"] == "—"


def test_comparing_an_unreadable_run_degrades_to_a_message_not_an_exception():
    make_run("a", {("psk", "5G"): "passed"})
    result = compare.compare("a", "does-not-exist")
    assert result["b"] is None
    assert result["headline"] == "One of these runs could not be read."
    assert [r["verdict"] for r in result["rows"]] == ["only_a"]


# ── summarise(): one run ─────────────────────────────────────────────────────

def test_summarise_groups_failures_by_cause_and_by_class():
    make_run("r", {
        ("psk", "5G"): "passed",
        ("wpa", "2G"): ("failed", WPA1),
        ("radius", "5G"): ("failed", SSH_LOST),
        ("wifi-6e", "6G"): ("skipped", "testbed lacks: 6 GHz radio"),
    })
    s = compare.summarise("r")
    assert s["totals"] == {"passed": 1, "failed": 2, "broken": 0, "skipped": 1,
                           "unknown": 0, "total": 4}
    assert {c["example"] for c in s["by_cause"]["AP advertised encryption it never describes"]} == {"wpa"}
    assert {c["example"] for c in s["by_cause"]["Testbed lacks the hardware"]} == {"wifi-6e"}
    assert {c["example"] for c in s["by_class"]["artefact"]} == {"radius"}
    assert "wifi-6e" not in {c["example"] for v in s["by_class"].values() for c in v}


def test_summarise_counts_per_area_from_the_feature_label():
    write_result("r", "psk", "5G", "passed", feature="security")
    write_result("r", "vlan", "5G", "failed", message="x", feature="vlan")
    write_result("r", "odd", "5G", "passed", feature="")
    by_area = compare.summarise("r")["by_area"]
    assert by_area["security"]["passed"] == 1
    assert by_area["vlan"]["failed"] == 1
    assert by_area["Uncategorised"]["passed"] == 1


def test_summarise_of_an_empty_run_is_empty_not_an_error():
    s = compare.summarise("nothing")
    assert s["totals"]["total"] == 0
    assert s["by_cause"] == {} and s["by_class"] == {} and s["by_area"] == {}
