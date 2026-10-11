"""
Offline tests for ``benchd.docsgen`` — the generated "what each test proves" page.

The page is derived from the catalog and the validator registries so that it
cannot drift from the code. These tests are the other half of that promise:
a check that is registered but not written up fails here, before the console
ever shows "Not documented yet" to someone deciding whether to trust a result.
"""
from __future__ import annotations

from benchd import docsgen
from framework.examples import catalog
from tests.regression import validators


def _registered_check_names() -> set[str]:
    funcs = (set(validators.ALWAYS_PER_SSID) | set(validators.ALWAYS_AP_SIDE)
             | set(validators.PER_SSID.values()) | set(validators.PER_SSID_BY_AREA.values())
             | set(validators.AP_SIDE.values()) | set(validators.AP_SIDE_BY_AREA.values()))
    return {f.__name__ for f in funcs}


# ── check_catalogue() ────────────────────────────────────────────────────────

def test_every_registered_check_appears_exactly_once():
    names = [c["func"] for c in docsgen.check_catalogue()]
    assert sorted(names) == sorted(_registered_check_names())


def test_a_check_registered_in_several_places_lists_each_application():
    """``check_qos_dscp_mapping`` serves both qos examples; one entry, two uses."""
    by_func = {c["func"]: c for c in docsgen.check_catalogue()}
    assert sorted(by_func["check_qos_dscp_mapping"]["applies"]) == ["qos", "qos-class"]
    assert by_func["check_radio_settings"]["applies"] == ["every case with a client"]
    assert by_func["check_regulatory_domain"]["applies"] == ["every case"]


def test_scope_is_per_ssid_or_ap_side_and_per_ssid_sorts_first():
    cat = docsgen.check_catalogue()
    assert {c["scope"] for c in cat} == {"per SSID", "AP side"}
    scopes = [c["scope"] for c in cat]
    assert scopes == sorted(scopes, key=lambda s: s != "per SSID")


def test_every_check_has_a_note_and_the_note_is_the_curated_one():
    for c in docsgen.check_catalogue():
        assert c["documented"], f"{c['func']} has no entry in CHECK_NOTES"
        assert c["note"] == docsgen.CHECK_NOTES[c["func"]]


def test_a_note_for_a_check_that_no_longer_exists_is_stale():
    """
    The reverse guard: a check removed from the registries must also lose its
    note, or the page keeps a paragraph about something that is not run.
    """
    assert set(docsgen.CHECK_NOTES) <= _registered_check_names()


def test_pretty_name_drops_the_prefix_and_underscores():
    assert docsgen._pretty(validators.check_qos_dscp_mapping) == "qos dscp mapping"


# ── validation_rows() ────────────────────────────────────────────────────────

def test_every_catalogued_example_has_a_row_and_nothing_else_does():
    rows = docsgen.validation_rows()
    assert sorted(r["name"] for r in rows) == sorted(e.name for e in catalog.EXAMPLES)


def test_a_check_registered_per_ssid_shows_up_in_that_examples_extra():
    rows = {r["name"]: r for r in docsgen.validation_rows()}
    for name, func in validators.PER_SSID.items():
        assert docsgen._pretty(func) in rows[name]["extra"], name


def test_a_check_registered_ap_side_shows_up_in_that_examples_extra():
    rows = {r["name"]: r for r in docsgen.validation_rows()}
    for name, func in validators.AP_SIDE.items():
        assert docsgen._pretty(func) in rows[name]["extra"], name


def test_area_wide_ap_side_checks_reach_every_example_in_the_area():
    rows = docsgen.validation_rows()
    for area, func in validators.AP_SIDE_BY_AREA.items():
        in_area = [r for r in rows if r["area"] == area]
        assert in_area, f"no catalogued examples in area {area}"
        for r in in_area:
            assert docsgen._pretty(func) in r["extra"], r["name"]


def test_the_radius_check_is_claimed_only_where_an_enterprise_ssid_exists():
    """
    Promising "RADIUS accepted the client" on a PSK-only security example would
    be a claim the suite never tests.
    """
    rows = {r["name"]: r for r in docsgen.validation_rows()}
    radius = docsgen._pretty(validators.check_radius_accepted)
    claimed = {n for n, r in rows.items() if radius in r["extra"]}
    assert "radius" in claimed
    assert "crypto-psk" not in claimed
    for name in claimed:
        assert rows[name]["area"] == "security"
        assert any(p in ("wpa-eap", "wpa2-eap", "wpa3-eap", "wpa3-192-eap", "wpa-mixed-eap",
                         "wpa3-eap-192")
                   for p in rows[name]["protos"]) or rows[name]["protos"], name


def test_rows_describe_the_example_not_just_the_checks():
    rows = {r["name"]: r for r in docsgen.validation_rows()}
    psk = rows["crypto-psk"]
    assert psk["area"] == "security"
    assert psk["area_label"] == "Security"
    assert psk["ssids"] >= 1
    assert "psk" in psk["protos"]
    assert psk["config_only"] is False
    assert psk["extra"] == []            # universals only — nothing special registered


def test_config_only_examples_are_labelled_readably():
    rows = docsgen.validation_rows()
    config_only = [r for r in rows if r["config_only"]]
    assert config_only, "the catalog has config-only examples"
    for r in config_only:
        assert r["mode"] == "config only"


def test_rows_are_sorted_by_area_label_then_name():
    rows = docsgen.validation_rows()
    keys = [(r["area_label"], r["name"]) for r in rows]
    assert keys == sorted(keys)


# ── summary() ────────────────────────────────────────────────────────────────

def test_summary_has_no_undocumented_checks():
    """
    The regression guard. Register a new validator without a CHECK_NOTES entry
    and this is the test that fails.
    """
    assert docsgen.summary()["undocumented"] == []


def test_summary_figures_agree_with_the_rows():
    rows = docsgen.validation_rows()
    s = docsgen.summary()
    assert s["examples"] == len(rows) == len(catalog.EXAMPLES)
    assert s["cases"] == 3 * len(rows)          # one case per band
    assert s["checks"] == len(docsgen.check_catalogue())
    assert s["with_extra"] + s["universals_only"] <= s["examples"]
    assert s["config_only"] == sum(1 for r in rows if r["config_only"])
