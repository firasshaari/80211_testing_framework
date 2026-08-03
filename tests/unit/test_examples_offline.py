"""
Offline checks over the vendored example corpus.

These need no hardware, so they run in CI and catch a bad catalog entry or a
normalizer regression before anyone books bench time. They are also the
executable specification of the cleanup rules the user asked for: regulatory
domain forced to US, no 80 MHz on 2.4 GHz, no out-of-band channels.
"""
from __future__ import annotations

import json

import pytest

from framework.examples import catalog
from framework.examples.inspect import iter_ssids
from framework.examples.loader import ParseReport, iter_example_paths, parse_ucentral_json
from framework.examples.normalize import (
    US_CHANNELS_2G,
    US_CHANNELS_5G,
    US_CHANNELS_5G_DFS,
    normalize_config,
    set_strict,
)

ALL_PATHS = list(iter_example_paths())
CATALOGUED = [pytest.param(e, id=e.name) for e in catalog.EXAMPLES]


def _load_normalized(name: str) -> dict:
    path = next(p for p in ALL_PATHS if p.stem == name)
    raw = parse_ucentral_json(path.read_text(), report=ParseReport())
    config, _ = normalize_config(raw, example=name)
    return config


# ── Corpus integrity ─────────────────────────────────────────────────────────

def test_corpus_is_present():
    assert len(ALL_PATHS) >= 60, (
        f"Only {len(ALL_PATHS)} vendored examples found — run 'make sync-examples'"
    )


@pytest.mark.parametrize("path", ALL_PATHS, ids=lambda p: p.stem)
def test_every_example_parses(path):
    """The tolerant parser handles the whole corpus, including the malformed ones."""
    config = parse_ucentral_json(path.read_text(), report=ParseReport())
    assert isinstance(config, dict) and config, f"{path.name} parsed to nothing"


def test_known_non_strict_files_need_the_tolerant_path():
    """
    Two upstream files are not valid JSON. If upstream fixes them this test
    fails, which is the signal to simplify the loader.
    """
    non_strict = {}
    for path in ALL_PATHS:
        report = ParseReport()
        parse_ucentral_json(path.read_text(), report=report)
        if not report.strict:
            non_strict[path.stem] = report.fixups

    assert "wpa2-radius" in non_strict, "wpa2-radius no longer needs comment stripping"
    assert "gre6" in non_strict, "gre6 no longer has a trailing comma"


# ── Catalog integrity ────────────────────────────────────────────────────────

@pytest.mark.parametrize("example", CATALOGUED)
def test_catalogued_example_exists_on_disk(example):
    assert any(p.stem == example.name for p in ALL_PATHS), (
        f"Catalog references {example.name!r} but no such file is vendored"
    )


def test_catalog_covers_the_runnable_corpus():
    """
    Every vendored example is catalogued, except ones deliberately excluded.

    An uncatalogued example is invisible to the regression sweep, which is the
    kind of gap that goes unnoticed for months.
    """
    on_disk = {p.stem for p in ALL_PATHS}
    catalogued = set(catalog.BY_NAME)
    missing = on_disk - catalogued - EXCLUDED
    assert not missing, (
        f"Vendored but not catalogued: {sorted(missing)}. "
        f"Add them to framework/examples/catalog.py or to EXCLUDED here."
    )


# Examples deliberately kept out of the sweep. Empty today — every vendored
# example is catalogued. Add a name here with the reason if one ever needs to
# be dropped, so the omission is visible rather than silent.
EXCLUDED: set[str] = set()


@pytest.mark.parametrize("example", CATALOGUED)
def test_catalog_mode_matches_config_structure(example):
    """The declared bridge/NAT/config-only mode matches what the config does."""
    config = _load_normalized(example.name)
    roles = {s.role for s in iter_ssids(config) if s.bss_mode == "ap"}

    if example.mode is catalog.Mode.CONFIG_ONLY:
        assert not roles, f"{example.name} is CONFIG_ONLY but declares SSIDs on {roles}"
    elif example.mode is catalog.Mode.BRIDGE:
        assert roles == {"upstream"}, f"{example.name} declared BRIDGE but has roles {roles}"
    elif example.mode is catalog.Mode.NAT:
        assert roles == {"downstream"}, f"{example.name} declared NAT but has roles {roles}"
    elif example.mode is catalog.Mode.MIXED:
        assert len(roles) > 1, f"{example.name} declared MIXED but has roles {roles}"


# ── Normalization rules ──────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ALL_PATHS, ids=lambda p: p.stem)
def test_normalization_forces_us_regulatory_domain(path):
    config = _load_normalized(path.stem)
    countries = {r.get("country") for r in config.get("radios") or []}
    assert countries <= {"US"}, (
        f"{path.stem} still declares {countries - {'US'}} after normalization"
    )


@pytest.mark.parametrize("path", ALL_PATHS, ids=lambda p: p.stem)
def test_normalization_fixes_24ghz_width(path):
    """
    No 2.4 GHz radio may exceed 20 MHz after cleanup.

    This is the rule that matters most: upstream ships 80 MHz on 2.4 GHz in 32
    examples, and the renderer does not reject it — it clamps the width *and
    deletes the pinned channel*, so the radio silently lands on auto.
    """
    config = _load_normalized(path.stem)
    for radio in config.get("radios") or []:
        if radio.get("band") == "2G":
            assert radio.get("channel-width") == 20, (
                f"{path.stem}: 2G radio has width {radio.get('channel-width')}"
            )


@pytest.mark.parametrize("path", ALL_PATHS, ids=lambda p: p.stem)
def test_normalization_fixes_out_of_band_channels(path):
    config = _load_normalized(path.stem)
    for radio in config.get("radios") or []:
        band, channel = radio.get("band"), radio.get("channel")
        if channel is None:
            continue
        if band == "2G":
            assert channel in US_CHANNELS_2G, f"{path.stem}: 2G channel {channel}"
        elif band == "5G":
            assert channel in US_CHANNELS_5G, f"{path.stem}: 5G channel {channel}"
            assert channel not in US_CHANNELS_5G_DFS, (
                f"{path.stem}: 5G channel {channel} is DFS and avoid_dfs is on"
            )


def test_normalization_reports_every_change():
    """A changed config must say what changed — silent edits are the failure mode."""
    path = next(p for p in ALL_PATHS if p.stem == "crypto-psk")
    raw = parse_ucentral_json(path.read_text(), report=ParseReport())
    config, report = normalize_config(raw, example="crypto-psk")

    assert report.modified
    joined = report.summary()
    assert "country" in joined and "channel-width" in joined and "channel" in joined, (
        f"crypto-psk needs country, width and channel fixes but reported: {joined}"
    )
    assert config != raw, "Normalizer reported changes but returned an identical config"


def test_normalizer_does_not_mutate_its_input():
    path = next(p for p in ALL_PATHS if p.stem == "crypto-psk")
    raw = parse_ucentral_json(path.read_text(), report=ParseReport())
    before = json.dumps(raw, sort_keys=True)
    normalize_config(raw, example="crypto-psk")
    assert json.dumps(raw, sort_keys=True) == before, "Normalizer mutated the caller's config"


def test_strict_flag_is_set():
    config = set_strict(_load_normalized("default"))
    assert config["strict"] is True


# ── Coverage the regression sweep claims to provide ──────────────────────────

def test_security_coverage_spans_the_common_protos():
    """The catalog must actually reach every mainstream security method."""
    covered = set()
    for example in catalog.EXAMPLES:
        covered |= set(example.protos)

    for proto in ("none", "psk", "psk2", "psk-mixed", "sae", "sae-mixed",
                  "owe", "owe-transition", "wpa2", "wpa3"):
        assert proto in covered, f"No catalogued example covers {proto!r}"


def test_both_forwarding_modes_are_covered():
    modes = {e.mode for e in catalog.EXAMPLES}
    assert catalog.Mode.BRIDGE in modes and catalog.Mode.NAT in modes


def test_minimal_bench_can_run_a_meaningful_share():
    """A bare AP + one station must reach a substantial part of the catalog."""
    ap_only = catalog.ap_only_examples()
    assert len(ap_only) >= 30, (
        f"Only {len(ap_only)} of {len(catalog.EXAMPLES)} examples run without "
        f"external hardware — the requirement mapping is probably too strict"
    )
