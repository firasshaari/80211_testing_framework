"""
Offline tests for the AP-side logic that hardware bugs taught us.

Every case here corresponds to something that actually broke against a real
DUT, so these are regression tests in the literal sense. They need no hardware.
"""
from __future__ import annotations

import pytest

from framework.ap.ap_client import parse_apply_output, parse_radio_caps
from framework.examples.inspect import iter_ssids
from framework.examples.loader import load_example
from framework.examples.normalize import (
    ensure_management_access,
    normalize_config,
    set_strict,
)

# Shape of a real capabilities.json from an IPQ4019 (Wi-Fi 5) AP.
WIFI5_CAPS = {
    "wifi": {
        "platform/soc/a000000.wifi": {
            "band": ["2G"],
            "htmode": ["HT20", "HT40"],
            "channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        },
        "platform/soc/a800000.wifi": {
            "band": ["5G"],
            "htmode": ["HT20", "HT40", "VHT20", "VHT40", "VHT80"],
            "channels": [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165],
            "dfs_channels": [52, 56, 60, 64],
        },
    }
}


# ── ucentral.uc output classification ────────────────────────────────────────
# ucentral.uc exits 0 whether it succeeded or failed on a custom config path,
# so every one of these must be decided from the text alone.

def test_successful_apply_is_recognised():
    out = "Log messages:\n\nUCI batch output:\nset wireless.radio0.channel='6'\n"
    result = parse_apply_output(out, "")
    assert result.success
    assert "wireless.radio0" in result.uci_batch


def test_strict_mode_rejection_is_recognised():
    """The real failure text seen when strict mode refuses a clamp."""
    out = (
        "Log messages:\n"
        "[W] (In /radios/0) Selected radio does not support requested HT mode HE20, "
        "falling back to HT40\n"
        "Rejecting config due to strict-mode validation\n"
    )
    result = parse_apply_output(out, "")
    assert not result.success
    assert "no UCI batch" in result.reason


def test_schema_error_is_recognised():
    out = "Log messages:\n[E] (In /radios/0/channel) Value must be at most 233\n"
    result = parse_apply_output(out, "")
    assert not result.success
    assert any("channel" in e for e in result.errors)


def test_renderer_fatal_is_recognised():
    result = parse_apply_output("", "Fatal error while generating UCI: boom")
    assert not result.success
    assert any("Fatal error" in e for e in result.errors)


def test_empty_output_is_a_failure_not_a_success():
    assert not parse_apply_output("", "").success


# ── Radio capability parsing ─────────────────────────────────────────────────

def test_radio_caps_parsed_per_band():
    caps = parse_radio_caps(WIFI5_CAPS)
    assert set(caps) == {"2G", "5G"}
    assert caps["2G"].modes == frozenset({"HT"})
    assert caps["2G"].widths_for("HT") == frozenset({20, 40})
    assert caps["5G"].modes == frozenset({"HT", "VHT"})
    assert caps["5G"].widths_for("VHT") == frozenset({20, 40, 80})
    assert 52 in caps["5G"].dfs_channels


def test_radio_caps_tolerates_missing_wifi_section():
    assert parse_radio_caps({}) == {}


# ── Capability-aware normalization ───────────────────────────────────────────

def test_he_is_downgraded_to_what_the_ap_supports():
    """
    85 radio entries in the corpus ask for HE. On a Wi-Fi 5 AP the renderer
    warns and falls back, and strict mode then rejects the whole config — so
    without this clamp almost nothing applies.
    """
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, report = normalize_config(
        load_example("crypto-psk"), example="crypto-psk", radio_caps=caps
    )
    radio = cfg["radios"][0]
    assert radio["band"] == "2G"
    assert radio["channel-mode"] == "HT", "HE should have been downgraded to HT"
    assert radio["channel-width"] in (20, 40)
    assert radio["channel"] in range(1, 12)
    assert any("channel-mode HE -> HT" in c for c in report.changes)


def test_channel_outside_the_radios_own_list_is_replaced():
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, report = normalize_config(
        {"radios": [{"band": "5G", "channel-mode": "VHT",
                     "channel-width": 80, "channel": 173, "country": "US"}]},
        radio_caps=caps,
    )
    allowed = WIFI5_CAPS["wifi"]["platform/soc/a800000.wifi"]["channels"]
    assert cfg["radios"][0]["channel"] in allowed
    assert any("channel 173" in c for c in report.changes)


def test_dfs_channel_avoided_using_the_aps_own_dfs_list():
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, _ = normalize_config(
        {"radios": [{"band": "5G", "channel-mode": "VHT",
                     "channel-width": 80, "channel": 52, "country": "US"}]},
        radio_caps=caps, avoid_dfs=True,
    )
    assert cfg["radios"][0]["channel"] not in (52, 56, 60, 64)


        # ── VLAN substitution ────────────────────────────────────────────────
        # Without this the AP is configured for VLAN 100 while the lab serves
        # something else, and the client silently never gets a lease.

def test_example_vlan_ids_are_remapped_to_the_lab():
    from framework.examples.normalize import collect_vlan_ids, substitute_vlans

    cfg, report = normalize_config(load_example("vlan"), example="vlan")
    assert collect_vlan_ids(cfg) == [100], "upstream example should pin VLAN 100"

    substitute_vlans(cfg, [20, 30], report=report)
    assert collect_vlan_ids(cfg) == [20]
    assert any("100->20" in c for c in report.changes)


def test_multi_psk_vlan_ids_are_remapped_too():
    """The id lives inside a multi-psk key entry, not on the interface."""
    from framework.examples.normalize import collect_vlan_ids, substitute_vlans

    cfg, _ = normalize_config(load_example("multi-psk"), example="multi-psk")
    assert 100 in collect_vlan_ids(cfg)
    substitute_vlans(cfg, [77])
    assert collect_vlan_ids(cfg) == [77]
    keys = [
        k for iface in cfg["interfaces"] for s in iface.get("ssids") or []
        for k in s.get("multi-psk") or []
    ]
    assert any(k.get("vlan-id") == 77 for k in keys)


def test_distinct_vlans_map_to_distinct_lab_vlans():
    from framework.examples.normalize import collect_vlan_ids, substitute_vlans

    cfg = {"interfaces": [
        {"name": "A", "vlan": {"id": 100}},
        {"name": "B", "vlan": {"id": 200}},
    ]}
    substitute_vlans(cfg, [11, 22])
    assert collect_vlan_ids(cfg) == [11, 22]


def test_vlan_substitution_is_a_noop_without_lab_vlans():
    from framework.examples.normalize import collect_vlan_ids, substitute_vlans

    cfg, _ = normalize_config(load_example("vlan"), example="vlan")
    substitute_vlans(cfg, [])
    assert collect_vlan_ids(cfg) == [100]


def test_reusing_too_few_vlans_is_reported():
    """Silently reusing one id would make a segregation test pass vacuously."""
    from framework.examples.normalize import NormalizationReport, substitute_vlans

    report = NormalizationReport(example="synthetic")
    cfg = {"interfaces": [
        {"name": "A", "vlan": {"id": 100}},
        {"name": "B", "vlan": {"id": 200}},
    ]}
    substitute_vlans(cfg, [11], report=report)
    assert any("segmentation between them is not tested" in c for c in report.changes)


def test_radios_for_absent_bands_are_dropped():
    """
    A 6 GHz radio on a dual-band AP makes the renderer warn "Can't find any
    suitable radio phy for band 6G", and strict mode then rejects the whole
    config. That is why every captive-portal example failed on a Wi-Fi 5 AP.
    """
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, report = normalize_config(load_example("captive"), example="captive", radio_caps=caps)
    bands = {r.get("band") for r in cfg.get("radios") or []}
    assert "6G" not in bands
    assert bands <= {"2G", "5G"}
    assert any("dropped radio" in c for c in report.changes)


def test_ssid_only_on_an_absent_band_is_removed():
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, report = normalize_config(load_example("wifi-6e"), example="wifi-6e", radio_caps=caps)
    for ssid in iter_ssids(cfg):
        assert ssid.bands, f"{ssid.name} left with no bands"
        assert set(ssid.bands) & {"2G", "5G"}
    assert any("removed SSID" in c for c in report.changes)


def test_band_dropping_needs_capabilities():
    """Without probed capabilities the config must be left alone."""
    cfg, _ = normalize_config(load_example("captive"), example="captive", radio_caps=None)
    assert "6G" in {r.get("band") for r in cfg.get("radios") or []}


def test_no_radio_caps_means_no_capability_clamping():
    """An unknown AP must not have its config silently rewritten."""
    cfg, _ = normalize_config(
        {"radios": [{"band": "5G", "channel-mode": "HE",
                     "channel-width": 80, "channel": 36, "country": "US"}]},
        radio_caps=None,
    )
    assert cfg["radios"][0]["channel-mode"] == "HE"


# ── Management access: the rule that keeps the AP reachable ──────────────────

@pytest.mark.parametrize(
    "name", ["crypto-psk", "default", "rate-limit", "owe", "qos", "telemetry"]
)
def test_every_applied_config_keeps_ssh_on_the_wan(name):
    """
    71 of 78 upstream interfaces in the corpus omit ssh, which tears down WAN
    management mid-run. Nothing may reach the AP without this guard.
    """
    cfg, _ = normalize_config(load_example(name), example=name)
    ensure_management_access(cfg)

    upstreams = [i for i in cfg["interfaces"] if i.get("role") == "upstream"]
    assert upstreams, f"{name} has no upstream interface"
    for iface in upstreams:
        services = [str(s).lower() for s in iface.get("services", [])]
        assert "ssh" in services, f"{name}: upstream {iface.get('name')} lacks ssh"

    assert cfg["services"]["ssh"]["port"] == 22
    assert cfg["services"]["ssh"]["idle-timeout"] == 0


def test_management_access_is_idempotent():
    cfg, _ = normalize_config(load_example("crypto-psk"), example="crypto-psk")
    ensure_management_access(cfg)
    ensure_management_access(cfg)
    upstream = [i for i in cfg["interfaces"] if i.get("role") == "upstream"][0]
    assert [s.lower() for s in upstream["services"]].count("ssh") == 1


def test_idle_timeout_can_be_omitted():
    cfg, _ = normalize_config(load_example("crypto-psk"), example="crypto-psk")
    ensure_management_access(cfg, idle_timeout=None)
    assert "idle-timeout" not in cfg["services"]["ssh"]
    assert cfg["services"]["ssh"]["port"] == 22


def test_management_access_does_not_disturb_ssids():
    before = {s.name for s in iter_ssids(load_example("crypto-psk"))}
    cfg, _ = normalize_config(load_example("crypto-psk"), example="crypto-psk")
    ensure_management_access(cfg)
    assert {s.name for s in iter_ssids(cfg)} == before


def test_full_pipeline_produces_an_applyable_config():
    """Everything the framework does to an example before it reaches the AP."""
    caps = parse_radio_caps(WIFI5_CAPS)
    cfg, report = normalize_config(
        load_example("crypto-psk"), example="crypto-psk", radio_caps=caps
    )
    ensure_management_access(cfg, report=report)
    set_strict(cfg)

    assert cfg["strict"] is True
    assert cfg["radios"][0]["channel-mode"] == "HT"
    assert cfg["services"]["ssh"]["idle-timeout"] == 0
    assert report.modified and len(report.changes) >= 4
