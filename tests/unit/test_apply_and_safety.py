"""
Offline tests for the AP-side logic that hardware bugs taught us.

Every case here corresponds to something that actually broke against a real
DUT, so these are regression tests in the literal sense. They need no hardware.
"""
from __future__ import annotations

import json

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
    # The renderer names its reason on a plain line with no [E] prefix. Report
    # that, and the warning behind it — "no UCI batch" tells a reader nothing.
    assert "strict-mode validation" in result.reason
    assert "HE20" in result.reason


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


# ── RADIUS redirection ───────────────────────────────────────────────────────
# The corpus points enterprise SSIDs at 10.0.0.1 and the RADIUS-backed captive
# portal at a public address. Left alone, every one of those cases authenticates
# against a host that does not exist on the bench, and the resulting failure is
# indistinguishable from a real AP defect.

def test_enterprise_radius_is_pointed_at_the_lab_server():
    from framework.examples.normalize import point_radius_at

    cfg, report = normalize_config(
        load_example("wpa2-radius"), example="wpa2-radius"
    )
    auth = cfg["interfaces"][0]["ssids"][0]["radius"]["authentication"]
    assert auth["host"] == "10.0.0.1", "upstream example should pin 10.0.0.1"

    point_radius_at(cfg, "10.0.127.77", "testing123", report=report)
    radius = cfg["interfaces"][0]["ssids"][0]["radius"]
    assert radius["authentication"] == {
        "host": "10.0.127.77", "port": 1812, "secret": "testing123",
    }
    assert radius["accounting"]["host"] == "10.0.127.77"
    assert radius["accounting"]["port"] == 1813
    assert any("10.0.127.77" in c for c in report.changes)


def test_captive_portal_radius_is_pointed_at_the_lab_server():
    """The captive service uses flat auth-server keys, not a radius block."""
    from framework.examples.normalize import point_radius_at

    cfg, _ = normalize_config(
        load_example("captive-radius"), example="captive-radius"
    )
    point_radius_at(cfg, "10.0.127.77", "testing123")
    captive = cfg["services"]["captive"]
    assert captive["auth-server"] == "10.0.127.77"
    assert captive["auth-secret"] == "testing123"
    assert captive["auth-port"] == 1812


def test_radius_redirection_leaves_portals_without_a_server_alone():
    from framework.examples.normalize import point_radius_at

    cfg, _ = normalize_config(load_example("captive-click"), example="captive-click")
    point_radius_at(cfg, "10.0.127.77", "testing123")
    assert cfg["services"]["captive"]["auth-mode"] == "click-to-continue"
    assert "auth-server" not in cfg["services"]["captive"]


# ── reading a portal back out of the config ──────────────────────────────────
# The test needs to know which form to submit, and with what, from the config it
# just applied rather than from a hardcoded table per example.

def test_click_to_continue_portal_is_read_from_the_ssid():
    ssid = iter_ssids(load_example("captive-click"))[0]
    assert ssid.has_captive
    assert ssid.captive["auth-mode"] == "click-to-continue"
    assert ssid.portal_login == ("", "")


def test_credential_portal_exposes_its_first_account():
    ssid = iter_ssids(load_example("captive-credentials"))[0]
    assert ssid.captive["auth-mode"] == "credentials"
    assert ssid.portal_login == ("abc", "def")


def test_an_ssid_without_a_portal_has_none():
    ssid = iter_ssids(load_example("crypto-psk"))[0]
    assert not ssid.has_captive
    assert ssid.portal_login == ("", "")


# ── SSID naming must stay unique ─────────────────────────────────────────────
# Naming purely by proto collapsed two same-proto SSIDs onto one name. Two BSSes
# sharing a name on one radio hung ucentral.uc on the DUT until it was killed
# and cost the AP its management path, failing the following test as well.

def test_same_proto_ssids_do_not_collide():
    from framework.examples.normalize import name_ssids_for_test

    cfg, _ = normalize_config(
        load_example("captive-multiple"), example="captive-multiple"
    )
    name_ssids_for_test(cfg, "ap1", password="12345678")
    names = [s.name for s in iter_ssids(cfg)]
    assert len(names) == len(set(names)), names


def test_a_collision_is_named_for_what_differs():
    """A reader watching a scan should see which portal is which."""
    from framework.examples.normalize import name_ssids_for_test

    cfg, _ = normalize_config(
        load_example("captive-multiple"), example="captive-multiple"
    )
    name_ssids_for_test(cfg, "ap1", password="12345678")
    assert [s.name for s in iter_ssids(cfg)] == ["ap1-psk2", "ap1-psk2-click"]


def test_collisions_fall_back_to_a_counter():
    from framework.examples.normalize import name_ssids_for_test

    cfg = {"interfaces": [{"name": "up", "ssids": [
        {"name": "a", "encryption": {"proto": "psk2"}},
        {"name": "b", "encryption": {"proto": "psk2"}},
        {"name": "c", "encryption": {"proto": "psk2"}},
    ]}]}
    name_ssids_for_test(cfg, "ap1")
    assert [s.name for s in iter_ssids(cfg)] == ["ap1-psk2", "ap1-psk2-2", "ap1-psk2-3"]


def test_disambiguated_names_still_fit_in_32_octets():
    """The suffix is what must survive the trim, not be cut off by it."""
    from framework.examples.normalize import name_ssids_for_test

    cfg = {"interfaces": [{"name": "up", "ssids": [
        {"name": "a", "encryption": {"proto": "psk2"}},
        {"name": "b", "encryption": {"proto": "psk2"}},
    ]}]}
    name_ssids_for_test(cfg, "a-very-long-access-point-name-indeed")
    names = [s.name for s in iter_ssids(cfg)]
    assert all(len(n.encode()) <= 32 for n in names), names
    assert names[1].endswith("-2")
    assert len(set(names)) == 2


def test_no_example_in_the_corpus_produces_duplicate_ssid_names():
    from framework.examples import catalog
    from framework.examples.normalize import name_ssids_for_test

    for example in catalog.EXAMPLES:
        cfg, _ = normalize_config(load_example(example.name), example=example.name)
        name_ssids_for_test(cfg, "spw2ac1200", password="12345678")
        names = [s.name for s in iter_ssids(cfg)]
        assert len(names) == len(set(names)), f"{example.name}: {names}"


# ── choosing what to submit at a portal ──────────────────────────────────────
# The helper reads credentials off the testbed config, and an attribute typo
# there is invisible until a portal case runs against real hardware — which is
# how `testbed_config.radius` (it lives under `external`) survived a live run.

class _RecordingStation:
    """Captures the arguments instead of talking to a portal."""

    def __init__(self, authorised=True):
        self.calls = []
        self._authorised = authorised

    def pass_captive_portal(self, mode, *, username="", password="", **kw):
        from framework.clients.rpi5_station import PortalResult

        self.calls.append((mode, username, password))
        return PortalResult(auth_mode=mode, action="test",
                            authorised=self._authorised)


def _full_lab_config():
    from framework.config import load_testbed_config

    return load_testbed_config("config/profiles/example_full_lab.yaml")


def test_click_portal_needs_no_credentials():
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _pass_the_portal

    ssid = iter_ssids(load_example("captive-click"))[0]
    station = _RecordingStation()
    _pass_the_portal(station, ssid, _full_lab_config())
    assert station.calls == [("click-to-continue", "", "")]


def test_credential_portal_uses_the_accounts_in_the_config():
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _pass_the_portal

    ssid = iter_ssids(load_example("captive-credentials"))[0]
    station = _RecordingStation()
    _pass_the_portal(station, ssid, _full_lab_config())
    assert station.calls == [("credentials", "abc", "def")]


def test_radius_portal_falls_back_to_the_testbed_account():
    """The config declares no accounts — the backend holds them."""
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _pass_the_portal

    ssid = iter_ssids(load_example("captive-radius"))[0]
    testbed = _full_lab_config()
    assert testbed.external.radius, "the full-lab profile should define RADIUS"

    station = _RecordingStation()
    _pass_the_portal(station, ssid, testbed)
    mode, user, pw = station.calls[0]
    assert mode == "radius"
    assert (user, pw) == (testbed.external.radius.identity,
                          testbed.external.radius.password)


def test_a_portal_that_keeps_intercepting_fails_the_test():
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _pass_the_portal

    ssid = iter_ssids(load_example("captive-click"))[0]
    with pytest.raises(AssertionError, match="still intercepting"):
        _pass_the_portal(_RecordingStation(authorised=False), ssid,
                         _full_lab_config())


# ── SSH sessions must survive going idle ─────────────────────────────────────
# A station session sits idle for the 45-60s an AP apply takes and gets reaped,
# then fails the next command with "Socket is closed". That flake broke two
# live cases for reasons that had nothing to do with the AP.

class _FlakyClient:
    """Fails to open a channel once, as a reaped session does."""

    def __init__(self, fail_times=1):
        self.fail_times = fail_times
        self.opened = 0

    def exec_command(self, command, timeout=None, get_pty=False):
        self.opened += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise OSError("Socket is closed")
        return ("stdin", "stdout", "stderr")


def test_a_stale_session_is_reconnected_and_the_command_retried():
    from framework.clients.ssh import SSHSession

    session = SSHSession("host", "user", "pw", label="STA")
    healthy = _FlakyClient(fail_times=0)
    session.close = lambda: None
    session.connect = lambda: healthy

    assert session._open_channel(_FlakyClient(fail_times=1), "uptime", 60) == (
        "stdin", "stdout", "stderr"
    )
    assert healthy.opened == 1, "should have retried on the fresh connection"


def test_a_command_is_never_retried_more_than_once():
    """A session that is genuinely gone must surface, not loop."""
    from framework.clients.ssh import SSHSession

    session = SSHSession("host", "user", "pw", label="STA")
    session.close = lambda: None
    session.connect = lambda: _FlakyClient(fail_times=1)

    with pytest.raises(OSError, match="Socket is closed"):
        session._open_channel(_FlakyClient(fail_times=1), "uptime", 60)


# ── reading the portal's own form ────────────────────────────────────────────
# The config is not a reliable guide to what a portal serves: an SSID declared
# `uam` was seen serving a plain click-to-continue page, and the splash lives on
# the AP's portal address rather than the client's gateway. So the form is read
# off the page, exactly as a browser would. Both fixtures below are the real
# markup this DUT served.

CLICK_PAGE = """<!DOCTYPE html><html><body>
<form action="/hotspot" method="post">
  <input type="hidden" name="action" value="click">
  <input type="checkbox" name="accept_terms" value="clicked">I accept the terms
  <input type="submit" value="Accept Terms of Service">
</form></body></html>"""

CREDENTIALS_PAGE = """<!DOCTYPE html><html><body>
<form action="/hotspot" method="POST">
  <table>
   <tr><td><label>Username:</label></td><td><input type="text" name="username"></td></tr>
   <tr><td><label>Password:</label></td><td><input type="password" name="password"></td></tr>
  </table>
  <input type="hidden" name="action" value="credentials">
  <input type="submit" value="Log in">
</form></body></html>"""


def test_click_form_is_read_and_the_checkbox_ticked():
    from framework.clients.rpi5_station import _fill_login_form, _parse_login_form

    form = _parse_login_form(CLICK_PAGE)
    assert form is not None
    assert (form.action, form.method) == ("/hotspot", "POST")
    assert _fill_login_form(form, "", "") == {
        "action": "click", "accept_terms": "clicked",
    }


def test_the_submit_button_is_not_posted_as_a_field():
    from framework.clients.rpi5_station import _fill_login_form, _parse_login_form

    fields = _fill_login_form(_parse_login_form(CLICK_PAGE), "", "")
    assert not any("Accept Terms" in v for v in fields.values())


def test_credential_form_gets_the_account_and_keeps_hidden_fields():
    from framework.clients.rpi5_station import _fill_login_form, _parse_login_form

    form = _parse_login_form(CREDENTIALS_PAGE)
    assert _fill_login_form(form, "testuser", "testpass") == {
        "username": "testuser", "password": "testpass", "action": "credentials",
    }


def test_a_page_with_no_form_is_reported_rather_than_guessed_at():
    from framework.clients.rpi5_station import _parse_login_form

    assert _parse_login_form("<html><body>Already online.</body></html>") is None


def test_the_form_posts_to_the_portal_the_redirect_led_to():
    """Posting to the client's gateway instead of the portal silently no-ops."""
    from framework.clients.rpi5_station import _resolve

    final = "http://10.10.100.245/hotspot/?redir=connectivitycheck.gstatic.com"
    assert _resolve(final, "/hotspot") == "http://10.10.100.245/hotspot"


def test_curls_final_url_marker_is_split_off_the_body():
    from framework.clients.rpi5_station import _FINAL_URL, _split_final_url

    body, url = _split_final_url(f"<html>hi</html>\n{_FINAL_URL}http://a/b\n")
    assert body.strip() == "<html>hi</html>"
    assert url == "http://a/b"


def test_what_was_posted_is_described_without_leaking_the_password():
    from framework.clients.rpi5_station import PortalResult

    evidence = PortalResult(
        submitted={"username": "testuser", "password": "hunter2"},
    ).evidence()
    assert "hunter2" not in evidence
    assert "username=testuser" in evidence


# ── uploading a config without corrupting it ─────────────────────────────────
# The AP has no SFTP and no base64, so configs go up over the shell. The old
# heredoc chunking appended a newline per chunk; inside a JSON string literal
# that is invalid JSON, and it recurred identically on every retry.

def _simulate_shell_upload(content: str, chunk_bytes: int):
    """Replay what the remote side assembles, chunk by chunk."""
    import shlex as _shlex

    written = []
    for start in range(0, len(content), chunk_bytes):
        chunk = content[start:start + chunk_bytes]
        quoted = _shlex.quote(chunk)
        # printf '%s' writes its argument verbatim; undo the shell quoting the
        # same way a shell would.
        assert quoted.startswith("'") or quoted == chunk
        written.append(chunk)
    return "".join(written)


def test_a_large_config_survives_the_chunked_upload_intact():
    from framework.clients.ssh import SSHSession

    payload = json.dumps(load_example("captive-webroot"), indent=2)
    assert len(payload) > SSHSession._CHUNK_BYTES, "should need several chunks"

    rebuilt = _simulate_shell_upload(payload, SSHSession._CHUNK_BYTES)
    assert rebuilt == payload
    assert json.loads(rebuilt) == json.loads(payload)


def test_the_old_heredoc_chunking_would_have_corrupted_it():
    """Guards the reason for the change, not just the change."""

    payload = json.dumps(load_example("captive-webroot"), indent=2)
    heredoc = "".join(
        payload[i:i + 8192] + "\n" for i in range(0, len(payload), 8192)
    )
    with pytest.raises(json.JSONDecodeError):
        json.loads(heredoc)


def test_no_example_is_corrupted_by_the_upload():
    from framework.clients.ssh import SSHSession
    from framework.examples import catalog

    for example in catalog.EXAMPLES:
        payload = json.dumps(load_example(example.name), indent=2)
        rebuilt = _simulate_shell_upload(payload, SSHSession._CHUNK_BYTES)
        assert rebuilt == payload, example.name


def test_chunks_containing_quotes_are_still_written_verbatim():
    from framework.clients.ssh import SSHSession

    nasty = json.dumps({"note": "it's \"quoted\" 100% \\ backslash", "pad": "x" * 9000})
    rebuilt = _simulate_shell_upload(nasty, SSHSession._CHUNK_BYTES)
    assert json.loads(rebuilt) == json.loads(nasty)


# ── strict-mode rejections must say why ──────────────────────────────────────
# `strict` refuses on a warning, and prints its reason on a plain line with no
# [E] prefix. That line was being discarded, so 19 of the 2 GHz failures in a
# sweep all read "no UCI batch ... config was rejected" and named no cause.

STRICT_REJECTION = """Log messages:
[W] (In /radios/0) Selected radio does not support requested HT mode VHT20, falling back to HT40
Rejecting config due to strict-mode validation
"""


def test_a_strict_rejection_reports_the_warning_that_caused_it():
    result = parse_apply_output(STRICT_REJECTION, "")
    assert not result.success
    assert "strict-mode validation" in result.reason
    assert "does not support requested HT mode VHT20" in result.reason


def test_an_empty_apply_is_still_reported_as_empty():
    """A lost session and a refused config must not read the same."""
    result = parse_apply_output("", "")
    assert not result.success
    assert "no UCI batch" in result.reason


# ── restricting to a band must respect what the radio can do ─────────────────
# Most examples declare no 2.4 GHz radio, so one is synthesised when the case
# targets 2G — after normalize_config has already clamped. Unclamped it asked
# for VHT on an HT-only radio and strict mode rejected the whole config.

def test_a_synthesised_2g_radio_is_clamped_to_what_the_ap_supports():
    from framework.examples.normalize import restrict_to_band

    caps = parse_radio_caps(WIFI5_CAPS)          # 2G is HT-only on this DUT
    cfg, _ = normalize_config(load_example("lldp"), example="lldp", radio_caps=caps)
    assert not [r for r in cfg.get("radios") or [] if r.get("band") == "2G"], (
        "this example should declare no 2.4 GHz radio"
    )

    restrict_to_band(cfg, "2G", radio_caps=caps)
    radio = cfg["radios"][0]
    assert radio["channel-mode"] == "HT"
    assert radio["channel-width"] == 20
    assert radio["channel"] == 1


def test_restricting_without_caps_is_unchanged():
    """Callers with no capability data must still get a usable config."""
    from framework.examples.normalize import restrict_to_band

    cfg, _ = normalize_config(load_example("lldp"), example="lldp")
    restrict_to_band(cfg, "2G")
    assert cfg["radios"][0]["band"] == "2G"


def test_no_example_asks_a_wifi5_ap_for_a_mode_it_lacks():
    """The whole corpus, on every band this DUT has, after the full pipeline."""
    from framework.examples import catalog
    from framework.examples.normalize import restrict_to_band

    caps = parse_radio_caps(WIFI5_CAPS)
    allowed = {"2G": {"HT"}, "5G": {"HT", "VHT"}}
    for example in catalog.EXAMPLES:
        for band, modes in allowed.items():
            cfg, _ = normalize_config(
                load_example(example.name), example=example.name, radio_caps=caps
            )
            restrict_to_band(cfg, band, radio_caps=caps)
            for radio in cfg["radios"]:
                assert radio.get("channel-mode") in modes, (
                    f"{example.name} on {band}: {radio.get('channel-mode')}"
                )


# ── bridged SSIDs must never land on the management interface ────────────────
# Bridge-forcing prefers a tagged upstream, but an example whose SSIDs all start
# on a downstream interface has no tagged twin to prefer, so they were bridged
# onto the untagged WAN — the interface the AP is managed over. Clients then get
# an address on the management subnet, which is how the harness locked itself
# out of its own station.

def _bridge_pipeline(name: str, vlan_id: int = 1000):
    from framework.examples.normalize import assign_bridge_vlan, force_forwarding_mode

    cfg, report = normalize_config(load_example(name), example=name)
    assign_bridge_vlan(cfg, vlan_id, report=report)
    force_forwarding_mode(cfg, "bridge", report=report)
    assign_bridge_vlan(cfg, vlan_id, report=report)
    ensure_management_access(cfg, report=report)
    return cfg


def _untagged_upstreams(cfg):
    return [
        i for i in cfg["interfaces"]
        if i.get("role") == "upstream" and not i.get("vlan")
    ]


def test_an_ssid_starting_downstream_is_bridged_onto_the_test_vlan():
    cfg = _bridge_pipeline("maverick")
    for iface in _untagged_upstreams(cfg):
        assert not iface.get("ssids"), (
            f"{iface['name']} is the management interface and carries "
            f"{[s['name'] for s in iface['ssids']]}"
        )
    tagged = [i for i in cfg["interfaces"]
              if i.get("role") == "upstream" and i.get("vlan")]
    assert tagged and tagged[0]["vlan"]["id"] == 1000
    assert tagged[0]["ssids"]


def test_the_second_pass_does_not_build_a_duplicate_vlan_interface():
    cfg = _bridge_pipeline("vlan")
    tagged = [i for i in cfg["interfaces"]
              if i.get("role") == "upstream" and i.get("vlan")]
    ids = [i["vlan"]["id"] for i in tagged]
    assert len(ids) == len(set(ids)), ids
    names = [i["name"] for i in cfg["interfaces"]]
    assert len(names) == len(set(names)), names


def test_the_untagged_upstream_keeps_ssh_for_management():
    cfg = _bridge_pipeline("maverick")
    upstream = _untagged_upstreams(cfg)[0]
    assert "ssh" in [s.lower() for s in upstream.get("services") or []]


def test_dynamically_assigned_vlans_stay_on_the_untagged_upstream():
    """RADIUS builds the VLAN interface per client; pre-tagging defeats that."""
    cfg = _bridge_pipeline("wpa2-radius")
    untagged = _untagged_upstreams(cfg)
    dynamic = [s["name"] for i in untagged for s in i.get("ssids") or []]
    assert dynamic, "the RADIUS SSID should have been left untagged"


def test_no_example_bridges_clients_onto_the_management_interface():
    from framework.examples import catalog

    offenders = []
    for example in catalog.EXAMPLES:
        cfg = _bridge_pipeline(example.name)
        for iface in _untagged_upstreams(cfg):
            for ssid in iface.get("ssids") or []:
                # Dynamic-VLAN SSIDs belong here: the AP creates their VLAN
                # interface per client from what the backend returns.
                from framework.examples.normalize import _has_dynamic_vlan
                if not _has_dynamic_vlan(ssid):
                    offenders.append(f"{example.name}:{ssid.get('name')}")
    assert not offenders, offenders


# ── roaming needs a key to hand over ─────────────────────────────────────────
# `maverick` puts 802.11r on an open SSID. There is no pairwise key to hand
# between APs, and the firmware refuses the whole config with "Roaming requires
# wpa2 or later" — an inconsistency in the example, like 80 MHz on 2.4 GHz.

def test_roaming_is_dropped_from_an_open_ssid():
    cfg, report = normalize_config(load_example("maverick"), example="maverick")
    open_ssids = [s for s in iter_ssids(cfg) if s.proto in ("none", "open")]
    assert open_ssids, "maverick should have an open SSID"
    raw = [s for i in cfg["interfaces"] for s in i.get("ssids") or []]
    assert not any(s.get("roaming") for s in raw)
    assert any("dropped roaming" in c for c in report.changes)


def test_roaming_is_kept_where_the_encryption_supports_it():
    cfg, _ = normalize_config(load_example("captive"), example="captive")
    raw = {
        s.get("name"): s for i in cfg["interfaces"] for s in i.get("ssids") or []
    }
    wpa2 = [s for s in raw.values()
            if (s.get("encryption") or {}).get("proto") == "psk2"]
    assert any(s.get("roaming") for s in wpa2), (
        "a WPA2 SSID's roaming block must survive"
    )


def test_no_example_asks_for_roaming_it_cannot_have():
    from framework.examples import catalog
    from framework.examples.normalize import _PRE_WPA2_PROTOS

    for example in catalog.EXAMPLES:
        cfg, _ = normalize_config(load_example(example.name), example=example.name)
        for ssid in iter_ssids(cfg):
            raw = [s for i in cfg["interfaces"] for s in i.get("ssids") or []
                   if s.get("name") == ssid.name]
            if ssid.proto in _PRE_WPA2_PROTOS:
                assert not any(s.get("roaming") for s in raw), (
                    f"{example.name}: {ssid.name} ({ssid.proto})"
                )


# ── "the AP says it is up" is not "it is on the air" ─────────────────────────
# hostapd answers `status` for an interface it configured even when the BSS
# never started. A WPA1/TKIP SSID does exactly that on this DUT — TKIP cannot
# coexist with the HT rates the radio runs — so the AP-side check passed, every
# station scan missed it, and the run failed later with "did not associate",
# blaming the client for an SSID that was never there.

class _ScriptedStation:
    """Returns a canned scan per call, to exercise the retry accumulation."""

    def __init__(self, rounds):
        self.rounds = list(rounds)
        self.scans = 0

    def scan(self):
        from framework.clients.rpi5_station import ScanResult

        names = self.rounds[min(self.scans, len(self.rounds) - 1)]
        self.scans += 1
        return [ScanResult(ssid=n, bssid="", freq_mhz=2412, signal_dbm=-40)
                for n in names]


def _visible(station, expected, **kw):
    from framework.clients.rpi5_station import Station

    return Station.visible_ssids(station, expected, delay=0, **kw)


def test_an_ssid_never_beaconing_is_reported_missing():
    station = _ScriptedStation([["ap-psk2", "ap-sae"]])
    seen = _visible(station, {"ap-psk2", "ap-sae", "ap-psk"})
    assert seen == {"ap-psk2", "ap-sae"}
    assert "ap-psk" not in seen


def test_a_bss_seen_in_any_round_counts_as_present():
    """A single scan often misses a freshly started BSS."""
    station = _ScriptedStation([[], ["ap-psk2"], ["ap-sae"]])
    assert _visible(station, {"ap-psk2", "ap-sae"}) == {"ap-psk2", "ap-sae"}


def test_scanning_stops_as_soon_as_everything_is_seen():
    station = _ScriptedStation([["ap-psk2"]])
    _visible(station, {"ap-psk2"}, retries=4)
    assert station.scans == 1


def test_a_failing_scan_does_not_abort_the_check():
    from framework.clients.ssh import SSHError

    class _Flaky(_ScriptedStation):
        def scan(self):
            if self.scans == 0:
                self.scans += 1
                raise SSHError("Socket is closed")
            return super().scan()

    assert _visible(_Flaky([["ap-psk2"]]), {"ap-psk2"}) == {"ap-psk2"}


# ── example values no schema accepts ─────────────────────────────────────────
# `fingerprint-raw` asks for mode "raw-data"; the schema allows only
# polled|final|raw, so the config is refused and the feature is never exercised.

def test_the_fingerprint_mode_typo_is_corrected():
    cfg, report = normalize_config(
        load_example("fingerprint-raw"), example="fingerprint-raw"
    )
    assert cfg["services"]["fingerprint"]["mode"] == "raw"
    assert any("raw-data" in c for c in report.changes)


def test_a_valid_fingerprint_mode_is_left_alone():
    cfg, report = normalize_config(
        load_example("fingerprint-final-always"), example="fingerprint-final-always"
    )
    assert cfg["services"]["fingerprint"]["mode"] == "final"
    assert not any("fingerprint" in c for c in report.changes)


def test_the_fixup_does_not_crash_on_configs_without_that_path():
    cfg, _ = normalize_config(load_example("crypto-psk"), example="crypto-psk")
    assert "fingerprint" not in (cfg.get("services") or {})


def test_every_example_renders_a_schema_valid_fingerprint_mode():
    from framework.examples import catalog

    valid = {"polled", "final", "raw"}
    for example in catalog.EXAMPLES:
        cfg, _ = normalize_config(load_example(example.name), example=example.name)
        mode = ((cfg.get("services") or {}).get("fingerprint") or {}).get("mode")
        if mode is not None:
            assert mode in valid, f"{example.name}: {mode}"


# ── a hang is not a rejection ────────────────────────────────────────────────
# Both surfaced as "no UCI batch ... config was rejected", which sent real
# renderer hangs to the wrong triage bucket and hid that the AP never answered.

def test_a_hang_is_reported_as_a_hang_not_a_rejection():
    result = parse_apply_output(
        "", "ucentral.uc hung and was killed after 180s (no apply.rc written)"
    )
    assert not result.success
    assert result.hung
    assert "hung" in result.reason
    assert "rejected" not in result.reason


def test_a_real_rejection_is_still_a_rejection():
    result = parse_apply_output("Log messages:\n[E] (In /radios/0) bad\n", "")
    assert not result.hung
    assert "rejected" not in result.reason or "[E]" not in result.reason
    assert any("bad" in e for e in result.errors)


# ── "did not associate" must say why ─────────────────────────────────────────
# The WPA1 SSID in crypto-psk is on the air and still never selected: it offers
# TKIP only, and 802.11n prohibits TKIP with HT rates, so the client refuses it.
# The supplicant log shows only "skip - SSID mismatch" for every *other* BSS,
# which reads as though the network were missing.

class _ScanStation:
    def __init__(self, results):
        self._results = results

    def scan(self):
        return self._results


def _detail(results, ssid):
    from framework.clients.rpi5_station import Station

    return Station._association_failure_detail(_ScanStation(results), ssid)


def _bss(ssid, flags=""):
    from framework.clients.rpi5_station import ScanResult

    return ScanResult(ssid=ssid, bssid="00:11:22:33:44:55", freq_mhz=2412,
                      signal_dbm=-45, flags=flags)


def test_a_tkip_only_bss_advertising_ht_is_explained():
    """TKIP-only *with HT* is the prohibited combination, not TKIP alone."""
    detail = _detail([_bss("ap-psk", "WPA,TKIP,group TKIP,HT")], "ap-psk")
    assert "IS on the air" in detail
    assert "802.11n prohibits TKIP" in detail


def test_a_tkip_bss_without_ht_is_not_blamed_on_802_11n():
    detail = _detail([_bss("ap-psk", "WPA,TKIP,group TKIP")], "ap-psk")
    assert "IS on the air" in detail
    assert "prohibits" not in detail


def test_a_bss_offering_ccmp_gets_no_tkip_note():
    detail = _detail([_bss("ap-psk2", "WPA2-PSK-CCMP-TKIP")], "ap-psk2")
    assert "IS on the air" in detail
    assert "prohibits" not in detail


def test_an_ssid_absent_from_the_scan_says_so():
    detail = _detail([_bss("other")], "ap-psk")
    assert "was not in the scan at all" in detail
    assert "other" in detail


def test_an_empty_scan_points_at_the_radio():
    assert "No SSIDs visible at all" in _detail([], "ap-psk")


# ── OWE transition needs protected management frames ─────────────────────────
# The AP publishes an open BSS carrying the transition element plus the real
# OWE BSS ("<ssid>-OWE"). wpa_supplicant follows the element to the OWE BSS,
# and OWE mandates PMF — asking for `ieee80211w=1` next to `key_mgmt=NONE`
# offered a combination that BSS cannot accept.

def test_owe_transition_requires_pmf():
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block("ap-owe", "owe-transition")
    assert "key_mgmt=OWE" in block
    assert "ieee80211w=2" in block
    assert "key_mgmt=OWE NONE" not in block


def test_plain_owe_is_unchanged():
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block("ap-owe", "owe")
    assert "key_mgmt=OWE" in block
    assert "ieee80211w=2" in block


def test_open_networks_still_take_no_pmf():
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block("ap-open", "none")
    assert "key_mgmt=NONE" in block
    assert "ieee80211w" not in block


# ── a splash page with no usable form must still be cleared ──────────────────
# `captive-webroot` serves a custom splash whose only control is the submit
# button. Requiring at least one named input threw the page away and left the
# client sitting behind a portal it could have cleared in one POST.

WEBROOT_PAGE = """<!DOCTYPE html><html><body>
<form action="/hotspot" method="post">
  <p>Press to continue.</p>
  <input type="submit" value="Continue">
</form></body></html>"""


def test_a_form_whose_only_control_is_submit_is_still_a_form():
    from framework.clients.rpi5_station import _parse_login_form

    form = _parse_login_form(WEBROOT_PAGE)
    assert form is not None
    assert form.action == "/hotspot"
    assert form.fields == {}


def test_a_page_with_no_form_at_all_yields_none():
    from framework.clients.rpi5_station import _parse_login_form

    assert _parse_login_form("<html><body>Online already.</body></html>") is None


def test_click_defaults_are_used_when_the_page_gives_nothing():
    from framework.clients.rpi5_station import _default_fields

    assert _default_fields("click-to-continue", "", "") == {
        "action": "click", "accept_terms": "clicked",
    }


def test_credential_defaults_carry_the_account():
    from framework.clients.rpi5_station import _default_fields

    for mode in ("credentials", "radius", "uam"):
        assert _default_fields(mode, "testuser", "testpass") == {
            "action": "credentials", "username": "testuser", "password": "testpass",
        }


def test_captive_multiple_declares_it_needs_an_external_backend():
    """Its UAM half redirects to a commercial hosted portal."""
    from framework.examples import catalog
    from framework.examples.catalog import Requirement

    assert Requirement.CAPTIVE_BACKEND in catalog.get("captive-multiple").requires


# ── the scan must record ciphers, not just "protected" ───────────────────────
# Recording only "WPA"/"RSN" meant the TKIP-only-with-HT diagnosis could never
# fire; every failure said "capabilities: (none advertised)".

IW_SCAN_TKIP = """BSS 28:76:10:28:83:14(on wlan0)
\tfreq: 2412
\tsignal: -40.00 dBm
\tSSID: ap-psk
\tWPA:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: TKIP
\tHT capabilities:
\t\tCapabilities: 0x9ef
"""


def test_the_scan_records_the_ciphers_a_bss_offers():
    from framework.clients.rpi5_station import _parse_iw_scan

    results = _parse_iw_scan(IW_SCAN_TKIP)
    assert len(results) == 1
    flags = results[0].flags
    assert "TKIP" in flags
    assert "group TKIP" in flags
    assert "HT" in flags


def test_a_tkip_only_ht_bss_from_a_real_scan_is_diagnosed():
    from framework.clients.rpi5_station import Station, _parse_iw_scan

    station = _ScanStation(_parse_iw_scan(IW_SCAN_TKIP))
    detail = Station._association_failure_detail(station, "ap-psk")
    assert "802.11n prohibits TKIP" in detail


# ── the portal form must never be posted to the probe host ───────────────────
# When the probe gets no answer, curl's url_effective is just the URL we asked
# for, and the form went to connectivitycheck.gstatic.com instead of the portal.

def test_a_probe_that_never_redirected_is_not_treated_as_the_portal():
    from framework.clients.rpi5_station import Station, _redirected

    assert not _redirected(Station.PORTAL_PROBE)
    assert not _redirected("")


def test_a_real_portal_redirect_is_recognised():
    from framework.clients.rpi5_station import _redirected

    assert _redirected("http://10.10.100.245/hotspot/?redir=x")


# ── a config that vanished is not a config that was refused ──────────────────

def test_an_unreadable_config_file_is_reported_as_such():
    out = (
        "Type error: left-hand side is not a function\n"
        "In /usr/share/ucentral/ucentral.uc, line 12, byte 42:\n"
        "  `let inputjson = json(inputfile.read(\"all\"));`\n"
    )
    result = parse_apply_output("", out)
    assert not result.success
    assert "could not read the config file" in result.reason
    assert "refused" in result.reason


# ── encryption advertised but never described ────────────────────────────────
# The real capture from this DUT for the WPA1 SSID: Privacy is set in the
# capability field, and the information elements carry no WPA and no RSN block.
# wpa_supplicant has nothing to match its network block against, so it skips
# the BSS — correct client behaviour, and an AP-side fault.

IW_SCAN_PRIVACY_NO_IE = """BSS 2a:76:10:28:83:14(on wlan0)
\tfreq: 2412.0
\tcapability: ESS Privacy ShortPreamble ShortSlotTime RadioMeasure (0x1431)
\tsignal: -39.00 dBm
\tSSID: spw2ac1200-psk
\tSupported rates: 6.0* 9.0 12.0* 18.0 24.0* 36.0 48.0 54.0
\tDS Parameter set: channel 1
\tERP: <no flags>
"""


def test_privacy_without_a_wpa_or_rsn_element_is_flagged_as_an_ap_fault():
    from framework.clients.rpi5_station import Station, _parse_iw_scan

    results = _parse_iw_scan(IW_SCAN_PRIVACY_NO_IE)
    assert results[0].flags == "Privacy"

    detail = Station._association_failure_detail(
        _ScanStation(results), "spw2ac1200-psk"
    )
    assert "IS on the air" in detail
    assert "neither a WPA nor an RSN information element" in detail
    assert "AP-side fault" in detail


def test_a_properly_advertised_wpa2_bss_gets_no_such_note():
    from framework.clients.rpi5_station import Station, _parse_iw_scan

    page = IW_SCAN_PRIVACY_NO_IE.replace(
        "\tERP: <no flags>\n",
        "\tRSN:\t * Version: 1\n\t\t * Pairwise ciphers: CCMP\n",
    )
    results = _parse_iw_scan(page)
    assert "RSN" in results[0].flags
    detail = Station._association_failure_detail(
        _ScanStation(results), "spw2ac1200-psk"
    )
    assert "AP-side fault" not in detail


def test_an_open_bss_is_not_mistaken_for_broken_encryption():
    """No Privacy bit means no encryption was ever claimed."""
    from framework.clients.rpi5_station import Station, _parse_iw_scan

    page = IW_SCAN_PRIVACY_NO_IE.replace(
        "capability: ESS Privacy ShortPreamble", "capability: ESS ShortPreamble"
    )
    detail = Station._association_failure_detail(
        _ScanStation(_parse_iw_scan(page)), "spw2ac1200-psk"
    )
    assert "AP-side fault" not in detail


# ── a scan must survive its own session being reaped ─────────────────────────
# A scan takes tens of seconds; the session can be collected underneath it, and
# that surfaced as an SSH error while diagnosing an unrelated failure.

class _FlakyScanSSH:
    def __init__(self, fail_times, output):
        self.fail_times = fail_times
        self.output = output
        self.closed = 0

    def run(self, command, **kw):
        from framework.clients.rpi5_station import SSHError

        if "scan" in command and self.fail_times > 0:
            self.fail_times -= 1
            raise SSHError("command transport failed: iw dev wlan0 scan")

        class R:
            stdout = self.output
        return R()

    def close(self):
        self.closed += 1


def _station_with(ssh):
    from framework.clients.rpi5_station import Station

    station = Station.__new__(Station)
    station.ssh = ssh
    station.iface = "wlan0"
    return station


def test_a_scan_is_retried_once_after_a_dead_session():
    station = _station_with(_FlakyScanSSH(1, IW_SCAN_PRIVACY_NO_IE))
    results = station.scan()
    assert [r.ssid for r in results] == ["spw2ac1200-psk"]
    assert station.ssh.closed == 1


def test_a_scan_that_keeps_failing_surfaces_the_error():
    from framework.clients.rpi5_station import SSHError

    station = _station_with(_FlakyScanSSH(5, ""))
    with pytest.raises(SSHError):
        station.scan()


# ── teardown must not destroy the result it is cleaning up after ─────────────
# disconnect() runs in a `finally` after every SSID. A dead session there
# replaced a real "5 of 6 SSIDs worked" result with an SSH error from
# `ip addr flush`, losing the finding the test had just produced.

class _DyingSSH:
    def __init__(self, fail_all=False):
        self.fail_all = fail_all
        self.ran = []
        self.closed = 0

    def run(self, command, **kw):
        from framework.clients.rpi5_station import SSHError

        if self.fail_all or (not self.ran and "pkill" in command):
            self.ran.append(command)
            raise SSHError("Socket is closed")
        self.ran.append(command)

        class R:
            stdout = ""
        return R()

    def close(self):
        self.closed += 1


def test_teardown_reconnects_and_finishes_after_a_dead_session():
    from framework.clients.rpi5_station import Station

    station = Station.__new__(Station)
    station.ssh = _DyingSSH()
    station.iface = "wlan0"
    station._current = object()

    station.disconnect()
    assert station._current is None
    assert station.ssh.closed == 1
    assert any("ip addr flush" in c for c in station.ssh.ran)


def test_a_teardown_that_cannot_recover_does_not_raise():
    from framework.clients.rpi5_station import Station

    station = Station.__new__(Station)
    station.ssh = _DyingSSH(fail_all=True)
    station.iface = "wlan0"
    station._current = object()

    station.disconnect()          # must not raise
    assert station._current is None


def test_the_failure_summary_keeps_the_diagnosis():
    """A 160-character cut removed the part explaining why a BSS was skipped."""
    from tests.regression.test_examples import _brief

    msg = (
        "Did not associate to 'ap-psk' within 45s (last wpa_state=SCANNING). "
        "'ap-psk' IS on the air (1 BSS, capabilities: Privacy) but was never "
        "selected — the beacon sets the Privacy bit but carries neither a WPA "
        "nor an RSN information element, so there is nothing for a client to "
        "negotiate against."
    )
    brief = _brief(RuntimeError(msg))
    assert "neither a WPA nor an RSN" in brief


# ── a DHCP attempt that cannot complete is a result, not a crash ─────────────
# Releasing a stale lease occasionally outlasts its own command timeout. Letting
# that escape aborted the whole case on whichever SSID it landed on, discarding
# the SSIDs after it — "this one got no lease" is a result the caller already
# records.

def test_a_dhcp_transport_failure_becomes_no_lease():
    from framework.clients.rpi5_station import SSHError, Station

    class _SSH:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    station = Station.__new__(Station)
    station.ssh = _SSH()
    station.iface = "wlan0"
    station._request_dhcp = lambda t: (_ for _ in ()).throw(SSHError("PipeTimeout"))

    assert station.request_dhcp() == ""
    assert station.ssh.closed == 1


def test_a_successful_lease_is_returned_unchanged():
    from framework.clients.rpi5_station import Station

    station = Station.__new__(Station)
    station.iface = "wlan0"
    station._request_dhcp = lambda t: "10.10.100.184"
    assert station.request_dhcp() == "10.10.100.184"


# ── the portal probe must not be defeated by DNS, or by silence ──────────────
# A portal that blocks DNS before authentication kills a name-based probe before
# it can be redirected: the splash comes back empty, which read as "the portal
# served nothing" when it means "the request never left". And an empty reply was
# being treated as "no portal", which is the one wrong answer this check must
# not give — it turns a dead probe into a pass.

class _ProbeSSH:
    def __init__(self, codes):
        self.codes = dict(codes)
        self.asked = []

    def run(self, command, **kw):
        url = next((w for w in command.split() if w.startswith("http")), "")
        url = url.strip("'\"")
        self.asked.append(url)

        class R:
            stdout = self.codes.get(url, "")
        return R()


def _presence(codes):
    from framework.clients.rpi5_station import Station

    station = Station.__new__(Station)
    station.ssh = _ProbeSSH(codes)
    station.iface = "wlan0"
    station.current_ip = lambda: "10.10.100.184"
    return Station.captive_portal_present(station), station.ssh


def test_a_204_from_either_probe_means_no_portal():
    from framework.clients.rpi5_station import Station

    present, _ = _presence({Station.PORTAL_PROBE: "204"})
    assert present is False


def test_a_named_probe_killed_by_dns_falls_back_to_the_ip_probe():
    from framework.clients.rpi5_station import Station

    present, ssh = _presence({Station.PORTAL_PROBE: "", Station.PORTAL_PROBE_IP: "204"})
    assert present is False
    assert Station.PORTAL_PROBE_IP in ssh.asked, "the IP probe must be tried"


def test_silence_from_every_probe_counts_as_still_intercepted():
    present, ssh = _presence({})
    assert present is True
    assert len(ssh.asked) == 2, "both probes must be tried before concluding"


def test_a_redirect_still_reads_as_a_portal():
    from framework.clients.rpi5_station import Station

    present, _ = _presence({Station.PORTAL_PROBE: "302"})
    assert present is True


# ── how long a BSS gets to come up belongs to the AP, not the test ───────────
# 60s was hard-coded in the test. A MediaTek MT7621 occasionally needs longer,
# and a healthy SSID was reported as "configured but not broadcasting".

def test_ssid_up_timeout_is_configurable_and_generous_by_default():
    from framework.config import Settings

    assert Settings().ssid_up_timeout >= 90
    assert Settings(ssid_up_timeout=200).ssid_up_timeout == 200


def test_the_ssid_wait_uses_the_configured_timeout():
    import inspect

    from tests.regression import test_examples

    src = inspect.getsource(test_examples.test_example)
    assert "settings.ssid_up_timeout" in src
    assert "wait_for_ssids(expected, timeout=60)" not in src


# ── EAP-TLS: a certificate identity for the enterprise SSIDs ─────────────────
# Enterprise SSIDs cannot be joined with a passphrase, so without a certificate
# identity every one of them was skipped. The bench issues its own chain.

CERTS = {
    "ca_cert": "/etc/regression-pki/ca.pem",
    "client_cert": "/etc/regression-pki/client.pem",
    "private_key": "/etc/regression-pki/client.key",
}


def test_eap_tls_block_carries_the_certificate_chain():
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block(
        "ap-wpa2", "wpa2", eap_method="TLS", identity="testuser",
        certificates=CERTS,
    )
    assert "key_mgmt=WPA-EAP" in block
    assert "eap=TLS" in block
    assert 'ca_cert="/etc/regression-pki/ca.pem"' in block
    assert 'client_cert="/etc/regression-pki/client.pem"' in block
    assert 'private_key="/etc/regression-pki/client.key"' in block
    # No password anywhere: possession of the key is the proof.
    assert "password=" not in block


def test_eap_tls_without_certificates_says_what_to_do():
    from framework.clients.rpi5_station import StationError, build_network_block

    with pytest.raises(StationError, match="make-pki.sh"):
        build_network_block("ap-wpa2", "wpa2", eap_method="TLS", identity="u")


def test_peap_still_uses_a_password_identity():
    """The password accounts must keep working alongside EAP-TLS."""
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block(
        "ap-wpa2", "wpa2", eap_method="PEAP", identity="testuser",
        eap_password="testpass",
    )
    assert "eap=PEAP" in block
    assert 'password="testpass"' in block
    assert 'phase2="auth=MSCHAPV2"' in block
    assert "client_cert" not in block


def test_a_key_password_is_included_when_the_bundle_has_one():
    from framework.clients.rpi5_station import build_network_block

    block = build_network_block(
        "ap-wpa2", "wpa2", eap_method="TLS", identity="testuser",
        certificates={**CERTS, "private_key_passwd": "whatever"},
    )
    assert 'private_key_passwd="whatever"' in block


# ── VHT does not exist on 2.4 GHz ────────────────────────────────────────────
# The Edgecore EAP102 advertises VHT on 2G in capabilities.json and then runs
# HT20 regardless. The renderer emits no warning, so `strict` does not catch it
# and the case silently stops testing the mode it asked for.

def test_vht_on_24ghz_is_downgraded_to_ht():
    cfg, report = normalize_config(
        {"radios": [{"band": "2G", "channel-mode": "VHT", "channel-width": 20,
                     "channel": 1, "country": "US"}]}
    )
    assert cfg["radios"][0]["channel-mode"] == "HT"
    assert any("802.11ac is not defined on 2.4 GHz" in c for c in report.changes)


def test_he_on_24ghz_is_left_alone():
    """802.11ax is genuinely valid on 2.4 GHz."""
    cfg, _ = normalize_config(
        {"radios": [{"band": "2G", "channel-mode": "HE", "channel-width": 20,
                     "channel": 1, "country": "US"}]}
    )
    assert cfg["radios"][0]["channel-mode"] == "HE"


def test_vht_on_5ghz_is_untouched():
    cfg, _ = normalize_config(
        {"radios": [{"band": "5G", "channel-mode": "VHT", "channel-width": 80,
                     "channel": 36, "country": "US"}]}
    )
    assert cfg["radios"][0]["channel-mode"] == "VHT"


def test_a_synthesised_2g_radio_never_asks_for_vht():
    from framework.examples.normalize import restrict_to_band

    cfg, _ = normalize_config(load_example("lldp"), example="lldp")
    restrict_to_band(cfg, "2G")
    assert cfg["radios"][0]["channel-mode"] != "VHT"


def test_no_example_asks_for_vht_on_24ghz():
    from framework.examples import catalog
    from framework.examples.normalize import restrict_to_band

    for example in catalog.EXAMPLES:
        cfg, _ = normalize_config(load_example(example.name), example=example.name)
        restrict_to_band(cfg, "2G")
        for radio in cfg["radios"]:
            if radio.get("band") == "2G":
                assert radio.get("channel-mode") != "VHT", example.name
