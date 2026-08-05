"""
Offline tests for the feature checks.

Each check exists because "a client joined and passed traffic" would have passed
while the feature under test did nothing. These tests pin both directions: the
working case is accepted, and the specific broken case the check was written for
is caught.
"""
from __future__ import annotations

import pytest

from framework.clients.rpi5_station import Association, PingResult
from framework.examples import catalog
from tests.regression import validators


class _FakeSSH:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.ran = []

    def run(self, command, **kw):
        self.ran.append(command)
        # Process checks are written as grep -c '[n]tpd' so the grep does not
        # match itself. Strip the brackets before matching, or these fakes
        # answer nothing and every service check looks broken.
        plain = command.replace("[", "").replace("]", "")
        out = ""
        for needle, value in self.responses.items():
            if needle in plain:
                out = value
                break

        class R:
            stdout = out
        return R()


class _FakeAP:
    def __init__(self, uci=None, responses=None):
        self._uci = uci or {}
        self.ssh = _FakeSSH(responses)

    def uci_show(self, package):
        return self._uci.get(package, "")


class _FakeStation:
    def __init__(self, mbps=0.0, ipv6="", pings=None, has_v6=True):
        self._mbps = mbps
        self._ipv6 = ipv6
        self._pings = pings or {}
        self._has_v6 = has_v6

    def lab_has_ipv6(self):
        return self._has_v6

    def measure_download_mbps(self, **kw):
        return self._mbps

    def global_ipv6(self):
        return self._ipv6

    def ping(self, target, count=3, **kw):
        got = self._pings.get(target, 0)
        return PingResult(transmitted=count, received=got)

    def verify_internet(self, count=3, **kw):
        return PingResult(transmitted=count, received=self._pings.get("internet", count))


class _Testbed:
    class ap:
        host = "10.0.127.220"


def _ssid(proto="psk2", name="ap-psk2", vlan_id=None):
    from framework.examples.inspect import SSIDSpec

    return SSIDSpec(name=name, proto=proto, vlan_id=vlan_id)


def _case(**kw):
    defaults = dict(
        ap=_FakeAP(), station=_FakeStation(), config={}, band="5G",
        example=catalog.get("crypto-psk"), mode="bridge", testbed=_Testbed(),
        ssid=_ssid(), assoc=Association(ssid="ap-psk2", ip="10.10.100.10"),
    )
    defaults.update(kw)
    return validators.Case(**defaults)


# ── negotiated encryption ────────────────────────────────────────────────────
# A config asking for WPA3 that quietly comes up as WPA2 passes connect-and-ping
# without complaint. What the client negotiated is what the network offers.

def test_wpa3_that_comes_up_as_wpa2_is_caught():
    case = _case(
        ssid=_ssid("sae", "ap-sae"),
        assoc=Association(ssid="ap-sae", ip="10.10.100.10",
                          key_mgmt="WPA2-PSK", pairwise_cipher="CCMP"),
    )
    with pytest.raises(AssertionError, match="weaker security than configured"):
        validators.check_negotiated_encryption(case)


def test_sae_negotiated_as_sae_passes():
    case = _case(
        ssid=_ssid("sae", "ap-sae"),
        assoc=Association(ssid="ap-sae", ip="10.10.100.10",
                          key_mgmt="SAE", pairwise_cipher="CCMP"),
    )
    assert "SAE" in validators.check_negotiated_encryption(case)


def test_wpa2_must_not_fall_back_to_tkip():
    case = _case(
        assoc=Association(ssid="ap-psk2", ip="10.10.100.10",
                          key_mgmt="WPA2-PSK", pairwise_cipher="TKIP"),
    )
    with pytest.raises(AssertionError, match="must not negotiate TKIP"):
        validators.check_negotiated_encryption(case)


def test_an_open_ssid_that_negotiated_a_key_is_caught():
    case = _case(
        ssid=_ssid("none", "ap-open"),
        assoc=Association(ssid="ap-open", ip="10.10.100.10", key_mgmt="WPA2-PSK"),
    )
    with pytest.raises(AssertionError, match="configured open"):
        validators.check_negotiated_encryption(case)


def test_a_protected_ssid_reporting_no_key_management_is_caught():
    case = _case(assoc=Association(ssid="ap-psk2", ip="10.10.100.10", key_mgmt=""))
    with pytest.raises(AssertionError, match="no key management at all"):
        validators.check_negotiated_encryption(case)


# ── forwarding mode ──────────────────────────────────────────────────────────
# A NATed client pings google just as happily as a bridged one.

BRIDGE_CFG = {"interfaces": [
    {"name": "LAN", "role": "downstream",
     "ipv4": {"addressing": "static", "subnet": "192.168.1.1/24"}},
]}


def test_a_bridged_client_that_was_actually_nated_is_caught():
    case = _case(config=BRIDGE_CFG, mode="bridge",
                 assoc=Association(ssid="s", ip="192.168.1.42"))
    with pytest.raises(AssertionError, match="being NATed, not bridged"):
        validators.check_forwarding_mode(case)


def test_a_properly_bridged_client_passes():
    case = _case(config=BRIDGE_CFG, mode="bridge",
                 assoc=Association(ssid="s", ip="10.10.100.42"))
    assert "upstream network" in validators.check_forwarding_mode(case)


def test_a_nat_case_whose_client_was_bridged_is_caught():
    case = _case(config=BRIDGE_CFG, mode="nat",
                 assoc=Association(ssid="s", ip="10.10.100.42"))
    with pytest.raises(AssertionError, match="bridged instead of NATed"):
        validators.check_forwarding_mode(case)


def test_a_client_on_the_management_subnet_is_caught():
    """The lockout this framework has been bitten by twice."""
    case = _case(config=BRIDGE_CFG, mode="bridge",
                 assoc=Association(ssid="s", ip="10.0.127.55"))
    with pytest.raises(AssertionError, match="management network"):
        validators.check_forwarding_mode(case)


# ── rate limiting ────────────────────────────────────────────────────────────
# The case the user named: apply 10 Mbps, measure, and see whether it bit.

RATE_CFG = {"interfaces": [{"name": "WAN", "ssids": [
    {"name": "ap-psk2", "rate-limit": {"ingress-rate": 10, "egress-rate": 10}},
]}]}


def test_a_rate_limit_that_never_took_effect_is_caught():
    case = _case(config=RATE_CFG, station=_FakeStation(mbps=715.0))
    with pytest.raises(AssertionError, match="not being applied"):
        validators.check_rate_limit(case)


def test_a_working_rate_limit_passes():
    case = _case(config=RATE_CFG, station=_FakeStation(mbps=9.6))
    assert "9.6 Mbps against a 10 Mbps cap" in validators.check_rate_limit(case)


def test_burst_above_the_cap_is_tolerated():
    """A short transfer sees burst allowance; the check must not be brittle."""
    case = _case(config=RATE_CFG, station=_FakeStation(mbps=12.0))
    assert "12.0 Mbps" in validators.check_rate_limit(case)


def test_no_measurement_at_all_is_not_read_as_a_working_limit():
    case = _case(config=RATE_CFG, station=_FakeStation(mbps=0.0))
    with pytest.raises(AssertionError, match="no throughput could be measured"):
        validators.check_rate_limit(case)


def test_an_ssid_without_a_rate_limit_is_skipped_cleanly():
    case = _case(config={"interfaces": []})
    assert "no rate-limit" in validators.check_rate_limit(case)


# ── dual stack ───────────────────────────────────────────────────────────────

def test_dual_stack_without_a_v6_address_is_caught():
    case = _case(station=_FakeStation(ipv6="", has_v6=True))
    with pytest.raises(AssertionError, match="no global IPv6"):
        validators.check_dual_stack(case)


def test_a_v4_only_bench_skips_dual_stack_instead_of_failing_it():
    """The AP bridges IPv6; it cannot invent it on a v4-only lab."""
    case = _case(station=_FakeStation(ipv6="", has_v6=False))
    assert "no IPv6 upstream" in validators.check_dual_stack(case)
    assert any("provides no IPv6" in n for n in case.notes)


def test_dual_stack_with_a_v6_address_passes():
    case = _case(station=_FakeStation(ipv6="2001:db8::42"))
    assert "2001:db8::42" in validators.check_dual_stack(case)


# ── RFC1918 blocking: the feature works when traffic *fails* ─────────────────

RFC1918_CFG = {"interfaces": [
    {"name": "LAN", "role": "downstream",
     "ipv4": {"subnet": "192.168.1.1/24",
              "disallow-upstream-subnet": ["10.0.0.0/8", "192.168.0.0/16"]}},
]}


def _rfc_case(**kw):
    return _case(config=RFC1918_CFG, ssid=_ssid(name="ap-psk2"), **kw)


def test_rfc1918_still_reachable_is_caught():
    case = _rfc_case(station=_FakeStation(pings={"10.0.127.220": 3, "internet": 3}))
    case.ssid.interface = "LAN"
    with pytest.raises(AssertionError, match="answered 3/3"):
        validators.check_block_rfc1918(case)


def test_rfc1918_blocked_while_the_internet_works_passes():
    case = _rfc_case(station=_FakeStation(pings={"10.0.127.220": 0, "internet": 3}))
    case.ssid.interface = "LAN"
    assert "unreachable" in validators.check_block_rfc1918(case)


def test_a_client_with_no_internet_cannot_judge_rfc1918_blocking():
    """Everything failing is not proof that blocking works."""
    case = _rfc_case(station=_FakeStation(pings={"10.0.127.220": 0, "internet": 0}))
    case.ssid.interface = "LAN"
    with pytest.raises(AssertionError, match="cannot judge"):
        validators.check_block_rfc1918(case)


def test_a_bridged_client_is_not_blamed_for_a_downstream_rule():
    """
    disallow-upstream-subnet is declared on the downstream interface. Bridge
    mode moves the SSID onto the tagged upstream, so the client is never behind
    the rule — asserting anyway blamed the AP for not enforcing it.
    """
    case = _rfc_case(station=_FakeStation(pings={"10.0.127.220": 3, "internet": 3}))
    case.ssid.interface = "WAN1000"
    assert "not exercised" in validators.check_block_rfc1918(case)


def test_a_config_without_the_rule_is_skipped_cleanly():
    case = _case(config={"interfaces": []})
    assert "no disallow-upstream-subnet" in validators.check_block_rfc1918(case)


# ── on-AP services ───────────────────────────────────────────────────────────

def test_igmp_snooping_missing_from_the_bridge_is_caught():
    case = _case(ap=_FakeAP(uci={"network": "network.up.ifname='eth0'"}))
    with pytest.raises(AssertionError, match="did not reach the network stack"):
        validators.check_igmp(case)


def test_igmp_snooping_present_passes():
    case = _case(ap=_FakeAP(uci={"network": "network.up.igmp_snooping='1'"}))
    assert "up" in validators.check_igmp(case)


def test_ntp_server_not_reaching_the_ap_is_caught():
    case = _case(
        config={"services": {"ntp": {"servers": ["time.cloudflare.com"]}}},
        ap=_FakeAP(uci={"system": "system.ntp.enabled='1'"},
                   responses={"ntpd": "1"}),
    )
    with pytest.raises(AssertionError, match="not in the AP's"):
        validators.check_ntp(case)


def test_ntp_configured_and_running_passes():
    case = _case(
        config={"services": {"ntp": {"servers": ["time.cloudflare.com"]}}},
        ap=_FakeAP(uci={"system": "system.ntp.server='time.cloudflare.com'"},
                   responses={"ntpd": "1"}),
    )
    assert "time.cloudflare.com" in validators.check_ntp(case)


def test_ntp_configured_but_daemon_dead_is_caught():
    case = _case(
        config={"services": {"ntp": {"servers": ["time.cloudflare.com"]}}},
        ap=_FakeAP(uci={"system": "system.ntp.server='time.cloudflare.com'"},
                   responses={"ntpd": "0"}),
    )
    with pytest.raises(AssertionError, match="ntpd is not running"):
        validators.check_ntp(case)


def test_lldp_description_not_advertised_is_caught():
    case = _case(
        config={"services": {"lldp": {"describe": "uCentral"}}},
        ap=_FakeAP(uci={"lldpd": "lldpd.config.lldp_class='4'"},
                   responses={"lldpd": "2"}),
    )
    with pytest.raises(AssertionError, match="does not carry it"):
        validators.check_lldp(case)


def test_lldp_running_and_advertising_passes():
    case = _case(
        config={"services": {"lldp": {"describe": "uCentral"}}},
        ap=_FakeAP(uci={"lldpd": "lldpd.config.lldp_description='uCentral'"},
                   responses={"lldpd": "2"}),
    )
    assert "uCentral" in validators.check_lldp(case)


def test_ssh_not_listening_on_the_configured_port_is_caught():
    case = _case(
        config={"services": {"ssh": {"port": 22}}},
        ap=_FakeAP(responses={"netstat": "0"}),
    )
    with pytest.raises(AssertionError, match="nothing is listening"):
        validators.check_ssh_service(case)


def test_ssh_listening_passes():
    case = _case(
        config={"services": {"ssh": {"port": 22}}},
        ap=_FakeAP(responses={"netstat": "1"}),
    )
    assert "port 22" in validators.check_ssh_service(case)


# ── telemetry: only what is honestly observable ──────────────────────────────

def test_telemetry_collector_not_running_is_caught():
    case = _case(ap=_FakeAP(responses={"ucentral-state": "0"}))
    with pytest.raises(AssertionError, match="is not running"):
        validators.check_telemetry(case)


def test_telemetry_records_that_delivery_is_out_of_scope():
    """The agent is disabled by design, so delivery cannot be observed."""
    case = _case(
        ap=_FakeAP(responses={"ucentral-state": "1"}),
        config={"metrics": {"statistics": {}, "health": {}}},
    )
    evidence = validators.check_telemetry(case)
    assert "health, statistics" in evidence
    assert any("not observable" in n for n in case.notes)


# ── registry wiring ──────────────────────────────────────────────────────────

def test_every_case_gets_the_universal_checks():
    case = _case()
    names = [n for n, _ in validators.per_ssid_checks(case)]
    assert "negotiated encryption" in names
    assert "forwarding mode" in names


def test_rate_limit_example_gets_its_own_check():
    case = _case(example=catalog.get("rate-limit"))
    assert any(n == "rate-limit" for n, _ in validators.per_ssid_checks(case))


def test_telemetry_examples_get_the_area_check():
    case = _case(example=catalog.get("metrics"),
                 config={"services": {"ssh": {"port": 22}}})
    assert any(n == "telemetry" for n, _ in validators.ap_side_checks(case))


def test_ssh_is_checked_on_every_example_that_declares_it():
    case = _case(example=catalog.get("crypto-psk"),
                 config={"services": {"ssh": {"port": 22}}})
    assert any(n == "ssh reachable" for n, _ in validators.ap_side_checks(case))


def test_every_registered_check_names_a_real_example():
    known = {e.name for e in catalog.EXAMPLES}
    for name in list(validators.PER_SSID) + list(validators.AP_SIDE):
        assert name in known, f"{name} is not an example in the catalog"


def test_every_registered_area_is_a_real_area():
    areas = {e.area.value for e in catalog.EXAMPLES}
    for area in validators.AP_SIDE_BY_AREA:
        assert area in areas
