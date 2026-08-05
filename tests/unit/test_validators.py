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


# ── QoS: DSCP must arrive in the right WMM access category ───────────────────
# The AP maps a marked frame onto an access category; the client can see which
# one it arrived in via per-TID counters. Nothing else in the suite would notice
# a classifier that silently did nothing.

class _QoSStation(_FakeStation):
    def __init__(self, mapping, peer="10.10.100.182"):
        super().__init__()
        self.mapping = mapping          # dscp -> tid the AP delivered it on
        self._peer = peer
        self._counters = {t: 0 for t in range(8)}
        self._pending = None

    def ensure_vlan_peer(self, vlan, **kw):
        if not self._peer:
            raise RuntimeError("no trunk")
        return self._peer

    def tid_counters(self):
        return dict(self._counters)

    def measure_from_peer(self, peer, seconds=8, dscp=None, udp_mbps=None):
        from framework.clients.rpi5_station import ThroughputResult

        if dscp is not None:
            tid = self.mapping.get(dscp)
            if tid is not None:
                self._counters[tid] += 1000
        return ThroughputResult(mbps=50.0)


CORRECT = {0: 0, 32: 4, 48: 7}       # what the AX820 actually did


def test_correct_dscp_to_wmm_mapping_passes():
    case = _case(station=_QoSStation(CORRECT), ssid=_ssid(vlan_id=1000))
    evidence = validators.check_qos_dscp_mapping(case)
    assert "DSCP 48 -> TID 7 (VO)" in evidence


def test_voice_delivered_as_best_effort_is_caught():
    """The failure that matters: marking ignored, everything lands in BE."""
    case = _case(station=_QoSStation({0: 0, 32: 0, 48: 0}), ssid=_ssid(vlan_id=1000))
    with pytest.raises(AssertionError, match="not mapping DSCP onto WMM"):
        validators.check_qos_dscp_mapping(case)


def test_either_voice_tid_is_accepted():
    """TID 6 and 7 are both AC_VO; asserting an exact TID would be wrong."""
    case = _case(station=_QoSStation({0: 0, 32: 4, 48: 6}), ssid=_ssid(vlan_id=1000))
    assert "(VO)" in validators.check_qos_dscp_mapping(case)


def test_traffic_that_never_arrives_is_not_a_pass():
    case = _case(station=_QoSStation({}), ssid=_ssid(vlan_id=1000))
    with pytest.raises(AssertionError, match="nothing arrived to classify"):
        validators.check_qos_dscp_mapping(case)


def test_qos_is_skipped_without_a_peer_rather_than_failed():
    case = _case(station=_QoSStation(CORRECT, peer=""), ssid=_ssid(vlan_id=1000))
    assert "skipped" in validators.check_qos_dscp_mapping(case)


# ── rate limiting now measures inside the lab ────────────────────────────────

def test_the_rate_limit_measures_against_the_wired_peer():
    """Not the internet: the uplink is not the thing under test."""
    class _S(_QoSStation):
        def measure_from_peer(self, peer, seconds=8, dscp=None, udp_mbps=None):
            from framework.clients.rpi5_station import ThroughputResult
            return ThroughputResult(mbps=9.4)

    case = _case(config=RATE_CFG, station=_S(CORRECT), ssid=_ssid(vlan_id=1000))
    evidence = validators.check_rate_limit(case)
    assert "9.4 Mbps against a 10 Mbps cap" in evidence
    assert "wired peer" in evidence


# ── roaming: the beacon must advertise the capability ────────────────────────

def test_rrm_not_advertised_in_the_beacon_is_caught():
    class _S(_FakeStation):
        def scan_for(self, ssid, retries=3):
            return [object()]

        def beacon_detail(self, ssid):
            return "BSS aa:bb\n\tcapability: ESS Privacy (0x1011)\n\tSSID: ap-psk2\n"

    with pytest.raises(AssertionError, match="advertises neither"):
        validators.check_rrm_elements(_case(station=_S()))


def test_the_radio_measurement_capability_bit_counts_as_advertised():
    """
    iw prints the baseline 802.11k advertisement as "RadioMeasure" in the
    capability field. Requiring the optional elements instead reported a
    correctly-advertising AP as broken.
    """
    class _S(_FakeStation):
        def scan_for(self, ssid, retries=3):
            return [object()]

        def beacon_detail(self, ssid):
            return "\tcapability: ESS Privacy ShortPreamble RadioMeasure (0x1031)\n"

    assert "802.11k" in validators.check_rrm_elements(_case(station=_S()))


def test_rrm_advertised_passes():
    class _S(_FakeStation):
        def scan_for(self, ssid, retries=3):
            return [object()]

        def beacon_detail(self, ssid):
            return "\tRM Enabled Capabilities:\n\t\t * Neighbor Report\n"

    assert "RM Enabled Capabilities" in validators.check_rrm_elements(
        _case(station=_S())
    )


# ── RADIUS: the server must have accepted this client ────────────────────────

class _RadiusTestbed(_Testbed):
    class external:
        class radius:
            dynamic_vlan = 1000
            identity = "testuser"


def test_association_without_any_access_accept_is_caught():
    class _S(_FakeStation):
        def radius_log(self, minutes=5):
            return "Login incorrect (No Auth-Type found)\n"

    case = _case(station=_S(), testbed=_RadiusTestbed())
    with pytest.raises(AssertionError, match="no Access-Accept"):
        validators.check_radius_accepted(case)


def test_an_access_accept_for_this_client_passes():
    class _S(_FakeStation):
        def radius_log(self, minutes=5):
            # The real wording from the bench server, MAC in dashed form.
            return ("Auth: (6) Login OK: [testuser] (from client lab port 1 "
                    "cli 5C-B4-7E-42-98-CA)\n")

    case = _case(
        station=_S(), testbed=_RadiusTestbed(),
        assoc=Association(ssid="s", ip="10.10.100.10", mac="5c:b4:7e:42:98:ca"),
    )
    assert "RADIUS accepted" in validators.check_radius_accepted(case)


def test_an_unreadable_radius_log_is_not_reported_as_a_failure():
    class _S(_FakeStation):
        def radius_log(self, minutes=5):
            return ""

    case = _case(station=_S(), testbed=_RadiusTestbed())
    assert "skipped" in validators.check_radius_accepted(case)


# ── dynamic VLAN: the client lands where the backend put it ──────────────────

def test_a_client_left_in_the_wrong_vlan_is_caught():
    class _S(_FakeStation):
        def ensure_vlan_peer(self, vlan, **kw):
            return "10.10.100.182"

    case = _case(station=_S(), testbed=_RadiusTestbed(),
                 assoc=Association(ssid="s", ip="192.168.9.20"))
    with pytest.raises(AssertionError, match="not placed in the assigned VLAN"):
        validators.check_dynamic_vlan(case)


def test_a_client_in_the_assigned_vlan_passes():
    class _S(_FakeStation):
        def ensure_vlan_peer(self, vlan, **kw):
            return "10.10.100.182"

    case = _case(station=_S(), testbed=_RadiusTestbed(),
                 assoc=Association(ssid="s", ip="10.10.100.184"))
    assert "shares VLAN 1000" in validators.check_dynamic_vlan(case)


# ── the radio must land where the config put it ──────────────────────────────
# `strict` prevents a silent clamp at render time; it says nothing about where
# the radio ended up. A radio that fell back to ACS still serves clients, so
# every other check passes while the case stops testing its band plan.

RADIO_CFG = {"radios": [{"band": "5G", "channel": 36, "channel-mode": "HE",
                         "channel-width": 20, "country": "US"}]}


class _RadioAP(_FakeAP):
    def __init__(self, htmode="HE20", uci=None):
        super().__init__(uci=uci or {"wireless": "wireless.radio0.country='US'"})
        self._htmode = htmode

    def iwinfo(self):
        return (f"wlan0     ESSID: \"ap-psk2\"\n"
                f"          Mode: Master  Channel: 36 (5.180 GHz)  "
                f"HT Mode: {self._htmode}\n")


def _radio_case(freq=5180, htmode="HE20", **kw):
    return _case(config=RADIO_CFG, band="5G", ap=_RadioAP(htmode),
                 assoc=Association(ssid="ap-psk2", ip="10.10.100.10",
                                   freq_mhz=freq), **kw)


def test_a_radio_on_the_configured_channel_and_width_passes():
    assert "HE20" in validators.check_radio_settings(_radio_case())


def test_a_radio_that_drifted_to_another_channel_is_caught():
    with pytest.raises(AssertionError, match="associated on channel 44"):
        validators.check_radio_settings(_radio_case(freq=5220))


def test_a_width_that_did_not_take_is_caught():
    """80 MHz asked for, 20 delivered — invisible to a ping test."""
    with pytest.raises(AssertionError, match="channel-width"):
        validators.check_radio_settings(_radio_case(htmode="HE80"))


def test_a_mode_that_fell_back_is_caught():
    with pytest.raises(AssertionError, match="channel-mode HE"):
        validators.check_radio_settings(_radio_case(htmode="VHT20"))


def test_a_band_the_config_does_not_declare_is_skipped():
    case = _case(config=RADIO_CFG, band="2G", ap=_RadioAP())
    assert "declares no 2G radio" in validators.check_radio_settings(case)


# ── regulatory domain ────────────────────────────────────────────────────────
# Every example ships CA and normalization rewrites it. If that never reached
# the radio the AP is transmitting under the wrong rules.

def test_the_configured_country_must_reach_the_radio():
    case = _case(config=RADIO_CFG,
                 ap=_RadioAP(uci={"wireless": "wireless.radio0.country='CA'"}))
    with pytest.raises(AssertionError, match="different regulatory domain"):
        validators.check_regulatory_domain(case)


def test_the_right_country_passes():
    assert "US" in validators.check_regulatory_domain(_radio_case())


# ── services with a local trace ──────────────────────────────────────────────

def test_online_check_hosts_the_ap_cannot_reach_are_caught():
    """Otherwise the feature acts on the bench's connectivity, not the AP's."""
    case = _case(
        config={"services": {"online-check": {"ping-hosts": ["192.168.178.1"]}}},
        ap=_FakeAP(responses={"ping": ""}),
    )
    with pytest.raises(AssertionError, match="can reach none of them"):
        validators.check_online_check(case)


def test_online_check_passes_when_the_ap_reaches_a_host():
    case = _case(
        config={"services": {"online-check": {"ping-hosts": ["1.1.1.1", "x.invalid"]}}},
        ap=_FakeAP(responses={"ping": "up"}),
    )
    assert "reaches 2 of 2" in validators.check_online_check(case)


def test_fingerprint_needs_its_collector_running():
    case = _case(config={"services": {"fingerprint": {"mode": "raw"}}},
                 ap=_FakeAP(responses={"ucentral-state": "0"}))
    with pytest.raises(AssertionError, match="is not running"):
        validators.check_fingerprint(case)


def test_dhcp_snooping_reports_the_filters_it_watches():
    case = _case(config={"metrics": {"dhcp-snooping": {"filters": ["ack", "offer"]}}},
                 ap=_FakeAP(responses={"ucentral-state": "1"}))
    assert "2 DHCP message type(s)" in validators.check_dhcp_snooping(case)


def test_every_case_gets_the_radio_and_country_checks():
    case = _case(config={"services": {"ssh": {"port": 22}}})
    assert any(n == "radio settings" for n, _ in validators.per_ssid_checks(case))
    assert any(n == "regulatory domain" for n, _ in validators.ap_side_checks(case))


def test_enterprise_key_mgmt_uses_the_form_wpa_supplicant_reports():
    """
    wpa_supplicant says "WPA2/IEEE 802.1X/EAP", not "WPA2-EAP". Matching the
    hyphenated form failed a BSS that had authenticated correctly over 802.1X.
    """
    case = _case(
        ssid=_ssid("wpa2", "ap-wpa2"),
        assoc=Association(ssid="ap-wpa2", ip="10.10.100.10",
                          key_mgmt="WPA2/IEEE 802.1X/EAP", pairwise_cipher="CCMP"),
    )
    assert "802.1X" in validators.check_negotiated_encryption(case)


def test_an_enterprise_ssid_that_came_up_as_psk_is_still_caught():
    case = _case(
        ssid=_ssid("wpa2", "ap-wpa2"),
        assoc=Association(ssid="ap-wpa2", ip="10.10.100.10",
                          key_mgmt="WPA2-PSK", pairwise_cipher="CCMP"),
    )
    with pytest.raises(AssertionError, match="weaker security"):
        validators.check_negotiated_encryption(case)


# ── which identity an enterprise SSID actually needs ─────────────────────────
# An SSID carrying radius.local is authenticated by the *AP's own* EAP server,
# which presents a vendor certificate signed by a root the bench has no copy of.
# Handing it the bench certificate identity fails with a TLS certificate error
# that reads like an AP fault.

class _Radius:
    identity = "testuser"
    eap_method = "TLS"
    ca_cert="/etc/regression-pki/ca.pem"
    client_cert="/etc/regression-pki/client.pem"
    private_key="/etc/regression-pki/client.key"


class _TB:
    class external:
        radius = _Radius()


def test_an_ap_local_eap_ssid_uses_the_aps_own_account():
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _identity_for

    cfg = {"interfaces": [{"name": "WAN", "ssids": [
        {"name": "ap-wpa2", "encryption": {"proto": "wpa2"},
         "radius": {"local": {"users": [{"user-name": "john", "password": "aaaaaaaa"}]}}},
    ]}]}
    got = _identity_for(iter_ssids(cfg)[0], _TB())
    assert got["identity"] == "john"
    assert got["eap_password"] == "aaaaaaaa"
    # EAP-PWD (method 52) is what the AP's own server offers; PEAP gets NAK'd.
    assert got["eap_method"] == "PWD"
    assert "certificates" not in got


def test_an_external_radius_ssid_uses_the_bench_certificate_identity():
    from framework.examples.inspect import iter_ssids
    from tests.regression.test_examples import _identity_for

    cfg = {"interfaces": [{"name": "WAN", "ssids": [
        {"name": "ap-wpa2", "encryption": {"proto": "wpa2"},
         "radius": {"authentication": {"host": "10.0.127.77", "secret": "x"}}},
    ]}]}
    got = _identity_for(iter_ssids(cfg)[0], _TB())
    assert got["eap_method"] == "TLS"
    assert got["certificates"]["ca_cert"].endswith("ca.pem")
