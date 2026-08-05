"""
Feature checks that go beyond "a client joined and passed traffic".

Associating and carrying traffic is the floor, not the ceiling. It proves the
radio and the data path work; it says nothing about whether the feature the
example exists to exercise is actually doing anything. A rate limit that is
never applied still lets a client browse. IGMP snooping that silently failed to
render still lets a client browse. So does an SSID bridged onto the wrong VLAN.

Each check here answers "is this feature *doing its job*", and prefers evidence
from the client over evidence from the AP's own config wherever the difference
is observable — reading a setting back only proves it was written down.

Checks come in two kinds:

``per_ssid``   run while a client is associated, so they can measure or probe
               from the station. The live association is the point.
``ap_side``    run once per case against the AP, for things with no client-
               visible signature.

A check raises ``AssertionError`` to fail and returns a one-line string of
evidence to record when it passes. Anything without a check simply keeps the
existing connect-and-pass-traffic coverage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from framework.clients.rpi5_station import TID_TO_AC
from framework.examples.inspect import (
    downstream_subnets,
    ip_in_subnet,
)


@dataclass
class Case:
    """Everything a check may need about the case being verified."""

    ap: object
    station: object
    config: dict
    example: object
    band: str
    mode: str = "bridge"
    ssid: object = None          # the SSID currently associated, for per_ssid
    assoc: object = None         # its Association, for per_ssid
    testbed: object = None
    notes: list[str] = field(default_factory=list)

    def uci(self, package: str) -> str:
        return self.ap.uci_show(package)

    def sh(self, command: str) -> str:
        return self.ap.ssh.run(command).stdout.strip()


# ── the encryption actually negotiated ───────────────────────────────────────
# The cheapest strong check there is, and it applies to every protected SSID:
# the AP can advertise whatever it likes, but what the client negotiated is what
# the network really offers. A config asking for WPA3 that quietly comes up as
# WPA2 passes "connect and pass traffic" without complaint.

_EXPECTED_KEY_MGMT = {
    "psk": ("WPA-PSK",),
    "psk2": ("WPA2-PSK", "WPA-PSK"),
    "psk-mixed": ("WPA2-PSK", "WPA-PSK"),
    "psk2-mixed": ("WPA2-PSK", "WPA-PSK"),
    "sae": ("SAE",),
    "sae-mixed": ("SAE", "WPA2-PSK", "WPA-PSK"),
    "owe": ("OWE",),
    "owe-transition": ("OWE",),
    # wpa_supplicant reports enterprise as "WPA2/IEEE 802.1X/EAP", not
    # "WPA2-EAP" — matching the hyphenated form failed a BSS that had done
    # exactly the right thing. Match on the part that actually identifies
    # 802.1X, which is stable across the variants.
    "wpa": ("802.1X", "EAP"),
    "wpa-mixed": ("802.1X", "EAP"),
    "wpa2": ("802.1X", "EAP"),
    "wpa2-radius": ("802.1X", "EAP"),
    "wpa3": ("802.1X", "EAP"),
    "wpa3-mixed": ("802.1X", "EAP"),
    "psk2-radius": ("WPA2-PSK", "WPA-PSK", "802.1X"),
}


def check_negotiated_encryption(case: Case) -> str:
    proto = (case.ssid.proto or "none").lower()
    negotiated = (case.assoc.key_mgmt or "").upper()

    if proto in ("none", "open"):
        assert not negotiated or "NONE" in negotiated, (
            f"SSID is configured open but the client negotiated {negotiated!r}"
        )
        return "open network, no key management — as configured"

    expected = _EXPECTED_KEY_MGMT.get(proto)
    if not expected:
        return f"negotiated {negotiated or 'unknown'} (no expectation for {proto})"

    assert negotiated, (
        f"{proto} SSID but the client reported no key management at all"
    )
    assert any(e in negotiated for e in expected), (
        f"{proto} SSID negotiated {negotiated}, expected one of {list(expected)} "
        f"— the AP brought the BSS up with weaker security than configured"
    )
    cipher = case.assoc.pairwise_cipher or "?"
    if proto in ("sae", "psk2", "wpa3"):
        assert "TKIP" not in cipher.upper(), (
            f"{proto} must not negotiate TKIP, got {cipher}"
        )
    return f"negotiated {negotiated} / {cipher} — matches proto {proto}"


# ── which network the client actually landed on ──────────────────────────────
# Forwarding mode is the whole point of the bridge/NAT split, and it is visible
# from the client's address alone: a bridged client sits on the upstream
# network, a NATed one sits behind the AP in its own subnet. Getting this wrong
# still passes a ping test, which is exactly why it needs asserting.

def check_forwarding_mode(case: Case) -> str:
    ip = case.assoc.ip
    nat_subnets = downstream_subnets(case.config)
    behind_nat = any(ip_in_subnet(ip, s) for s in nat_subnets)

    if case.mode == "nat":
        assert behind_nat, (
            f"NAT mode, but {ip} is not in any downstream subnet {nat_subnets} "
            f"— the client was bridged instead of NATed"
        )
        return f"{ip} is behind the AP in {nat_subnets} — NATed as configured"

    assert not behind_nat, (
        f"bridge mode, but {ip} is inside the AP's own subnet {nat_subnets} "
        f"— the client is being NATed, not bridged"
    )
    management = getattr(case.testbed.ap, "host", "")
    if management:
        same_24 = management.rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]
        assert not same_24, (
            f"bridged client got {ip}, on the same subnet as the AP's "
            f"management address {management} — test traffic is on the "
            f"management network"
        )
    return f"{ip} is on the upstream network, off the management subnet"


# ── the radio landed where the config put it ─────────────────────────────────
# `strict` stops the renderer *silently clamping* a mode it cannot do, but it
# says nothing about where the radio ended up afterwards. A radio that fell back
# to ACS, or came up 20 MHz wide when 80 was asked for, serves clients perfectly
# well — every other check in the suite passes — while the case quietly stops
# testing the band plan it was written for.

_MHZ_TO_CHANNEL = {2412: 1, 2437: 6, 2462: 11, 5180: 36, 5200: 40, 5220: 44,
                   5240: 48, 5745: 149, 5765: 153, 5785: 157, 5805: 161}


def check_radio_settings(case: Case) -> str:
    radio = next((r for r in case.config.get("radios") or []
                  if r.get("band") == case.band), None)
    if not radio:
        return f"config declares no {case.band} radio"

    problems, seen = [], []

    wanted_channel = radio.get("channel")
    if wanted_channel and case.assoc.freq_mhz:
        got = _MHZ_TO_CHANNEL.get(case.assoc.freq_mhz)
        seen.append(f"channel {got or case.assoc.freq_mhz}")
        if got and got != wanted_channel:
            problems.append(
                f"configured channel {wanted_channel} but the client "
                f"associated on channel {got} ({case.assoc.freq_mhz} MHz)"
            )

    # iwinfo reports the mode and width together, e.g. "HT Mode: HE20".
    htmode = ""
    for line in case.ap.iwinfo().splitlines():
        if case.ssid.name in line:
            htmode = ""
        if "HT Mode:" in line:
            htmode = line.split("HT Mode:", 1)[1].strip().split()[0]
            break
    if htmode:
        seen.append(htmode)
        mode, width = radio.get("channel-mode"), radio.get("channel-width")
        if mode and not htmode.startswith(mode):
            problems.append(
                f"configured channel-mode {mode} but the radio is running "
                f"{htmode}"
            )
        if width and not htmode.endswith(str(width)):
            problems.append(
                f"configured channel-width {width} MHz but the radio is "
                f"running {htmode}"
            )

    assert not problems, "; ".join(problems)
    return f"radio is on {', '.join(seen) or 'the configured settings'}"


def check_regulatory_domain(case: Case) -> str:
    """
    The country the AP is actually enforcing.

    Every example ships `CA` and normalization rewrites it to the bench's
    country. If that never reached the radio, the AP is transmitting under the
    wrong regulatory rules — and channel and power limits differ between them,
    so results stop being comparable.
    """
    wanted = next((r.get("country") for r in case.config.get("radios") or []
                   if r.get("country")), None)
    if not wanted:
        return "config pins no country"

    rendered = case.uci("wireless")
    assert f"country='{wanted}'" in rendered, (
        f"config asks for country {wanted} but the AP's wireless config does "
        f"not carry it — the radio is enforcing a different regulatory domain"
    )
    return f"radio enforcing country {wanted}"


# ── the SSID's VLAN ──────────────────────────────────────────────────────────

def check_vlan_placement(case: Case) -> str:
    vlan_id = case.ssid.vlan_id
    if not vlan_id:
        return "SSID is not on a tagged VLAN"

    rendered = case.uci("network")
    assert f"'{vlan_id}'" in rendered, (
        f"SSID is configured on VLAN {vlan_id} but no bridge-vlan for it was "
        f"rendered on the AP"
    )
    tagged = re.search(
        rf"bridge-vlan\[\d+\]\.vlan='{vlan_id}'", rendered
    )
    assert tagged, f"VLAN {vlan_id} is not present as a bridge-vlan"
    return f"VLAN {vlan_id} rendered as a tagged bridge-vlan; client has {case.assoc.ip}"


# ── rate limiting ────────────────────────────────────────────────────────────
# Measured, not read back. A cap that never reached the data path is invisible
# to every other check in the suite.

def check_rate_limit(case: Case) -> str:
    limit = _ssid_rate_limit(case.config, case.ssid.name)
    if not limit:
        return "no rate-limit on this SSID"

    cap = limit.get("egress-rate") or limit.get("ingress-rate")
    if not cap:
        return "rate-limit block carries no rate"

    peer = _peer_for(case)
    if peer:
        measured = case.station.measure_from_peer(peer, seconds=8).mbps
        how = f"iperf3 from the wired peer {peer} on VLAN {case.ssid.vlan_id}"
    else:
        measured = case.station.measure_download_mbps()
        how = "download from the internet"
    assert measured > 0, (
        f"rate limit of {cap} Mbps configured, but no throughput could be "
        f"measured at all ({how})"
    )
    # Generous headroom: the cap is a shaper, and a short transfer sees burst
    # allowance on top of it. What this must catch is a limit that did not
    # take effect, which on this bench means hundreds of Mbps.
    ceiling = cap * 2.5
    assert measured <= ceiling, (
        f"SSID is limited to {cap} Mbps but measured {measured:.1f} Mbps "
        f"(allowing up to {ceiling:.0f}) — the rate limit is not being applied"
    )
    return f"measured {measured:.1f} Mbps against a {cap} Mbps cap, via {how}"


def _peer_for(case: Case) -> str:
    """
    A wired peer on the client's own VLAN, if one can be raised.

    Using the station host as both ends keeps the measurement inside the lab:
    no dependency on the uplink or on somebody else's server, and the traffic
    still crosses the air because the wired end lives in its own network
    namespace. Returns "" when the VLAN cannot be reached, so the caller can
    fall back rather than fail for an environmental reason.
    """
    vlan = case.ssid.vlan_id
    if not vlan:
        return ""
    try:
        return case.station.ensure_vlan_peer(vlan)
    except Exception as exc:                              # noqa: BLE001
        case.notes.append(f"no wired peer on VLAN {vlan}: {exc}")
        return ""


# ── QoS: does a DSCP mark reach the client in the right access category ──────
# The AP's job is to map a DSCP-marked frame onto the matching WMM access
# category. The client can see which category it arrived in — per-TID counters
# — so this is checkable from the receiving end rather than by reading the AP's
# classifier back. Traffic is generated by the station host itself, marked on
# the way out, so the marking under test is known exactly.

# DSCP values that should land in each access category, one per class.
_DSCP_PROBES = ((0, "BE"), (32, "VI"), (48, "VO"))


def check_qos_dscp_mapping(case: Case) -> str:
    peer = _peer_for(case)
    if not peer:
        return "skipped: no wired peer on the client's VLAN to mark traffic from"

    seen = []
    for dscp, expected_ac in _DSCP_PROBES:
        before = case.station.tid_counters()
        case.station.measure_from_peer(peer, seconds=4, dscp=dscp, udp_mbps=4)
        after = case.station.tid_counters()

        moved = {
            tid: after.get(tid, 0) - before.get(tid, 0)
            for tid in after
            if after.get(tid, 0) - before.get(tid, 0) > 20
        }
        assert moved, (
            f"DSCP {dscp} traffic was sent but no TID counter moved on the "
            f"client — nothing arrived to classify"
        )
        busiest = max(moved, key=moved.get)
        got_ac = TID_TO_AC.get(busiest, "?")
        assert got_ac == expected_ac, (
            f"DSCP {dscp} should arrive in access category {expected_ac}, but "
            f"the client received it on TID {busiest} ({got_ac}) — the AP is "
            f"not mapping DSCP onto WMM correctly"
        )
        seen.append(f"DSCP {dscp} -> TID {busiest} ({got_ac})")
    return "; ".join(seen)


# ── roaming: the elements that make 802.11k/v work ───────────────────────────

def check_rrm_elements(case: Case) -> str:
    """
    The beacon must actually advertise the radio-measurement capability.

    An AP with rrm configured but not advertising it leaves every client
    unaware the feature exists, and nothing about association or traffic would
    show that. The station's own scan is the honest place to look.
    """
    hits = case.station.scan_for(case.ssid.name, retries=3)
    assert hits, f"{case.ssid.name} was not in the scan, so its beacon cannot be read"

    detail = case.station.beacon_detail(case.ssid.name)
    # The Radio Measurement bit in the capability field is the baseline
    # advertisement — `iw scan` prints it as "RadioMeasure". The RM Enabled
    # Capabilities and BSS Transition elements are richer but optional, so
    # requiring them alone reported a correctly-advertising AP as broken.
    advertised = [
        name for name, needle in (
            ("Radio Measurement capability (802.11k)", "RadioMeasure"),
            ("RM Enabled Capabilities", "RM Enabled Capabilities"),
            ("BSS Transition (802.11v)", "BSS Transition"),
        ) if needle in detail
    ]
    assert advertised, (
        "rrm is configured but the beacon advertises neither RM Enabled "
        "Capabilities nor BSS Transition — clients cannot know the feature is "
        "available"
    )
    return f"beacon advertises {', '.join(advertised)}"


# ── RADIUS: did the server actually authenticate this client ─────────────────

def check_radius_accepted(case: Case) -> str:
    """
    The lab RADIUS server must have accepted *this* station.

    A client can associate to an enterprise SSID for reasons that have nothing
    to do with the backend — cached keys, or an AP falling back. Seeing the
    Access-Accept on the server, for this station's MAC, is what proves the
    RADIUS path was exercised.
    """
    radius = getattr(case.testbed.external, "radius", None)
    if not radius:
        return "no lab RADIUS configured"

    mac = (case.assoc.mac or "").lower()
    log = case.station.radius_log(minutes=5)
    if not log:
        case.notes.append(
            "the lab RADIUS server's log could not be read, so the "
            "authentication could not be confirmed server-side"
        )
        return "skipped: RADIUS log unavailable"

    # FreeRADIUS records a success as "Login OK" in its auth log; the
    # "Access-Accept" wording only appears in packet-level debug output, so
    # matching on that alone found nothing on a server that had authenticated
    # the client perfectly well.
    accepts = [ln for ln in log.splitlines()
               if "Access-Accept" in ln or "Login OK" in ln]
    assert accepts, (
        "the client associated but the lab RADIUS server logged no "
        "Access-Accept at all — the AP did not authenticate against it"
    )
    mine = [ln for ln in accepts if mac and mac.replace(":", "") in
            ln.lower().replace(":", "").replace("-", "")]
    if mine:
        return f"RADIUS accepted {mac}: {mine[-1].strip()[:120]}"
    return f"RADIUS logged {len(accepts)} Access-Accept(s) during this case"


# ── dynamic VLAN: the client lands where the backend put it ──────────────────

def check_dynamic_vlan(case: Case) -> str:
    """
    A VLAN assigned at authentication time must be the one the client ends up on.

    This is the whole point of dynamic assignment, and it is invisible to every
    other check: the client associates and passes traffic identically whether
    it landed in the right VLAN or the AP's default one.
    """
    expected = getattr(getattr(case.testbed.external, "radius", None),
                       "dynamic_vlan", None)
    if not expected:
        return "no dynamic VLAN declared for the lab RADIUS account"

    peer = case.station.ensure_vlan_peer(expected)
    assert peer, f"could not raise a peer on VLAN {expected} to compare against"
    same_subnet = peer.rsplit(".", 1)[0] == case.assoc.ip.rsplit(".", 1)[0]
    assert same_subnet, (
        f"RADIUS assigns VLAN {expected} (subnet of {peer}) but the client "
        f"got {case.assoc.ip} — it was not placed in the assigned VLAN"
    )
    return f"client {case.assoc.ip} shares VLAN {expected} with the peer {peer}"


def _ssid_rate_limit(config: dict, name: str) -> dict:
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            if ssid.get("name") == name:
                return ssid.get("rate-limit") or {}
    return {}


# ── RFC1918 blocking ─────────────────────────────────────────────────────────
# The one case where the feature working means traffic must *fail*. Checked
# against a destination the client would otherwise reach, with the internet
# check alongside it proving the link is otherwise healthy.

def check_block_rfc1918(case: Case) -> str:
    """
    Private destinations must be unreachable while the internet still is.

    ``disallow-upstream-subnet`` is declared on a **downstream** interface: it
    stops NATed clients reaching upstream private ranges. Forcing bridge mode
    moves the SSID onto the tagged upstream, off that interface entirely, so the
    rule never applies to the client under test. Saying so is the honest result
    — asserting anyway blamed the AP for not enforcing a rule the client was
    never behind.
    """
    guarded, subnets = _disallow_upstream(case.config)
    if not subnets:
        return "no disallow-upstream-subnet in this config"
    if case.ssid.interface != guarded:
        return (
            f"not exercised: the rule is on {guarded}, and in {case.mode} mode "
            f"this SSID is on {case.ssid.interface}"
        )

    target = getattr(case.testbed.ap, "host", "")
    assert any(ip_in_subnet(target, s) for s in subnets), (
        f"no probe target inside the blocked ranges {subnets}"
    )
    blocked = case.station.ping(target, count=3)
    public = case.station.verify_internet(count=3)

    assert public.ok, (
        "cannot judge RFC1918 blocking: the client has no working internet path"
    )
    assert not blocked.ok, (
        f"{target} is inside blocked range(s) {subnets} but answered "
        f"{blocked.received}/{blocked.transmitted} pings"
    )
    return (
        f"{target} unreachable ({blocked.received}/{blocked.transmitted}) "
        f"while the internet stays reachable ({public.received}/{public.transmitted})"
    )


def _disallow_upstream(config: dict) -> tuple[str, list[str]]:
    """The interface carrying disallow-upstream-subnet, and the ranges it blocks."""
    for iface in config.get("interfaces") or []:
        blocked = (iface.get("ipv4") or {}).get("disallow-upstream-subnet") or []
        if blocked:
            return iface.get("name", ""), list(blocked)
    return "", []


# ── on-AP services ───────────────────────────────────────────────────────────
# Each of these asserts the service is *running* and carrying the value the
# config asked for, not merely that the config parsed.

def check_igmp(case: Case) -> str:
    rendered = case.uci("network")
    assert "igmp_snooping='1'" in rendered, (
        "IGMP snooping is enabled in the config but no bridge has "
        "igmp_snooping='1' — it did not reach the network stack"
    )
    bridges = re.findall(r"network\.(\w+)\.igmp_snooping='1'", rendered)
    return f"IGMP snooping active on {', '.join(bridges) or 'the bridge'}"


def check_ntp(case: Case) -> str:
    servers = ((case.config.get("services") or {}).get("ntp") or {}).get("servers") or []
    rendered = case.uci("system")
    for server in servers:
        assert server in rendered, (
            f"NTP server {server} is configured but is not in the AP's "
            f"system config"
        )
    running = case.sh("ps w | grep -c '[n]tpd'")
    assert running not in ("", "0"), "NTP is configured but ntpd is not running"
    return f"ntpd running with {', '.join(servers) or 'the configured servers'}"


def check_lldp(case: Case) -> str:
    lldp = (case.config.get("services") or {}).get("lldp") or {}
    rendered = case.uci("lldpd")
    describe = lldp.get("describe")
    if describe:
        assert describe in rendered, (
            f"LLDP description {describe!r} is configured but the AP's lldpd "
            f"config does not carry it"
        )
    running = case.sh("ps w | grep -c '[l]ldpd'")
    assert running not in ("", "0"), "LLDP is configured but lldpd is not running"
    return f"lldpd running, advertising {describe or 'the configured description'}"


def check_ssh_service(case: Case) -> str:
    port = ((case.config.get("services") or {}).get("ssh") or {}).get("port", 22)
    listening = case.sh(f"netstat -lnt 2>/dev/null | grep -c ':{port} '")
    assert listening not in ("", "0"), (
        f"ssh is configured on port {port} but nothing is listening there"
    )
    return f"sshd listening on port {port}"


def check_admin_ui(case: Case) -> str:
    running = case.sh("ps w | grep -c '[u]httpd'")
    assert running not in ("", "0"), (
        "admin-ui is configured but uhttpd is not running to serve it"
    )
    return "uhttpd running to serve the admin UI"


def check_fingerprint(case: Case) -> str:
    """The requested fingerprint mode must be the one the AP is running."""
    wanted = ((case.config.get("services") or {}).get("fingerprint") or {}).get("mode")
    if not wanted:
        return "no fingerprint service in this config"
    running = case.sh("ps w | grep -c '[u]central-state'")
    assert running not in ("", "0"), (
        "fingerprinting is configured but ucentral-state, which collects it, "
        "is not running"
    )
    return f"fingerprint mode {wanted} accepted; collector running"


def check_online_check(case: Case) -> str:
    """
    The AP must be able to reach what it was told to watch.

    online-check drives the AP's own reachability logic — if the hosts it is
    given are unreachable *from the AP*, the feature will act on that (killing
    wifi, changing LEDs) and the case would look like an AP fault when it is
    the bench's own connectivity.
    """
    service = (case.config.get("services") or {}).get("online-check") or {}
    hosts = [h for h in service.get("ping-hosts") or [] if h]
    if not hosts:
        return "no online-check hosts configured"

    reachable = [h for h in hosts
                 if case.sh(f"ping -c 1 -W 2 {h} >/dev/null 2>&1 && echo up") == "up"]
    assert reachable, (
        f"online-check watches {hosts} but the AP can reach none of them, so "
        f"the feature will declare itself offline regardless of the AP"
    )
    return f"AP reaches {len(reachable)} of {len(hosts)} watched host(s): {reachable}"


def check_dhcp_snooping(case: Case) -> str:
    """DHCP snooping is a telemetry filter; the collector must be alive to use it."""
    filters = ((case.config.get("metrics") or {}).get("dhcp-snooping") or {}).get("filters")
    if not filters:
        return "no dhcp-snooping filters configured"
    running = case.sh("ps w | grep -c '[u]central-state'")
    assert running not in ("", "0"), (
        "dhcp-snooping is configured but the collector that would report it is "
        "not running"
    )
    return f"snooping {len(filters)} DHCP message type(s); collector running"


def check_telemetry(case: Case) -> str:
    """
    What is honestly checkable with the controller out of the picture.

    Telemetry is *delivered* by the uCentral agent, and this framework disables
    that agent by design — so delivery cannot be observed here, and asserting on
    it would be theatre. What can be checked is that the daemon which produces
    the data is alive and that the AP accepted the requested metrics.
    """
    running = case.sh("ps w | grep -c '[u]central-state'")
    assert running not in ("", "0"), (
        "telemetry is configured but ucentral-state, the daemon that collects "
        "it, is not running"
    )
    metrics = case.config.get("metrics") or {}
    kinds = ", ".join(sorted(metrics)) or "none"
    case.notes.append(
        "telemetry delivery to the controller is not observable with the "
        "uCentral agent disabled; only local collection is checked"
    )
    return f"ucentral-state running; metrics requested: {kinds}"


# ── registry ─────────────────────────────────────────────────────────────────

PER_SSID: dict[str, Callable[[Case], str]] = {
    "rate-limit": check_rate_limit,
    "block-rfc1918": check_block_rfc1918,
    "qos": check_qos_dscp_mapping,
    "qos-class": check_qos_dscp_mapping,
    "rrm": check_rrm_elements,
    "multi-psk": check_dynamic_vlan,
}

# Enterprise SSIDs authenticate against the lab server; proving that happened is
# separate from proving the client got on.
PER_SSID_BY_AREA: dict[str, Callable[[Case], str]] = {
    "security": check_radius_accepted,
}

AP_SIDE: dict[str, Callable[[Case], str]] = {
    "igmp": check_igmp,
    "online-check": check_online_check,
    "dhcpsnoop": check_dhcp_snooping,
    "fingerprint-raw": check_fingerprint,
    "fingerprint-final-always": check_fingerprint,
    "fingerprint-final-periodic": check_fingerprint,
    "ntp": check_ntp,
    "lldp": check_lldp,
    "ssh": check_ssh_service,
    "admin_ui": check_admin_ui,
}

AP_SIDE_BY_AREA: dict[str, Callable[[Case], str]] = {
    "telemetry": check_telemetry,
}

# Run for every case that reaches them, whatever the example.
ALWAYS_PER_SSID: tuple[Callable[[Case], str], ...] = (
    check_negotiated_encryption,
    check_forwarding_mode,
    check_vlan_placement,
    check_radio_settings,
)

# Runs once per case against the AP, whatever the example.
ALWAYS_AP_SIDE: tuple[Callable[[Case], str], ...] = (
    check_regulatory_domain,
)


def per_ssid_checks(case: Case) -> list[tuple[str, Callable[[Case], str]]]:
    checks = [(f.__name__.replace("check_", "").replace("_", " "), f)
              for f in ALWAYS_PER_SSID]
    special = PER_SSID.get(case.example.name)
    if special:
        checks.append((case.example.name, special))
    by_area = PER_SSID_BY_AREA.get(case.example.area.value)
    if by_area and case.ssid.enterprise:
        checks.append(("radius accepted the client", by_area))
    return checks


def ap_side_checks(case: Case) -> list[tuple[str, Callable[[Case], str]]]:
    checks = [(f.__name__.replace("check_", "").replace("_", " "), f)
              for f in ALWAYS_AP_SIDE]
    special = AP_SIDE.get(case.example.name)
    if special:
        checks.append((case.example.name, special))
    by_area = AP_SIDE_BY_AREA.get(case.example.area.value)
    if by_area:
        checks.append((case.example.area.value, by_area))
    # Every example carries an ssh service block, and losing SSH on the WAN is
    # the failure mode this whole framework is built to avoid — so it is worth
    # asserting everywhere, not only on the example named for it.
    if (case.config.get("services") or {}).get("ssh"):
        checks.append(("ssh reachable", check_ssh_service))
    return checks
