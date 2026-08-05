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
    "wpa2": ("WPA2-EAP", "WPA-EAP"),
    "wpa3": ("WPA3-EAP", "WPA2-EAP", "WPA-EAP"),
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

    measured = case.station.measure_download_mbps()
    assert measured > 0, (
        f"rate limit of {cap} Mbps configured, but no throughput could be "
        f"measured at all"
    )
    # Generous headroom: the cap is a shaper, and a short transfer sees burst
    # allowance on top of it. What this must catch is a limit that did not
    # take effect, which on this bench means hundreds of Mbps.
    ceiling = cap * 2.5
    assert measured <= ceiling, (
        f"SSID is limited to {cap} Mbps but measured {measured:.1f} Mbps "
        f"(allowing up to {ceiling:.0f}) — the rate limit is not being applied"
    )
    return f"measured {measured:.1f} Mbps against a {cap} Mbps cap"


def _ssid_rate_limit(config: dict, name: str) -> dict:
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            if ssid.get("name") == name:
                return ssid.get("rate-limit") or {}
    return {}


# ── IPv6 ─────────────────────────────────────────────────────────────────────

def check_dual_stack(case: Case) -> str:
    """
    The client should hold both families — but only if the lab serves both.

    In bridge mode the AP does not source IPv6 itself; it forwards the upstream
    network's RAs. On a bench with no IPv6 upstream there is nothing for the AP
    to pass on, and asserting would report an environmental gap as an AP defect
    — the same trap as testing a VLAN the DHCP server does not serve.
    """
    if not case.station.lab_has_ipv6():
        case.notes.append(
            "the lab network provides no IPv6, so dual-stack cannot be "
            "validated here — the AP bridges IPv6 rather than sourcing it"
        )
        return "skipped: no IPv6 upstream on this bench"

    address = case.station.global_ipv6()
    assert address, (
        "dual-stack is configured and the lab serves IPv6, but the client got "
        "no global IPv6 address — only IPv4 was served"
    )
    return f"client holds IPv4 {case.assoc.ip} and IPv6 {address}"


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
    "dual-stack": check_dual_stack,
    "block-rfc1918": check_block_rfc1918,
}

AP_SIDE: dict[str, Callable[[Case], str]] = {
    "igmp": check_igmp,
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
)


def per_ssid_checks(case: Case) -> list[tuple[str, Callable[[Case], str]]]:
    checks = [(f.__name__.replace("check_", "").replace("_", " "), f)
              for f in ALWAYS_PER_SSID]
    special = PER_SSID.get(case.example.name)
    if special:
        checks.append((case.example.name, special))
    return checks


def ap_side_checks(case: Case) -> list[tuple[str, Callable[[Case], str]]]:
    checks = []
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
