"""The documentation the console shows, derived from the code it documents.

A hand-written page listing "what each test validates" is wrong the day someone
adds a validator. So the table is generated: it walks ``catalog.EXAMPLES`` and
the registries in ``tests/regression/validators.py``. Register a new check and
it appears here with no edit to any template — and, just as importantly, a check
that is *removed* stops being claimed.

Prose that genuinely is prose — what a check means, why it exists — lives in
``CHECK_NOTES`` below, keyed by function name. A check with no note still shows
up, labelled as undocumented, because silently omitting it would be the exact
failure this module exists to prevent.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

from framework.examples import catalog
from framework.examples.inspect import iter_ssids
from framework.examples.loader import load_example
from framework.reporting.html_report import AREA_LABELS      # imported, not re-declared


def _validators():
    """``tests/`` is not an installed package, so it is imported by path."""
    repo = Path(__file__).resolve().parent.parent
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))
    return importlib.import_module("tests.regression.validators")


# The five that run on every case that gets a client associated, plus the SSH
# service check that runs almost everywhere.
UNIVERSAL = ("negotiated encryption", "forwarding mode", "vlan placement",
             "radio settings", "regulatory domain", "ssh service")

CHECK_NOTES: dict[str, str] = {
    "check_negotiated_encryption":
        "What the client actually negotiated matches the proto the config asked for, and "
        "WPA3/PSK2/SAE never negotiate TKIP. An AP that quietly brings a WPA3 SSID up as "
        "WPA2 passes connect-and-traffic without complaint.",
    "check_forwarding_mode":
        "A bridged client sits on the upstream network and a NATed one behind the AP — "
        "judged from the address DHCP handed out. A bridged client must also never land on "
        "the management subnet.",
    "check_radio_settings":
        "The radio is on the configured channel, mode and width, not something it quietly "
        "fell back to. A radio that dropped to ACS serves clients perfectly well while the "
        "case stops testing the band plan it was written for.",
    "check_vlan_placement":
        "An SSID configured on a tagged VLAN has a matching bridge-vlan rendered on the AP.",
    "check_regulatory_domain":
        "The country the config pins is the one the radio is enforcing. Channel and power "
        "limits differ between domains, so results stop being comparable if this drifts.",
    "check_rate_limit":
        "Measured, not read back. iperf3 from a wired peer on the client's own VLAN; fails "
        "if throughput exceeds 2.5x the cap. The headroom is deliberate — a shaper grants "
        "burst allowance on a short transfer, and what this must catch is a limit that "
        "never took effect at all.",
    "check_qos_dscp_mapping":
        "Sends DSCP 0, 32 and 48 from the wired peer and reads the client's per-TID "
        "counters. The TID that moved must map to the expected WMM access category, so it "
        "proves the AP's classifier acted rather than that it was configured.",
    "check_rrm_elements":
        "The station scans and reads the beacon, which must advertise the Radio Measurement "
        "capability. An AP with 802.11k configured but not advertised leaves every client "
        "unaware the feature exists.",
    "check_radius_accepted":
        "The lab RADIUS server logged an Access-Accept for this station's MAC. A client can "
        "associate to an enterprise SSID for reasons unrelated to the backend, so "
        "server-side confirmation is what proves the RADIUS path was exercised.",
    "check_dynamic_vlan":
        "The VLAN assigned at authentication time is the one the client lands in. Invisible "
        "to every other check — the client passes traffic identically either way.",
    "check_block_rfc1918":
        "The one check where success means traffic must fail: a private destination "
        "unreachable while the internet stays reachable, so a dead link cannot masquerade "
        "as a working filter.",
    "check_telemetry":
        "The daemon that produces the data is alive and the requested metrics were accepted. "
        "Delivery to the controller is deliberately not asserted — the uCentral agent is "
        "disabled by design, so claiming it would be theatre.",
    "check_fingerprint": "The requested fingerprint mode is accepted and the collector is running.",
    "check_dhcp_snooping": "The collector that would report snooped DHCP is alive.",
    "check_igmp": "IGMP snooping reached a real bridge in the rendered network config.",
    "check_ntp": "Every configured NTP server is in the AP's system config and ntpd is running.",
    "check_lldp": "The configured description reached lldpd's config and the daemon is running.",
    "check_ssh_service": "Something is genuinely listening on the configured SSH port.",
    "check_admin_ui": "uhttpd is running to serve the admin UI.",
    "check_online_check":
        "The AP can reach at least one of the hosts it was told to watch, from the AP. If it "
        "cannot, the feature declares itself offline and the case looks like an AP fault "
        "when it is the bench's own connectivity.",
}


def _pretty(func) -> str:
    return func.__name__.replace("check_", "").replace("_", " ")


def check_catalogue() -> list[dict]:
    """Every registered check, with where it applies and what it asserts."""
    v = _validators()
    seen: dict[str, dict] = {}

    def add(func, scope: str, applies: str):
        entry = seen.setdefault(func.__name__, {
            "name": _pretty(func),
            "func": func.__name__,
            "scope": scope,
            "applies": [],
            "note": CHECK_NOTES.get(func.__name__) or (
                (func.__doc__ or "").strip().splitlines()[0] if func.__doc__
                else "Not documented yet — add a note in benchd/docsgen.py."),
            "documented": func.__name__ in CHECK_NOTES,
        })
        entry["applies"].append(applies)

    for f in v.ALWAYS_PER_SSID:
        add(f, "per SSID", "every case with a client")
    for f in v.ALWAYS_AP_SIDE:
        add(f, "AP side", "every case")
    for name, f in sorted(v.PER_SSID.items()):
        add(f, "per SSID", name)
    for area, f in sorted(v.PER_SSID_BY_AREA.items()):
        add(f, "per SSID", f"{area} examples with an enterprise SSID")
    for name, f in sorted(v.AP_SIDE.items()):
        add(f, "AP side", name)
    for area, f in sorted(v.AP_SIDE_BY_AREA.items()):
        add(f, "AP side", f"all {area} examples")

    return sorted(seen.values(), key=lambda e: (e["scope"] != "per SSID", e["name"]))


def validation_rows() -> list[dict]:
    """One row per catalogued example: what it is, and what proves it works."""
    v = _validators()
    rows = []
    for ex in catalog.EXAMPLES:
        try:
            cfg = load_example(ex.name)
            ssids = iter_ssids(cfg)
        except Exception:                                         # noqa: BLE001
            cfg, ssids = {}, []

        enterprise = any(getattr(s, "enterprise", False) for s in ssids)
        extra: list[str] = []
        if ex.name in v.PER_SSID:
            extra.append(_pretty(v.PER_SSID[ex.name]))
        if ex.area.value in v.PER_SSID_BY_AREA and enterprise:
            extra.append(_pretty(v.PER_SSID_BY_AREA[ex.area.value]))
        if ex.name in v.AP_SIDE:
            extra.append(_pretty(v.AP_SIDE[ex.name]))
        if ex.area.value in v.AP_SIDE_BY_AREA:
            extra.append(_pretty(v.AP_SIDE_BY_AREA[ex.area.value]))

        rows.append({
            "name": ex.name,
            "area": ex.area.value,
            "area_label": AREA_LABELS.get(ex.area.value, ex.area.value.title()),
            "group": catalog.group_of(ex),
            "mode": "config only" if ex.mode.value == "config_only" else ex.mode.value,
            "summary": ex.summary,
            "ssids": len(ssids),
            "protos": sorted({s.proto for s in ssids if s.proto and s.proto != "none"}),
            "requires": sorted(r.value for r in ex.requires),
            "extra": sorted(set(extra)),
            "config_only": ex.mode.value == "config_only",
        })
    return sorted(rows, key=lambda r: (r["area_label"], r["name"]))


def summary() -> dict:
    rows = validation_rows()
    return {
        "examples": len(rows),
        "cases": len(rows) * 3,
        "with_extra": sum(1 for r in rows if r["extra"]),
        "universals_only": sum(1 for r in rows if not r["extra"] and r["ssids"]),
        "config_only": sum(1 for r in rows if r["config_only"]),
        "checks": len(check_catalogue()),
        "undocumented": [c["name"] for c in check_catalogue() if not c["documented"]],
    }
