"""
One test per example, per band. One result, reported through Allure.

Applying a config, the SSIDs coming up, a client associating and that client
reaching the internet are steps of one test, not four tests. Each case runs them
in order and stops at the first failure, because every later step depends on the
one before it — there is nothing to learn from trying to associate to an SSID
that never came up.

Each step is an ``allure.step``, so the report shows exactly how far a case got,
and the config, station evidence and logs are attached to the step that produced
them. Failure classification is handled by ``allure-categories/categories.json``
rather than by anything here.
"""
from __future__ import annotations

import allure
import pytest

from framework.clients.rpi5_station import StationError
from framework.examples import catalog
from framework.examples.inspect import iter_ssids, station_ready_ssids

BANDS = ["2G", "5G", "6G"]

# Readable names for the feature level of the report hierarchy.
_AREA_LABELS = {
    "security": "Security", "network_mode": "Forwarding",
    "rate_limit": "Rate limiting", "qos": "Quality of service",
    "roaming": "Roaming and steering", "captive": "Captive portal",
    "vlan": "VLAN", "tunnel": "Tunnels and mesh", "services": "On-AP services",
    "telemetry": "Telemetry", "switch": "Switch fabric",
    "wifi_gen": "6 GHz and Wi-Fi 7", "wwan": "Cellular uplink",
}

# Bridge only, by request. NAT is implemented (force_forwarding_mode) and can be
# reinstated by extending this.
MODE = "bridge"


def _cases():
    """
    Parametrize on the example *name*, not the object.

    Allure records the parametrize arguments verbatim, and a dataclass repr
    lands in the report as 300-odd characters of noise. The name is what a
    reader recognises; the catalog entry is looked up inside the test.
    """
    for example in catalog.EXAMPLES:
        for band in BANDS:
            yield pytest.param(
                example.name, band,
                marks=[getattr(pytest.mark, example.area.value), pytest.mark.regression],
                id=f"{example.name}-{band}",
            )


@allure.epic("OpenWiFi regression")
@pytest.mark.parametrize("example_name,band", list(_cases()))
def test_example(example_name, band, apply_case, ap, station, capabilities,
                 testbed_config, ctx):
    """Apply one upstream example on one band and verify it end to end."""
    example = catalog.get(example_name)
    # epic > feature > story gives the report a hierarchy that means something:
    # "Security > Enterprise — external RADIUS > Baseline WPA2 Enterprise",
    # rather than a flat list of example filenames.
    allure.dynamic.feature(_AREA_LABELS.get(example.area.value,
                                            example.area.value.title()))
    allure.dynamic.story(catalog.group_of(example))
    allure.dynamic.title(f"{example.summary} · {band}")
    allure.dynamic.description(
        f"**{example.name}** — {example.summary}\n\n"
        f"- Area: {example.area.value.replace('_', ' ')}\n"
        f"- Group: {catalog.group_of(example)}\n"
        f"- Band: {band}, forwarding: {MODE}\n"
        f"- Needs: {', '.join(sorted(r.value for r in example.requires)) or 'AP only'}"
    )
    for tag in (band, MODE, example.area.value):
        allure.dynamic.tag(tag)

    if band not in capabilities.usable_bands:
        pytest.skip(
            f"{band} unusable here — testbed lacks it "
            f"(AP {sorted(capabilities.ap_bands) or 'none'}, "
            f"station {sorted(capabilities.station_bands) or 'none'})"
        )

    # ── 1. the AP accepts and renders the config ─────────────────────────────
    with allure.step(f"Apply {example.name} on {band}"):
        applied, config = apply_case(example, band=band, mode=MODE)

    # ── 2. the SSIDs it declares are on the air ──────────────────────────────
    expected = {
        s.name for s in iter_ssids(config)
        if s.bss_mode == "ap" and (not s.bands or band in s.bands)
    }
    if expected:
        with allure.step(f"{len(expected)} SSID(s) come up"):
            missing = ap.wait_for_ssids(expected, timeout=60)
            allure.attach(
                "\n".join(sorted(expected)), "SSIDs configured",
                allure.attachment_type.TEXT,
            )
            assert not missing, (
                f"{', '.join(sorted(missing))} configured but not broadcasting"
            )

    # ── 3. the station can join ──────────────────────────────────────────────
    targets = station_ready_ssids(config, bands=frozenset({band}))
    if not targets:
        allure.dynamic.parameter("client", "no SSID this station can join unaided")
        return

    joined, failed = [], []
    with allure.step(f"Client connects ({len(targets)} SSID(s))"):
        for ssid in targets:
            try:
                assoc = station.connect(
                    ssid.name, ssid.proto,
                    passphrase=ssid.key or testbed_config.settings.default_passphrase,
                    timeout=testbed_config.settings.association_timeout,
                )
                if not assoc.has_ip:
                    failed.append(f"{ssid.name} ({ssid.proto}): no DHCP lease")
                else:
                    joined.append((ssid, assoc))
                    allure.attach(
                        assoc.evidence(), f"{ssid.name} — station evidence",
                        allure.attachment_type.TEXT,
                    )
            except StationError as exc:
                failed.append(f"{ssid.name} ({ssid.proto}): {_brief(exc)}")
                allure.attach(
                    station.supplicant_evidence(),
                    f"{ssid.name} — wpa_supplicant", allure.attachment_type.TEXT,
                )
            finally:
                if not joined:
                    station.disconnect()
        assert joined, "; ".join(failed)

    # ── 4. that client can actually use the network ──────────────────────────
    ssid, assoc = joined[0]
    try:
        with allure.step(f"Client reaches the internet from {assoc.ip}"):
            ping = station.verify_internet(count=testbed_config.settings.ping_count)
            allure.attach(
                f"{ping.received}/{ping.transmitted} replies, "
                f"{ping.loss_pct:.0f}% loss, avg {ping.rtt_avg_ms} ms",
                "ping google.com", allure.attachment_type.TEXT,
            )
            if not ping.ok:
                allure.attach(
                    station.diagnose_path(), "path diagnosis",
                    allure.attachment_type.TEXT,
                )
            assert ping.ok, (
                f"got {assoc.ip} but cannot reach the internet "
                f"({ping.received}/{ping.transmitted} replies)"
            )
    finally:
        station.disconnect()

    if failed:
        pytest.fail(
            f"reached the internet, but {len(failed)} of {len(targets)} SSIDs "
            f"did not connect\n  " + "\n  ".join(failed)
        )


def _brief(exc: Exception) -> str:
    """First meaningful line — station errors carry long scan dumps."""
    text = str(exc)
    for marker in ("Visible SSIDs:", "\n"):
        if marker in text:
            text = text.split(marker)[0]
    return text.strip()[:160]
