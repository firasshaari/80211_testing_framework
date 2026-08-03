"""
Security-method regression.

The upstream examples are unusually good value here: ``crypto-psk`` alone
declares open, psk, psk2, psk-mixed, sae and sae-mixed as six SSIDs on one
radio, so a single apply covers six association paths. Each SSID in an example
is associated to in turn and the failures are reported together, so one broken
mode does not hide the state of the other five.

Enterprise modes are handled separately because they need credentials the
config does not carry — those come from ``external.radius`` in testbed.yaml.
"""
from __future__ import annotations

import pytest

from framework.clients.rpi5_station import StationError
from framework.examples import catalog
from framework.examples.inspect import iter_ssids, station_ready_ssids

SECURITY_EXAMPLES = [
    pytest.param(e, id=e.name)
    for e in catalog.EXAMPLES
    if e.area in (catalog.Area.SECURITY, catalog.Area.WIFI_GEN)
]


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize("example", SECURITY_EXAMPLES)
def test_personal_security_modes(
    example, apply_example, station, capabilities, testbed_config
):
    """Associate to every personal-security SSID the example declares."""
    applied, config = apply_example(example)

    targets = station_ready_ssids(config, bands=capabilities.usable_bands)
    if not targets:
        pytest.skip(
            f"{applied.name} declares no personal-security SSID usable on "
            f"bands {sorted(capabilities.usable_bands) or 'none'}"
        )

    failures: list[str] = []
    succeeded: list[str] = []

    for ssid in targets:
        try:
            assoc = station.connect(
                ssid.name,
                ssid.proto,
                passphrase=ssid.key or testbed_config.settings.default_passphrase,
                timeout=testbed_config.settings.association_timeout,
                dhcp=True,
            )
            if not assoc.has_ip:
                failures.append(f"{ssid.name} ({ssid.proto}): associated but got no DHCP lease")
            else:
                succeeded.append(f"{ssid.name} ({ssid.proto}) -> {assoc.ip} on {assoc.band}")
        except StationError as exc:
            failures.append(f"{ssid.name} ({ssid.proto}): {exc}")
        finally:
            station.disconnect()

    assert not failures, (
        f"{applied.name}: {len(failures)} of {len(targets)} SSIDs failed\n"
        + "\n".join(f"  FAIL {f}" for f in failures)
        + ("\n" + "\n".join(f"  ok   {s}" for s in succeeded) if succeeded else "")
    )


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize(
    "example",
    [pytest.param(e, id=e.name) for e in catalog.EXAMPLES
     if catalog.Requirement.RADIUS in e.requires
     and e.mode is not catalog.Mode.CONFIG_ONLY],
)
def test_enterprise_security_modes(
    example, apply_example, station, testbed_config, capabilities
):
    """Associate to 802.1X SSIDs using the credentials from testbed.yaml."""
    applied, config = apply_example(example)

    radius = testbed_config.external.radius
    assert radius is not None, "capability gate should have skipped this test"

    targets = [
        s for s in iter_ssids(config)
        if s.enterprise and s.bss_mode == "ap"
        and (not s.bands or set(s.bands) & set(capabilities.usable_bands))
    ]
    if not targets:
        pytest.skip(f"{applied.name} declares no enterprise SSID on a usable band")

    failures: list[str] = []
    for ssid in targets:
        try:
            assoc = station.connect(
                ssid.name,
                ssid.proto,
                identity=radius.identity,
                eap_password=radius.password,
                eap_method=radius.eap_method,
                timeout=testbed_config.settings.association_timeout,
                dhcp=True,
            )
            if not assoc.has_ip:
                failures.append(f"{ssid.name} ({ssid.proto}): authenticated but no DHCP lease")
        except StationError as exc:
            failures.append(f"{ssid.name} ({ssid.proto}): {exc}")
        finally:
            station.disconnect()

    assert not failures, (
        f"{applied.name}: enterprise association failed\n"
        + "\n".join(f"  {f}" for f in failures)
    )


@pytest.mark.security
def test_open_and_encrypted_ssids_differ_in_beacons(
    apply_example, station, capabilities
):
    """
    An open SSID must not advertise RSN, and a WPA2 one must.

    Cheap sanity check that the encryption setting reaches the air rather than
    just the config file — a station can associate to a misconfigured-open BSS
    perfectly happily.
    """
    applied, config = apply_example("crypto-psk")

    by_name = {s.name: s for s in iter_ssids(config)}
    scanned = {r.ssid: r for r in station.scan()}
    visible = set(scanned) & set(by_name)
    if not visible:
        pytest.skip("None of the crypto-psk SSIDs were visible in a scan")

    problems = []
    for name in sorted(visible):
        expected_encrypted = by_name[name].proto not in ("none", "open")
        advertises_rsn = bool(scanned[name].flags)
        if expected_encrypted and not advertises_rsn:
            problems.append(f"{name}: proto={by_name[name].proto} but beacon advertises no RSN/WPA")
        if not expected_encrypted and advertises_rsn:
            problems.append(f"{name}: declared open but beacon advertises {scanned[name].flags}")

    assert not problems, "Beacon security mismatch:\n" + "\n".join(problems)
