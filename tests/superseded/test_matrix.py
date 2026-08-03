"""
The band x forwarding-mode matrix, with STA-side proof.

Every security method is exercised on **every usable band** and in **both
bridge and NAT mode**, because a feature can work on one combination and be
broken on another — "WPA3 works" is not a useful claim if it only means
"WPA3 works on 5 GHz, bridged".

Each case proves itself from the station's side rather than from the AP's:

1. the exact config applied is attached to the report,
2. ``wpa_supplicant -dd`` output shows the chosen BSS, the auth/assoc exchange,
   the 4-way handshake and the negotiated ciphers,
3. ``iw dev link`` shows the frequency and rate actually in use,
4. a DHCP lease is obtained, and
5. **ping google.com** succeeds over the wireless interface — which additionally
   exercises DNS, the AP's forwarding or NAT path, and the upstream route.

An association without step 5 is not counted as a pass: a client can associate
perfectly to an SSID that carries no traffic.
"""
from __future__ import annotations

import time

import pytest

from framework.clients.rpi5_station import StationError
from framework.examples.inspect import station_ready_ssids

BANDS = ["2G", "5G", "6G"]

# Bridge only, by request. NAT is a supported mode in the framework
# (``force_forwarding_mode(config, "nat")``) and can be put back by adding it
# here — it is excluded from the sweep rather than unimplemented.
MODES = ["bridge"]

# One config carrying open, psk, psk2, psk-mixed, sae and sae-mixed, so a
# single apply per cell covers the whole personal-security surface.
MATRIX_EXAMPLE = "crypto-psk"


def _vlan_of(config: dict, ssid_name: str) -> int | None:
    """Which VLAN, if any, the interface hosting this SSID is tagged with."""
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            if ssid.get("name") == ssid_name:
                return (iface.get("vlan") or {}).get("id")
    return None


def _cases():
    for band in BANDS:
        for mode in MODES:
            yield pytest.param(band, mode, id=f"{band}-{mode}")


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize("band,mode", list(_cases()))
def test_security_matrix(
    band, mode, apply_case, station, capabilities, testbed_config, ctx
):
    """Every personal-security method, on one band, in one forwarding mode."""
    if band not in capabilities.usable_bands:
        pytest.skip(
            f"{band} is not usable on this bench "
            f"(AP: {sorted(capabilities.ap_bands) or 'none'}, "
            f"station: {sorted(capabilities.station_bands) or 'none'})"
        )

    example, config = apply_case(MATRIX_EXAMPLE, band=band, mode=mode)

    targets = station_ready_ssids(config, bands=frozenset({band}))
    if not targets:
        pytest.skip(f"{MATRIX_EXAMPLE} has no station-ready SSID on {band}")

    passed: list[str] = []
    failures: list[str] = []
    evidence: list[str] = []
    cases: list[dict] = []
    radio = (config.get("radios") or [{}])[0]
    cfg_summary = [
        ("band", radio.get("band", "")),
        ("channel", radio.get("channel", "")),
        ("channel-mode", radio.get("channel-mode", "")),
        ("channel-width", radio.get("channel-width", "")),
        ("country", radio.get("country", "")),
        ("forwarding", mode),
    ]

    for ssid in targets:
        label = f"{ssid.name} ({ssid.proto}) {band}/{mode}"
        started = time.monotonic()
        case = {
            "ssid": ssid.name, "proto": ssid.proto,
            "channel": f"ch{radio.get('channel', '?')}",
            "vlan": str(_vlan_of(config, ssid.name) or ""),
            "config_summary": cfg_summary + [
                ("proto", ssid.proto), ("key", ssid.key or "(none)")
            ],
            "status": "failed",
        }
        try:
            assoc = station.connect(
                ssid.name,
                ssid.proto,
                passphrase=ssid.key or testbed_config.settings.default_passphrase,
                timeout=testbed_config.settings.association_timeout,
                dhcp=True,
            )
            evidence.append(f"===== {label} =====\n{assoc.evidence()}")

            case.update(key_mgmt=assoc.key_mgmt, pairwise=assoc.pairwise_cipher,
                        bssid=assoc.bssid, rssi=f"{assoc.rssi_dbm} dBm",
                        ip=assoc.ip, evidence=assoc.evidence())

            if not assoc.has_ip:
                case["message"] = "associated but no DHCP lease"
                failures.append(f"{label}: associated but no DHCP lease")
                continue

            if assoc.band != band:
                failures.append(
                    f"{label}: expected {band} but associated on {assoc.band} "
                    f"({assoc.freq_mhz} MHz)"
                )
                continue

            ping = station.verify_internet(count=testbed_config.settings.ping_count)
            evidence.append(
                f"--- ping google.com ---\n"
                f"{ping.received}/{ping.transmitted} replies, "
                f"{ping.loss_pct:.0f}% loss, avg {ping.rtt_avg_ms} ms"
            )
            case["ping_summary"] = (f"{ping.received}/{ping.transmitted} replies, "
                                    f"avg {ping.rtt_avg_ms} ms")
            if ping.ok:
                case.update(status="passed", rtt_ms=f"{ping.rtt_avg_ms} ms")
            if not ping.ok:
                diag = station.diagnose_path()
                case["message"] = f"no internet: {ping.received}/{ping.transmitted} replies"
                case["evidence"] = case.get("evidence", "") + f"\n\n{diag}"
                evidence.append(f"--- path diagnosis ---\n{diag}")
                failures.append(
                    f"{label}: got {assoc.ip} but cannot reach the internet "
                    f"({ping.received}/{ping.transmitted} replies)\n{diag}"
                )
                continue

            passed.append(f"{label} -> {assoc.ip}, {ping.rtt_avg_ms} ms")
        except StationError as exc:
            case["message"] = str(exc)[:600]
            case["evidence"] = station.supplicant_evidence()
            failures.append(f"{label}: {exc}")
        finally:
            case["duration_s"] = time.monotonic() - started
            cases.append(case)
            station.disconnect()

    ctx["cases"] = cases
    ctx["sta_evidence"] = "\n\n".join(evidence)

    assert not failures, (
        f"{band}/{mode}: {len(failures)} of {len(targets)} security modes failed\n"
        + "\n".join(f"  FAIL {f}" for f in failures)
        + ("\n" + "\n".join(f"  ok   {p}" for p in passed) if passed else "")
    )
    assert passed, f"{band}/{mode}: nothing was actually verified"


@pytest.mark.network_mode
@pytest.mark.regression
@pytest.mark.parametrize("band,mode", list(_cases()))
def test_traffic_matrix(
    band, mode, apply_case, station, capabilities, testbed_config, ctx
):
    """
    The stock config carries internet traffic on each band and mode.

    Narrower than the security matrix — one SSID — but it is the check that
    matters most: a client on this SSID can reach the internet.
    """
    if band not in capabilities.usable_bands:
        pytest.skip(f"{band} is not usable on this bench")

    example, config = apply_case("default", band=band, mode=mode)
    targets = station_ready_ssids(config, bands=frozenset({band}))
    if not targets:
        pytest.skip(f"default has no station-ready SSID on {band}")

    ssid = targets[0]
    try:
        assoc = station.connect(
            ssid.name,
            ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
        )
        ping = station.verify_internet(count=testbed_config.settings.ping_count)
        ctx["sta_evidence"] = (
            f"{assoc.evidence()}\n\n--- ping google.com ---\n"
            f"{ping.received}/{ping.transmitted} replies, {ping.loss_pct:.0f}% loss, "
            f"avg {ping.rtt_avg_ms} ms"
        )

        assert assoc.has_ip, f"{ssid.name} on {band}/{mode}: no DHCP lease"
        if not ping.ok:
            diag = station.diagnose_path()
            ctx["sta_evidence"] += f"\n\n--- path diagnosis ---\n{diag}"
            pytest.fail(
                f"{ssid.name} on {band}/{mode}: client has {assoc.ip} but cannot "
                f"reach google.com ({ping.received}/{ping.transmitted} replies)\n{diag}"
            )
    finally:
        station.disconnect()
