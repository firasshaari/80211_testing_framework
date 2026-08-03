"""
Baseline connectivity and rate limiting.

These are the tests that prove the link carries traffic, not just that it forms.
Throughput assertions need an iperf3 server declared under ``external:``; without
one they skip rather than silently passing on association alone.
"""
from __future__ import annotations

import pytest

from framework.examples.inspect import station_ready_ssids

# Shaping is never exact — allow generous headroom so the test flags a broken
# limiter rather than ordinary variance.
RATE_LIMIT_TOLERANCE = 1.35


def _first_ssid(config, capabilities):
    targets = station_ready_ssids(config, bands=capabilities.usable_bands)
    if not targets:
        pytest.skip("No station-ready SSID on a usable band")
    return targets[0]


@pytest.mark.regression
@pytest.mark.services
def test_default_config_association_and_dhcp(
    apply_example, station, capabilities, testbed_config
):
    """The stock example produces a working, addressable link."""
    applied, config = apply_example("default")
    ssid = _first_ssid(config, capabilities)
    try:
        assoc = station.connect(
            ssid.name,
            ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
        )
        assert assoc.has_ip, f"Associated to {ssid.name} but got no DHCP lease"
        assert assoc.band in capabilities.usable_bands, (
            f"Associated on {assoc.band}, which is not in the usable band set "
            f"{sorted(capabilities.usable_bands)}"
        )
    finally:
        station.disconnect()


@pytest.mark.regression
@pytest.mark.services
def test_client_passes_traffic(
    apply_example, station, capabilities, testbed_config
):
    """The associated client can actually move data to the iperf3 server."""
    if not capabilities.has_iperf_server:
        pytest.skip("No iperf3 server declared under external.iperf_server")

    applied, config = apply_example("default")
    ssid = _first_ssid(config, capabilities)
    server = testbed_config.external.iperf_server
    try:
        assoc = station.connect(
            ssid.name,
            ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
        )
        assert assoc.has_ip, "No DHCP lease, cannot test throughput"

        result = station.iperf3(
            server,
            direction="downstream",
            duration_s=testbed_config.settings.traffic_duration_s,
        )
        assert result.mbps > 1.0, (
            f"Downstream throughput was {result.mbps:.2f} Mbps on {assoc.band} — "
            f"the link formed but is not carrying traffic"
        )
    finally:
        station.disconnect()


@pytest.mark.rate_limit
@pytest.mark.regression
def test_rate_limit_is_enforced(
    apply_example, station, capabilities, testbed_config
):
    """
    Measured throughput stays near the configured cap.

    The example's own declared rate is the expectation, so this keeps working if
    upstream changes the numbers.
    """
    if not capabilities.has_iperf_server:
        pytest.skip("No iperf3 server declared under external.iperf_server")

    applied, config = apply_example("rate-limit")
    ssid = _first_ssid(config, capabilities)

    limit_mbps = _declared_downstream_limit(config)
    if limit_mbps is None:
        pytest.skip("rate-limit example declares no downstream egress rate to check")

    server = testbed_config.external.iperf_server
    try:
        assoc = station.connect(
            ssid.name,
            ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
        )
        assert assoc.has_ip, "No DHCP lease, cannot measure shaping"

        result = station.iperf3(
            server,
            direction="downstream",
            duration_s=max(testbed_config.settings.traffic_duration_s, 10),
        )
        ceiling = limit_mbps * RATE_LIMIT_TOLERANCE
        assert result.mbps <= ceiling, (
            f"Downstream shaped to {limit_mbps} Mbps but measured "
            f"{result.mbps:.1f} Mbps (ceiling {ceiling:.1f} Mbps) — limiter not applied"
        )
        assert result.mbps > 0.5, (
            f"Measured {result.mbps:.2f} Mbps — the limiter blocked traffic entirely "
            f"rather than shaping it"
        )
    finally:
        station.disconnect()


def _declared_downstream_limit(config: dict) -> float | None:
    """Find an egress rate in the config, in Mbps. uCentral declares these in Mbps."""
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            limit = ssid.get("rate-limit") or {}
            rate = limit.get("egress-rate") or limit.get("downstream")
            if rate:
                return float(rate)
    return None
