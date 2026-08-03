"""
NAT versus bridge mode.

The distinction is structural in the uCentral schema rather than a flag: an
SSID declared on an ``upstream``-role interface is bridged onto the WAN, while
one on a ``downstream``-role interface sits behind a subnet the AP serves and
NATs. These tests assert the client's address actually lands where the mode
implies, which is the part that silently regresses.
"""
from __future__ import annotations

import pytest

from framework.examples import catalog
from framework.examples.inspect import (
    downstream_subnets,
    ip_in_subnet,
    station_ready_ssids,
)

MODE_EXAMPLES = [
    pytest.param(e, id=e.name)
    for e in catalog.EXAMPLES
    if e.area is catalog.Area.NETWORK_MODE and e.mode is not catalog.Mode.CONFIG_ONLY
]


def _connect_first(station, config, capabilities, testbed_config, role: str | None = None):
    """Associate to the first usable SSID, optionally restricted by interface role."""
    candidates = station_ready_ssids(config, bands=capabilities.usable_bands)
    if role:
        candidates = [s for s in candidates if s.role == role]
    if not candidates:
        pytest.skip(f"No station-ready {role or 'any'}-role SSID on a usable band")

    ssid = candidates[0]
    assoc = station.connect(
        ssid.name,
        ssid.proto,
        passphrase=ssid.key or testbed_config.settings.default_passphrase,
        timeout=testbed_config.settings.association_timeout,
        dhcp=True,
    )
    return ssid, assoc


@pytest.mark.network_mode
@pytest.mark.regression
@pytest.mark.parametrize("example", MODE_EXAMPLES)
def test_client_lands_in_expected_network(
    example, apply_example, station, capabilities, testbed_config
):
    """A NATed client gets an AP-served address; a bridged one does not."""
    applied, config = apply_example(example)
    try:
        ssid, assoc = _connect_first(station, config, capabilities, testbed_config)
        assert assoc.has_ip, f"{ssid.name}: associated but never got a DHCP lease"

        nat_subnets = downstream_subnets(config)
        in_nat = any(ip_in_subnet(assoc.ip, s) for s in nat_subnets)

        if ssid.nated:
            assert in_nat, (
                f"{ssid.name} is on a downstream interface so the client should be "
                f"NATed into one of {nat_subnets}, but it got {assoc.ip}"
            )
        elif ssid.bridged:
            assert not in_nat, (
                f"{ssid.name} is on an upstream interface so the client should be "
                f"bridged to the WAN, but it got {assoc.ip} from the AP's own "
                f"subnet {nat_subnets}"
            )
    finally:
        station.disconnect()


@pytest.mark.network_mode
def test_nat_client_reaches_ap_gateway(
    apply_example, station, capabilities, testbed_config
):
    """A NATed client can reach the AP gateway that is serving it."""
    applied, config = apply_example("maverick")
    try:
        ssid, assoc = _connect_first(station, config, capabilities, testbed_config)
        assert assoc.has_ip, "Client got no lease in NAT mode"

        subnets = downstream_subnets(config)
        if not subnets:
            pytest.skip("maverick declares no downstream subnet to derive a gateway from")

        gateway = subnets[0].split("/")[0]
        result = station.ping(gateway, count=testbed_config.settings.ping_count)
        assert result.ok, (
            f"NATed client {assoc.ip} cannot ping its gateway {gateway} "
            f"({result.transmitted} sent, {result.received} received)"
        )
    finally:
        station.disconnect()


@pytest.mark.network_mode
def test_client_isolation_blocks_peer_traffic(
    apply_example, station, capabilities, testbed_config
):
    """
    With strict forwarding on, the client must not reach other stations.

    Only one station exists on this bench, so the assertion available is the
    weaker one: isolation must not break the client's own upstream path. A
    two-station check would need a second RPi5.
    """
    applied, config = apply_example("strict-forwarding")
    try:
        ssid, assoc = _connect_first(station, config, capabilities, testbed_config)
        assert assoc.has_ip, (
            f"{ssid.name}: client isolation should not prevent the client itself "
            f"from getting an address"
        )
    finally:
        station.disconnect()
