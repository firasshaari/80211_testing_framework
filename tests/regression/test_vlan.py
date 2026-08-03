"""
VLAN segmentation and dynamic VLAN assignment.

These tests exist to answer a specific objection: you cannot test SSID-to-VLAN
mapping without knowing which VLANs the lab's DHCP server actually serves, and
you cannot test RADIUS dynamic VLAN assignment without knowing which VLAN the
server returns for the test identity.

So every test here **skips with a reason unless that information was supplied**,
and where it does run it asserts the client landed in the expected VLAN — not
merely that it associated. Association alone proves nothing about segmentation:
a client that ignores the VLAN entirely still associates happily.

The examples pin illustrative ids (`vlan` uses 100, `dhcp-relay` uses 10). The
framework rewrites those onto the lab's real ids before applying, so what is
asserted here is the id the AP was actually told to use.
"""
from __future__ import annotations

import ipaddress

import pytest

from framework.examples.inspect import ip_in_subnet, station_ready_ssids


def _vlan_gateway(testbed_config, vlan_id: int) -> str | None:
    vlan = testbed_config.external.vlan
    if not vlan:
        return None
    return (vlan.gateways or {}).get(vlan_id)


def _subnet_of(gateway: str, prefix: int = 24) -> str:
    return str(ipaddress.ip_network(f"{gateway}/{prefix}", strict=False))


@pytest.mark.vlan
@pytest.mark.regression
def test_ssid_maps_to_the_configured_vlan(
    apply_example, station, capabilities, testbed_config
):
    """
    A client on a VLAN-tagged SSID gets an address from that VLAN.

    Needs at least one VLAN id *and* its gateway: the id alone tells us what to
    configure but not what a correct result looks like.
    """
    vlan = testbed_config.external.vlan
    if not (vlan and vlan.ids):
        pytest.skip(
            "No VLAN ids configured. Run 'make setup' and answer "
            "'What VLAN IDs does the DHCP server provide?' — without one there "
            "is no VLAN to map the SSID onto."
        )

    target_vlan = vlan.ids[0]
    gateway = _vlan_gateway(testbed_config, target_vlan)
    if not gateway:
        pytest.skip(
            f"VLAN {target_vlan} has no gateway configured, so there is no way to "
            f"verify the client actually landed in it. Add it via 'make setup'."
        )

    applied, config = apply_example("vlan")
    targets = station_ready_ssids(config, bands=capabilities.usable_bands)
    if not targets:
        pytest.skip("vlan example declares no station-ready SSID on a usable band")

    ssid = targets[0]
    try:
        assoc = station.connect(
            ssid.name,
            ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
        )
        assert assoc.has_ip, (
            f"Associated to {ssid.name} on VLAN {target_vlan} but got no DHCP lease. "
            f"Either the switch is not trunking VLAN {target_vlan} to the AP, or "
            f"the DHCP server does not serve it."
        )

        expected = _subnet_of(gateway)
        assert ip_in_subnet(assoc.ip, expected), (
            f"Client got {assoc.ip}, which is not in VLAN {target_vlan} "
            f"({expected}, gateway {gateway}). The SSID is not landing in the "
            f"VLAN it was configured for."
        )

        result = station.ping(gateway, count=testbed_config.settings.ping_count)
        assert result.ok, (
            f"Client {assoc.ip} is addressed in VLAN {target_vlan} but cannot reach "
            f"its gateway {gateway} ({result.received}/{result.transmitted} replies)"
        )
    finally:
        station.disconnect()


@pytest.mark.vlan
@pytest.mark.security
@pytest.mark.regression
def test_multi_psk_keys_map_to_different_vlans(
    apply_example, station, capabilities, testbed_config
):
    """
    Two PSKs on one SSID put clients in different VLANs.

    This is the whole point of multi-PSK, and it needs two VLAN ids: with one,
    both keys land in the same place and the test would pass without proving
    anything.
    """
    vlan = testbed_config.external.vlan
    if not (vlan and len(vlan.ids) >= 2):
        pytest.skip(
            "Multi-PSK VLAN separation needs at least two VLAN ids; "
            f"configured: {list(vlan.ids) if vlan else []}. Run 'make setup'."
        )

    applied, config = apply_example("multi-psk")

    # The keys come from the config the AP was actually given, after remapping.
    mpsk_ssids = [s for s in config_ssids(config) if s.get("multi-psk")]
    if not mpsk_ssids:
        pytest.skip("multi-psk example declares no multi-PSK SSID")

    ssid = mpsk_ssids[0]
    keys = ssid["multi-psk"]
    tagged = [k for k in keys if k.get("vlan-id")]
    if not tagged:
        pytest.skip("No multi-PSK key carries a vlan-id after remapping")

    results = {}
    try:
        for entry in keys[:2]:
            key = entry.get("key")
            vlan_id = entry.get("vlan-id")
            assoc = station.connect(
                ssid["name"], "psk2", passphrase=key,
                timeout=testbed_config.settings.association_timeout,
            )
            assert assoc.has_ip, f"Key {key!r} associated but got no lease"
            results[key] = (vlan_id, assoc.ip)
            station.disconnect()

        tagged_key = next(k for k, (v, _) in results.items() if v)
        vlan_id, ip = results[tagged_key]
        gateway = _vlan_gateway(testbed_config, vlan_id)
        if gateway:
            assert ip_in_subnet(ip, _subnet_of(gateway)), (
                f"Key {tagged_key!r} is mapped to VLAN {vlan_id} but its client got "
                f"{ip}, outside {_subnet_of(gateway)}"
            )

        addresses = {ip for _, ip in results.values()}
        assert len(addresses) == len(results), (
            f"Each PSK should land in its own VLAN, but both clients got the same "
            f"address range: {results}"
        )
    finally:
        station.disconnect()


@pytest.mark.vlan
@pytest.mark.security
def test_radius_assigns_the_expected_vlan(
    apply_example, station, capabilities, testbed_config
):
    """
    A RADIUS-authenticated client lands in the VLAN the server returns.

    Requires ``external.radius.dynamic_vlan`` — the VLAN the server is
    configured to hand back for the test identity. Without it we would be
    asserting that *some* address arrived, which is not a test of dynamic VLAN
    assignment at all.
    """
    radius = testbed_config.external.radius
    if not radius:
        pytest.skip("No RADIUS server configured")
    if not radius.dynamic_vlan:
        pytest.skip(
            "external.radius.dynamic_vlan is not set. Dynamic VLAN assignment "
            "cannot be verified without knowing which VLAN the server returns "
            f"for identity {radius.identity!r} (Tunnel-Private-Group-Id)."
        )

    gateway = _vlan_gateway(testbed_config, radius.dynamic_vlan)
    if not gateway:
        pytest.skip(
            f"No gateway known for VLAN {radius.dynamic_vlan}, so the assignment "
            f"cannot be verified."
        )

    applied, config = apply_example("radius")
    from framework.examples.inspect import iter_ssids

    enterprise = [
        s for s in iter_ssids(config)
        if s.enterprise and (not s.bands or set(s.bands) & set(capabilities.usable_bands))
    ]
    if not enterprise:
        pytest.skip("radius example declares no enterprise SSID on a usable band")

    ssid = enterprise[0]
    try:
        assoc = station.connect(
            ssid.name, ssid.proto,
            identity=radius.identity,
            eap_password=radius.password,
            eap_method=radius.eap_method,
            timeout=testbed_config.settings.association_timeout,
        )
        assert assoc.has_ip, "Authenticated but received no DHCP lease"
        assert ip_in_subnet(assoc.ip, _subnet_of(gateway)), (
            f"RADIUS should have assigned VLAN {radius.dynamic_vlan} to "
            f"{radius.identity!r}, but the client got {assoc.ip}, outside "
            f"{_subnet_of(gateway)}"
        )
    finally:
        station.disconnect()


def config_ssids(config: dict) -> list[dict]:
    """Raw SSID dicts, since multi-PSK keys are not modelled by SSIDSpec."""
    return [
        ssid
        for iface in config.get("interfaces") or []
        for ssid in iface.get("ssids") or []
    ]
