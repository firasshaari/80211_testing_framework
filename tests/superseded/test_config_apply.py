"""
Broadest sweep: every catalogued example must render and apply cleanly.

This is the backbone of the regression run. It catches schema drift, renderer
regressions and radio-capability mismatches across the whole feature surface
before any station is involved, and it is the only suite that covers the
config-only examples (switch, 802.1X, LLDP, IGMP) at all.

Applying with ``"strict": true`` is what makes the assertion meaningful — the
renderer otherwise clamps an unsupported request and reports success, so a
green result would not mean the AP is running what the example asked for.
"""
from __future__ import annotations

import pytest

from framework.examples import catalog
from framework.examples.inspect import iter_ssids

ALL_EXAMPLES = [
    pytest.param(
        example,
        marks=[getattr(pytest.mark, example.area.value), pytest.mark.regression],
        id=example.name,
    )
    for example in catalog.EXAMPLES
]


@pytest.mark.parametrize("example", ALL_EXAMPLES)
def test_config_applies(example, apply_example, ap):
    """The AP accepts the example and renders a UCI batch for it."""
    applied, config = apply_example(example)

    batch = ap.rendered_uci()
    assert batch.strip(), (
        f"{applied.name} reported success but /tmp/ucentral.uci is empty — "
        f"nothing was actually rendered"
    )


@pytest.mark.parametrize(
    "example",
    [
        pytest.param(e, marks=[getattr(pytest.mark, e.area.value)], id=e.name)
        for e in catalog.EXAMPLES
        if e.mode is not catalog.Mode.CONFIG_ONLY
    ],
)
def test_ssids_come_up(example, apply_example, ap, capabilities):
    """
    Every SSID the config declares is broadcasting afterwards.

    Only SSIDs on a band this AP actually has are required — a 6 GHz SSID on a
    dual-band AP is a configuration the AP is right to leave down.
    """
    applied, config = apply_example(example)

    expected = {
        s.name
        for s in iter_ssids(config)
        if s.bss_mode == "ap"
        and (not s.bands or set(s.bands) & set(capabilities.ap_bands))
    }
    if not expected:
        pytest.skip(f"{applied.name} declares no SSIDs on bands this AP supports")

    # hostapd brings each BSS up slightly after the radios stop reporting
    # "pending", so poll rather than reading once.
    missing = ap.wait_for_ssids(expected, timeout=60)

    assert not missing, (
        f"{applied.name}: SSID(s) {sorted(missing)} are configured but did not come "
        f"up within 60s. Live SSIDs: {sorted({s['ssid'] for s in ap.ssids()}) or 'none'}"
    )


@pytest.mark.parametrize(
    "example",
    [pytest.param(e, id=e.name) for e in catalog.EXAMPLES
     if e.mode is catalog.Mode.CONFIG_ONLY],
)
@pytest.mark.config_only
def test_config_only_commits_to_uci(example, apply_example, ap):
    """
    Config-only examples have no SSID to observe, so assert on committed UCI.

    ucentral.uc commits its shadow config into /etc/config, so a successful
    apply must leave the wireless package readable and non-empty.
    """
    applied, config = apply_example(example)

    committed = ap.uci_show("wireless")
    assert committed.strip(), (
        f"{applied.name} applied but 'uci show wireless' is empty — "
        f"the shadow config was not committed"
    )
