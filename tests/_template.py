"""
TEST SCRIPT TEMPLATE — copy this file to create a new test.

Most coverage does NOT need a new file. The regression sweep is driven by
``framework/examples/catalog.py``, so adding an upstream example to the catalog
gives you apply, SSID-bring-up and (where relevant) association coverage for
free. Write a file like this one only when an example needs a *bespoke
assertion* — something beyond "it applied and a client could associate".

Steps:
  1. Copy into tests/regression/ as test_<feature>.py
  2. Pick the right area marker (must exist in pytest.ini)
  3. Use the `apply_example` fixture — it normalizes, applies and fails with the
     renderer's own error text if the AP rejects the config
  4. Derive SSIDs from the config you applied rather than hardcoding names
  5. Run: pytest tests/regression/test_your_test.py -v --testbed-config config/testbed.yaml

DO NOT modify conftest.py, framework/ or pytest.ini.
"""
from __future__ import annotations

import allure
import pytest

from framework.examples.inspect import station_ready_ssids
from framework.reporting.allure_helper import (
    attach_ap_log,
    attach_association,
    step,
)


@allure.epic("Feature area")
@allure.feature("Specific behaviour")
@allure.title("What this proves")
@allure.severity(allure.severity_level.NORMAL)
@pytest.mark.security          # an area marker from pytest.ini
@pytest.mark.regression        # include in the standard sweep
def test_template(apply_example, station, ap, capabilities, testbed_config):
    """
    One sentence on what this verifies.

    Hardware requirements are NOT declared here — they come from the catalog
    entry for the example, and the framework skips with a reason naming what is
    missing.
    """
    with step("Apply the example config"):
        # Raises/fails with the renderer's error detail when the AP rejects it.
        example, config = apply_example("crypto-psk")

    with step("Pick an SSID this bench can actually reach"):
        targets = station_ready_ssids(config, bands=capabilities.usable_bands)
        if not targets:
            pytest.skip("No station-ready SSID on a usable band")
        ssid = targets[0]

    try:
        with step(f"Associate to {ssid.name}"):
            assoc = station.connect(
                ssid.name,
                ssid.proto,
                passphrase=ssid.key or testbed_config.settings.default_passphrase,
                timeout=testbed_config.settings.association_timeout,
            )
            attach_association(assoc)
            assert assoc.has_ip, f"Associated to {ssid.name} but got no DHCP lease"

        with step("Assert the behaviour this test exists for"):
            # Replace with the real assertion. Say what went wrong and with
            # which values — the message lands in the HTML report verbatim.
            clients = ap.associated_clients()
            assert any(c["mac"] == assoc.mac.lower() for c in clients), (
                f"Station {assoc.mac} has an IP but the AP does not list it as "
                f"associated. AP sees: {[c['mac'] for c in clients]}"
            )
    finally:
        attach_ap_log(ap.logread(200))
        station.disconnect()
