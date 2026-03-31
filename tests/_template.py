"""
TEST SCRIPT TEMPLATE — copy this file to create a new test.

Naming convention: test_{security}_{mode}_{metric}_{band}.py
Example:          test_wpa3_bridge_downstream_10mbps_5g.py

Steps:
  1. Copy this file into the appropriate tests/ subdirectory
  2. Update the module docstring
  3. Update the allure metadata (epic, feature, story, title, severity)
  4. Update the capability markers (@requires_*)
  5. Update pytest markers (@pytest.mark.*)
  6. Write the test body — use `with step(...)` blocks for allure steps
  7. Run: pytest tests/<subdir>/test_your_new_test.py -v -s

DO NOT modify conftest.py, framework/, or pytest.ini.
"""
import pytest
import allure

# Framework imports — use these, don't import pytest fixtures directly
from framework.markers                 import requires_two_endpoints  # change as needed
from framework.ap.config_loader        import load_ap_config  # preferred: load from JSON template
# from framework.ap.config_builder    import ConfigBuilder    # alternative: build programmatically
from framework.reporting.allure_helper import (
    attach_ap_config,
    attach_traffic_result,
    attach_ssid_scan,
    attach_ucentral_status,
    step,
)

# ── Allure Metadata ────────────────────────────────────────────────────────────
@allure.epic("Category")           # e.g. "Rate Limiting", "Connectivity", "Capacity"
@allure.feature("Sub-feature")     # e.g. "Per-SSID Rate Limiting"
@allure.story("Security mode")     # e.g. "WPA2 Personal - Bridge Mode"
@allure.title("Short test title")
@allure.severity(allure.severity_level.NORMAL)

# ── Capability Requirement ─────────────────────────────────────────────────────
@requires_two_endpoints            # replace with appropriate marker(s)

# ── pytest Markers ─────────────────────────────────────────────────────────────
@pytest.mark.connectivity          # replace with appropriate category marker
@pytest.mark.wpa2_personal
@pytest.mark.bridge
@pytest.mark.fiveg

# ── Test Function ──────────────────────────────────────────────────────────────
def test_template(ap, traffic_engine):
    """
    Describe what this test verifies in one sentence.

    Steps:
      1. ...
      2. ...
    """
    ssid     = "test-ssid"
    password = "testpass123"

    with step("Build and push AP config"):
        # Load your AP config JSON file and substitute ${VAR} placeholders.
        # Place JSON files under configs/ap/<category>/<name>.json.
        # String vars keep their JSON quotes; int/float/bool vars replace
        # the surrounding quotes so JSON types are preserved:
        #   "egress-rate": "${RATE_KBPS}"  +  RATE_KBPS=10000  →  "egress-rate": 10000
        config = load_ap_config(
            "configs/ap/<category>/<your_config>.json",
            vars={"SSID": ssid, "PASSWORD": password},
        )
        attach_ap_config(config)
        ap.push_config(config)

    with step("Verify AP connected to controller"):
        status = ap.wait_for_state("connected", timeout=30)
        attach_ucentral_status(status)

    with step("Connect client"):
        handle = traffic_engine.connect_client(
            ssid=ssid, password=password, band="5G", security="wpa2",
        )
        assert handle.ip is not None, "Client did not get an IP address"

    with step("Verify SSID in scan"):
        ssids = traffic_engine.scan_ssids()
        attach_ssid_scan(ssids)
        assert ssid in [s.ssid for s in ssids], \
            f"SSID '{ssid}' not visible. Seen: {[s.ssid for s in ssids]}"

    with step("Run traffic and assert"):
        result = traffic_engine.run_traffic(
            handle=handle, direction="downstream",
            protocol="udp", duration_s=10, target_rate_mbps=100.0,
        )
        attach_traffic_result(result)
        assert result.rx_throughput_mbps > 0, "No traffic received"
