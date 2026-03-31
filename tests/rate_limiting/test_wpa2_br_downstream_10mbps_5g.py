"""
Rate Limiting — WPA2 Personal Bridge — Downstream 10 Mbps — 5 GHz

Verifies that the AP enforces a 10 Mbps downstream per-SSID rate limit
on a WPA2 Personal bridge-mode SSID on 5 GHz.

Run individually:
    pytest tests/rate_limiting/test_wpa2_br_downstream_10mbps_5g.py -v -s \\
        --testbed-config config/testbed.yaml
"""
import pytest
import allure

from framework.markers              import requires_two_endpoints
from framework.ap.config_builder    import ConfigBuilder
from framework.reporting.allure_helper import (
    attach_ap_config,
    attach_traffic_result,
    attach_ssid_scan,
    attach_ucentral_status,
    step,
)

SSID        = "test-ratelimit-wpa2-5g"
PASSWORD    = "testpass123"
LIMIT_MBPS  = 10.0


@allure.epic("Rate Limiting")
@allure.feature("Per-SSID Rate Limiting")
@allure.story("WPA2 Personal - Bridge Mode")
@allure.title("Downstream 10 Mbps rate limit — WPA2 Personal 5 GHz Bridge")
@allure.severity(allure.severity_level.NORMAL)
@requires_two_endpoints
@pytest.mark.rate_limiting
@pytest.mark.wpa2_personal
@pytest.mark.bridge
@pytest.mark.fiveg
@pytest.mark.downstream
def test_wpa2_br_downstream_10mbps_5g(ap, traffic_engine):
    """
    Push a WPA2 Personal SSID with 10 Mbps downstream limit, connect a client,
    send 50 Mbps, and verify the measured throughput is capped at ~10 Mbps.
    """

    with step("Build and push AP config with 10 Mbps downstream rate limit"):
        config = (
            ConfigBuilder()
            .mode("BRIDGE")
            .radio("5G", channel="auto", channel_mode="HE", channel_width=80)
            .ssid(
                name=SSID,
                band="5G",
                security="psk2",
                password=PASSWORD,
                downstream_rate_kbps=int(LIMIT_MBPS * 1000),
            )
            .build()
        )
        attach_ap_config(config)
        ap.push_config(config)

    with step("Verify AP connected to uCentral controller"):
        status = ap.wait_for_state("connected", timeout=30)
        attach_ucentral_status(status, label="after config push")

    with step("Connect client to SSID"):
        handle = traffic_engine.connect_client(
            ssid=SSID, password=PASSWORD, band="5G", security="wpa2",
        )
        assert handle.ip is not None, "Client did not get an IP address"
        allure.attach(
            body=f"Client IP:  {handle.ip}\nClient MAC: {handle.mac}",
            name="Client Info",
            attachment_type=allure.attachment_type.TEXT,
        )

    with step("Verify SSID is visible in RF scan"):
        ssids = traffic_engine.scan_ssids()
        attach_ssid_scan(ssids)
        assert SSID in [s.ssid for s in ssids], \
            f"SSID '{SSID}' not found in scan. Visible: {[s.ssid for s in ssids]}"

    with step(f"Run downstream UDP traffic at 50 Mbps for 30 s (limit = {LIMIT_MBPS} Mbps)"):
        result = traffic_engine.run_traffic(
            handle=handle,
            direction="downstream",
            protocol="udp",
            duration_s=30,
            target_rate_mbps=50.0,
        )
        attach_traffic_result(result)

    with step("Assert rate limit is enforced"):
        upper = LIMIT_MBPS * 1.10
        lower = LIMIT_MBPS * 0.80
        result.passed_threshold = lower <= result.rx_throughput_mbps <= upper

        allure.attach(
            body=(
                f"Measured:  {result.rx_throughput_mbps:.2f} Mbps\n"
                f"Expected:  {lower:.1f} – {upper:.1f} Mbps\n"
                f"Passed:    {result.passed_threshold}"
            ),
            name="Rate Limit Verdict",
            attachment_type=allure.attachment_type.TEXT,
        )

        assert result.rx_throughput_mbps <= upper, (
            f"Rate limit NOT enforced: got {result.rx_throughput_mbps:.2f} Mbps "
            f"> limit ceiling {upper:.1f} Mbps"
        )
        assert result.rx_throughput_mbps >= lower, (
            f"Throughput too low: got {result.rx_throughput_mbps:.2f} Mbps "
            f"< floor {lower:.1f} Mbps — rate limit may be blocking all traffic"
        )
