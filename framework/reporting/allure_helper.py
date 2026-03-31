"""
Allure reporting helpers — salvaged and cleaned up from OpenWiFi wlan-testing framework.
Test scripts import these to attach diagnostic data to allure reports.
"""
from __future__ import annotations
import json
import allure


def attach_ap_config(config: dict, name: str = "AP Config Pushed") -> None:
    allure.attach(body=json.dumps(config, indent=2), name=name,
                  attachment_type=allure.attachment_type.JSON)


def attach_traffic_result(result, name: str = "Traffic Result") -> None:
    summary = {
        "rx_throughput_mbps": result.rx_throughput_mbps,
        "tx_throughput_mbps": result.tx_throughput_mbps,
        "lost_packets":       result.lost_packets,
        "duration_s":         result.duration_s,
        "passed_threshold":   result.passed_threshold,
    }
    allure.attach(body=json.dumps(summary, indent=2), name=name,
                  attachment_type=allure.attachment_type.JSON)


def attach_raw_engine_output(result, name: str = "Raw Engine Output") -> None:
    allure.attach(body=json.dumps(result.raw, indent=2), name=name,
                  attachment_type=allure.attachment_type.JSON)


def attach_ap_log(log_text: str, name: str = "AP logread") -> None:
    allure.attach(body=log_text, name=name,
                  attachment_type=allure.attachment_type.TEXT)


def attach_ssid_scan(ssids: list, name: str = "SSID Scan") -> None:
    if not ssids:
        allure.attach(body="No SSIDs found", name=name,
                      attachment_type=allure.attachment_type.TEXT)
        return
    body = "\n".join(
        f"{s.ssid:<32} {s.bssid}  {s.band:<6}  ch{s.channel:<4}"
        f"  {s.security:<22}  {s.signal_dbm} dBm"
        for s in ssids
    )
    allure.attach(body=body, name=name,
                  attachment_type=allure.attachment_type.TEXT)


def attach_ucentral_status(status: dict, label: str = "") -> None:
    name = f"ucentral status{' — ' + label if label else ''}"
    allure.attach(body=json.dumps(status, indent=2), name=name,
                  attachment_type=allure.attachment_type.JSON)


def attach_testbed_capabilities(caps) -> None:
    data = {
        "has_lanforge":       caps.has_lanforge,
        "has_rpi5":           caps.has_rpi5,
        "has_radius":         caps.has_radius,
        "has_vlan_infra":     caps.has_vlan_infra,
        "has_multi_sta_radio": caps.has_multi_sta_radio,
        "has_wifi7_radio":    caps.has_wifi7_radio,
        "total_sta_capacity": caps.total_sta_capacity,
        "best_engine":        caps.best_engine,
        "radios": [
            {"name": r.name, "chipset": r.chipset,
             "type": r.radio_type.value, "max_stations": r.max_stations,
             "wifi_gen": r.wifi_gen, "bands": r.supported_bands}
            for r in caps.radios
        ],
    }
    allure.attach(body=json.dumps(data, indent=2), name="Testbed Capabilities",
                  attachment_type=allure.attachment_type.JSON)


def step(description: str):
    """Named allure step — use as context manager: `with step('...')`."""
    return allure.step(description)
