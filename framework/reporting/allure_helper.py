"""
Allure attachment helpers.

The standalone HTML report in :mod:`framework.reporting.html_report` is the
primary artifact; Allure is kept for interactive drilldown when a failure needs
digging into. Tests call these to attach evidence.
"""
from __future__ import annotations

import json

import allure


def attach_ap_config(config: dict, name: str = "AP config applied") -> None:
    allure.attach(
        body=json.dumps(config, indent=2),
        name=name,
        attachment_type=allure.attachment_type.JSON,
    )


def attach_apply_result(result, name: str = "ucentral.uc apply") -> None:
    """Attach the parsed outcome of an apply, including the rendered UCI batch."""
    summary = {
        "success": result.success,
        "reason": result.reason,
        "errors": result.errors,
        "warnings": result.warnings,
        "duration_s": round(result.duration_s, 2),
    }
    allure.attach(
        body=json.dumps(summary, indent=2),
        name=name,
        attachment_type=allure.attachment_type.JSON,
    )
    if result.uci_batch:
        allure.attach(
            body=result.uci_batch,
            name="Rendered UCI batch",
            attachment_type=allure.attachment_type.TEXT,
        )


def attach_normalization(changes: list[str], name: str = "Config normalization") -> None:
    body = "\n".join(changes) if changes else "no changes — example used as published"
    allure.attach(body=body, name=name, attachment_type=allure.attachment_type.TEXT)


def attach_association(assoc, name: str = "Association") -> None:
    allure.attach(
        body=json.dumps(
            {
                "ssid": assoc.ssid,
                "bssid": assoc.bssid,
                "mac": assoc.mac,
                "ip": assoc.ip,
                "band": assoc.band,
                "freq_mhz": assoc.freq_mhz,
                "rssi_dbm": assoc.rssi_dbm,
            },
            indent=2,
        ),
        name=name,
        attachment_type=allure.attachment_type.JSON,
    )


def attach_throughput(result, name: str = "Throughput") -> None:
    allure.attach(
        body=json.dumps(
            {
                "mbps": round(result.mbps, 2),
                "direction": result.direction,
                "protocol": result.protocol,
                "duration_s": result.duration_s,
                "retransmits": result.retransmits,
            },
            indent=2,
        ),
        name=name,
        attachment_type=allure.attachment_type.JSON,
    )


def attach_ap_log(log_text: str, name: str = "AP logread") -> None:
    allure.attach(body=log_text, name=name, attachment_type=allure.attachment_type.TEXT)


def attach_scan(results: list, name: str = "Station scan") -> None:
    if not results:
        allure.attach(body="No SSIDs found", name=name,
                      attachment_type=allure.attachment_type.TEXT)
        return
    body = "\n".join(
        f"{r.ssid:<32} {r.bssid}  {r.band:<4}  {r.freq_mhz:>5} MHz  "
        f"{r.signal_dbm:>6.1f} dBm  {r.flags}"
        for r in results
    )
    allure.attach(body=body, name=name, attachment_type=allure.attachment_type.TEXT)


def attach_capabilities(caps) -> None:
    allure.attach(
        body=json.dumps(dict(caps.as_rows()), indent=2),
        name="Testbed capabilities",
        attachment_type=allure.attachment_type.JSON,
    )


def step(description: str):
    """Named Allure step — use as a context manager: ``with step('...')``."""
    return allure.step(description)
