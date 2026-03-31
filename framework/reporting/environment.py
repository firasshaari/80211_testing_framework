"""
Writes allure-results/environment.properties after a test session.
Salvaged from OpenWiFi framework — extended with capability info.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def write_environment_properties(
    allure_results_dir: str,
    ap_serial: str,
    ap_firmware: str | None,
    controller_url: str,
    testbed_name: str,
    capabilities,
) -> None:
    path = Path(allure_results_dir) / "environment.properties"
    path.parent.mkdir(parents=True, exist_ok=True)

    radio_summary = ", ".join(
        f"{r.chipset}({r.radio_type.value})" for r in capabilities.radios
    ) or "none"

    lines = [
        f"Testbed={testbed_name}",
        f"AP.Serial={ap_serial}",
        f"AP.Firmware={ap_firmware or 'unknown'}",
        f"Controller.URL={controller_url}",
        f"Engine={capabilities.best_engine}",
        f"Radios={radio_summary}",
        f"Total.STA.Capacity={capabilities.total_sta_capacity}",
        f"Has.RADIUS={capabilities.has_radius}",
        f"Has.VLAN.Infra={capabilities.has_vlan_infra}",
        f"Run.Timestamp={datetime.now(timezone.utc).isoformat()}",
    ]

    path.write_text("\n".join(lines) + "\n")
    log.info(f"Allure environment.properties written to {path}")
