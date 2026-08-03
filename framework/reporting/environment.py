"""
Writes ``allure-results/environment.properties`` so Allure shows which bench
and which firmware a run came from.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def write_environment_properties(
    allure_results_dir: str,
    *,
    testbed_name: str,
    ap_info,
    station_info: dict | None = None,
    capabilities=None,
) -> Path:
    path = Path(allure_results_dir) / "environment.properties"
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"Testbed={testbed_name}",
        f"AP.Model={ap_info.model}",
        f"AP.Firmware={ap_info.firmware}",
        f"AP.Platform={ap_info.platform}",
        f"AP.Serial={ap_info.serial}",
        f"AP.Kernel={ap_info.kernel}",
        "Management=direct-ssh (uCentral agent disabled)",
    ]

    if station_info:
        lines += [
            f"Station.Adapter={station_info.get('adapter', 'unknown')}",
            f"Station.Driver={station_info.get('driver', 'unknown')}",
            f"Station.OS={station_info.get('os', 'unknown')}",
            f"Station.Regdomain={station_info.get('regdomain', 'unknown')}",
        ]

    if capabilities is not None:
        lines += [
            f"Usable.Bands={','.join(sorted(capabilities.usable_bands)) or 'none'}",
            f"Has.RADIUS={capabilities.has_radius}",
            f"Has.VLAN={capabilities.has_vlan}",
            f"Has.WiFi7={capabilities.has_wifi7}",
        ]

    lines.append(f"Run.Timestamp={datetime.now(timezone.utc).isoformat()}")

    path.write_text("\n".join(lines) + "\n")
    log.info("Allure environment.properties written to %s", path)
    return path
