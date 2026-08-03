"""
Convert a finished run's JSON sidecar into allure-results.

Runs made before Allure was wired in still wrote a full JSON sidecar beside
their HTML. That is enough to reconstruct Allure result files, so hours of bench
time do not have to be spent re-running a sweep just to view it in the new
report.

    python -m framework.allure_import reports/regression-<stamp>.json \\
        --out allure-results-imported

Then:  allure generate allure-results-imported -o allure-report-imported --clean
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime
from pathlib import Path

# pytest outcome -> allure status. "error" becomes "broken": the test did not
# run to a verdict, which is a different thing from an assertion failing.
STATUS = {
    "passed": "passed",
    "failed": "failed",
    "error": "broken",
    "skipped": "skipped",
}


AREA_LABELS = {
    "security": "Security", "network_mode": "Forwarding",
    "rate_limit": "Rate limiting", "qos": "Quality of service",
    "roaming": "Roaming and steering", "captive": "Captive portal",
    "vlan": "VLAN", "tunnel": "Tunnels and mesh", "services": "On-AP services",
    "telemetry": "Telemetry", "switch": "Switch fabric",
    "wifi_gen": "6 GHz and Wi-Fi 7", "wwan": "Cellular uplink",
}


def _labels(rec: dict) -> list[dict]:
    from framework.examples import catalog

    area = rec.get("area") or "other"
    example = rec.get("example") or rec.get("name", "")
    feature = AREA_LABELS.get(area, area.replace("_", " ").title())
    group = catalog.group_of(example) if example else feature
    labels = [
        {"name": "epic", "value": "OpenWiFi regression"},
        {"name": "feature", "value": feature},
        {"name": "suite", "value": feature},
        {"name": "subSuite", "value": group},
        {"name": "framework", "value": "pytest"},
    ]
    if group:
        labels.append({"name": "story", "value": group})
    if rec.get("band"):
        labels.append({"name": "tag", "value": rec["band"]})
    if rec.get("mode"):
        labels.append({"name": "tag", "value": rec["mode"]})
    for req in rec.get("requirements", []):
        labels.append({"name": "tag", "value": f"needs:{req}"})
    return labels


def _rebuild_config(example_name: str, band: str, mode: str, radio_caps: dict,
                    vlans: list[int]) -> str:
    """
    Reconstruct the config a case was given.

    Older sidecars predate storing the applied config, but the pipeline that
    produces it is deterministic: the same example, band, mode and radio
    capabilities yield the same document. Reconstructing beats showing nothing,
    provided it is labelled as a reconstruction rather than a capture.
    """
    from framework.examples import catalog
    from framework.examples.loader import load_example
    from framework.examples.normalize import (
        assign_bridge_vlan,
        enable_vlan_awareness,
        ensure_management_access,
        force_forwarding_mode,
        name_ssids_for_test,
        normalize_config,
        restrict_to_band,
        set_strict,
        substitute_vlans,
    )

    try:
        catalog.get(example_name)
        cfg, rep = normalize_config(load_example(example_name),
                                    example=example_name, radio_caps=radio_caps)
        name_ssids_for_test(cfg, "spw2ac1200", password="12345678", report=rep)
        if vlans:
            substitute_vlans(cfg, vlans, report=rep)
        if band:
            restrict_to_band(cfg, band, report=rep)
        if mode:
            force_forwarding_mode(cfg, mode, report=rep)
        if vlans:
            assign_bridge_vlan(cfg, vlans[0], report=rep)
            enable_vlan_awareness(cfg, vlans, report=rep)
        ensure_management_access(cfg, report=rep)
        set_strict(cfg)
        return json.dumps(cfg, indent=2)
    except Exception:
        return ""


def convert(sidecar: Path, out_dir: Path, radio_caps: dict | None = None,
            vlans: list[int] | None = None) -> int:
    data = json.loads(sidecar.read_text())
    out_dir.mkdir(parents=True, exist_ok=True)

    start_ms = int(datetime.fromisoformat(data["started"]).timestamp() * 1000)
    cursor = start_ms
    written = 0

    for rec in data.get("results", []):
        status = STATUS.get(rec.get("status", "passed"), "broken")
        duration_ms = int(float(rec.get("duration_s") or 0) * 1000)
        # The sidecar has no per-test timestamps, so lay the cases end to end in
        # recorded order. Durations are real; absolute times are approximate.
        stop = cursor + duration_ms

        from framework.examples import catalog as _cat

        example = rec.get("example") or ""
        entry = _cat.BY_NAME.get(example)
        name = entry.summary if entry else (example or rec.get("name", "case"))
        if rec.get("band"):
            name = f"{name} · {rec['band']}"

        result = {
            "uuid": str(uuid.uuid4()),
            "historyId": f"{rec.get('area','')}-{rec.get('example','')}-{rec.get('band','')}",
            "name": name,
            "fullName": f"{rec.get('area','')}.{rec.get('name','')}",
            "status": status,
            "stage": "finished",
            "start": cursor,
            "stop": stop,
            "labels": _labels(rec),
        }

        message = (rec.get("message") or "").strip()
        if message and status != "passed":
            first = next(
                (ln[1:].strip() for ln in message.splitlines()
                 if ln.startswith("E ") and ln[1:].strip()),
                message.splitlines()[0] if message.splitlines() else message,
            )
            for prefix in ("Failed: ", "AssertionError: "):
                if first.startswith(prefix):
                    first = first[len(prefix):]
            result["statusDetails"] = {"message": first[:600], "trace": message[:8000]}

        # Only the config the AP actually received. How it was derived from
        # the upstream example is not what a reader is trying to find out.
        params = []
        if rec.get("band"):
            params.append({"name": "band", "value": rec["band"]})
        if rec.get("mode"):
            params.append({"name": "forwarding", "value": rec["mode"]})
        config = rec.get("config") or ""
        label = "config applied"
        if not config and radio_caps:
            config = _rebuild_config(
                rec.get("example", ""), rec.get("band", ""),
                rec.get("mode", "") or "bridge", radio_caps, vlans or [],
            )
            label = "config applied (reconstructed)"
        if config:
            params.append({"name": label, "value": config[:20000]})
        if params:
            result["parameters"] = params

        (out_dir / f"{result['uuid']}-result.json").write_text(
            json.dumps(result), encoding="utf-8"
        )
        cursor = stop
        written += 1

    # Carry the bench identity and the failure buckets across too.
    env = {**data.get("ap", {}), **{f"Station.{k}": v
                                    for k, v in data.get("station", {}).items()},
           **data.get("capabilities", {}), "Testbed": data.get("testbed", "")}
    (out_dir / "environment.properties").write_text(
        "\n".join(f"{k.replace(' ', '.')}={v}" for k, v in env.items() if v) + "\n",
        encoding="utf-8",
    )
    categories = Path("allure-categories/categories.json")
    if categories.exists():
        (out_dir / "categories.json").write_text(categories.read_text(), encoding="utf-8")

    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("sidecar", type=Path)
    ap.add_argument("--out", type=Path, default=Path("allure-results-imported"))
    ap.add_argument("--ap", default=None,
                    help="AP host — read its radio capabilities so configs "
                         "missing from an older sidecar can be reconstructed")
    ap.add_argument("--vlans", default="",
                    help="Comma-separated VLAN ids the run used")
    args = ap.parse_args(argv)

    caps = None
    if args.ap:
        from framework.ap.ap_client import APClient
        caps = APClient(args.ap).radio_capabilities()
    vlans = [int(v) for v in args.vlans.split(",") if v.strip().isdigit()]
    n = convert(args.sidecar, args.out, caps, vlans)
    print(f"wrote {n} results to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
