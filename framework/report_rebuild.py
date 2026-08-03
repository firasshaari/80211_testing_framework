"""
Re-render a finished run's HTML report from its JSON sidecar.

Every run writes both. Re-rendering means a report-format improvement can be
applied to results already gathered, instead of spending hours of bench time
re-running a sweep to see a layout change.

    python -m framework.report_rebuild reports/regression-<stamp>.json
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from framework.reporting.html_report import RegressionReport, TestRecord


def rebuild(json_path: Path, out_dir: Path | None = None) -> Path:
    data = json.loads(json_path.read_text())
    rep = RegressionReport(
        testbed_name=data.get("testbed", ""),
        operator=data.get("operator", ""),
        started=datetime.fromisoformat(data["started"]),
    )
    rep.finished = datetime.fromisoformat(data["finished"])
    rep.ap_info = list(data.get("ap", {}).items())
    rep.station_info = list(data.get("station", {}).items())
    rep.capability_rows = list(data.get("capabilities", {}).items())
    rep.capability_notes = list(data.get("notes", []))

    for r in data.get("results", []):
        rep.add(TestRecord(
            name=r.get("name", ""),
            example=r.get("example", ""),
            area=r.get("area", ""),
            mode=r.get("mode", ""),
            band=r.get("band", ""),
            status=r.get("status", "passed"),
            duration_s=r.get("duration_s", 0.0),
            message=r.get("message", ""),
            requirements=r.get("requirements", []),
            normalization=r.get("normalization", []),
        ))

    return rep.write(out_dir or json_path.parent)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("json", type=Path)
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args(argv)
    print(rebuild(args.json, args.out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
