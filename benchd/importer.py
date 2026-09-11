"""Adopting results produced before the console existed.

Only runs that are actually quotable should be imported. Three EAP102 sweeps
from this bench were destroyed by bench faults — a station that fell over, 541
station SSH errors, a RADIUS container that had exited — and each produced a
convincing pile of failures that were not the AP's. Importing those would
poison exactly the comparisons this feature exists to enable, so provenance is
recorded per import and anything unfit is left out deliberately rather than by
accident.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from benchd import runner, store
from benchd.store import Meta


def import_results(src: Path, *, label: str = "", note: str = "",
                   started: str = "", generate: bool = True) -> tuple[str | None, str]:
    """Copy an ``allure-results`` directory in as a run. ``(run_id, error)``."""
    src = Path(src)
    if not src.is_dir():
        return None, f"{src} is not a directory"
    if not any(src.glob("*result.json")):
        return None, f"{src} holds no Allure results"

    tmp_id = f"import-{src.name}"
    dest = store.results_dir(tmp_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, dirs_exist_ok=True)

    env = store.environment(tmp_id)
    ap = store.ap_from_environment(env)
    run_id = store.new_id(ap.get("model") or src.name)

    # Re-home under the identity-derived id now that we know the AP.
    final = store.run_dir(run_id)
    store.run_dir(tmp_id).rename(final)

    meta = Meta(
        id=run_id, status="imported", label=label,
        scope_kind="full", mode="bridge",
        started=started or store.now(), finished=started or store.now(),
        ap=ap, imported=True, note=note,
        station={k.removeprefix("Station."): v
                 for k, v in env.items() if k.startswith("Station.")},
    )
    meta.totals = store.totals(run_id)
    status_of = meta.totals
    meta.status = "failed" if (status_of.get("failed") or status_of.get("broken")) else "passed"
    store.write_meta(meta)

    if generate:
        runner.regenerate(run_id)
    return run_id, ""
