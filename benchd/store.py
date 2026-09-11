"""Run storage: one directory per run, ``meta.json`` as the record of truth.

Deliberately no database. A bench produces a few hundred runs a year and every
question the console asks ("list them", "compare two") is answered by reading a
few small JSON files. A SQLite index would be one more thing to migrate and
corrupt for no gain at this size; if listing ever gets slow, the fix is a cache,
not a schema.

The one thing this *must* get right is recording **which AP a run was against**.
Result directory names do not carry it — that has already cost real time, with
report directories whose provenance had to be recovered by grepping the result
JSON for an IP address. So identity is captured at run time and written here.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from benchd import paths

_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str, limit: int = 24) -> str:
    return _SLUG.sub("-", (text or "ap").lower()).strip("-")[:limit] or "ap"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Meta:
    id: str
    status: str = "queued"          # queued|preflight|running|passed|failed|stopped|interrupted|error
    label: str = ""
    scope_kind: str = "full"        # full|area|example
    scope_value: str = ""
    mode: str = "bridge"
    started: str = ""
    finished: str = ""
    ap: dict = field(default_factory=dict)      # host, model, firmware, platform, serial, kernel, board
    station: dict = field(default_factory=dict)
    preflight: dict = field(default_factory=dict)   # ok, lines, overridden
    totals: dict = field(default_factory=dict)      # passed, failed, broken, skipped, total
    pid: int | None = None
    exit_code: int | None = None
    imported: bool = False
    note: str = ""

    @property
    def ap_label(self) -> str:
        """How this run is named in a list — model first, falling back to host."""
        return self.ap.get("model") or self.ap.get("host") or "unknown AP"

    @property
    def fw(self) -> str:
        return self.ap.get("firmware") or "unknown"

    @property
    def scope_label(self) -> str:
        if self.scope_kind == "full":
            return "full sweep"
        return f"{self.scope_kind}: {self.scope_value}"

    @property
    def is_live(self) -> bool:
        return self.status in ("queued", "preflight", "running")


def new_id(ap_hint: str) -> str:
    return f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{_slug(ap_hint)}"


def run_dir(run_id: str) -> Path:
    return paths.RUNS / run_id


def results_dir(run_id: str) -> Path:
    return run_dir(run_id) / "allure-results"


def report_dir(run_id: str) -> Path:
    return run_dir(run_id) / "allure-report"


def console_log(run_id: str) -> Path:
    return run_dir(run_id) / "console.log"


def write_meta(meta: Meta) -> None:
    d = run_dir(meta.id)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "meta.json.tmp"
    tmp.write_text(json.dumps(asdict(meta), indent=2))
    tmp.replace(d / "meta.json")          # atomic, so a crash mid-write cannot
                                          # leave an unreadable run


def read_meta(run_id: str) -> Meta | None:
    f = run_dir(run_id) / "meta.json"
    if not f.exists():
        return None
    try:
        return Meta(**json.loads(f.read_text()))
    except (json.JSONDecodeError, TypeError):
        return None


def list_runs() -> list[Meta]:
    """Newest first. Unreadable directories are skipped, not fatal."""
    paths.ensure()
    out = []
    for d in paths.RUNS.iterdir():
        if not d.is_dir():
            continue
        meta = read_meta(d.name)
        if meta:
            out.append(meta)
    return sorted(out, key=lambda m: m.started or m.id, reverse=True)


def delete_run(run_id: str) -> bool:
    d = run_dir(run_id)
    if not d.exists():
        return False
    shutil.rmtree(d)
    return True


# ── reading what a finished run actually produced ────────────────────────────

_STATUS_KEYS = ("passed", "failed", "broken", "skipped", "unknown")


def _unquote(value) -> str:
    """Allure records parametrize values as Python reprs: "'crypto-psk'"."""
    s = str(value)
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def cases(run_id: str) -> dict[tuple[str, str], dict]:
    """
    Every case in a run, keyed by ``(example_name, band)``.

    That pair is the stable identity of a case *across* runs and across APs: it
    comes from the pytest parametrize arguments, which Allure records verbatim.
    The Allure title is prose (``"<summary> · <band>"``) and would drift the
    moment a summary is reworded, so it is not used as a key.
    """
    out: dict[tuple[str, str], dict] = {}
    rdir = results_dir(run_id)
    if not rdir.is_dir():
        return out
    for f in rdir.glob("*result.json"):
        try:
            d = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        params = {p.get("name"): _unquote(p.get("value")) for p in d.get("parameters", [])}
        example, band = params.get("example_name"), params.get("band")
        if not example or not band:
            continue
        labels = {l["name"]: l["value"] for l in d.get("labels", [])}
        out[(example, band)] = {
            "status": d.get("status", "unknown"),
            "title": d.get("name", ""),
            "feature": labels.get("feature", ""),
            "story": labels.get("story", ""),
            "message": (d.get("statusDetails") or {}).get("message", "") or "",
            "trace": (d.get("statusDetails") or {}).get("trace", "") or "",
            "ms": max(0, (d.get("stop", 0) or 0) - (d.get("start", 0) or 0)),
        }
    return out


def totals(run_id: str) -> dict:
    counts = {k: 0 for k in _STATUS_KEYS}
    for case in cases(run_id).values():
        counts[case["status"] if case["status"] in counts else "unknown"] += 1
    counts["total"] = sum(counts[k] for k in _STATUS_KEYS)
    return counts


def environment(run_id: str) -> dict:
    """
    AP and station identity as the *suite itself* recorded it.

    ``conftest._seed_allure`` writes AP.Model / AP.Firmware / AP.Serial /
    AP.Kernel into ``environment.properties``. Reading it back is how an
    imported historical run recovers its provenance, and how a live run's
    metadata is cross-checked against what the AP reported at probe time.
    """
    f = results_dir(run_id) / "environment.properties"
    if not f.exists():
        return {}
    env = {}
    for line in f.read_text(errors="replace").splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


def ap_from_environment(env: dict) -> dict:
    return {
        "host": env.get("AP.Host", ""),
        "model": env.get("AP.Model", ""),
        "firmware": env.get("AP.Firmware", ""),
        "serial": env.get("AP.Serial", ""),
        "kernel": env.get("AP.Kernel", ""),
        "platform": env.get("AP.Platform", ""),
    }
