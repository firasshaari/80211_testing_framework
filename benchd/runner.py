"""Starting, watching and finishing a run.

The console never reimplements a test. It spawns the *same* pytest command a
person would type, in the same repo, with the same flags — the only difference
is that the testbed config and the output directories are per-run. That is the
whole reason ``framework/`` needs no changes.

One run at a time, enforced by a lock: there is one AP and one station, so a
second concurrent run would not be slow, it would be wrong.
"""
from __future__ import annotations

import json
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from benchd import paths, store, testbed
from benchd.store import Meta

_lock = threading.Lock()
_current: str | None = None
_procs: dict[str, subprocess.Popen] = {}

# conftest hardcodes this path relative to the working directory and it does not
# follow --report-dir, so every run writes to the same file. With one run at a
# time that is harmless as long as it is truncated on the way in and copied out
# on the way finished.
_PROGRESS = paths.REPO / "reports" / "progress.log"


def current_id() -> str | None:
    return _current


def current() -> Meta | None:
    return store.read_meta(_current) if _current else None


def busy() -> bool:
    return _current is not None


# ── preflight ────────────────────────────────────────────────────────────────

def preflight(cfg_path: Path, timeout: int = 180) -> dict:
    """
    Is the bench fit to be believed?

    Runs the existing ``framework.preflight`` module and returns its verdict
    plus the lines it printed. A failure here is not an AP result and must never
    be recorded as one — which is precisely why the console runs this before
    every sweep rather than trusting that someone remembered.
    """
    try:
        proc = subprocess.run(
            [str(paths.PYTHON), "-m", "framework.preflight", "--config", str(cfg_path)],
            cwd=paths.REPO, capture_output=True, text=True, timeout=timeout,
        )
        lines = [l for l in (proc.stdout + proc.stderr).splitlines() if l.strip()]
        return {"ok": proc.returncode == 0, "lines": lines, "overridden": False}
    except subprocess.TimeoutExpired:
        return {"ok": False, "lines": [f"preflight timed out after {timeout}s"],
                "overridden": False}
    except Exception as exc:                                      # noqa: BLE001
        return {"ok": False, "lines": [f"preflight could not run: {exc}"],
                "overridden": False}


# ── starting ─────────────────────────────────────────────────────────────────

def _pytest_argv(meta: Meta, cfg_path: Path) -> list[str]:
    argv = [
        str(paths.PYTHON), "-m", "pytest", "tests/regression",
        "--testbed-config", str(cfg_path),
        "--alluredir", str(store.results_dir(meta.id)), "--clean-alluredir",
        "--report-dir", str(store.run_dir(meta.id) / "reports"),
        "-p", "no:cacheprovider",
    ]
    if meta.scope_kind == "area" and meta.scope_value:
        argv += ["-m", meta.scope_value]
    elif meta.scope_kind == "example" and meta.scope_value:
        argv += ["-k", meta.scope_value]
    return argv


def start(*, cfg: dict, ap_info: dict, label: str = "", scope_kind: str = "full",
          scope_value: str = "", mode: str = "bridge",
          preflight_result: dict | None = None) -> tuple[str | None, str]:
    """Returns ``(run_id, "")`` or ``(None, reason)``."""
    global _current
    with _lock:
        if _current is not None:
            return None, f"a run is already in progress ({_current})"

        validated, err = testbed.validate(cfg)
        if err:
            return None, f"config rejected: {err}"

        meta = Meta(
            id=store.new_id(ap_info.get("model") or ap_info.get("host") or "ap"),
            status="running", label=label.strip(),
            scope_kind=scope_kind, scope_value=scope_value, mode=mode,
            started=store.now(), ap=dict(ap_info),
            preflight=preflight_result or {},
        )
        d = store.run_dir(meta.id)
        d.mkdir(parents=True, exist_ok=True)

        cfg_path = testbed.write(cfg, d / "testbed.yaml")
        (d / "testbed.redacted.yaml").write_text(
            json.dumps(testbed.redacted(cfg), indent=2))

        try:
            _PROGRESS.parent.mkdir(parents=True, exist_ok=True)
            _PROGRESS.write_text("")
        except OSError:
            pass

        log = open(store.console_log(meta.id), "wb", buffering=0)
        proc = subprocess.Popen(
            _pytest_argv(meta, cfg_path), cwd=paths.REPO,
            stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,     # so stopping the run kills the whole
                                        # process group, not just pytest
        )
        meta.pid = proc.pid
        store.write_meta(meta)
        _procs[meta.id] = proc
        _current = meta.id

    threading.Thread(target=_watch, args=(meta.id, proc, log), daemon=True).start()
    return meta.id, ""


def _watch(run_id: str, proc: subprocess.Popen, log) -> None:
    global _current
    code = proc.wait()
    try:
        log.close()
    except Exception:                                             # noqa: BLE001
        pass

    meta = store.read_meta(run_id) or Meta(id=run_id)
    meta.exit_code = code
    meta.finished = store.now()
    meta.pid = None
    meta.totals = store.totals(run_id)

    # The AP identity the suite itself recorded, which is the authority: the
    # probe happened before the run, this happened during it.
    env = store.environment(run_id)
    if env:
        recorded = store.ap_from_environment(env)
        meta.ap = {**meta.ap, **{k: v for k, v in recorded.items() if v}}
        meta.station = {k.removeprefix("Station."): v
                        for k, v in env.items() if k.startswith("Station.")}

    if meta.status == "stopping":
        meta.status = "stopped"
    elif code == 0:
        meta.status = "passed"
    elif meta.totals.get("total"):
        meta.status = "failed"          # pytest exits non-zero on failures; a
                                        # run that produced results did run
    else:
        meta.status = "error"           # nothing came out — the run never
                                        # really started

    try:
        if _PROGRESS.exists():
            shutil.copy2(_PROGRESS, store.run_dir(run_id) / "progress.log")
    except OSError:
        pass

    store.write_meta(meta)
    _generate_report(run_id)

    with _lock:
        _procs.pop(run_id, None)
        if _current == run_id:
            _current = None


# ── the Allure report ────────────────────────────────────────────────────────

def _previous_history() -> Path | None:
    """
    The most recent finished run's Allure history, for trend charts.

    Allure builds trends by carrying a ``history/`` folder forward from the
    previous report into the next results directory. Nothing in this repo ever
    did that, so every report has been a standalone snapshot with empty trends.
    """
    for meta in store.list_runs():
        h = store.report_dir(meta.id) / "history"
        if h.is_dir() and any(h.iterdir()):
            return h
    return None


def _generate_report(run_id: str) -> bool:
    results, report = store.results_dir(run_id), store.report_dir(run_id)
    if not results.is_dir():
        return False

    if paths.CATEGORIES.exists():
        shutil.copy2(paths.CATEGORIES, results / "categories.json")

    prev = _previous_history()
    if prev:
        shutil.copytree(prev, results / "history", dirs_exist_ok=True)

    if not shutil.which("allure"):
        return False
    try:
        subprocess.run(["allure", "generate", str(results), "-o", str(report), "--clean"],
                       capture_output=True, timeout=600, check=False)
        return (report / "index.html").exists()
    except Exception:                                             # noqa: BLE001
        return False


def regenerate(run_id: str) -> bool:
    return _generate_report(run_id)


# ── stopping and reconciling ─────────────────────────────────────────────────

def stop(run_id: str) -> str:
    proc = _procs.get(run_id)
    meta = store.read_meta(run_id)
    if not meta or not meta.is_live:
        return "that run is not running"
    meta.status = "stopping"
    store.write_meta(meta)
    if proc and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)      # let pytest write its results
            for _ in range(20):
                if proc.poll() is not None:
                    break
                time.sleep(0.5)
            if proc.poll() is None:
                proc.kill()
        except Exception as exc:                                  # noqa: BLE001
            return f"could not stop it: {exc}"
    return ""


def _pid_alive(pid: int | None) -> bool:
    """Signal 0 checks existence without delivering anything, and unlike /proc
    it works on a developer's laptop as well as on the Pi."""
    if not pid:
        return False
    try:
        import os
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, ValueError):
        return False
    except PermissionError:
        return True          # exists, owned by someone else


def reconcile() -> int:
    """
    Fix up runs that were live when the console died.

    The Pi is the runner, the station and the web server all at once, so a
    hang takes everything with it. Without this, such a run stays "running"
    for ever and blocks every future run behind the one-at-a-time lock.
    """
    global _current
    fixed = 0
    for meta in store.list_runs():
        if not meta.is_live:
            continue
        alive = _pid_alive(meta.pid)
        if alive:
            _current = meta.id           # it outlived us; adopt it back
            continue
        meta.status = "interrupted"
        meta.finished = meta.finished or store.now()
        meta.pid = None
        meta.totals = store.totals(meta.id) or meta.totals
        store.write_meta(meta)
        fixed += 1
    return fixed
