"""
Isolation for the offline ``benchd`` tests.

``benchd`` resolves every on-disk location once, in ``benchd.paths``. A test
that forgot to redirect them would write into the bench's real ``runs/`` tree
or its ``benchd.env`` secrets file, so the redirection is applied to every test
in this directory rather than left to each one to remember. The cost is three
attribute swaps per test, which is nothing.

The helpers below build the few Allure artefacts the store reads — a
``*-result.json`` per case and ``environment.properties`` per run — in the same
shape ``allure-pytest`` writes them, so the tests exercise the real parsing
path rather than a convenient subset of it.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from benchd import paths, store
from benchd.store import Meta


@pytest.fixture(autouse=True)
def bench_paths(tmp_path, monkeypatch):
    """Every benchd location lives under this test's tmp_path. No exceptions."""
    monkeypatch.setattr(paths, "RUNS", tmp_path / "runs")
    monkeypatch.setattr(paths, "ENV_FILE", tmp_path / "benchd.env")
    monkeypatch.setattr(paths, "BASE_TESTBED", tmp_path / "testbed.yaml")
    return tmp_path


def write_result(run_id: str, example: str, band: str, status: str, *,
                 message: str = "", trace: str = "", feature: str = "security",
                 story: str = "", title: str = "", start: int = 1000,
                 stop: int = 1500, quoted: bool = True) -> Path:
    """
    One Allure result file, the way allure-pytest records a parametrised case.

    ``quoted`` reproduces the detail that matters most: parametrize values are
    stored as their Python repr, so the string ``crypto-psk`` arrives as
    ``"'crypto-psk'"`` and the store has to strip the quotes to get a key that
    lines up across runs.
    """
    rdir = store.results_dir(run_id)
    rdir.mkdir(parents=True, exist_ok=True)
    q = (lambda v: repr(v)) if quoted else (lambda v: v)
    doc = {
        "name": title or f"{example} · {band}",
        "status": status,
        "statusDetails": {"message": message, "trace": trace},
        "start": start, "stop": stop,
        "parameters": [
            {"name": "example_name", "value": q(example)},
            {"name": "band", "value": q(band)},
        ],
        "labels": [
            {"name": "feature", "value": feature},
            {"name": "story", "value": story},
        ],
    }
    f = rdir / f"{uuid.uuid4().hex}-result.json"
    f.write_text(json.dumps(doc))
    return f


def write_environment(run_id: str, **props: str) -> Path:
    rdir = store.results_dir(run_id)
    rdir.mkdir(parents=True, exist_ok=True)
    f = rdir / "environment.properties"
    f.write_text("".join(f"{k}={v}\n" for k, v in props.items()))
    return f


def make_run(run_id: str, cases: dict[tuple[str, str], str | tuple[str, str]],
             *, model: str = "EAP102", firmware: str = "3.0.1",
             host: str = "10.0.127.220", started: str = "2026-01-01T00:00:00+00:00") -> Meta:
    """
    A whole run: meta plus one result per case.

    ``cases`` maps ``(example, band)`` to a status, or to ``(status, message)``
    for a failure whose text matters.
    """
    for (example, band), outcome in cases.items():
        status, message = outcome if isinstance(outcome, tuple) else (outcome, "")
        write_result(run_id, example, band, status, message=message)
    meta = Meta(id=run_id, status="passed", started=started,
                ap={"host": host, "model": model, "firmware": firmware})
    store.write_meta(meta)
    return meta
