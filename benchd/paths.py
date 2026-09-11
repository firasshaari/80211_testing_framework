"""Where things live, on the Pi and on a laptop checkout alike.

The console runs in two places: as a service on the bench Pi (``/opt/bench``)
and from a developer checkout while it is being worked on. Rather than branch on
that everywhere, every location is resolved once here.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# On the Pi this is /opt/bench. In a checkout it defaults to the repo itself, so
# `python -m benchd` works with no environment set up.
_REPO_FROM_SOURCE = Path(__file__).resolve().parent.parent

BENCH_ROOT = Path(os.environ.get("BENCH_ROOT", "")) if os.environ.get("BENCH_ROOT") else None
REPO = Path(os.environ.get("BENCH_REPO") or (BENCH_ROOT / "repo" if BENCH_ROOT else _REPO_FROM_SOURCE))
ROOT = BENCH_ROOT or REPO

RUNS = Path(os.environ.get("BENCH_RUNS") or ROOT / "runs")
ENV_FILE = Path(os.environ.get("BENCH_ENV") or ROOT / "benchd.env")

# The interpreter that runs pytest. On the Pi that is the bench venv; in a
# checkout it is whatever is running the console, which is what a developer
# expects.
_venv_py = ROOT / "venv" / "bin" / "python"
PYTHON = Path(os.environ.get("BENCH_PYTHON") or (_venv_py if _venv_py.exists() else sys.executable))

# Defaults for a new run's testbed config: station, RADIUS and VLAN rarely
# change, so the console reuses the bench's own file and overrides only the AP.
BASE_TESTBED = Path(os.environ.get("BENCH_TESTBED") or REPO / "config" / "testbed.yaml")

CATEGORIES = REPO / "allure-categories" / "categories.json"
TEMPLATES = Path(__file__).resolve().parent / "templates"
STATIC = Path(__file__).resolve().parent / "static"


def ensure() -> None:
    RUNS.mkdir(parents=True, exist_ok=True)
