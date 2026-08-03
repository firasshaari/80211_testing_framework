"""
Tolerant loader for uCentral example configs.

The upstream examples under ``configs/examples/upstream/`` are *not* all strict
JSON.  Real deviations found in the wlan-ap tree:

* ``wpa2-radius.json`` opens with a ``#`` shell-style comment line.
* ``gre6.json`` has a trailing comma before a closing bracket.

``ucentral.uc`` is a ucode program and accepts these; :func:`json.loads` does
not.  :func:`parse_ucentral_json` strips the deviations before parsing so the
whole corpus loads, and records which files needed the tolerant path.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
UPSTREAM_DIR = _PROJECT_ROOT / "configs" / "examples" / "upstream"

# Comment forms seen in the upstream corpus. Applied to whole lines only, so a
# '#' or '//' inside a JSON string value (a URL, a password) is left intact.
_HASH_COMMENT = re.compile(r"^\s*#.*$", re.MULTILINE)
_LINE_COMMENT = re.compile(r"^\s*//.*$", re.MULTILINE)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


@dataclass
class ParseReport:
    """Records whether a file needed the tolerant path, and why."""

    strict: bool = True
    fixups: list[str] = field(default_factory=list)


def parse_ucentral_json(text: str, *, report: ParseReport | None = None) -> dict:
    """
    Parse uCentral config *text*, tolerating the deviations above.

    Strict JSON is tried first so well-formed files take the fast path and the
    report records that no fixups were needed.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    if report is not None:
        report.strict = False

    cleaned = text
    if _HASH_COMMENT.search(cleaned):
        cleaned = _HASH_COMMENT.sub("", cleaned)
        if report is not None:
            report.fixups.append("stripped '#' comment lines")
    if _BLOCK_COMMENT.search(cleaned):
        cleaned = _BLOCK_COMMENT.sub("", cleaned)
        if report is not None:
            report.fixups.append("stripped /* */ block comments")
    if _LINE_COMMENT.search(cleaned):
        cleaned = _LINE_COMMENT.sub("", cleaned)
        if report is not None:
            report.fixups.append("stripped '//' comment lines")
    if _TRAILING_COMMA.search(cleaned):
        cleaned = _TRAILING_COMMA.sub(r"\1", cleaned)
        if report is not None:
            report.fixups.append("removed trailing commas")

    return json.loads(cleaned)


def load_example(name: str, *, report: ParseReport | None = None) -> dict:
    """
    Load a single upstream example by file name (with or without ``.json``).

    Returns the raw, *un-normalized* config — call
    :func:`framework.examples.normalize.normalize_config` before sending it to
    an AP.
    """
    stem = name[:-5] if name.endswith(".json") else name
    path = UPSTREAM_DIR / f"{stem}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No upstream example named {stem!r} in {UPSTREAM_DIR}. "
            f"Run 'make sync-examples' to refresh the vendored corpus."
        )
    return parse_ucentral_json(path.read_text(encoding="utf-8"), report=report)


def iter_example_paths() -> list[Path]:
    """Every vendored upstream example, sorted by name."""
    return sorted(UPSTREAM_DIR.glob("*.json"))
