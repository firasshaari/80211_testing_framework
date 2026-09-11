"""Summarising one run, and diffing two.

Both views avoid shelling out to Allure. The full drill-down report needs the
Allure CLI and a JRE, but a summary and a comparison only need the result JSON,
so they stay fast and keep working even if the CLI is missing.

Failure grouping reuses the bench's own ``allure-categories/categories.json``
matched exactly the way Allure matches it, and triage reuses
``classify_failure`` from the existing HTML reporter rather than inventing a
second opinion about what counts as an AP defect.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache

from benchd import paths, store
from framework.reporting.html_report import CLASS_BLURB, CLASS_LABEL, classify_failure


@lru_cache(maxsize=1)
def _categories() -> list[dict]:
    if not paths.CATEGORIES.exists():
        return []
    try:
        return json.loads(paths.CATEGORIES.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def categorise(status: str, message: str, trace: str = "") -> str:
    """The bench's own failure buckets — cause, not symptom."""
    blob = f"{message}\n{trace}"
    for cat in _categories():
        if status not in (cat.get("matchedStatuses") or ["failed", "broken"]):
            continue
        pattern = cat.get("messageRegex")
        if pattern and re.search(pattern, blob, re.S | re.I):
            return cat["name"]
    return ""


def summarise(run_id: str) -> dict:
    """Totals, failures grouped by cause, and a triage split."""
    cases = store.cases(run_id)
    totals = {k: 0 for k in ("passed", "failed", "broken", "skipped", "unknown")}
    by_cause: dict[str, list] = {}
    by_class: dict[str, list] = {}
    by_area: dict[str, dict] = {}

    for (example, band), c in sorted(cases.items()):
        status = c["status"] if c["status"] in totals else "unknown"
        totals[status] += 1

        area = c.get("feature") or "Uncategorised"
        slot = by_area.setdefault(area, {"passed": 0, "failed": 0, "broken": 0,
                                         "skipped": 0, "unknown": 0})
        slot[status] += 1

        if status in ("failed", "broken", "skipped"):
            cause = categorise(status, c["message"], c["trace"])
            if cause:
                by_cause.setdefault(cause, []).append(
                    {"example": example, "band": band, "title": c["title"]})
        if status in ("failed", "broken"):
            klass = classify_failure(c["message"])
            by_class.setdefault(klass, []).append({
                "example": example, "band": band, "title": c["title"],
                "message": c["message"].splitlines()[0][:200] if c["message"] else "",
            })

    totals["total"] = sum(totals[k] for k in
                          ("passed", "failed", "broken", "skipped", "unknown"))
    return {
        "totals": totals,
        "by_cause": dict(sorted(by_cause.items(), key=lambda kv: -len(kv[1]))),
        "by_class": {k: by_class[k] for k in ("defect", "investigate", "artefact")
                     if k in by_class},
        "class_labels": CLASS_LABEL,
        "class_blurbs": CLASS_BLURB,
        "by_area": dict(sorted(by_area.items())),
    }


# ── two runs, side by side ───────────────────────────────────────────────────

VERDICTS = ("regressed", "fixed", "both_failed", "skip_diff", "both_passed",
            "only_a", "only_b")

_LABEL = {
    "regressed":   "Regressed",
    "fixed":       "Fixed",
    "both_failed": "Failing in both",
    "skip_diff":   "Ran in one, skipped in the other",
    "both_passed": "Passing in both",
    "only_a":      "Only in the first run",
    "only_b":      "Only in the second run",
}

_BAD = ("failed", "broken")


def _first_line(case: dict | None, limit: int = 180) -> str:
    """A passing case has no message at all, so splitlines() is empty."""
    lines = (case or {}).get("message", "").splitlines()
    return lines[0][:limit] if lines else ""


def _verdict(a: dict | None, b: dict | None) -> str:
    if a is None:
        return "only_b"
    if b is None:
        return "only_a"
    sa, sb = a["status"], b["status"]
    if sa == "skipped" or sb == "skipped":
        # A case that ran on one bench and skipped on the other is a capability
        # difference, not a regression — calling it one would blame the AP for
        # hardware the bench did not have.
        return "both_passed" if sa == sb == "skipped" else "skip_diff"
    if sa == "passed" and sb in _BAD:
        return "regressed"
    if sa in _BAD and sb == "passed":
        return "fixed"
    if sa in _BAD and sb in _BAD:
        return "both_failed"
    return "both_passed"


def compare(run_a: str, run_b: str) -> dict:
    """
    Diff two runs, keyed on ``(example_name, band)``.

    That key comes from the pytest parametrize arguments and contains no AP
    identity, so the same case lines up across different APs and different
    firmware. AP identity belongs to the *run*, which is where it is read from.
    """
    a_meta, b_meta = store.read_meta(run_a), store.read_meta(run_b)
    a_cases, b_cases = store.cases(run_a), store.cases(run_b)

    rows, counts = [], {v: 0 for v in VERDICTS}
    for key in sorted(set(a_cases) | set(b_cases)):
        a, b = a_cases.get(key), b_cases.get(key)
        verdict = _verdict(a, b)
        counts[verdict] += 1

        # A raw "regressed" count is the most misleading number this page can
        # show. A case that passed on one run and failed on the next because the
        # harness lost SSH has regressed in the arithmetic sense and says
        # nothing whatever about the AP. So each regression is classified by the
        # *new* failure, and the artefacts are separated out before anyone reads
        # a verdict into the total.
        blame = ""
        if verdict in ("regressed", "both_failed") and b:
            blame = classify_failure(b.get("message", ""))
            cause = categorise(b["status"], b.get("message", ""), b.get("trace", ""))
            if cause == "Harness lost the AP or the station":
                blame = "artefact"
        if verdict == "regressed" and blame:
            counts[f"regressed_{blame}"] = counts.get(f"regressed_{blame}", 0) + 1

        rows.append({
            "example": key[0], "band": key[1],
            "title": (a or b or {}).get("title", ""),
            "area": (a or b or {}).get("feature", "Uncategorised"),
            "a": a["status"] if a else "—",
            "b": b["status"] if b else "—",
            "a_message": _first_line(a),
            "b_message": _first_line(b),
            "verdict": verdict,
            "verdict_label": _LABEL[verdict],
            "blame": blame,
            "cause": categorise(b["status"], b.get("message", ""), b.get("trace", "")) if b else "",
        })

    same_model = bool(a_meta and b_meta
                      and a_meta.ap.get("model")
                      and a_meta.ap.get("model") == b_meta.ap.get("model"))
    return {
        "a": a_meta, "b": b_meta,
        "rows": rows,
        "counts": counts,
        "labels": _LABEL,
        "kind": "firmware" if same_model else "ap",
        "headline": _headline(a_meta, b_meta, counts, same_model),
    }


def _headline(a, b, counts, same_model: bool) -> str:
    if not (a and b):
        return "One of these runs could not be read."
    what = (f"{a.ap.get('firmware','?')} → {b.ap.get('firmware','?')}"
            if same_model else f"{a.ap_label} → {b.ap_label}")

    reg, fixed = counts["regressed"], counts["fixed"]
    artefact = counts.get("regressed_artefact", 0)
    real = reg - artefact

    if not reg and not fixed:
        return f"{what} — no change in pass/fail"

    bits = []
    if reg:
        bits.append(f"{reg} regressed" + (
            f" ({real} worth looking at, {artefact} bench artefacts)" if artefact else ""))
    if fixed:
        bits.append(f"{fixed} fixed")
    return f"{what} — {', '.join(bits)}"
