"""
AP Config Loader — loads uCentral JSON config templates from disk and
substitutes ${VAR} placeholders before returning a parsed dict.

Variable substitution rules
---------------------------
``"key": "${VAR}"``
    If ``vars[VAR]`` is **int / float / bool**, the surrounding JSON quotes
    are stripped so the value lands as the correct JSON type::

        "egress-rate": "${DOWNSTREAM_RATE_KBPS}"  →  "egress-rate": 10000
        "allow-dfs":   "${ALLOW_DFS}"              →  "allow-dfs":   false

    If ``vars[VAR]`` is a **str**, the quotes are kept::

        "name": "${SSID}"   →   "name": "my-ssid"

``${VAR|default}``
    Uses *default* (as a string) if VAR is absent from *vars*.

Unresolved ``${VAR}`` references (no default and not in *vars*) raise
``ValueError`` before any JSON parsing, so the error message is clear.

Usage
-----
    from framework.ap.config_loader import load_ap_config

    config = load_ap_config(
        "configs/ap/rate_limiting/wpa2_bridge_5g.json",
        vars={
            "SSID":                 "test-ratelimit",
            "PASSWORD":             "testpass123",
            "DOWNSTREAM_RATE_KBPS": 10000,
            "UPSTREAM_RATE_KBPS":   0,
        },
    )
    ap.push_config(config)

Relative paths are resolved first against the current working directory
(where pytest is launched), then against the project root.
"""
from __future__ import annotations
import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# Matches a *complete* JSON string value that is a single placeholder:
#   "key": "${VAR}"  or  "key": "${VAR|default}"
# Group 1 = var name, group 2 = default (may be None)
_QUOTED_PLACEHOLDER = re.compile(r'"(\$\{(\w+)(?:\|([^}]*))?\})"')

# Matches any bare placeholder inside an already-open string:
#   ${VAR}  or  ${VAR|default}
# Group 1 = var name, group 2 = default (may be None)
_BARE_PLACEHOLDER = re.compile(r'\$\{(\w+)(?:\|([^}]*))?\}')

# Project root (two levels up from this file: framework/ap/config_loader.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_ap_config(path: str, vars: dict | None = None) -> dict:
    """
    Load a JSON AP config template from *path* and substitute variables.

    Parameters
    ----------
    path :
        Path to the ``.json`` template. Relative paths are resolved from
        the directory where pytest is run (project root), so
        ``"configs/ap/connectivity/wpa2_bridge_5g.json"`` works from the
        command line and in CI.
    vars :
        Placeholder substitution map ``{"VARNAME": value}``.
        Values may be ``str``, ``int``, ``float``, or ``bool``.
        Keys are case-sensitive and must match the template exactly.

    Returns
    -------
    dict
        Rendered, parsed configuration ready for ``ap.push_config()``.

    Raises
    ------
    FileNotFoundError
        Template file does not exist.
    ValueError
        One or more ``${VAR}`` placeholders are unresolved.
    json.JSONDecodeError
        Rendered text is not valid JSON (usually a bad default value).
    """
    variables = vars or {}
    resolved  = _resolve_path(path)

    if not resolved.exists():
        raise FileNotFoundError(
            f"AP config template not found: {resolved}\n"
            f"(looked up from cwd={Path.cwd()} and project root={_PROJECT_ROOT})"
        )

    raw      = resolved.read_text(encoding="utf-8")
    rendered = _render(raw, variables)
    log.debug("Loaded AP config template '%s' with vars %s", path, list(variables.keys()))

    try:
        return json.loads(rendered)
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"JSON error in rendered template '{path}': {exc.msg}",
            exc.doc, exc.pos,
        ) from exc


def render_template(text: str, vars: dict) -> str:
    """
    Apply variable substitution to a raw JSON template string.

    Exposed for unit testing; prefer ``load_ap_config`` for normal use.
    """
    return _render(text, vars)


# ── Internal ──────────────────────────────────────────────────────────────────

def _resolve_path(path: str) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    cwd_rel = Path.cwd() / p
    if cwd_rel.exists():
        return cwd_rel
    return _PROJECT_ROOT / p


def _render(text: str, variables: dict) -> str:
    """
    Two-pass substitution over raw JSON text.

    Pass 1 — quoted placeholders where the replacement is non-string.
      Replaces the entire  ``"${VAR}"``  token (including JSON quotes) with
      a bare JSON literal: integer, float, ``true``, or ``false``.

    Pass 2 — remaining bare placeholders.
      Replaces  ``${VAR}``  inside string values (quotes already present in
      the template).  String values from *variables* are inserted as-is.
    """
    # --- Pass 1: quoted non-string replacements ---
    def _replace_quoted(m: re.Match) -> str:
        inner    = m.group(1)   # e.g. "${RATE}"  (no outer quotes)
        var_name = m.group(2)
        default  = m.group(3)   # string default from template, may be None

        val = variables.get(var_name)

        if val is None:
            if default is not None:
                # Default is always treated as a string literal in the template.
                # Keep it as a quoted JSON string.
                return f'"{default}"'
            # Leave unchanged; pass 2 will report the error.
            return f'"{inner}"'

        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (int, float)):
            return str(val)
        # String value — keep JSON quotes, insert value.
        return f'"{val}"'

    text = _QUOTED_PLACEHOLDER.sub(_replace_quoted, text)

    # --- Pass 2: bare placeholder substitution (string context) ---
    unresolved: list[str] = []

    def _replace_bare(m: re.Match) -> str:
        var_name = m.group(1)
        default  = m.group(2)

        val = variables.get(var_name)
        if val is None:
            if default is not None:
                return default
            unresolved.append(var_name)
            return m.group(0)   # leave in place so the JSON decode error is descriptive
        return str(val)

    text = _BARE_RE.sub(_replace_bare, text)

    if unresolved:
        raise ValueError(
            f"Unresolved template placeholder(s): {sorted(set(unresolved))}. "
            "Pass these as keys in the vars= dict."
        )

    return text


# Private alias used inside this module (avoids shadowing the public name)
_BARE_RE = _BARE_PLACEHOLDER
