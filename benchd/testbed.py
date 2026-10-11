"""Building a per-run testbed config.

Station, RADIUS and VLAN settings are properties of the *bench* and barely
change; the AP is what varies from run to run. So a run's config starts from the
bench's own ``config/testbed.yaml`` and overrides only the AP block, rather than
asking a person to retype the whole thing in a web form.

Validation is not reimplemented: ``TestbedConfig(**data)`` in
``framework/config.py`` is a pydantic model, so constructing it *is* the
validation step, and its ``ValidationError`` is what the form displays.
"""
from __future__ import annotations

import copy
from pathlib import Path

import yaml
from pydantic import ValidationError

from benchd import paths
from framework.config import TestbedConfig, load_testbed_config   # noqa: F401  (re-exported)

_REDACT = "********"


def base_dict() -> dict:
    if paths.BASE_TESTBED.exists():
        return yaml.safe_load(paths.BASE_TESTBED.read_text()) or {}
    return {}


def build(ap_host: str, ap_user: str, ap_password: str, *,
          cleanup: str = "factory_reset") -> dict:
    """The bench's config with this run's AP substituted in."""
    cfg = copy.deepcopy(base_dict())
    ap = dict(cfg.get("ap") or {})
    ap.update(host=ap_host.strip(), user=ap_user.strip() or "root",
              password=ap_password, cleanup=cleanup)
    cfg["ap"] = ap
    return cfg


def validate(cfg: dict) -> tuple[TestbedConfig | None, str]:
    """``(config, "")`` or ``(None, human-readable error)``."""
    try:
        return TestbedConfig(**cfg), ""
    except ValidationError as exc:
        problems = []
        for err in exc.errors():
            where = ".".join(str(p) for p in err.get("loc", ()))
            problems.append(f"{where}: {err.get('msg', 'invalid')}")
        return None, "; ".join(problems)


def write(cfg: dict, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False))
    dest.chmod(0o600)          # it carries the AP and station passwords
    return dest


def redacted(cfg: dict) -> dict:
    """A copy safe to show in a browser or keep alongside the results."""
    out = copy.deepcopy(cfg)
    # ``or {}`` rather than a ``.get`` default: a key that is *present* with a
    # null value (``radius: null`` is how a profile says "no RADIUS") must read
    # as absent, not as something to call ``.get`` on.
    for section in ("ap", "station"):
        for key in ("password", "root_password"):
            if (out.get(section) or {}).get(key):
                out[section][key] = _REDACT
    ext = out.get("external") or {}
    radius = ext.get("radius") or {}
    if radius.get("secret"):
        radius["secret"] = _REDACT
    if radius.get("password"):
        radius["password"] = _REDACT
    for user in ext.get("local_radius_users") or []:
        if user and user.get("password"):
            user["password"] = _REDACT
    return out
