"""One shared bench password.

The console holds AP root passwords and can start and stop tests on live
hardware, so it is not left open. Per-user accounts would be the wrong trade for
a lab box that a handful of people share — one password, hashed at rest, is the
amount of ceremony this deserves.

The hash lives in ``benchd.env`` outside the repo, so it is never committed.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from benchd import paths

_ITERATIONS = 240_000


def _read_env() -> dict[str, str]:
    if not paths.ENV_FILE.exists():
        return {}
    out = {}
    for line in paths.ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest.hex()}"


def verify(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, expected = stored.split("$", 3)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, AttributeError):
        return False


def configured() -> bool:
    return bool(_read_env().get("BENCH_PASSWORD_HASH"))


def check(password: str) -> bool:
    stored = _read_env().get("BENCH_PASSWORD_HASH", "")
    if not stored:
        return False
    return verify(password, stored)


def secret_key() -> str:
    """Session signing key, generated and persisted on first use."""
    env = _read_env()
    key = env.get("BENCH_SECRET_KEY")
    if key:
        return key
    key = secrets.token_hex(32)
    write_env({**env, "BENCH_SECRET_KEY": key})
    return key


def write_env(values: dict[str, str]) -> None:
    paths.ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    paths.ENV_FILE.write_text(
        "# Bench Console secrets. Not in the repo, not in backups you share.\n"
        + body + "\n")
    os.chmod(paths.ENV_FILE, 0o600)


def set_password(password: str) -> None:
    env = _read_env()
    env["BENCH_PASSWORD_HASH"] = hash_password(password)
    env.setdefault("BENCH_SECRET_KEY", secrets.token_hex(32))
    write_env(env)
