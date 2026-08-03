"""
Deploy the self-contained lab services to the station host.

Copies ``infra/`` to the station and runs the container scripts there, so a
checkout of this repo reproduces the same testbed on identical hardware. See
``infra/README.md`` for what runs and why it uses macvlan.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from framework.clients.ssh import SSHSession
from framework.config import load_testbed_config

REMOTE = "/opt/regression-infra"
FILES = [
    "infra.env",
    "up.sh",
    "down.sh",
    "freeradius/Containerfile",
    "freeradius/clients.conf.tmpl",
    "freeradius/authorize",
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("action", choices=["up", "down", "status"])
    ap.add_argument("--testbed-config", default="config/testbed.yaml")
    args = ap.parse_args(argv)

    cfg = load_testbed_config(args.testbed_config)
    s = SSHSession(cfg.station.host, cfg.station.user, cfg.station.password,
                   sudo_password=cfg.station.root_password, label="STA")

    if args.action == "status":
        print(s.run("podman ps --format '{{.Names}}\t{{.Status}}'", sudo=True).stdout)
        return 0

    if args.action == "down":
        print(s.run(f"sh {REMOTE}/down.sh", sudo=True, timeout=120).stdout.strip())
        return 0

    local = Path(__file__).resolve().parents[1] / "infra"
    s.run(f"mkdir -p {REMOTE}/freeradius", sudo=True)
    s.run(f"chown -R {cfg.station.user} {REMOTE}", sudo=True)
    for rel in FILES:
        src = local / rel
        if not src.exists():
            print(f"missing {src}", file=sys.stderr)
            return 2
        s.put_text(src.read_text(), f"{REMOTE}/{rel}")
    s.run(f"chmod +x {REMOTE}/up.sh {REMOTE}/down.sh")

    print("starting services (first run builds the arm64 RADIUS image)...")
    r = s.run(f"sh {REMOTE}/up.sh 2>&1 | tail -12", sudo=True, timeout=1800)
    print(r.stdout.strip() or r.stderr.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
