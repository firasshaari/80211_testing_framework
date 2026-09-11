"""
Prove the bench is fit to test before spending hours on it.

Three long sweeps were lost in one session to conditions that take seconds to
detect: the station unreachable, the station's radio missing, and the lab RADIUS
container not running after a reboot. Each produced a full run of failures that
looked like AP defects and were not. Nothing here tests the AP — it tests the
things a result would otherwise be silently wrong about.

    python -m framework.preflight [--wait SECONDS]
"""
from __future__ import annotations

import argparse
import sys

from framework.clients.ssh import SSHError, SSHSession
from framework.config import load_testbed_config


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/testbed.yaml")
    ap.add_argument("--wait", type=int, default=0,
                    help="seconds to wait for the station to come back first")
    args = ap.parse_args()
    cfg = load_testbed_config(args.config)

    print(f"Preflight — station {cfg.station.host}, AP {cfg.ap.host}")
    station = SSHSession(cfg.station.host, cfg.station.user, cfg.station.password,
                         label="STA")
    if args.wait:
        print(f"  waiting up to {args.wait}s for the station...")
        station.wait_until_reachable(timeout=args.wait, interval=10)

    ok = True
    try:
        ok &= check("station reachable", station.is_reachable())
    except SSHError as exc:
        return 1 if not check("station reachable", False, str(exc)[:60]) else 0

    iface = cfg.station.iface
    ok &= check(f"station radio {iface} present",
                station.run(f"test -d /sys/class/net/{iface}").ok)

    # Prepare the interface the same way a test does before judging it. After a
    # reboot NetworkManager owns the radio and a scan returns nothing, which is
    # not a fault — it is simply a step that has not run yet.
    from framework.clients.rpi5_station import Station

    sta = Station(cfg.station.host, cfg.station.user, cfg.station.password,
                  iface=iface, root_password=cfg.station.root_password)
    try:
        sta.prepare()
    except Exception as exc:                                  # noqa: BLE001
        check("station interface prepared", False, str(exc)[:60])

    # The radio must not merely exist — it has to be able to scan, which is what
    # every "SSID not on the air" verdict depends on.
    scan = station.run(f"iw dev {iface} scan | grep -c '^BSS '",
                       sudo=True, timeout=90).stdout.strip()
    ok &= check("station can scan", scan.isdigit() and int(scan) > 0,
                f"{scan or '0'} BSS visible")

    if cfg.external.radius:
        # Deliberately *not* sudo. infra/up.sh runs the container rootless as
        # the station user, so its store is /run/user/1000/containers; asking
        # root's podman returns an empty list and the check fails even while
        # RADIUS is up and answering Access-Accepts. A gate that cries wolf is
        # worse than no gate, because the habit it teaches is to override it.
        running = station.run(
            "podman ps --format '{{.Names}}' | grep -c '^radius$'"
        ).stdout.strip()
        ok &= check("lab RADIUS running", running not in ("", "0"),
                    "start it with infra/up.sh" if running in ("", "0") else "")

    ap_ssh = SSHSession(cfg.ap.host, cfg.ap.user, cfg.ap.password, label="AP")
    try:
        ok &= check("AP reachable", ap_ssh.is_reachable())
    except SSHError as exc:
        ok &= check("AP reachable", False, str(exc)[:60])

    print("\nBench is ready." if ok else "\nBench is NOT ready — fix the above first.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
