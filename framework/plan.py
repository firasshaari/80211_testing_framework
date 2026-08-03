"""
Discovery and test-plan preview.

Run this before a sweep to see exactly what this bench can and cannot test:

    python -m framework.plan --testbed-config config/testbed.yaml
    make plan

It follows the same order the regression run does — log in to the AP, stop the
uCentral agent so the controller cannot push config underneath the tests, read
the AP's real capabilities, then report which examples are feasible and why the
rest are not. The agent is restored on exit unless ``--keep-disabled`` is given.

Nothing is applied to the AP. This is read-only apart from stopping the agent.
"""
from __future__ import annotations

import argparse
import logging
import sys

from framework.ap.ap_client import APClient
from framework.capability.registry import CapabilityRegistry
from framework.clients.rpi5_station import Station
from framework.config import load_testbed_config
from framework.examples import catalog

log = logging.getLogger(__name__)

_COL = {"ok": "\033[32m", "skip": "\033[33m", "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}


def _c(text: str, style: str, colour: bool) -> str:
    return f"{_COL[style]}{text}{_COL['off']}" if colour else text


def build_plan(capabilities) -> tuple[list, list[tuple]]:
    """Split the catalog into (runnable, [(example, reason), ...])."""
    runnable, skipped = [], []
    for example in catalog.EXAMPLES:
        reason = capabilities.skip_reason(example)
        if reason:
            skipped.append((example, reason))
        else:
            runnable.append(example)
    return runnable, skipped


def render_plan(capabilities, device_info, radio_caps, station_info, *, colour=True) -> str:
    out: list[str] = []
    add = out.append

    add(_c("\n=== Device under test ===", "bold", colour))
    for k, v in (device_info.as_rows() if device_info else [("AP", "unreachable")]):
        add(f"  {k:<12} {v}")

    if radio_caps:
        add(_c("\n=== Radio capability (as advertised by the AP) ===", "bold", colour))
        for band, caps in sorted(radio_caps.items()):
            best = max(caps.modes, key=lambda m: ("HT", "VHT", "HE", "EHT").index(m)) \
                if caps.modes else "?"
            widths = sorted(caps.widths_for(best)) if caps.modes else []
            add(f"  {band:<4} modes={sorted(caps.modes)} max={best} "
                f"widths={widths} channels={len(caps.channels)}")

    if station_info:
        add(_c("\n=== Station ===", "bold", colour))
        for k, v in station_info.items():
            add(f"  {k:<12} {v}")

    add(_c("\n=== Testbed capability ===", "bold", colour))
    for k, v in capabilities.as_rows():
        add(f"  {k:<20} {v}")
    for note in capabilities.notes:
        add(_c(f"  note: {note}", "dim", colour))

    runnable, skipped = build_plan(capabilities)

    add(_c("\n=== FEASIBLE TESTS ===", "bold", colour))
    by_area: dict[str, list] = {}
    for e in runnable:
        by_area.setdefault(e.area.value, []).append(e)
    for area in sorted(by_area):
        names = ", ".join(e.name for e in sorted(by_area[area], key=lambda x: x.name))
        add(f"  {_c('RUN ', 'ok', colour)}{area:<14} ({len(by_area[area]):>2}) {names}")

    add(_c("\n=== NOT FEASIBLE ON THIS BENCH ===", "bold", colour))
    by_reason: dict[str, list[str]] = {}
    for e, reason in skipped:
        by_reason.setdefault(reason, []).append(e.name)
    for reason in sorted(by_reason):
        names = ", ".join(sorted(by_reason[reason]))
        add(f"  {_c('SKIP', 'skip', colour)} {reason}")
        add(_c(f"         {names}", "dim", colour))

    total = len(catalog.EXAMPLES)
    add(_c(f"\n{len(runnable)} of {total} examples runnable, "
           f"{len(skipped)} skipped.", "bold", colour))
    add("Run them with:  make regression        (or: make sweep AREA=security)")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--testbed-config", default="config/testbed.yaml")
    parser.add_argument("--keep-disabled", action="store_true",
                        help="Leave the uCentral agent stopped, ready for a test run")
    parser.add_argument("--no-colour", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level="INFO", format="%(levelname)-7s %(name)s: %(message)s")
    cfg = load_testbed_config(args.testbed_config)
    colour = not args.no_colour and sys.stdout.isatty()

    ap = APClient(cfg.ap.host, cfg.ap.user, cfg.ap.password,
                  port=cfg.ap.port, key_path=cfg.ap.key_path)
    station = Station(cfg.station.host, cfg.station.user, cfg.station.password,
                      iface=cfg.station.iface, root_password=cfg.station.root_password,
                      country=cfg.station.country, port=cfg.station.port)

    device_info, radio_caps, station_info = None, {}, {}
    disabled = False
    try:
        if ap.ssh.is_reachable():
            ap.disable_agent()          # step 1: cut the controller loose
            disabled = True
            device_info = ap.device_info()
            radio_caps = ap.radio_capabilities()
        else:
            print(f"AP {cfg.ap.host} is not reachable over SSH.", file=sys.stderr)

        if station.ssh.is_reachable():
            try:
                station.prepare()
                station_info = station.driver_info()
            except Exception as exc:
                log.warning("Station preparation failed: %s", exc)

        capabilities = CapabilityRegistry(cfg, ap_client=ap, station=station).probe()
        print(render_plan(capabilities, device_info, radio_caps, station_info, colour=colour))
        return 0
    finally:
        if disabled and not args.keep_disabled:
            ap.restore_agent()
            print("\nuCentral agent restored. Note the controller will re-push its own "
                  "config, so the AP briefly drops SSH and reverts its SSIDs.")
        elif disabled:
            print("\nuCentral agent left STOPPED — the AP stays under local control.")
        ap.close()
        station.ssh.close()


if __name__ == "__main__":
    raise SystemExit(main())
