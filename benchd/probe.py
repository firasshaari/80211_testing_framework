"""Identify a DUT before committing to a run.

This is deliberately read-only: it reads the AP's identity and radio
capability and asks the capability layer what would run, but it does **not**
stop the uCentral agent or write anything to the device. A person clicking
"Probe" to find out what a box is should not change that box.

Everything here is a thin adapter over existing framework APIs —
``APClient.device_info()``, ``.radio_capabilities()``,
``CapabilityRegistry.probe()`` and ``plan.build_plan()``. ``plan.render_plan()``
is intentionally unused: it returns formatted text for a terminal, and parsing
it back would be scraping our own output when the structured form is right
there.
"""
from __future__ import annotations

from framework.ap.ap_client import APClient
from framework.capability.registry import CapabilityRegistry
from framework.clients.rpi5_station import Station
from framework.plan import build_plan


def _example_row(example, reason: str = "") -> dict:
    row = {
        "name": example.name,
        "area": example.area.value,
        "mode": example.mode.value,
        "summary": example.summary,
        "requires": sorted(r.value for r in example.requires),
        "bands": sorted(example.bands),
        "protos": sorted(example.protos),
    }
    if reason:
        row["reason"] = reason
    return row


def probe(cfg) -> dict:
    """
    Identity, capability and feasibility for one AP.

    Returns a JSON-serialisable dict; every failure is reported in-band as
    ``ok: False`` with a reason, because "the AP did not answer" is a normal
    thing for a person to be told, not an exception for them to decode.
    """
    out: dict = {"ok": False, "ap": {}, "radios": [], "station": {},
                 "capability": [], "notes": [], "runnable": [], "skipped": [],
                 "error": ""}
    ap = station = None
    try:
        ap = APClient(
            host=cfg.ap.host, user=cfg.ap.user, password=cfg.ap.password,
            port=cfg.ap.port, key_path=cfg.ap.key_path,
        )
        info = ap.device_info()
        out["ap"] = {
            "host": cfg.ap.host,
            "model": info.model, "board": info.board_name,
            "platform": info.platform, "firmware": info.firmware,
            "kernel": info.kernel, "serial": info.serial,
            "short_name": ap.short_name(),
        }
        out["rows"] = [list(r) for r in info.as_rows()]

        for band, caps in sorted(ap.radio_capabilities().items()):
            out["radios"].append({
                "band": band,
                "modes": sorted(caps.modes),
                "widths": {m: sorted(caps.widths_for(m)) for m in sorted(caps.modes)},
                "channels": sorted(caps.channels),
                "dfs": sorted(caps.dfs_channels),
            })

        try:
            station = Station(
                host=cfg.station.host, user=cfg.station.user,
                password=cfg.station.password, iface=cfg.station.iface,
                root_password=cfg.station.root_password, port=cfg.station.port,
                country=cfg.station.country,
            )
            station.prepare()
            out["station"] = station.driver_info()
        except Exception as exc:                                  # noqa: BLE001
            out["notes"].append(f"station not ready: {str(exc)[:140]}")

        caps = CapabilityRegistry(cfg, ap_client=ap, station=station).probe()
        out["capability"] = [list(r) for r in caps.as_rows()]
        out["notes"].extend(caps.notes)

        runnable, skipped = build_plan(caps)
        out["runnable"] = [_example_row(e) for e in runnable]
        out["skipped"] = [_example_row(e, reason) for e, reason in skipped]
        out["ok"] = True
    except Exception as exc:                                      # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
    finally:
        for client in (ap, station):
            try:
                if client:
                    client.close()
            except Exception:                                     # noqa: BLE001
                pass
    return out
