"""
Interactive testbed setup.

    python -m framework.setup          # or: make setup

Asks for everything the framework needs and writes ``config/testbed.yaml``.
Each question says which examples the answer unlocks, so it is obvious what a
blank answer costs — skipping a section is always allowed and simply means the
tests needing it will skip with a reason rather than fail.

Existing files are backed up, and current values are offered as defaults, so
re-running it to add (say) a RADIUS server later is safe.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

from framework.examples import catalog

DEFAULT_PATH = Path("config/testbed.yaml")


# ── Prompt helpers ───────────────────────────────────────────────────────────

def ask(prompt: str, default: str | None = None, *, secret: bool = False) -> str:
    suffix = f" [{'*****' if secret and default else default}]" if default else ""
    while True:
        raw = input(f"  {prompt}{suffix}: ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        print("    (a value is required)")


def ask_bool(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    raw = input(f"  {prompt} [{d}]: ").strip().lower()
    if not raw:
        return default
    return raw.startswith("y")


def ask_int(prompt: str, default: int | None = None) -> int | None:
    while True:
        raw = input(f"  {prompt}{f' [{default}]' if default is not None else ''}: ").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            print("    (must be a whole number)")


def unlocks(*requirements) -> str:
    """Name the examples a requirement would unlock, for the prompt text."""
    names = sorted({
        e.name for e in catalog.EXAMPLES
        if any(r in e.requires for r in requirements)
    })
    if not names:
        return ""
    shown = ", ".join(names[:6])
    more = f" (+{len(names) - 6} more)" if len(names) > 6 else ""
    return f"unlocks {len(names)}: {shown}{more}"


def section(title: str, detail: str = "") -> None:
    print(f"\n\033[1m{title}\033[0m")
    if detail:
        print(f"  {detail}")


# ── The interview ────────────────────────────────────────────────────────────

def interview(existing: dict) -> dict:
    ap = existing.get("ap", {})
    sta = existing.get("station", {})
    ext = existing.get("external", {})
    meta = existing.get("testbed", {})

    print("\n=== OpenWiFi regression testbed setup ===")
    print("Press Enter to accept a default. Leave an optional section blank to skip it.")

    section("Testbed identity")
    cfg: dict = {
        "testbed": {
            "name": ask("Testbed name", meta.get("name", "bench-1")),
            "description": ask("Description", meta.get("description", "")),
            "operator": ask("Operator", meta.get("operator", "")),
        }
    }

    section("Access point under test", "Reached over SSH; the uCentral agent is "
                                       "stopped for the run and the AP handed back afterwards.")
    cfg["ap"] = {
        "host": ask("AP IP address", ap.get("host")),
        "user": ask("AP SSH user", ap.get("user", "root")),
        "password": ask("AP SSH password", ap.get("password", "openwifi"), secret=True),
        "disable_ucentral_agent": True,
        "cleanup": ask("Cleanup when done (factory_reset/restore_agent/none)",
                       ap.get("cleanup", "factory_reset")),
    }

    section("Station (RPi5 + BE200)", "The wireless client used for association, "
                                      "DHCP, ping and throughput checks.")
    cfg["station"] = {
        "host": ask("Station IP address", sta.get("host")),
        "user": ask("Station SSH user", sta.get("user", "pi")),
        "password": ask("Station SSH password", sta.get("password"), secret=True),
        "root_password": ask("Station root/sudo password (blank = same)",
                             sta.get("root_password", "")) or None,
        "iface": ask("BE200 interface (wlan0 if onboard wifi is disabled)",
                     sta.get("iface", "wlan0")),
        "country": ask("Regulatory domain", sta.get("country", "US")),
    }

    external: dict = {}

    # ── RADIUS ───────────────────────────────────────────────────────────────
    section("External RADIUS server", unlocks(catalog.Requirement.RADIUS))
    if ask_bool("Do you have a RADIUS server?", bool(ext.get("radius"))):
        r = ext.get("radius") or {}
        external["radius"] = {
            "host": ask("RADIUS server IP", r.get("host")),
            "secret": ask("Shared secret", r.get("secret"), secret=True),
            "auth_port": ask_int("Authentication port", r.get("auth_port", 1812)),
            "acct_port": ask_int("Accounting port", r.get("acct_port", 1813)),
            "identity": ask("Test user identity", r.get("identity", "testuser")),
            "password": ask("Test user password", r.get("password", "testpass"), secret=True),
            "eap_method": ask("EAP method (PEAP/TTLS/TLS)", r.get("eap_method", "PEAP")),
        }
        print("\n  Dynamic VLAN assignment: if this server returns a VLAN for the test")
        print("  identity (Tunnel-Private-Group-Id), give the id. Without it we cannot")
        print("  tell a correct assignment from no assignment, so that test is skipped.")
        dv = ask_int("VLAN the server assigns to "
                     f"{external['radius']['identity']!r} (blank if none)",
                     r.get("dynamic_vlan"))
        if dv:
            external["radius"]["dynamic_vlan"] = dv

    # ── Local RADIUS (the AP's own EAP server) ───────────────────────────────
    section("Local RADIUS (eap_local)",
            "The AP can serve EAP itself. The upstream example ships one account "
            "and no VLAN, so supply accounts here to test it properly.")
    if ask_bool("Configure local EAP accounts?", bool(ext.get("local_radius_users"))):
        users = []
        existing_users = ext.get("local_radius_users") or []
        idx = 0
        while True:
            prior = existing_users[idx] if idx < len(existing_users) else {}
            name = ask(f"  User {idx + 1} username (blank to finish)",
                       prior.get("username", "")) if idx else ask(
                       "  User 1 username", prior.get("username", "testuser"))
            if not name:
                break
            entry = {
                "username": name,
                "password": ask(f"  User {idx + 1} password",
                                prior.get("password", "testpass"), secret=True),
            }
            vid = ask_int(f"  VLAN to assign {name!r} (blank for none)",
                          prior.get("vlan_id"))
            if vid:
                entry["vlan_id"] = vid
            users.append(entry)
            idx += 1
            if not ask_bool("  Add another account?", idx < len(existing_users)):
                break
        if users:
            external["local_radius_users"] = users

    # ── VLANs ────────────────────────────────────────────────────────────────
    section("VLANs", unlocks(catalog.Requirement.VLAN))
    print("  These are the VLANs your switch trunks to the AP and your DHCP server")
    print("  serves. Tests map an SSID onto a VLAN and check the client lands in it.")
    if ask_bool("Do you have VLANs trunked to the AP?", bool(ext.get("vlan"))):
        v = ext.get("vlan") or {}
        raw = ask("What VLAN IDs does the DHCP server provide? (comma separated, e.g. 100,200)",
                  ",".join(str(x) for x in v.get("ids", [])) or None)
        ids = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
        gateways: dict[int, str] = {}
        existing_gw = {int(k): val for k, val in (v.get("gateways") or {}).items()}
        for vid in ids:
            gw = ask(f"Gateway IP on VLAN {vid} (blank to skip connectivity checks)",
                     existing_gw.get(vid, ""))
            if gw:
                gateways[vid] = gw
        external["vlan"] = {"ids": ids, "gateways": gateways}

    # ── Traffic peer ─────────────────────────────────────────────────────────
    section("iperf3 server", "Needed for throughput and rate-limit enforcement checks.")
    if ask_bool("Do you have an iperf3 server reachable from the client subnet?",
                bool(ext.get("iperf_server"))):
        external["iperf_server"] = ask("iperf3 server IP", ext.get("iperf_server"))

    # ── Peer AP ──────────────────────────────────────────────────────────────
    section("Second AP / tunnel endpoint", unlocks(catalog.Requirement.PEER_AP))
    if ask_bool("Do you have a second AP or tunnel endpoint?", bool(ext.get("peer_ap_host"))):
        external["peer_ap_host"] = ask("Peer AP IP", ext.get("peer_ap_host"))

    # ── Other optional resources ─────────────────────────────────────────────
    section("Other resources")
    if ask_bool("External DHCP server for the relay test?", bool(ext.get("dhcp_server"))):
        external["dhcp_server"] = ask("DHCP server IP", ext.get("dhcp_server"))
    if ask_bool("External captive-portal / UAM backend?", bool(ext.get("captive_backend"))):
        external["captive_backend"] = ask("Portal URL", ext.get("captive_backend"))

    section("Device hardware", "Answer for the AP under test.")
    external["has_switch_hw"] = ask_bool("Does the AP have a managed switch fabric?",
                                         ext.get("has_switch_hw", False))
    external["has_gps_hw"] = ask_bool("Does the AP have GPS hardware?",
                                      ext.get("has_gps_hw", False))
    external["has_wwan_hw"] = ask_bool("Does the AP have a WWAN modem?",
                                       ext.get("has_wwan_hw", False))
    external["has_internet"] = ask_bool("Does the bench have internet access?",
                                        ext.get("has_internet", True))

    cfg["external"] = external
    cfg["normalization"] = existing.get("normalization", {
        "country": cfg["station"]["country"],
        "avoid_dfs": True,
        "force_2g_width": 20,
        "strict_apply": True,
    })
    cfg["settings"] = existing.get("settings", {"report_dir": "reports"})
    return cfg


def summarize(cfg: dict) -> None:
    """Show what this configuration will and will not be able to test."""
    ext = cfg.get("external", {})
    have = set()
    R = catalog.Requirement
    have.add(R.STATION)
    if ext.get("radius"):
        have.add(R.RADIUS)
    if (ext.get("vlan") or {}).get("ids"):
        have.add(R.VLAN)
    if ext.get("peer_ap_host"):
        have.add(R.PEER_AP)
    if ext.get("dhcp_server"):
        have.add(R.DHCP_SERVER)
    if ext.get("captive_backend"):
        have.add(R.CAPTIVE_BACKEND)
    if ext.get("has_switch_hw"):
        have.add(R.SWITCH_HW)
    if ext.get("has_gps_hw"):
        have.add(R.GPS_HW)
    if ext.get("has_wwan_hw"):
        have.add(R.WWAN_HW)
    if ext.get("has_internet"):
        have.add(R.INTERNET)

    runnable = [e for e in catalog.EXAMPLES if set(e.requires) <= have]
    print(f"\n\033[1mThis configuration can run {len(runnable)} of "
          f"{len(catalog.EXAMPLES)} examples.\033[0m")
    print("  Radio-dependent needs (6 GHz, Wi-Fi 7) are probed from the hardware,")
    print("  so the real number is confirmed by 'make plan'.")


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = Path(argv[0]) if argv else DEFAULT_PATH

    if not sys.stdin.isatty():
        print("framework.setup needs an interactive terminal.", file=sys.stderr)
        return 2

    existing = {}
    if path.exists():
        existing = yaml.safe_load(path.read_text()) or {}
        print(f"Found an existing {path}; its values are offered as defaults.")

    cfg = interview(existing)

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
        print(f"\nBacked up previous config to {backup}")

    path.write_text(yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False))
    print(f"Wrote {path}")
    summarize(cfg)
    print("\nNext:  make plan       (confirm against the real hardware)")
    print("       make regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
