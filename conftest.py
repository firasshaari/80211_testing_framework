"""
Root conftest — session fixtures, capability gating and report collection.

CORE FILE — adding a test never requires changing this.

Session lifecycle:

1. Load and validate ``testbed.yaml``.
2. Connect to the AP, **stop and disable the uCentral agent** so nothing
   reverts a config mid-test, and connect to the RPi5 station.
3. Probe capabilities once. Tests whose example needs absent hardware skip with
   the reason spelled out.
4. Record every outcome and write a standalone HTML report at the end.
"""
from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import allure
import pytest

from framework.ap.ap_client import APClient
from framework.capability.registry import CapabilityRegistry
from framework.clients.rpi5_station import Station
from framework.config import load_testbed_config
from framework.examples import catalog
from framework.examples.loader import ParseReport, load_example
from framework.examples.normalize import (
    assign_bridge_vlan,
    enable_vlan_awareness,
    ensure_management_access,
    force_forwarding_mode,
    name_ssids_for_test,
    normalize_config,
    point_radius_at,
    restrict_to_band,
    set_strict,
    substitute_vlans,
)
from framework.reporting.html_report import RegressionReport, TestRecord

log = logging.getLogger(__name__)

# Per-test context, keyed by nodeid, merged into the report by the makereport hook.
_CONTEXT: dict[str, dict] = {}


# ── CLI options ──────────────────────────────────────────────────────────────

def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("openwifi")
    group.addoption(
        "--testbed-config",
        action="store",
        default="config/testbed.yaml",
        help="Path to the testbed YAML descriptor (default: config/testbed.yaml)",
    )
    group.addoption(
        "--keep-agent",
        action="store_true",
        default=False,
        help="Leave the uCentral agent running (only for cloud-managed testing)",
    )
    group.addoption(
        "--report-dir",
        action="store",
        default=None,
        help="Directory for the standalone HTML report (default: from testbed.yaml)",
    )
    group.addoption(
        "--cleanup",
        action="store",
        default=None,
        choices=["factory_reset", "restore_agent", "none"],
        help="Override ap.cleanup for this run. 'none' keeps the AP under local "
             "control, which is much faster when running batches back to back.",
    )


def pytest_configure(config: pytest.Config) -> None:
    for area in catalog.Area:
        config.addinivalue_line(
            "markers", f"{area.value}: example feature area '{area.value}'"
        )
    config.addinivalue_line("markers", "regression: part of the standard regression sweep")
    config.addinivalue_line("markers", "config_only: applies a config with no station involved")


# ── Session fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def testbed_config(request):
    path = request.config.getoption("--testbed-config")
    cfg = load_testbed_config(path)
    logging.getLogger("framework").setLevel(cfg.settings.log_level)
    log.info("Loaded testbed %s from %s", cfg.testbed.name, path)
    return cfg


@pytest.fixture(scope="session")
def ap(testbed_config, request):
    """The AP under test, with the uCentral agent stopped for the session."""
    client = APClient(
        host=testbed_config.ap.host,
        user=testbed_config.ap.user,
        password=testbed_config.ap.password,
        port=testbed_config.ap.port,
        key_path=testbed_config.ap.key_path,
    )

    keep_agent = request.config.getoption("--keep-agent")
    disable = testbed_config.ap.disable_ucentral_agent and not keep_agent
    if disable and client.ssh.is_reachable():
        client.disable_agent()

    yield client

    # Hand the AP back. A factory reset is the cleanest end state: it drops
    # everything the tests committed and lets the AP re-onboard to the
    # controller from a known baseline.
    cleanup = request.config.getoption("--cleanup") or testbed_config.ap.cleanup
    if not disable or cleanup == "none":
        pass
    elif cleanup == "factory_reset":
        client.factory_reset(wait_for_boot=True)
    elif cleanup == "restore_agent":
        client.restore_agent()
    client.close()


@pytest.fixture(scope="session")
def station(testbed_config):
    """The RPi5 + BE200 client, taken out of NetworkManager's hands."""
    sta = Station(
        host=testbed_config.station.host,
        user=testbed_config.station.user,
        password=testbed_config.station.password,
        iface=testbed_config.station.iface,
        root_password=testbed_config.station.root_password,
        country=testbed_config.station.country,
        port=testbed_config.station.port,
    )
    if sta.ssh.is_reachable():
        try:
            sta.prepare()
        except Exception as exc:
            log.warning("Station preparation failed: %s", exc)

    yield sta
    sta.teardown()


@pytest.fixture(scope="session")
def capabilities(testbed_config, ap, station):
    return CapabilityRegistry(testbed_config, ap_client=ap, station=station).probe()


@pytest.fixture(scope="session")
def radio_caps(ap, capabilities):
    """
    Per-band radio limits for this DUT, probed once.

    Used to clamp each example's requested mode/width/channel to what the AP
    can actually do — without it, every example asking for HE on a Wi-Fi 5 AP
    is rejected by strict mode.
    """
    if not capabilities.ap_reachable:
        return {}
    try:
        caps = ap.radio_capabilities()
        log.info(
            "AP radio capabilities: %s",
            {b: sorted(c.modes) for b, c in caps.items()} or "none reported",
        )
        return caps
    except Exception as exc:
        log.warning("Could not read AP radio capabilities: %s", exc)
        return {}


@pytest.fixture(scope="session")
def report(request, testbed_config, ap, station, capabilities):
    """Accumulates results and writes the HTML report at session end."""
    rep = RegressionReport(
        testbed_name=testbed_config.testbed.name,
        operator=testbed_config.testbed.operator,
    )

    if capabilities.ap_reachable:
        try:
            rep.ap_info = ap.device_info().as_rows()
        except Exception as exc:
            rep.capability_notes.append(f"Could not read AP identity: {exc}")
    if capabilities.station_reachable:
        try:
            rep.station_info = [
                (k.replace("_", " ").title(), v) for k, v in station.driver_info().items()
            ]
        except Exception as exc:
            rep.capability_notes.append(f"Could not read station identity: {exc}")

    rep.capability_rows = capabilities.as_rows()
    rep.capability_notes.extend(capabilities.notes)

    yield rep

    _seed_allure(request, testbed_config, ap, station, capabilities)

    out_dir = request.config.getoption("--report-dir") or testbed_config.settings.report_dir
    path = rep.write(out_dir)
    print(f"\n\nRegression report: {Path(path).resolve()}")
    print(f"Verdict: {rep.verdict}  "
          f"({rep.count('passed')} passed, {rep.count('failed') + rep.count('error')} failed, "
          f"{rep.count('skipped')} skipped)\n")


def _seed_allure(request, cfg, ap, station, capabilities) -> None:
    """
    Give Allure the context it needs: which bench produced the run, and how to
    classify a failure. Categories mean a reader sees "AP rejected the config"
    and "harness lost the AP" as separate buckets rather than one failure count.
    """
    results = request.config.getoption("--alluredir", None)
    if not results:
        return
    out = Path(results)
    out.mkdir(parents=True, exist_ok=True)

    env = {"Testbed": cfg.testbed.name, "AP.Host": cfg.ap.host,
           "Station.Host": cfg.station.host, "Station.Interface": cfg.station.iface,
           "Bands.Usable": ",".join(sorted(capabilities.usable_bands)) or "none",
           "RADIUS": str(capabilities.has_radius),
           "VLANs": ",".join(
               str(v) for v in
               ((cfg.external.vlan.ids if cfg.external.vlan else []) or [])
           ) or "none"}
    try:
        info = ap.device_info()
        env.update({"AP.Model": info.model, "AP.Firmware": info.firmware,
                    "AP.Serial": info.serial, "AP.Kernel": info.kernel})
    except Exception:
        pass
    try:
        env.update({f"Station.{k.title()}": v
                    for k, v in station.driver_info().items()
                    if k in ("adapter", "driver", "kernel", "os", "regdomain")})
    except Exception:
        pass
    (out / "environment.properties").write_text(
        "\n".join(f"{k}={v}" for k, v in env.items()) + "\n", encoding="utf-8"
    )

    categories = Path("allure-categories/categories.json")
    if categories.exists():
        (out / "categories.json").write_text(categories.read_text(), encoding="utf-8")


def _apply_transcript(result) -> str:
    """
    Everything ``ucentral.uc`` said, so a rejection can actually be diagnosed.

    Empty output and a schema error both surface as "rejected" but mean
    different things: the first is the renderer dying or never starting, the
    second is a config this firmware will not accept. The transcript is what
    tells them apart, so it says so explicitly when there was no output at all.
    """
    parts = [f"exit reason: {result.reason}", f"took {result.duration_s:.1f}s"]
    if result.errors:
        parts.append("errors:\n  " + "\n  ".join(result.errors))
    if result.warnings:
        parts.append("warnings:\n  " + "\n  ".join(result.warnings))
    for label, text in (("stdout", result.stdout), ("stderr", result.stderr)):
        parts.append(f"--- {label} ---\n" + (text.strip() or "(empty)"))
    if not result.stdout.strip() and not result.stderr.strip():
        parts.append(
            "ucentral.uc produced no output at all. That is the renderer never "
            "running or dying before it printed, not the config being refused."
        )
    return "\n\n".join(parts)


def record_config_in_allure(config: dict) -> None:
    """
    Put the config the AP is being given into the Allure report.

    Parameters carry the settings under test so they are visible without
    opening anything; the whole document is attached as JSON. This is the
    finished file as sent over the wire, not the upstream example.
    """
    try:
        import json as _json

        import allure
    except ImportError:  # pragma: no cover - allure is a hard dependency
        return

    radio = (config.get("radios") or [{}])[0]
    for key in ("band", "channel", "channel-mode", "channel-width", "country"):
        if radio.get(key) is not None:
            allure.dynamic.parameter(key, radio[key])

    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            enc = ssid.get("encryption") or {}
            vlan = (iface.get("vlan") or {}).get("id")
            allure.dynamic.parameter(
                f"ssid: {ssid.get('name')}",
                f"{enc.get('proto', 'none')}"
                + (f", key {enc['key']}" if enc.get("key") else "")
                + (f", VLAN {vlan}" if vlan else ", untagged")
                + f", {iface.get('role', '?')}",
            )

    pretty = _json.dumps(config, indent=2)
    allure.dynamic.parameter("config applied", pretty)
    allure.attach(pretty, "config applied to the AP", allure.attachment_type.JSON)


# ── Per-test helpers ─────────────────────────────────────────────────────────

@pytest.fixture
def ctx(request):
    """
    Mutable per-test context picked up by the report.

    Tests rarely touch this directly — :func:`apply_example` fills it in.
    """
    data = {
        "example": "",
        "area": "",
        "mode": "",
        "requirements": [],
        "normalization": [],
        "protos": [],
        "applied_config": "",
        "sta_evidence": "",
        "band": "",
        "cases": [],
        "steps": [],
        "evidence": "",
        "_report": None,
    }
    _CONTEXT[request.node.nodeid] = data
    return data


@pytest.fixture
def prepared_example(testbed_config, capabilities, radio_caps, ctx, ap):
    """
    Returns ``load(example)`` — a callable that resolves a catalog entry to a
    normalized config, skipping first if the bench cannot support it.

    Skipping here rather than in a marker means the reason can name the exact
    missing resource.
    """
    def load(name: str | catalog.Example) -> tuple[catalog.Example, dict]:
        example = name if isinstance(name, catalog.Example) else catalog.get(name)

        ctx["example"] = example.name
        ctx["area"] = example.area.value
        ctx["mode"] = example.mode.value
        ctx["requirements"] = sorted(r.value for r in example.requires)
        ctx["protos"] = sorted(example.protos)

        # Without the AP there is no test at all, so say that plainly rather
        # than letting every case fail with an SSH error.
        if not capabilities.ap_reachable:
            pytest.skip(
                f"AP {testbed_config.ap.host} is not reachable over SSH — "
                f"check the host, credentials and that the AP is powered up"
            )

        # A config can cost the AP its management path mid-sweep. The rollback
        # timer factory-resets and reboots it, so it comes back on its own —
        # but only if we wait. Without this, pytest tears through every
        # remaining test in about a second on connect errors, turning one bad
        # config into sixty bogus failures and destroying the run.
        if not ap.ssh.is_reachable():
            grace = testbed_config.settings.rollback_seconds + 180
            log.warning(
                "AP %s is unreachable; waiting up to %ss for the rollback timer "
                "to restore it before continuing", testbed_config.ap.host, grace,
            )
            if ap.ssh.wait_until_reachable(timeout=grace, interval=10):
                log.info("AP recovered; re-disabling the uCentral agent")
                ap.disable_agent()
            else:
                pytest.skip(
                    f"AP {testbed_config.ap.host} did not come back within "
                    f"{grace}s of going unreachable — it needs a power cycle"
                )

        reason = capabilities.skip_reason(example)
        if reason:
            pytest.skip(reason)

        parse_report = ParseReport()
        raw = load_example(example.name, report=parse_report)

        norm = testbed_config.normalization
        config, changes = normalize_config(
            raw,
            example=example.name,
            country=norm.country,
            avoid_dfs=norm.avoid_dfs,
            force_2g_width=norm.force_2g_width,
            radio_caps=radio_caps,
        )
        # The examples pin illustrative VLAN ids (100, 10, ...). Rewrite them
        # onto the VLANs this lab's DHCP server actually serves, or the client
        # gets no lease and the test fails for an environmental reason.
        vlan_cfg = testbed_config.external.vlan
        if vlan_cfg and vlan_cfg.ids:
            substitute_vlans(config, list(vlan_cfg.ids), report=changes)

            # Put bridged SSIDs on a test VLAN rather than the untagged
            # upstream, so clients land off the management subnet. This is
            # what stops a bridged SSID handing the station an address on the
            # same network it is managed over.
            if norm.bridge_vlan_from_pool:
                assign_bridge_vlan(config, vlan_cfg.ids[0], report=changes)

            # SSIDs whose VLAN comes from RADIUS or a multi-PSK key stay on the
            # untagged interface, but the bridge must be told which VIDs may
            # egress tagged.
            enable_vlan_awareness(config, list(vlan_cfg.ids), report=changes)

        # The corpus points RADIUS at 10.0.0.1 (and the captive portal at a
        # public address). Left alone, every enterprise and portal-RADIUS case
        # authenticates against a host that does not exist here.
        radius_cfg = testbed_config.external.radius
        if radius_cfg:
            point_radius_at(
                config, radius_cfg.host, radius_cfg.secret,
                auth_port=radius_cfg.auth_port, acct_port=radius_cfg.acct_port,
                report=changes,
            )

        # Non-negotiable: keep SSH on the WAN or the AP disappears mid-run.
        # 71 of 78 upstream interfaces in the corpus omit it.
        ensure_management_access(
            config,
            report=changes,
            idle_timeout=norm.ssh_idle_timeout,
        )

        if norm.strict_apply:
            set_strict(config)

        ctx["_report"] = changes
        ctx["normalization"] = list(changes.changes)
        if not parse_report.strict:
            ctx["normalization"].append(
                f"source was not strict JSON ({', '.join(parse_report.fixups)})"
            )
        return example, config

    return load


@pytest.fixture
def apply_example(ap, testbed_config, prepared_example, ctx):
    """
    Returns ``apply(example)`` — prepare, push and verify one example config.

    Fails the test with the renderer's own error text when the AP rejects the
    config, since ``ucentral.uc`` exits 0 either way.
    """
    import json as _json

    def apply(name: str | catalog.Example) -> tuple[catalog.Example, dict]:
        example, config = prepared_example(name)
        ctx["applied_config"] = _json.dumps(config, indent=2)

        result = ap.apply_config(
            config,
            name=example.name,
            timeout=testbed_config.settings.apply_timeout,
            rollback_seconds=testbed_config.settings.rollback_seconds,
        )
        if not result.success:
            pytest.fail(
                f"AP rejected '{example.name}': {result.reason}\n"
                f"(ucentral.uc exits 0 on a custom config path, so this is "
                f"parsed from its output)"
            )
        if result.warnings:
            log.warning("%s applied with warnings: %s", example.name, result.warnings)

        ap.wait_for_wireless(timeout=testbed_config.settings.wireless_settle_timeout)
        return example, config

    return apply


@pytest.fixture
def apply_case(ap, testbed_config, prepared_example, radio_caps, ctx):
    """
    Apply one example pinned to a specific band and forwarding mode.

    The matrix suites use this instead of :func:`apply_example` so each cell
    tests exactly one combination: with every band live at once the station
    picks whichever it prefers, and the result says nothing about the others.
    """
    import json as _json

    def apply(name, *, band: str, mode: str):
        example, config = prepared_example(name)

        name_ssids_for_test(
            config,
            ap.short_name(),
            password=testbed_config.settings.default_passphrase,
            report=ctx["_report"],
        )
        restrict_to_band(
            config, band,
            channel_plan=testbed_config.normalization.channel_plan,
            radio_caps=radio_caps,
            report=ctx["_report"],
        )
        force_forwarding_mode(config, mode, report=ctx["_report"])

        # Bridge-forcing can land SSIDs on the untagged upstream — that is the
        # management interface, and an example whose SSIDs all started on a
        # downstream interface (maverick, ssh, igmp, ...) has no tagged twin for
        # it to prefer. Clients would then be bridged onto the management subnet
        # itself, which is how the harness locked itself out of the station.
        # Re-running the assignment moves them onto the test VLAN where they
        # belong.
        vlan_cfg = testbed_config.external.vlan
        if mode == "bridge" and vlan_cfg and vlan_cfg.ids:
            assign_bridge_vlan(config, vlan_cfg.ids[0], report=ctx["_report"])

        ensure_management_access(
            config, report=ctx["_report"],
            idle_timeout=testbed_config.normalization.ssh_idle_timeout,
        )
        if testbed_config.normalization.strict_apply:
            set_strict(config)

        ctx["normalization"] = list(ctx["_report"].changes)
        ctx["mode"] = mode
        ctx["band"] = band
        ctx["applied_config"] = _json.dumps(config, indent=2)

        # Record before applying, not after. A rejected config is exactly the
        # one a reader needs to see, and recording on the success path only
        # meant it was missing from every failure.
        record_config_in_allure(config)

        result = ap.apply_config(
            config,
            name=f"{example.name}-{band}-{mode}",
            timeout=testbed_config.settings.apply_timeout,
            rollback_seconds=testbed_config.settings.rollback_seconds,
        )
        if not result.success:
            # Without this the largest failure bucket reads "config was
            # rejected" and nothing else — there is no way to tell a schema
            # error from a renderer that produced nothing at all, which are
            # different problems with different owners.
            allure.attach(
                _apply_transcript(result),
                f"ucentral.uc output — {example.name} on {band}",
                allure.attachment_type.TEXT,
            )
            pytest.fail(f"AP rejected '{example.name}' on {band}/{mode}: {result.reason}")

        ap.wait_for_wireless(timeout=testbed_config.settings.wireless_settle_timeout)
        return example, config

    return apply


# ── Result collection ────────────────────────────────────────────────────────

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    result = outcome.get_result()

    # One record per test: the call phase, or the setup phase when setup is
    # what decided the outcome (a capability skip, or a fixture blowing up).
    if result.when == "call":
        pass
    elif result.when == "setup" and (result.skipped or result.failed):
        pass
    else:
        return

    session_report: RegressionReport | None = getattr(item.session, "_regression_report", None)
    if session_report is None:
        return

    data = _CONTEXT.get(item.nodeid, {})
    if result.skipped:
        status = "skipped"
    elif result.failed:
        status = "error" if result.when == "setup" else "failed"
    else:
        status = "passed"

    message = _outcome_message(result, status)

    icon = {"passed": "PASS ", "failed": "FAIL ", "error": "ERROR", "skipped": "SKIP "}[status]
    detail = f" — {_truncate_line(message)}" if message and status != "passed" else ""
    _progress(f"{icon}  {item.name}{detail}")

    # A test may report several independent cases (one per SSID). Emit a record
    # for each so the report can show a card per case rather than burying five
    # good results inside one failed test's message.
    cases = data.get("cases") or []
    if cases and result.when == "call":
        for c in cases:
            session_report.add(
                TestRecord(
                    name=f"{item.name}:{c.get('ssid', '?')}",
                    example=data.get("example", ""),
                    area=data.get("area", ""),
                    mode=data.get("mode", ""),
                    band=data.get("band", ""),
                    status=c.get("status", "passed"),
                    duration_s=c.get("duration_s", 0.0),
                    message=c.get("message", ""),
                    ssid=c.get("ssid", ""),
                    channel=c.get("channel", ""),
                    vlan=c.get("vlan", ""),
                    ip=c.get("ip", ""),
                    rtt_ms=c.get("rtt_ms", ""),
                    key_mgmt=c.get("key_mgmt", ""),
                    pairwise=c.get("pairwise", ""),
                    bssid=c.get("bssid", ""),
                    rssi=c.get("rssi", ""),
                    ping_summary=c.get("ping_summary", ""),
                    config_summary=c.get("config_summary", []),
                    applied_config=data.get("applied_config", ""),
                    sta_evidence=c.get("evidence", ""),
                    protos=[c.get("proto", "")] if c.get("proto") else [],
                )
            )
        return

    session_report.add(
        TestRecord(
            name=item.name,
            example=data.get("example", ""),
            area=data.get("area", ""),
            mode=data.get("mode", ""),
            status=status,
            duration_s=getattr(result, "duration", 0.0),
            message=message,
            requirements=data.get("requirements", []),
            normalization=data.get("normalization", []),
            protos=data.get("protos", []),
            applied_config=data.get("applied_config", ""),
            ap_log=data.get("ap_log", ""),
            sta_evidence=data.get("sta_evidence") or data.get("evidence", ""),
            band=data.get("band", ""),
            steps=data.get("steps", []),
        )
    )


# ── Live progress ────────────────────────────────────────────────────────────
# A hardware sweep takes minutes per test, and pytest's own output is buffered
# when piped, so a long run looks hung. Every test start and finish is written
# immediately to stderr and appended to reports/progress.log, which can be
# followed with `tail -f` from another terminal.

_PROGRESS_PATH = Path("reports/progress.log")
_STARTED: dict[str, float] = {}


def _progress(line: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    text = f"[{stamp}] {line}"
    print(text, file=sys.stderr, flush=True)
    try:
        _PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _PROGRESS_PATH.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError:
        pass


def pytest_runtest_logstart(nodeid, location):
    _STARTED[nodeid] = time.monotonic()
    _progress(f"START  {nodeid.split('::')[-1]}")


def pytest_runtest_logfinish(nodeid, location):
    started = _STARTED.pop(nodeid, None)
    if started is not None:
        _progress(f"       ...{time.monotonic() - started:.0f}s elapsed")


def _truncate_line(text: str, limit: int = 110) -> str:
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _outcome_message(result, status: str) -> str:
    """
    Human-readable detail for the report.

    pytest represents a skip as the tuple ``(path, lineno, "Skipped: reason")``.
    Only the reason is worth showing — the location is already implied by the
    test name.
    """
    if status == "passed" or result.longrepr is None:
        return ""

    if status == "skipped" and isinstance(result.longrepr, tuple):
        reason = str(result.longrepr[2])
        return reason.removeprefix("Skipped: ")

    return str(getattr(result, "longreprtext", None) or result.longrepr)


# Fixtures whose presence means a test is talking to real hardware and should
# therefore appear in the regression report.
_HARDWARE_FIXTURES = {"ap", "station", "capabilities", "apply_example", "prepared_example"}


@pytest.fixture(autouse=True)
def _bind_report_to_session(request):
    """
    Make the session report reachable from the makereport hook.

    The hook has no fixture access, so the report is built on the first
    hardware-touching test and stashed on the session. It is deliberately not
    built for the offline suite under ``tests/unit``, which has no testbed and
    must stay runnable in CI.
    """
    if _HARDWARE_FIXTURES & set(request.fixturenames):
        request.session._regression_report = request.getfixturevalue("report")
    yield
