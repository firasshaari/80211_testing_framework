"""
One test per example, per band. One result, reported through Allure.

Applying a config, the SSIDs coming up, a client associating and that client
reaching the internet are steps of one test, not four tests. Each case runs them
in order and stops at the first failure, because every later step depends on the
one before it — there is nothing to learn from trying to associate to an SSID
that never came up.

Each step is an ``allure.step``, so the report shows exactly how far a case got,
and the config, station evidence and logs are attached to the step that produced
them. Failure classification is handled by ``allure-categories/categories.json``
rather than by anything here.
"""
from __future__ import annotations

import allure
import pytest

from framework.clients.rpi5_station import StationError
from framework.examples import catalog
from framework.examples.inspect import iter_ssids, station_ready_ssids
from tests.regression import validators

BANDS = ["2G", "5G", "6G"]

# Readable names for the feature level of the report hierarchy.
_AREA_LABELS = {
    "security": "Security", "network_mode": "Forwarding",
    "rate_limit": "Rate limiting", "qos": "Quality of service",
    "roaming": "Roaming and steering", "captive": "Captive portal",
    "vlan": "VLAN", "tunnel": "Tunnels and mesh", "services": "On-AP services",
    "telemetry": "Telemetry", "switch": "Switch fabric",
    "wifi_gen": "6 GHz and Wi-Fi 7", "wwan": "Cellular uplink",
}

# Bridge only, by request. NAT is implemented (force_forwarding_mode) and can be
# reinstated by extending this.
MODE = "bridge"


def _cases():
    """
    Parametrize on the example *name*, not the object.

    Allure records the parametrize arguments verbatim, and a dataclass repr
    lands in the report as 300-odd characters of noise. The name is what a
    reader recognises; the catalog entry is looked up inside the test.
    """
    for example in catalog.EXAMPLES:
        for band in BANDS:
            yield pytest.param(
                example.name, band,
                marks=[getattr(pytest.mark, example.area.value), pytest.mark.regression],
                id=f"{example.name}-{band}",
            )


@allure.epic("OpenWiFi regression")
@pytest.mark.parametrize("example_name,band", list(_cases()))
def test_example(example_name, band, apply_case, ap, station, capabilities,
                 testbed_config, ctx):
    """Apply one upstream example on one band and verify it end to end."""
    example = catalog.get(example_name)
    # epic > feature > story gives the report a hierarchy that means something:
    # "Security > Enterprise — external RADIUS > Baseline WPA2 Enterprise",
    # rather than a flat list of example filenames.
    allure.dynamic.feature(_AREA_LABELS.get(example.area.value,
                                            example.area.value.title()))
    allure.dynamic.story(catalog.group_of(example))
    allure.dynamic.title(f"{example.summary} · {band}")
    allure.dynamic.description(
        f"**{example.name}** — {example.summary}\n\n"
        f"- Area: {example.area.value.replace('_', ' ')}\n"
        f"- Group: {catalog.group_of(example)}\n"
        f"- Band: {band}, forwarding: {MODE}\n"
        f"- Needs: {', '.join(sorted(r.value for r in example.requires)) or 'AP only'}"
    )
    for tag in (band, MODE, example.area.value):
        allure.dynamic.tag(tag)

    if band not in capabilities.usable_bands:
        pytest.skip(
            f"{band} unusable here — testbed lacks it "
            f"(AP {sorted(capabilities.ap_bands) or 'none'}, "
            f"station {sorted(capabilities.station_bands) or 'none'})"
        )

    # ── 1. the AP accepts and renders the config ─────────────────────────────
    with allure.step(f"Apply {example.name} on {band}"):
        applied, config = apply_case(example, band=band, mode=MODE)

    # ── 2. the SSIDs it declares are on the air ──────────────────────────────
    expected = {
        s.name for s in iter_ssids(config)
        if s.bss_mode == "ap" and (not s.bands or band in s.bands)
    }
    if expected:
        with allure.step(f"{len(expected)} SSID(s) come up"):
            missing = ap.wait_for_ssids(
                expected, timeout=testbed_config.settings.ssid_up_timeout
            )
            allure.attach(
                "\n".join(sorted(expected)), "SSIDs configured",
                allure.attachment_type.TEXT,
            )
            assert not missing, (
                f"{', '.join(sorted(missing))} configured but not broadcasting"
            )

            # The AP answering for a BSS is not the same as that BSS being on
            # the air. Confirm from the station, which is the only side that
            # can tell the difference — and say so here rather than letting it
            # resurface later as a client that "did not associate".
            seen = station.visible_ssids(expected)
            allure.attach(
                "\n".join(f"{'yes' if s in seen else 'NO '}  {s}"
                          for s in sorted(expected)),
                "visible in a station scan", allure.attachment_type.TEXT,
            )
            silent = expected - seen
            assert not silent, (
                f"{', '.join(sorted(silent))} configured on the AP but not on "
                f"the air — no beacon reached the station"
            )

    # ── 3. the station can join ──────────────────────────────────────────────
    # Enterprise SSIDs are joinable only when the bench holds a certificate
    # identity for them (infra/pki). Without this the RADIUS examples would
    # only ever exercise their companion PSK SSID.
    targets = station_ready_ssids(
        config, bands=frozenset({band}),
        enterprise=bool(_eap_identity(testbed_config)),
    )
    if not targets:
        allure.dynamic.parameter("client", "no SSID this station can join unaided")
        return

    # Each SSID is joined and then immediately made to carry traffic, while
    # that association is the live one. Checking traffic once at the end
    # instead measured whatever the station happened to be attached to after
    # the last connect, while reporting the *first* SSID's address — so a
    # working network could be reported as "got 10.10.100.184 but cannot reach
    # the internet" when the diagnosis underneath said there was no address at
    # all. It also matches the rule that every successful connect has to pass
    # traffic, not just one of them.
    passed, failed = [], []
    case = validators.Case(
        ap=ap, station=station, config=config, example=example, band=band,
        mode=MODE, testbed=testbed_config,
    )
    with allure.step(f"Client joins and passes traffic ({len(targets)} SSID(s))"):
        for ssid in targets:
            label = f"{ssid.name} ({ssid.proto})"
            try:
                with allure.step(label):
                    assoc = _join_and_use(station, ssid, testbed_config)
                    # Still associated, so anything measured or probed here is
                    # measured over the link under test.
                    case.ssid, case.assoc = ssid, assoc
                    failed.extend(_run_checks(
                        validators.per_ssid_checks(case), case, label
                    ))
                passed.append(ssid.name)
            except (AssertionError, StationError) as exc:
                failed.append(f"{label}: {_brief(exc)}")
            finally:
                station.disconnect()

    # ── 5. the feature the example exists to exercise actually works ─────────
    ap_checks = validators.ap_side_checks(case)
    if ap_checks and passed:
        with allure.step(f"{example.name} behaves as configured"):
            failed.extend(_run_checks(ap_checks, case, example.name))
            for note in case.notes:
                allure.attach(note, "scope of this check",
                              allure.attachment_type.TEXT)

    if failed:
        pytest.fail(
            f"{len(passed)} of {len(targets)} SSID(s) worked end to end; "
            f"{len(failed)} did not\n  " + "\n  ".join(failed)
        )


def _eap_identity(testbed_config) -> dict:
    """
    The certificate identity for enterprise SSIDs, or {} if the bench has none.

    Returning an empty dict rather than raising keeps a bench without a PKI
    working exactly as before: the enterprise SSIDs simply stay out of the
    joinable set instead of failing.
    """
    radius = getattr(testbed_config.external, "radius", None)
    if not radius or not (radius.ca_cert and radius.client_cert and radius.private_key):
        return {}
    return {
        "identity": radius.identity,
        "eap_method": radius.eap_method,
        "certificates": {
            "ca_cert": radius.ca_cert,
            "client_cert": radius.client_cert,
            "private_key": radius.private_key,
        },
    }


def _run_checks(checks, case, label) -> list[str]:
    """
    Run feature checks, recording each as its own step.

    A failing check is collected rather than raised, so one feature assertion
    going wrong still lets the others report — the point of these is to say
    *which* parts of a feature work, and stopping at the first failure throws
    that away.
    """
    problems = []
    for name, check in checks:
        with allure.step(f"{name}"):
            try:
                evidence = check(case)
                allure.attach(evidence, f"{name} — evidence",
                              allure.attachment_type.TEXT)
            except AssertionError as exc:
                problems.append(f"{label} [{name}]: {_brief(exc)}")
            except Exception as exc:                  # noqa: BLE001
                # A check that cannot run is not the same as a feature that is
                # broken, and must not be reported as one.
                allure.attach(f"{type(exc).__name__}: {exc}",
                              f"{name} — could not run",
                              allure.attachment_type.TEXT)
    return problems


def _join_and_use(station, ssid, testbed_config):
    """
    Associate to one SSID, clear any portal, and prove it carries traffic.

    Raises with the reason if any of that fails; the caller records it against
    this SSID. Evidence is attached whether it worked or not, because a
    successful association is as much a result as a failed one.
    """
    try:
        eap = _eap_identity(testbed_config) if ssid.enterprise else {}
        assoc = station.connect(
            ssid.name, ssid.proto,
            passphrase=ssid.key or testbed_config.settings.default_passphrase,
            timeout=testbed_config.settings.association_timeout,
            **eap,
        )
    except StationError:
        allure.attach(station.supplicant_evidence(),
                      f"{ssid.name} — wpa_supplicant", allure.attachment_type.TEXT)
        raise

    allure.attach(assoc.evidence(), f"{ssid.name} — station evidence",
                  allure.attachment_type.TEXT)
    assert assoc.has_ip, "associated but DHCP never answered"

    if ssid.has_captive:
        _pass_the_portal(station, ssid, testbed_config)

    ping = station.verify_internet(count=testbed_config.settings.ping_count)
    allure.attach(
        f"{ping.received}/{ping.transmitted} replies, {ping.loss_pct:.0f}% loss, "
        f"avg {ping.rtt_avg_ms} ms",
        f"{ssid.name} — ping google.com from {assoc.ip}",
        allure.attachment_type.TEXT,
    )
    if not ping.ok:
        allure.attach(station.diagnose_path(), f"{ssid.name} — path diagnosis",
                      allure.attachment_type.TEXT)
    assert ping.ok, (
        f"had {assoc.ip} but no traffic "
        f"({ping.received}/{ping.transmitted} replies)"
    )
    return assoc


def _pass_the_portal(station, ssid, testbed_config) -> None:
    """
    Authenticate at the captive portal, the way a guest would.

    Until this happens the AP holds the client in a walled garden, so the
    internet check that follows would fail for a portal that is working exactly
    as designed. Credentials come from the config where the portal keeps its own
    list, and from the testbed otherwise — a ``radius`` or ``uam`` portal
    validates against a backend, not against anything the config declares.
    """
    mode = ssid.captive.get("auth-mode", "click-to-continue")
    username, password = ssid.portal_login
    radius = testbed_config.external.radius
    if mode in ("radius", "uam") and radius:
        username = username or radius.identity
        password = password or radius.password

    with allure.step(f"Client passes the {mode} captive portal"):
        result = station.pass_captive_portal(
            mode, username=username, password=password,
        )
        allure.attach(result.evidence(), f"{ssid.name} — captive portal",
                      allure.attachment_type.TEXT)
        assert result.authorised, (
            f"{mode} portal still intercepting HTTP after {result.action}"
        )


def _brief(exc: Exception) -> str:
    """
    First meaningful line — station errors carry long scan dumps.

    Long enough to keep the diagnosis. The old 160-character cut removed the
    part that explained *why* a BSS was never selected, leaving only "was never
    selected"; the scan dump is still stripped by the markers above it, so the
    extra room costs nothing.
    """
    text = str(exc)
    for marker in ("Visible SSIDs:", "\n"):
        if marker in text:
            text = text.split(marker)[0]
    return text.strip()[:420]
