"""
Standalone HTML regression report.

Self-contained by design — one file, inline CSS, no network fetches — so it can
be emailed or attached to a ticket and still render. Allure remains available
for interactive drilldown; this is the artifact you hand to someone who wants
to know whether the build is good.
"""
from __future__ import annotations

import html
import json
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = ["TestRecord", "RegressionReport"]

_STATUS_ORDER = {"failed": 0, "error": 1, "passed": 2, "skipped": 3}

# A raw failure count is misleading: most failures in a long sweep are the
# framework losing the AP or an apply producing no output, not the AP being
# wrong. Classifying them is what makes the number mean something.
DEFECT, INVESTIGATE, ARTEFACT = "defect", "investigate", "artefact"

CLASS_LABEL = {
    DEFECT: "Real AP defects",
    INVESTIGATE: "Needs investigation",
    ARTEFACT: "Framework / transport artefacts (not the AP)",
}
CLASS_BLURB = {
    DEFECT: "The AP rejected or mis-rendered a config. These are findings.",
    INVESTIGATE: "The AP accepted the config but the client could not use it. "
                 "Could be the AP, the station, or the example.",
    ARTEFACT: "The harness lost the AP, or an apply returned nothing. These say "
              "nothing about the AP and should not count against it.",
}

# Ordered: first match wins, so the specific patterns precede the generic ones.
_ARTEFACT_PATTERNS = (
    "in connect", "cannot ssh", "not reachable over ssh", "transport failed",
    "hung and was killed", "did not finish", "no uci batch in ucentral.uc output",
)
_DEFECT_PATTERNS = (
    "value must be", "[e]", "rejecting config due to strict", "fatal error",
)
_INVESTIGATE_PATTERNS = (
    "did not associate", "no dhcp lease", "cannot reach", "did not come up",
    "not up", "no internet",
)


def classify_failure(message: str) -> str:
    """Bucket a failure by what it actually tells you about the AP."""
    m = (message or "").lower()
    for pat in _DEFECT_PATTERNS:
        if pat in m:
            return DEFECT
    for pat in _INVESTIGATE_PATTERNS:
        if pat in m:
            return INVESTIGATE
    for pat in _ARTEFACT_PATTERNS:
        if pat in m:
            return ARTEFACT
    return INVESTIGATE


@dataclass
class TestRecord:
    """One test outcome, plus the context needed to interpret it."""

    name: str
    example: str = ""
    area: str = ""
    mode: str = ""
    status: str = "passed"          # passed | failed | skipped | error
    duration_s: float = 0.0
    message: str = ""
    requirements: list[str] = field(default_factory=list)
    normalization: list[str] = field(default_factory=list)
    protos: list[str] = field(default_factory=list)
    applied_config: str = ""
    ap_log: str = ""
    # Proof from the station: supplicant debug, link detail, ping results.
    sta_evidence: str = ""
    band: str = ""
    # Per-case detail, for the card layout.
    ssid: str = ""
    channel: str = ""
    vlan: str = ""
    ip: str = ""
    rtt_ms: str = ""
    key_mgmt: str = ""
    pairwise: str = ""
    bssid: str = ""
    rssi: str = ""
    ping_summary: str = ""
    config_summary: list[tuple[str, str]] = field(default_factory=list)
    # Ordered steps of one test: apply -> SSIDs up -> connect -> internet.
    steps: list[dict] = field(default_factory=list)

    @property
    def is_failure(self) -> bool:
        return self.status in ("failed", "error")


@dataclass
class RegressionReport:
    """Accumulates results across a session and renders the HTML."""

    testbed_name: str = "openwifi-regression"
    operator: str = ""
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc).astimezone())
    finished: datetime | None = None

    ap_info: list[tuple[str, str]] = field(default_factory=list)
    station_info: list[tuple[str, str]] = field(default_factory=list)
    capability_rows: list[tuple[str, str]] = field(default_factory=list)
    capability_notes: list[str] = field(default_factory=list)

    records: list[TestRecord] = field(default_factory=list)

    # ── Accumulation ─────────────────────────────────────────────────────────

    def add(self, record: TestRecord) -> None:
        self.records.append(record)

    # ── Derived counts ───────────────────────────────────────────────────────

    @property
    def total(self) -> int:
        return len(self.records)

    def count(self, status: str) -> int:
        return sum(1 for r in self.records if r.status == status)

    @property
    def executed(self) -> int:
        """Tests that actually ran — the denominator that matters for pass rate."""
        return self.total - self.count("skipped")

    @property
    def pass_rate(self) -> float:
        return 100.0 * self.count("passed") / self.executed if self.executed else 0.0

    @property
    def duration_s(self) -> float:
        end = self.finished or datetime.now(timezone.utc).astimezone()
        return (end - self.started).total_seconds()

    @property
    def verdict(self) -> str:
        if self.count("failed") or self.count("error"):
            return "FAILED"
        if self.executed == 0:
            return "NOTHING RAN"
        return "PASSED"

    def by_area(self) -> dict[str, list[TestRecord]]:
        grouped: dict[str, list[TestRecord]] = {}
        for r in self.records:
            grouped.setdefault(r.area or "uncategorized", []).append(r)
        for records in grouped.values():
            records.sort(key=lambda r: (_STATUS_ORDER.get(r.status, 9), r.name))
        return dict(sorted(grouped.items()))

    def security_coverage(self) -> list[tuple[str, str]]:
        """Which encryption protos were actually exercised, and how they fared."""
        outcomes: dict[str, list[str]] = {}
        for r in self.records:
            for proto in r.protos:
                outcomes.setdefault(proto, []).append(r.status)
        rows = []
        for proto, statuses in sorted(outcomes.items()):
            if "failed" in statuses or "error" in statuses:
                verdict = "failed"
            elif "passed" in statuses:
                verdict = "passed"
            else:
                verdict = "skipped"
            rows.append((proto, verdict))
        return rows

    # ── Triage ───────────────────────────────────────────────────────────────

    def triage(self) -> dict[str, list[TestRecord]]:
        out: dict[str, list[TestRecord]] = {DEFECT: [], INVESTIGATE: [], ARTEFACT: []}
        for r in self.records:
            if r.is_failure:
                out[classify_failure(r.message)].append(r)
        return out

    def merged(self) -> list[dict]:
        """
        One entry per example+band, with attempt counts.

        A flaky example that failed once in four attempts is one shaky result,
        not four defects, and the raw list makes it look like the latter.
        """
        groups: dict[tuple, dict] = {}
        for r in self.records:
            key = (r.area, _display_name(r), r.band, _kind(r.name))
            g = groups.setdefault(key, {
                "area": r.area, "name": key[1], "band": r.band, "kind": key[3],
                "attempts": 0, "passed": 0, "failed": 0, "skipped": 0,
                "messages": [], "records": [],
            })
            g["attempts"] += 1
            g[r.status if r.status in ("passed", "skipped") else "failed"] += 1
            g["records"].append(r)
            if r.is_failure and r.message:
                g["messages"].append(r.message)
        return sorted(groups.values(), key=lambda g: (g["area"], g["name"], g["band"]))

    # ── Rendering ────────────────────────────────────────────────────────────

    def write(self, directory: str | Path) -> Path:
        self.finished = self.finished or datetime.now(timezone.utc).astimezone()
        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)

        stamp = self.started.strftime("%Y%m%d-%H%M%S")

        # The console is the artefact people open; the flat document remains
        # for printing and for pasting into a ticket.
        from framework.reporting.console import render as render_console

        path = out_dir / f"regression-{stamp}.html"
        path.write_text(render_console(self), encoding="utf-8")
        (out_dir / f"regression-{stamp}-document.html").write_text(
            self._render(), encoding="utf-8"
        )

        # A stable filename makes CI links and bookmarks work run over run.
        latest = out_dir / "latest.html"
        latest.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

        (out_dir / f"regression-{stamp}.json").write_text(
            json.dumps(self._as_dict(), indent=2), encoding="utf-8"
        )
        return path

    def _as_dict(self) -> dict:
        return {
            "testbed": self.testbed_name,
            "operator": self.operator,
            "started": self.started.isoformat(),
            "finished": (self.finished or self.started).isoformat(),
            "duration_s": round(self.duration_s, 1),
            "verdict": self.verdict,
            "totals": {
                "total": self.total,
                "passed": self.count("passed"),
                "failed": self.count("failed"),
                "error": self.count("error"),
                "skipped": self.count("skipped"),
                "pass_rate": round(self.pass_rate, 1),
            },
            "ap": dict(self.ap_info),
            "station": dict(self.station_info),
            "capabilities": dict(self.capability_rows),
            "notes": self.capability_notes,
            "results": [
                {
                    "name": r.name,
                    "example": r.example,
                    "area": r.area,
                    "mode": r.mode,
                    "band": r.band,
                    "status": r.status,
                    "duration_s": round(r.duration_s, 2),
                    "message": r.message,
                    "requirements": r.requirements,
                    "config": r.applied_config,
                    "steps": r.steps,
                }
                for r in self.records
            ],
        }

    def _render(self) -> str:
        e = html.escape
        ap = dict(self.ap_info)
        t = self.triage()
        defects = len(t[DEFECT])
        tone = "clean" if not defects else ("critical" if defects > 2 else "attention")
        plural = "" if defects == 1 else "s"
        station = dict(self.station_info).get("Adapter", "").split("(")[0].strip()

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(ap.get("Model", "AP"))} regression &middot; {self.started:%Y-%m-%d %H:%M}</title>
<style>{_CSS}</style>
</head>
<body>
<main>

<header class="masthead">
  <p class="eyebrow">OpenWiFi regression</p>
  <h1 class="verdict {tone}">{defects} real defect{plural}</h1>
  <p class="verdict-sub">{self.count("passed")} passed &middot;
     {self.count("failed") + self.count("error")} failed &middot;
     {self.count("skipped")} skipped &middot; {_humanize(self.duration_s)}</p>

  <dl class="spec">
    {_spec("Device", ap.get("Model"))}
    {_spec("Firmware", ap.get("Firmware"))}
    {_spec("Serial", ap.get("Serial"))}
    {_spec("Station", station)}
    {_spec("Bands", dict(self.capability_rows).get("Usable bands"))}
    {_spec("Run", format(self.started, "%d %b %Y %H:%M"))}
  </dl>
</header>

{self._render_triage()}
{self._render_results()}
{self._render_environment()}

<footer>
  <p>{e(self.testbed_name)} &middot; generated
     {self.finished:%Y-%m-%d %H:%M} on {e(platform.node())}</p>
</footer>

</main>
</body>
</html>
"""

    # ── Sections ─────────────────────────────────────────────────────────────

    def _render_triage(self) -> str:
        """
        Failures grouped by cause, then by reason within each cause.

        Listing every example separately repeats the same sentence five times
        and buries the signal; one line per distinct reason with the affected
        examples beside it says the same thing in a fifth of the space.
        """
        t = self.triage()
        if not any(t.values()):
            return ('<section><h2>Failures</h2>'
                    '<p class="none">Nothing failed.</p></section>')

        lanes = []
        for cls in (DEFECT, INVESTIGATE, ARTEFACT):
            recs = t[cls]
            if not recs:
                continue
            by_reason: dict[str, list[str]] = {}
            for r in recs:
                reason = _short_reason(r.message)
                who = _display_name(r) + (f" {r.band}" if r.band else "")
                names = by_reason.setdefault(reason, [])
                if who not in names:
                    names.append(who)
            items = []
            for reason, names in list(by_reason.items())[:8]:
                shown = ", ".join(names[:5])
                if len(names) > 5:
                    shown += f" +{len(names) - 5}"
                items.append(
                    '<li><span class="reason">' + html.escape(reason) + "</span>"
                    '<span class="who">' + html.escape(shown) + "</span></li>"
                )
            lanes.append(
                '<div class="lane ' + cls + '">'
                '<div class="lane-head"><span class="lane-n">' + str(len(recs)) + "</span>"
                '<span class="lane-title">' + html.escape(CLASS_LABEL[cls]) + "</span></div>"
                '<ul class="lane-list">' + "".join(items) + "</ul></div>"
            )
        return ('<section><h2>Failures by cause</h2><div class="lanes">'
                + "".join(lanes) + "</div></section>")

    def _render_results(self) -> str:
        """One table for the whole run; detail expands in place."""
        rows = []
        current_area = None
        for g in self.merged():
            if g["area"] != current_area:
                current_area = g["area"]
                peers = [x for x in self.merged() if x["area"] == current_area]
                ok = sum(1 for x in peers if x["passed"] and not x["failed"])
                rows.append(
                    '<tr class="group"><td class="stripe"></td>'
                    '<td colspan="6"><span class="group-name">'
                    + html.escape(_area_label(current_area))
                    + '</span><span class="group-n">' + str(ok) + "/"
                    + str(len(peers)) + "</span></td></tr>"
                )
            worst = "failed" if g["failed"] else ("passed" if g["passed"] else "skipped")
            flaky = bool(g["failed"] and g["passed"])
            stripe = worst
            if worst == "failed" and g["messages"]:
                stripe = classify_failure(g["messages"][0])
            attempts = f'{g["passed"]}/{g["attempts"]}' if g["attempts"] > 1 else ""
            flaky_pill = '<span class="pill flaky">flaky</span>' if flaky else ""
            rows.append(
                '<tr class="' + worst + '">'
                '<td class="stripe ' + stripe + '"></td>'
                '<td class="name"><code>' + html.escape(g["name"]) + "</code></td>"
                '<td class="check">' + html.escape(g["kind"]) + "</td>"
                '<td class="band-col">' + html.escape(g["band"] or "") + "</td>"
                '<td class="state"><span class="pill ' + worst + '">' + worst + "</span>"
                + flaky_pill + "</td>"
                '<td class="num">' + attempts + "</td>"
                '<td class="more">' + self._render_detail(g) + "</td>"
                "</tr>"
            )
        return (
            '<section><h2>Every case <span class="n">' + str(len(rows)) + "</span></h2>"
            '<div class="scroll"><table>'
            "<thead><tr><th></th><th>Example</th><th>Check</th><th>Band</th>"
            "<th>Result</th><th>Steps</th><th>Attempts</th><th></th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table></div></section>"
        )

    def _render_detail(self, g: dict) -> str:
        """Config, evidence and logs for one merged case."""
        rec = next((r for r in g["records"] if r.is_failure), g["records"][0])
        parts = []
        if g["messages"]:
            parts.append('<p class="dl">Result</p><p class="detail-lead">'
                         + html.escape(_first_line(g["messages"][0])) + "</p>")

        if rec.config_summary:
            rows = "".join(
                "<tr><th>" + html.escape(str(k)) + "</th><td>"
                + html.escape(str(v)) + "</td></tr>"
                for k, v in rec.config_summary
            )
            parts.append('<p class="dl">Config applied</p><table class="kv">' + rows + "</table>")
        elif rec.applied_config.strip():
            parts.append('<p class="dl">Config applied</p><pre>'
                         + html.escape(rec.applied_config[:12000]) + "</pre>")

        ev = [(k, v) for k, v in (
            ("key_mgmt", rec.key_mgmt), ("pairwise", rec.pairwise),
            ("BSSID", rec.bssid), ("RSSI", rec.rssi),
            ("IP", rec.ip), ("ping", rec.ping_summary)) if v]
        if ev:
            rows = "".join(
                "<tr><th>" + html.escape(k) + "</th><td>"
                + html.escape(str(v)) + "</td></tr>" for k, v in ev
            )
            parts.append('<p class="dl">Evidence</p><table class="kv">' + rows + "</table>")

        if rec.is_failure and rec.message:
            parts.append('<p class="dl">Failure</p><pre class="bad">'
                         + html.escape(_truncate(rec.message, 900)) + "</pre>")
        if rec.sta_evidence.strip():
            parts.append('<p class="dl">Station log</p><pre>'
                         + html.escape(clean_evidence(rec.sta_evidence)[:9000]) + "</pre>")
        if rec.is_failure and rec.ap_log.strip():
            parts.append('<p class="dl">AP log</p><pre>'
                         + html.escape(rec.ap_log[-4000:]) + "</pre>")

        if not parts:
            return ""
        return ("<details><summary>open</summary><div class=\"detail\">"
                + "".join(parts) + "</div></details>")

    def _render_environment(self) -> str:
        rows = "".join(
            "<tr><th>" + html.escape(str(k)) + "</th><td>"
            + html.escape(str(v)) + "</td></tr>"
            for k, v in self.capability_rows
        )
        notes = ""
        if self.capability_notes:
            items = "".join("<li>" + html.escape(n) + "</li>" for n in self.capability_notes)
            notes = '<ul class="notes">' + items + "</ul>"
        return ('<section class="env"><h2>Testbed</h2>'
                '<div class="scroll"><table class="kv wide">' + rows + "</table></div>"
                + notes + "</section>")


AREA_LABELS = {
    "security": "Security",
    "network_mode": "Forwarding",
    "rate_limit": "Rate limiting",
    "qos": "Quality of service",
    "roaming": "Roaming and steering",
    "captive": "Captive portal",
    "vlan": "VLAN",
    "tunnel": "Tunnels and mesh",
    "services": "On-AP services",
    "telemetry": "Telemetry",
    "switch": "Switch fabric",
    "wifi_gen": "6 GHz and Wi-Fi 7",
    "wwan": "Cellular uplink",
}


def _area_label(area: str) -> str:
    if area in AREA_LABELS:
        return AREA_LABELS[area]
    words = (area or "other").replace("_", " ")
    return words[:1].upper() + words[1:]


def _spec(label: str, value) -> str:
    if not value:
        return ""
    return ("<div><dt>" + html.escape(label) + "</dt><dd>"
            + html.escape(str(value)) + "</dd></div>")


_NOISE_TAIL = re.compile(
    r"(Visible SSIDs:|\(ucentral\.uc exits 0|\(last wpa_state|Live SSIDs:).*",
    re.S,
)


def _short_reason(message: str) -> str:
    """One compact sentence naming the cause, with per-run detail stripped."""
    text = _first_line(message)
    text = _NOISE_TAIL.sub("", text).strip(" .,")
    # "radius: enterprise association failed" -> "enterprise association failed"
    text = re.sub(r"^[\w.-]+:\s+", "", text)
    text = re.sub(r"^AP rejected '[^']+':\s*", "", text)
    text = re.sub(r"\b\d+ of \d+\b", "some", text)
    text = re.sub(r"\s+", " ", text)
    return _truncate(text, 78) or "unclassified"


def _first_line(text: str) -> str:
    """
    The failure itself, with pytest's traceback stripped.

    A stored message is a full longrepr: file/line/function, the offending
    source, then the actual error on lines prefixed ``E``. Only those last
    lines say anything a reader wants — showing the traceback header instead
    puts "tests/regression/test_config_apply.py:33" where the reason belongs.
    """
    raw = text or ""
    said = [
        line[1:].strip()
        for line in raw.splitlines()
        if line.startswith("E ") and line[1:].strip()
    ]
    if said:
        msg = said[0]
        for prefix in ("Failed: ", "AssertionError: ", "StationError: ", "SSHError: "):
            if msg.startswith(prefix):
                msg = msg[len(prefix):]
                break
        return msg

    # No pytest error lines — a skip reason or a plain string.
    for line in raw.splitlines():
        line = line.strip()
        if line and not _TRACEBACK_LINE.match(line):
            return line
    return raw.strip()[:160]


# "path/to/file.py:123: in function" and bare source/caret lines.
_TRACEBACK_LINE = re.compile(r"^(\S+\.py:\d+:|\^+$|self\b|_{3,})")


# ── Helpers ──────────────────────────────────────────────────────────────────
# ── Rendering helpers ────────────────────────────────────────────────────────




# What each pytest function actually checks, in words a reader recognises.
CHECK_NAMES = {
    "config_applies": "AP accepted the config",
    "ssids_come_up": "SSIDs are broadcasting",
    "config_only_commits_to_uci": "Config committed to UCI",
    "security_matrix": "Connects on every security mode",
    "traffic_matrix": "Client reaches the internet",
    "personal_security_modes": "Personal security modes work",
    "enterprise_security_modes": "802.1X authentication works",
    "open_and_encrypted_ssids_differ_in_beacons": "Beacons advertise right security",
    "client_lands_in_expected_network": "Client lands in the right network",
    "nat_client_reaches_ap_gateway": "NATed client reaches its gateway",
    "client_isolation_blocks_peer_traffic": "Client isolation holds",
    "default_config_association_and_dhcp": "Associates and gets an address",
    "client_passes_traffic": "Link carries traffic",
    "rate_limit_is_enforced": "Rate limit is enforced",
    "ssid_maps_to_the_configured_vlan": "SSID lands on its VLAN",
    "multi_psk_keys_map_to_different_vlans": "Each PSK lands on its own VLAN",
    "radius_assigns_the_expected_vlan": "RADIUS assigns the VLAN",
}


def _display_name(record) -> str:
    """
    What to call a case in the report.

    Prefers the SSID, then the example, and only then the check itself — a raw
    pytest node name like ``test_client_passes_traffic`` should never reach the
    page.
    """
    return record.ssid or record.example or _kind(record.name)


def _kind(name: str) -> str:
    """A readable name for the check a case belongs to."""
    base = name.split("[")[0].replace("test_", "")
    if base in CHECK_NAMES:
        return CHECK_NAMES[base]
    words = base.replace("_", " ").strip()
    return words[:1].upper() + words[1:]


def _anchor(r: "TestRecord") -> str:
    raw = f"{r.area}-{r.name}-{r.band}"
    return "c-" + "".join(ch if ch.isalnum() else "-" for ch in raw).strip("-").lower()


_EPOCH_TS = re.compile(r"^\d{10}\.\d+:\s*")


def clean_evidence(text: str) -> str:
    """
    Make supplicant output readable: drop epoch timestamps and the interface
    prefix that repeats on every line, and collapse blank runs. The raw form is
    unreadable in a report even though it holds the proof.
    """
    out = []
    for line in (text or "").splitlines():
        line = _EPOCH_TS.sub("", line.strip())
        line = re.sub(r"^(wlan\d+(-\d+)?|p2p-dev-wlan\d+):\s*", "", line)
        if line:
            out.append(line)
    return "\n".join(out)


def _truncate(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _humanize(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"



_CSS = """
/* Test-equipment readout. Mono carries every datum and label, sans is reserved
   for prose, so the page reads like instrument output rather than a dashboard.
   Neutrals take a cool slate bias; the accent is a signal teal held apart from
   the semantic pass/warn/fail hues so status never competes with chrome. */
:root{
  --ink:#10151c; --paper:#f6f7f9; --surface:#ffffff; --line:#dde2e9;
  --muted:#5a6472; --faint:#8b95a3;
  --accent:#0e7c86;
  --pass:#1a7f4b; --pass-bg:#e8f4ed;
  --warn:#b26a00; --warn-bg:#fbf1e0;
  --fail:#c02a37; --fail-bg:#fbe9ea;
  --idle:#7b8594; --idle-bg:#eef1f5;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,"Cascadia Mono",Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme:dark){
  :root{
    --ink:#e6ebf2; --paper:#0c1015; --surface:#141a21; --line:#242c36;
    --muted:#97a1af; --faint:#6d7885; --accent:#3fb3bd;
    --pass:#4cc48a; --pass-bg:#102a1d;
    --warn:#e2a944; --warn-bg:#2c2211;
    --fail:#ff7d87; --fail-bg:#2e1418;
    --idle:#79838f; --idle-bg:#1a212a;
  }
}
:root[data-theme="dark"]{
  --ink:#e6ebf2; --paper:#0c1015; --surface:#141a21; --line:#242c36;
  --muted:#97a1af; --faint:#6d7885; --accent:#3fb3bd;
  --pass:#4cc48a; --pass-bg:#102a1d; --warn:#e2a944; --warn-bg:#2c2211;
  --fail:#ff7d87; --fail-bg:#2e1418; --idle:#79838f; --idle-bg:#1a212a;
}
:root[data-theme="light"]{
  --ink:#10151c; --paper:#f6f7f9; --surface:#ffffff; --line:#dde2e9;
  --muted:#5a6472; --faint:#8b95a3; --accent:#0e7c86;
  --pass:#1a7f4b; --pass-bg:#e8f4ed; --warn:#b26a00; --warn-bg:#fbf1e0;
  --fail:#c02a37; --fail-bg:#fbe9ea; --idle:#7b8594; --idle-bg:#eef1f5;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
main{max-width:1180px;margin:0 auto;padding:0 1.25rem 4rem;
  display:flex;flex-direction:column;gap:2.25rem}

.masthead{padding:2.5rem 0 1.5rem;border-bottom:1px solid var(--line);
  display:flex;flex-direction:column;gap:.1rem}
.eyebrow{margin:0;font-family:var(--mono);font-size:.7rem;letter-spacing:.16em;
  text-transform:uppercase;color:var(--accent)}
.verdict{margin:.45rem 0 0;font-family:var(--mono);
  font-size:clamp(1.9rem,4.5vw,2.9rem);font-weight:600;letter-spacing:-.02em;
  text-wrap:balance;line-height:1.1}
.verdict.clean{color:var(--pass)}
.verdict.attention{color:var(--warn)}
.verdict.critical{color:var(--fail)}
.verdict-sub{margin:.4rem 0 0;font-family:var(--mono);font-size:.85rem;
  color:var(--muted);font-variant-numeric:tabular-nums}
.spec{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:.9rem 1.5rem;margin:1.7rem 0 0}
.spec div{display:flex;flex-direction:column;gap:.15rem}
.spec dt{font-family:var(--mono);font-size:.66rem;letter-spacing:.12em;
  text-transform:uppercase;color:var(--faint)}
.spec dd{margin:0;font-family:var(--mono);font-size:.84rem;word-break:break-word}

section{display:flex;flex-direction:column;gap:.8rem}
h2{margin:0;font-family:var(--mono);font-size:.78rem;letter-spacing:.14em;
  text-transform:uppercase;color:var(--muted);display:flex;align-items:center;gap:.6rem}
h2 .n{color:var(--faint);font-weight:400}
.none{margin:0;font-family:var(--mono);color:var(--pass)}

.lanes{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:1rem}
.lane{background:var(--surface);border:1px solid var(--line);border-radius:4px;
  padding:1rem 1.1rem;display:flex;flex-direction:column;gap:.5rem}
.lane-head{display:flex;align-items:baseline;gap:.6rem}
.lane-n{font-family:var(--mono);font-size:2rem;font-weight:600;line-height:1;
  font-variant-numeric:tabular-nums}
.lane.defect .lane-n{color:var(--fail)}
.lane.investigate .lane-n{color:var(--warn)}
.lane.artefact .lane-n{color:var(--idle)}
.lane-title{font-family:var(--mono);font-size:.74rem;letter-spacing:.1em;
  text-transform:uppercase;color:var(--muted)}
.lane-list{margin:.2rem 0 0;padding:0;list-style:none;display:flex;
  flex-direction:column;gap:.55rem}
.lane-list li{display:flex;flex-direction:column;gap:.1rem;font-size:.82rem}
.what{font-family:var(--mono);font-weight:600}
.reason{font-size:.82rem;color:var(--ink)}
.who{font-family:var(--mono);font-size:.72rem;color:var(--faint);margin-top:.1rem}
.band{font-family:var(--mono);font-size:.7rem;color:var(--accent)}
.why{color:var(--muted);font-size:.78rem}

.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:4px;
  background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:.84rem}
thead th{text-align:left;font-family:var(--mono);font-size:.66rem;letter-spacing:.11em;
  text-transform:uppercase;color:var(--faint);font-weight:500;padding:.6rem .7rem;
  border-bottom:1px solid var(--line);white-space:nowrap}
tbody td{padding:.5rem .7rem;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
td.stripe{width:3px;padding:0}
td.stripe.defect{background:var(--fail)}
td.stripe.investigate{background:var(--warn)}
td.stripe.artefact{background:var(--idle)}
td.stripe.failed{background:var(--fail)}
td.stripe.passed{background:var(--pass)}
td.stripe.skipped{background:var(--line)}
td.name code{font-family:var(--mono);font-size:.83rem}
td.check,td.band-col{font-family:var(--mono);font-size:.76rem;color:var(--muted);
  white-space:nowrap}
td.num{font-family:var(--mono);font-variant-numeric:tabular-nums;color:var(--muted);
  white-space:nowrap}
td.note{color:var(--muted);font-size:.78rem;max-width:34ch}
.pill{display:inline-block;font-family:var(--mono);font-size:.68rem;
  letter-spacing:.05em;padding:.14rem .5rem;border-radius:2px}
.pill.passed{background:var(--pass-bg);color:var(--pass)}
.pill.failed{background:var(--fail-bg);color:var(--fail)}
.pill.skipped{background:var(--idle-bg);color:var(--idle)}
.pill.flaky{background:var(--warn-bg);color:var(--warn);margin-left:.25rem}
tr.group td{background:var(--paper);border-bottom:1px solid var(--line);
  padding:.55rem .7rem;position:sticky;top:0}
.group-name{font-family:var(--mono);font-size:.72rem;letter-spacing:.13em;
  text-transform:uppercase;color:var(--ink);font-weight:600}
.group-n{font-family:var(--mono);font-size:.7rem;color:var(--faint);margin-left:.6rem;
  font-variant-numeric:tabular-nums}

details summary{font-family:var(--mono);font-size:.72rem;color:var(--accent);
  cursor:pointer;list-style:none;padding:.1rem .4rem;border:1px solid var(--line);
  border-radius:2px;display:inline-block}
details summary::-webkit-details-marker{display:none}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.detail{margin-top:.4rem;background:var(--paper);border:1px solid var(--line);
  border-radius:4px;padding:.8rem .9rem;min-width:min(560px,70vw)}
.dl{margin:.7rem 0 .25rem;font-family:var(--mono);font-size:.65rem;
  letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
.dl:first-child{margin-top:0}
.detail-lead{margin:0 0 .2rem;font-size:.8rem;color:var(--ink)}
table.kv th{width:38%;font-family:var(--mono);font-size:.74rem;color:var(--muted);
  font-weight:400;padding:.2rem .4rem;border:0}
table.kv td{font-family:var(--mono);font-size:.78rem;padding:.2rem .4rem;border:0}
table.kv.wide th{width:26%}
pre{margin:.2rem 0;padding:.6rem .7rem;background:var(--surface);
  border:1px solid var(--line);border-radius:3px;font-family:var(--mono);
  font-size:.72rem;line-height:1.45;white-space:pre-wrap;word-break:break-word;
  max-height:22rem;overflow:auto}
pre.bad{border-color:var(--fail);background:var(--fail-bg)}
.notes{margin:.2rem 0 0;padding-left:1.1rem;font-size:.8rem;color:var(--muted)}
footer{border-top:1px solid var(--line);padding-top:1rem;color:var(--muted);
  font-size:.8rem;display:flex;flex-direction:column;gap:.3rem}
.fine{margin:0;font-size:.74rem;color:var(--faint)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""
