"""
Interactive results console.

A long sweep produces a few hundred cases, and a document forces the reader to
scroll past everything to find the one thing that matters. This renders the same
data as a small application instead: a filterable index on the left, a detail
pane on the right, and a band matrix that shows the whole run at once.

Self-contained — the data is embedded as JSON and rendered client-side, so the
file works from disk with no server and no network.
"""
from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from framework.reporting.html_report import RegressionReport

BANDS = ["2G", "5G", "6G"]


def build_payload(report: "RegressionReport") -> dict:
    """Everything the console needs, as plain data."""
    from framework.reporting.html_report import (
        CLASS_LABEL,
        _area_label,
        _display_name,
        _first_line,
        _kind,
        classify_failure,
        clean_evidence,
    )

    cases = []
    for r in report.records:
        cases.append({
            "id": f"c{len(cases)}",
            "name": _display_name(r),
            "example": r.example or _display_name(r),
            "area": r.area or "other",
            "areaLabel": _area_label(r.area or "other"),
            "band": r.band or "",
            "mode": r.mode or "",
            "check": _kind(r.name),
            "status": r.status,
            "cls": classify_failure(r.message) if r.is_failure else "",
            "duration": round(r.duration_s, 1),
            "reason": _first_line(r.message) if r.is_failure else "",
            "steps": r.steps,
            "config": r.config_summary or [],
            "configJson": r.applied_config[:20000],
            "evidence": [
                (k, v) for k, v in (
                    ("key_mgmt", r.key_mgmt), ("pairwise", r.pairwise),
                    ("BSSID", r.bssid), ("RSSI", r.rssi),
                    ("IP", r.ip), ("ping", r.ping_summary)) if v
            ],
            "staLog": clean_evidence(r.sta_evidence)[:9000],
            "apLog": r.ap_log[-4000:] if r.ap_log else "",
            "message": r.message[:4000],
        })

    triage = {k: len(v) for k, v in report.triage().items()}
    return {
        "meta": {
            "testbed": report.testbed_name,
            "started": report.started.strftime("%d %b %Y %H:%M"),
            "duration": report.duration_s,
            "ap": dict(report.ap_info),
            "station": dict(report.station_info),
            "capabilities": dict(report.capability_rows),
            "notes": report.capability_notes,
        },
        "totals": {
            "passed": report.count("passed"),
            "failed": report.count("failed") + report.count("error"),
            "skipped": report.count("skipped"),
        },
        "triage": triage,
        "triageLabels": CLASS_LABEL,
        "bands": BANDS,
        "cases": cases,
    }


def render(report: "RegressionReport") -> str:
    payload = json.dumps(build_payload(report), separators=(",", ":"))
    ap = dict(report.ap_info)
    title = f'{ap.get("Model", "AP")} regression'
    return _PAGE.replace("__TITLE__", html.escape(title)).replace("__DATA__", payload)


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --ink:#10151c; --bg:#eef1f5; --panel:#fff; --line:#d8dee6;
  --muted:#5a6472; --faint:#8b95a3; --accent:#0e7c86;
  --pass:#1a7f4b; --pass-bg:#e6f3ec; --fail:#c02a37; --fail-bg:#fbe9ea;
  --warn:#b26a00; --warn-bg:#fbf1e0; --idle:#7b8594; --idle-bg:#e7ebf0;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme:dark){:root{
  --ink:#e6ebf2; --bg:#0b0f14; --panel:#141a21; --line:#232b35;
  --muted:#97a1af; --faint:#6d7885; --accent:#3fb3bd;
  --pass:#4cc48a; --pass-bg:#0f2a1d; --fail:#ff7d87; --fail-bg:#2d1418;
  --warn:#e2a944; --warn-bg:#2b2211; --idle:#79838f; --idle-bg:#19202a;
}}
:root[data-theme=dark]{
  --ink:#e6ebf2; --bg:#0b0f14; --panel:#141a21; --line:#232b35;
  --muted:#97a1af; --faint:#6d7885; --accent:#3fb3bd;
  --pass:#4cc48a; --pass-bg:#0f2a1d; --fail:#ff7d87; --fail-bg:#2d1418;
  --warn:#e2a944; --warn-bg:#2b2211; --idle:#79838f; --idle-bg:#19202a;
}
:root[data-theme=light]{
  --ink:#10151c; --bg:#eef1f5; --panel:#fff; --line:#d8dee6;
  --muted:#5a6472; --faint:#8b95a3; --accent:#0e7c86;
  --pass:#1a7f4b; --pass-bg:#e6f3ec; --fail:#c02a37; --fail-bg:#fbe9ea;
  --warn:#b26a00; --warn-bg:#fbf1e0; --idle:#7b8594; --idle-bg:#e7ebf0;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px}
.app{height:100vh;display:grid;grid-template-rows:auto 1fr;gap:0}

/* top bar */
.bar{background:var(--panel);border-bottom:1px solid var(--line);
  padding:.7rem 1rem;display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap}
.brand{font-family:var(--mono);font-size:.72rem;letter-spacing:.14em;
  text-transform:uppercase;color:var(--accent)}
.headline{font-family:var(--mono);font-size:1rem;font-weight:600}
.tallies{display:flex;gap:.9rem;margin-left:auto;font-family:var(--mono);font-size:.78rem;
  font-variant-numeric:tabular-nums}
.tally b{font-weight:600}
.tally.p b{color:var(--pass)} .tally.f b{color:var(--fail)} .tally.s b{color:var(--idle)}
.meta{font-family:var(--mono);font-size:.72rem;color:var(--muted)}

/* body */
.body{display:grid;grid-template-columns:340px 1fr;min-height:0}
@media(max-width:860px){.body{grid-template-columns:1fr}.detail{display:none}}
.side{background:var(--panel);border-right:1px solid var(--line);
  display:flex;flex-direction:column;min-height:0}
.tools{padding:.6rem .7rem;border-bottom:1px solid var(--line);display:flex;
  flex-direction:column;gap:.5rem}
input[type=search]{width:100%;padding:.4rem .55rem;border:1px solid var(--line);
  border-radius:3px;background:var(--bg);color:var(--ink);font-family:var(--mono);
  font-size:.78rem}
input[type=search]:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.filters{display:flex;gap:.3rem;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:.68rem;padding:.2rem .5rem;border-radius:2px;
  border:1px solid var(--line);background:transparent;color:var(--muted);cursor:pointer}
.chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:#fff}
.chip:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.list{overflow:auto;flex:1;min-height:0}
.grp{position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--line);
  padding:.45rem .7rem;font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;
  text-transform:uppercase;color:var(--faint);display:flex;justify-content:space-between}
.row{display:flex;align-items:center;gap:.5rem;padding:.4rem .7rem;cursor:pointer;
  border-bottom:1px solid var(--line);width:100%;background:none;
  border-left:3px solid transparent;text-align:left;color:inherit;font:inherit}
.row:hover{background:var(--bg)}
.row[aria-selected=true]{background:var(--bg);border-left-color:var(--accent)}
.row:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.row.failed{border-left-color:var(--fail)}
.row .nm{font-family:var(--mono);font-size:.78rem;flex:1;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.row .bd{font-family:var(--mono);font-size:.66rem;color:var(--faint)}
.dot{width:.55rem;height:.55rem;border-radius:50%;flex:none}
.dot.passed{background:var(--pass)} .dot.failed{background:var(--fail)}
.dot.skipped{background:var(--idle)}

/* detail */
.detail{overflow:auto;padding:1.1rem 1.3rem;min-height:0}
.empty{color:var(--faint);font-family:var(--mono);font-size:.8rem;margin-top:2rem}
.dh{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap}
.dh h2{margin:0;font-family:var(--mono);font-size:1.05rem;font-weight:600}
.badge{font-family:var(--mono);font-size:.68rem;padding:.16rem .5rem;border-radius:2px}
.badge.passed{background:var(--pass-bg);color:var(--pass)}
.badge.failed{background:var(--fail-bg);color:var(--fail)}
.badge.skipped{background:var(--idle-bg);color:var(--idle)}
.sub{font-family:var(--mono);font-size:.74rem;color:var(--muted);margin:.25rem 0 1rem}
.steps{display:flex;flex-direction:column;gap:0;margin:0 0 1.2rem;padding:0;list-style:none}
.steps li{display:flex;gap:.7rem;align-items:flex-start;padding:.4rem 0;
  border-left:2px solid var(--line);padding-left:.9rem;margin-left:.35rem}
.steps li.passed{border-left-color:var(--pass)}
.steps li.failed{border-left-color:var(--fail)}
.steps li.partial{border-left-color:var(--warn)}
.steps .g{font-family:var(--mono);width:1rem;flex:none}
.steps li.passed .g{color:var(--pass)} .steps li.failed .g{color:var(--fail)}
.steps li.skipped .g,.steps li.skipped .t{color:var(--idle)}
.steps .t{font-size:.83rem}
.steps .d{font-family:var(--mono);font-size:.72rem;color:var(--muted)}
h3{margin:1.2rem 0 .4rem;font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;
  text-transform:uppercase;color:var(--faint)}
table.kv{border-collapse:collapse;width:100%;max-width:640px}
table.kv th{text-align:left;width:34%;font-family:var(--mono);font-size:.73rem;
  color:var(--muted);font-weight:400;padding:.18rem .4rem}
table.kv td{font-family:var(--mono);font-size:.77rem;padding:.18rem .4rem}
pre{margin:.2rem 0;padding:.6rem .7rem;background:var(--panel);border:1px solid var(--line);
  border-radius:3px;font-family:var(--mono);font-size:.72rem;line-height:1.45;
  white-space:pre-wrap;word-break:break-word;max-height:20rem;overflow:auto}
pre.bad{border-color:var(--fail);background:var(--fail-bg)}
details summary{font-family:var(--mono);font-size:.72rem;color:var(--accent);cursor:pointer}

/* matrix */
.matrix{margin:0 0 1.4rem}
.mrow{display:grid;grid-template-columns:190px repeat(3,1fr);gap:2px;align-items:center}
.mrow+.mrow{margin-top:2px}
.mname{font-family:var(--mono);font-size:.72rem;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;padding-right:.4rem}
.cell{height:1.35rem;border-radius:2px;background:var(--idle-bg);cursor:pointer;border:0;
  display:flex;align-items:center;justify-content:center;font-family:var(--mono);
  font-size:.62rem;color:var(--muted)}
.cell.passed{background:var(--pass-bg);color:var(--pass)}
.cell.failed{background:var(--fail-bg);color:var(--fail)}
.cell:focus-visible{outline:2px solid var(--accent)}
.mhead{display:grid;grid-template-columns:190px repeat(3,1fr);gap:2px;
  font-family:var(--mono);font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint);margin-bottom:.3rem}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="app">
  <header class="bar">
    <div>
      <div class="brand">OpenWiFi regression</div>
      <div class="headline" id="hl"></div>
      <div class="meta" id="mt"></div>
    </div>
    <div class="tallies" id="tal"></div>
  </header>
  <div class="body">
    <nav class="side">
      <div class="tools">
        <input type="search" id="q" placeholder="filter by name, band or reason"
               aria-label="Filter cases">
        <div class="filters" id="fl"></div>
      </div>
      <div class="list" id="ls" role="listbox" aria-label="Test cases"></div>
    </nav>
    <main class="detail" id="dt">
      <p class="empty">Select a case, or click a cell in the matrix.</p>
    </main>
  </div>
</div>
<script>
const DATA = __DATA__;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let filter = "all", query = "", selected = null;

const dur = s => s >= 3600 ? `${Math.floor(s/3600)}h ${Math.round(s%3600/60)}m`
  : s >= 60 ? `${Math.floor(s/60)}m ${Math.round(s%60)}s` : `${Math.round(s)}s`;

function header(){
  const t = DATA.totals, m = DATA.meta;
  $("#hl").textContent = `${t.failed} failed · ${t.passed} passed`;
  $("#mt").textContent = [m.ap.Model, m.ap.Firmware, m.started,
    dur(m.duration)].filter(Boolean).join("  ·  ");
  $("#tal").innerHTML =
    `<span class="tally p">passed <b>${t.passed}</b></span>` +
    `<span class="tally f">failed <b>${t.failed}</b></span>` +
    `<span class="tally s">skipped <b>${t.skipped}</b></span>`;
  const counts = {all: DATA.cases.length, failed: t.failed, passed: t.passed,
                  skipped: t.skipped};
  $("#fl").innerHTML = ["all","failed","passed","skipped"].map(k =>
    `<button class="chip" data-f="${k}" aria-pressed="${k===filter}">${k} ${counts[k]}</button>`
  ).join("");
  $("#fl").querySelectorAll("button").forEach(b => b.onclick = () => {
    filter = b.dataset.f; header(); list();
  });
}

function visible(){
  return DATA.cases.filter(c => {
    if (filter !== "all" && c.status !== filter) return false;
    if (!query) return true;
    const hay = `${c.name} ${c.band} ${c.check} ${c.reason} ${c.areaLabel}`.toLowerCase();
    return hay.includes(query);
  });
}

function list(){
  const rows = visible(); const out = []; let area = null;
  for (const c of rows){
    if (c.areaLabel !== area){
      area = c.areaLabel;
      const peers = rows.filter(x => x.areaLabel === area);
      const ok = peers.filter(x => x.status === "passed").length;
      out.push(`<div class="grp"><span>${esc(area)}</span>` +
        `<span>${ok}/${peers.length}</span></div>`);
    }
    out.push(
      `<button class="row ${c.status}" role="option" data-id="${c.id}"
        aria-selected="${selected === c.id}">
        <span class="dot ${c.status}"></span>
        <span class="nm">${esc(c.name)}</span>
        <span class="bd">${esc(c.band)}</span>
      </button>`);
  }
  const ls = $("#ls");
  ls.innerHTML = out.join("") || '<p class="empty" style="padding:1rem">Nothing matches.</p>';
  ls.querySelectorAll(".row").forEach(b => b.onclick = () => select(b.dataset.id));
}

function matrix(cases){
  const names = [...new Set(cases.map(c => c.example))];
  const head = `<div class="mhead"><span>Example</span>` +
    DATA.bands.map(b => `<span>${b}</span>`).join("") + `</div>`;
  const rows = names.slice(0, 40).map(n => {
    const cells = DATA.bands.map(b => {
      const c = cases.find(x => x.example === n && x.band === b);
      if (!c) return `<span class="cell"></span>`;
      const lab = c.status === "passed" ? "pass"
        : c.status === "failed" ? "fail" : "skip";
      return `<button class="cell ${c.status}" data-id="${c.id}"
        title="${esc(n)} ${b}: ${esc(c.reason || c.status)}">${lab}</button>`;
    }).join("");
    return `<div class="mrow"><span class="mname">${esc(n)}</span>${cells}</div>`;
  }).join("");
  return `<div class="matrix">${head}${rows}</div>`;
}

function select(id){
  selected = id;
  const c = DATA.cases.find(x => x.id === id);
  list();
  if (!c) return;
  const steps = (c.steps || []).map(s => {
    const g = {passed:"✓", failed:"✗", partial:"◦", skipped:"·"}[s.status] || "·";
    return `<li class="${s.status}"><span class="g">${g}</span>
      <span><span class="t">${esc(s.name)}</span>
      ${s.detail ? `<br><span class="d">${esc(s.detail)}</span>` : ""}</span></li>`;
  }).join("");
  const kv = (rows) => rows.length ? `<table class="kv">` + rows.map(
    ([k,v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") + `</table>` : "";
  $("#dt").innerHTML = `
    <div class="dh"><h2>${esc(c.name)}</h2>
      <span class="badge ${c.status}">${c.status}</span></div>
    <p class="sub">${[c.areaLabel, c.band, c.mode, c.check,
      c.duration + "s"].filter(Boolean).map(esc).join("  ·  ")}</p>
    ${steps ? `<ul class="steps">${steps}</ul>` : ""}
    ${c.reason ? `<h3>Result</h3><pre class="bad">${esc(c.reason)}</pre>` : ""}
    ${c.config.length ? `<h3>Config applied</h3>${kv(c.config)}` : ""}

    ${c.evidence.length ? `<h3>Evidence</h3>${kv(c.evidence)}` : ""}
    ${c.staLog ? `<h3>Station log</h3><pre>${esc(c.staLog)}</pre>` : ""}
    ${c.apLog ? `<h3>AP log</h3><pre>${esc(c.apLog)}</pre>` : ""}
    ${c.configJson ? `<details><summary>full config JSON</summary>
       <pre>${esc(c.configJson)}</pre></details>` : ""}`;
  $("#dt").scrollTop = 0;
}

function overview(){
  const m = DATA.meta;
  $("#dt").innerHTML = matrix(DATA.cases) +
    `<h3>Testbed</h3><table class="kv">` +
    Object.entries(m.capabilities).map(([k,v]) =>
      `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") + `</table>` +
    (m.notes.length ? `<h3>Probe notes</h3><pre>${esc(m.notes.join("\n"))}</pre>` : "");
  $("#dt").querySelectorAll(".cell[data-id]").forEach(b =>
    b.onclick = () => select(b.dataset.id));
}

$("#q").addEventListener("input", e => { query = e.target.value.toLowerCase(); list(); });
header(); list(); overview();
</script>
</body>
</html>
"""
