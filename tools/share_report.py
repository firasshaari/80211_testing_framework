"""
Turn an allure-results directory into one self-contained, redacted JSON payload.

Allure's own report is a multi-file site that fetches its JSON at runtime, so it
cannot be shared as a single page. This flattens the same data — every case, its
step tree, its attachments — into one object, with every credential stripped on
the way through.
"""
import json, glob, os, re, sys, html

SRC = sys.argv[1]
OUT = sys.argv[2]

# ── redaction ────────────────────────────────────────────────────────────────
# Anything that authenticates. Lab RFC1918 addresses are kept: they are not
# routable, and they are load-bearing evidence in half the failure messages.
# Match on the *suffix* of the field name, not the whole name: the configs
# carry auth-secret, acct-secret and wifi-key alongside plain key and secret,
# and an exact-match list silently missed the hyphenated ones.
SECRET_KEYS = ("key", "secret", "password", "passphrase", "psk")
_NAME = r"[\w.-]*(?:%s)" % "|".join(SECRET_KEYS)
LITERALS = ("12345678", "testing123", "openwifi", "lanforge", "whatever")

_json_pairs = re.compile(
    r'(\\?"%s\\?"\s*:\s*)\\?"(?:[^"\\]|\\.)*?\\?"' % _NAME, re.I)
_uci_pairs = re.compile(
    r"\b(%s\s*=\s*)('[^']*'|\"[^\"]*\"|\S+)" % _NAME, re.I)
# The framework formats an SSID parameter as "psk2, key <secret>, VLAN 1000,
# upstream". Scope the prose rule to that exact comma-delimited shape — an
# unanchored `key \S+` also ate "per-key VLAN assignment" out of a summary.
_prose = re.compile(r"(?<=,\s)key\s+[^,]+(?=,)", re.I)


def scrub(text: str) -> str:
    if not text:
        return text
    text = _json_pairs.sub(r'\1"[redacted]"', text)
    text = _uci_pairs.sub(r"\1[redacted]", text)
    text = _prose.sub("key [redacted]", text)
    for lit in LITERALS:
        text = re.sub(re.escape(lit), "[redacted]", text, flags=re.I)
    return text


# ── attachments ──────────────────────────────────────────────────────────────
MAX_ATTACH = 60_000        # per attachment; the long logs are tail-truncated


def read_attachment(source: str) -> str | None:
    path = os.path.join(SRC, source)
    if not os.path.exists(path):
        return None
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    if len(raw) > MAX_ATTACH:
        raw = ("[truncated — showing the last %d of %d characters]\n\n"
               % (MAX_ATTACH, len(raw))) + raw[-MAX_ATTACH:]
    return scrub(raw)


def walk_steps(steps):
    out = []
    for s in steps or []:
        out.append({
            "n": scrub(s.get("name", "")),
            "s": s.get("status", "unknown"),
            "m": scrub((s.get("statusDetails") or {}).get("message", "") or "")[:2000],
            "a": [{"n": scrub(a.get("name", "")), "b": read_attachment(a.get("source", ""))}
                  for a in s.get("attachments", [])
                  if read_attachment(a.get("source", "")) is not None],
            "c": walk_steps(s.get("steps")),
        })
    return out


cases = []
for f in glob.glob(os.path.join(SRC, "*result.json")):
    d = json.load(open(f, encoding="utf-8"))
    labels = {l["name"]: l["value"] for l in d.get("labels", [])}
    tags = [l["value"] for l in d.get("labels", []) if l["name"] == "tag"]
    params = [{"n": scrub(p.get("name", "")), "v": scrub(str(p.get("value", "")))}
              for p in d.get("parameters", [])]
    cases.append({
        "t": scrub(d.get("name", "")),
        "s": d.get("status", "unknown"),
        "f": labels.get("feature", "Uncategorised"),
        "y": labels.get("story", ""),
        "g": tags,
        "d": scrub(d.get("description", "")),
        "m": scrub((d.get("statusDetails") or {}).get("message", "") or ""),
        "r": scrub((d.get("statusDetails") or {}).get("trace", "") or "")[:4000],
        "ms": max(0, (d.get("stop", 0) or 0) - (d.get("start", 0) or 0)),
        "p": params,
        "st": walk_steps(d.get("steps")),
        "at": [{"n": scrub(a.get("name", "")), "b": read_attachment(a.get("source", ""))}
               for a in d.get("attachments", [])
               if read_attachment(a.get("source", "")) is not None],
    })

cases.sort(key=lambda c: ({"failed": 0, "broken": 1, "passed": 2, "skipped": 3}
                          .get(c["s"], 4), c["f"], c["t"]))

# ── categories, matched the way allure does it: regex over the message ───────
cat_file = os.path.join(SRC, "categories.json")
categories = json.load(open(cat_file)) if os.path.exists(cat_file) else []
for c in cases:
    c["cat"] = ""
    if c["s"] not in ("failed", "broken", "skipped"):
        continue
    blob = f"{c['m']}\n{c['r']}"
    for cat in categories:
        statuses = cat.get("matchedStatuses") or ["failed", "broken"]
        if c["s"] not in statuses:
            continue
        pat = cat.get("messageRegex")
        if pat and re.search(pat, blob, re.S | re.I):
            c["cat"] = cat["name"]
            break

payload = {"cases": cases,
           "categories": [c["name"] for c in categories]}
json.dump(payload, open(OUT, "w", encoding="utf-8"), separators=(",", ":"))

counts = {}
for c in cases:
    counts[c["s"]] = counts.get(c["s"], 0) + 1
print("cases:", len(cases), counts)
print("payload:", os.path.getsize(OUT) // 1024, "KB")

# ── leak check ───────────────────────────────────────────────────────────────
# Two passes: the credentials known to this bench, and — more importantly —
# any credential-shaped field that still carries a value. The vendored example
# configs ship their own secrets (aaaaaaaa, secret2, ...) that no hand-written
# literal list would have caught.
blob = open(OUT, encoding="utf-8").read()
bad = [lit for lit in LITERALS if re.search(re.escape(lit), blob, re.I)]

survivors = set()
for m in re.finditer(r'\\?"(%s)\\?"\s*:\s*\\?"([^"\\]{1,80})' % _NAME, blob, re.I):
    if m.group(2) != "[redacted]":
        survivors.add(f"{m.group(1)}={m.group(2)!r}")
for m in re.finditer(r"\b(%s)\s*=\s*'([^']{1,80})'" % _NAME, blob, re.I):
    if m.group(2) != "[redacted]":
        survivors.add(f"{m.group(1)}={m.group(2)!r}")

if bad or survivors:
    print("LEAK CHECK: FAILED")
    if bad:
        print("  known literals:", ", ".join(bad))
    for s in sorted(survivors)[:20]:
        print("  unredacted field:", s)
    sys.exit(1)
print("LEAK CHECK: clean — no credential-shaped field carries a value")
