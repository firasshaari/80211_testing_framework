# 80211 Testing Framework

Regression testing for OpenWiFi APs, driven **directly over SSH** — no uCentral
cloud SDK, no controller, no gateway. The framework logs into the AP, stops the
uCentral agent, and applies configs locally with
`/usr/share/ucentral/ucentral.uc`.

Test material comes from the [wlan-ap uCentral schema
examples](https://github.com/Telecominfraproject/wlan-ap/tree/main/feeds/ucentral/ucentral-schema/files/etc/ucentral/examples):
71 configs covering every security method, bridge and NAT forwarding, VLANs,
tunnels, captive portals, QoS, telemetry and 6 GHz/Wi-Fi 7. They are vendored,
categorized and normalized, then applied one at a time. Each is run once per
band, so a full sweep is **213 cases** and takes two to three hours.

There are two ways to drive it: `make` from a checkout, or the
**[Bench Console](#the-bench-console)** — a web UI on the station host, which is
how the bench is normally used now.

## Key design principles

- **Core is immutable** — most new coverage is a catalog entry plus a validator,
  not a new file. Nothing in `framework/` changes when you extend the sweep.
- **Capability-aware** — the bench is probed once at session start. An example
  needing hardware you do not have skips with a reason that names it
  ("testbed lacks a RADIUS server"), rather than failing.
- **No SDK** — the AP is managed entirely over SSH as `root`. The uCentral
  agent is stopped and disabled for the run so nothing reverts a config
  mid-test, then restored afterwards.
- **The station is the source of truth** — reading a setting back off the AP
  only proves it was written down. Wherever the difference is observable, a
  check prefers evidence from the client: what it negotiated, which address it
  got, which access category a marked frame arrived in.
- **Connect-and-pass-traffic is the floor, not the ceiling** — see
  [What each test proves](#what-each-test-proves).
- **Upstream examples are normalized, visibly** — every change is recorded and
  attached to the report. See [Config normalization](#config-normalization).
- **A bench fault is not a result** — preflight refuses to sweep a bench that is
  not fit, because a dead station reads exactly like an AP defect.

## Hardware

| Role | Hardware | Notes |
|---|---|---|
| DUT | Any OpenWiFi AP | Reached over SSH as `root` |
| Station | RPi5 + Intel BE200 (PCIe hat) | Debian 13 (trixie); see [Notes on the RPi5 station](#notes-on-the-rpi5-station) |
| Services | FreeRADIUS in podman, on the station host | `make infra-up`; see [infra/README.md](infra/README.md) |
| Optional | VLAN trunk, peer AP, 6 GHz radio, managed switch | Each unlocks a group of tests |

How far the catalog gets on a given bench:

| Bench | Examples runnable |
|---|---|
| A bare AP plus one RPi5 | **33** |
| …plus the RADIUS container (`make infra-up`) | **45** |
| …plus a VLAN trunk | **47** |
| …plus internet (NTP, online-check, AFC) | **49** |
| Needs hardware beyond that | **22** |

Those 22 break down as a peer AP (8), 6 GHz (5), a managed switch (3), an
external captive backend (2), and one each of Wi-Fi 7, GPS, WWAN and an
external DHCP server. 16 examples reference RADIUS in total, but only 12 are
unlocked by RADIUS *alone* — the other four also want a peer AP, a captive
backend or 6 GHz.

A further **14 declare no AP-mode BSS at all**. For those the test is that the
AP accepts and renders the config and that any service it names is genuinely
running; there is nothing for a station to associate to.

## The run workflow

```
make plan                      →  log in, stop the uCentral agent, read capabilities,
                                  print which examples are feasible and why the rest are not
python -m framework.preflight  →  prove the bench itself is fit before trusting any result
make regression                →  run them, write the report, hand the AP back
```

Per test:

1. Load the upstream example and normalize it — regulatory domain, channel plan,
   width, SSID names, forwarding mode, **and clamp mode/width/channel to what
   this AP advertises**.
2. Force `ssh` onto the upstream interface (see below), set `strict`.
3. **Arm a rollback**, upload, and apply with `ucentral.uc` detached.
4. Parse the result. **`ucentral.uc` exits 0 whether it succeeded or failed**
   on a custom config path, so success comes from whether it rendered a UCI
   batch — never from the exit code. A `strict` rejection prints on a plain
   line with **no `[E]` prefix**, so it is parsed separately.
5. Confirm management access still works and cancel the rollback.
6. **Re-stop the agent** — every apply ends in `reload_config`, which fires
   procd's reload trigger and restarts the agent, which then reconnects to the
   controller and pushes its config over the one under test.
7. Confirm the SSIDs are up — first from the AP, then from a **station scan**,
   because the AP answering for a BSS is not the same as a beacon reaching the
   air.
8. For each SSID the station can join: associate, take a DHCP lease, pass a
   captive portal if there is one, carry traffic, and run the per-SSID checks
   **while that association is still live**.
9. Run the AP-side checks once per case, for features with no client-visible
   signature.

Every stage is an `allure.step`, so the report shows exactly how far a case got.

**Forwarding is bridge by default.** NAT is implemented and selectable per run
with `BENCH_FORWARDING=nat` (the Bench Console exposes it as a dropdown), but
the sweep's default is bridge and the matrix is one mode at a time.

## What each test proves

Associating and passing traffic proves the radio and the data path work. It says
nothing about whether the feature the example exists to exercise is doing
anything — a rate limit that never reached the data path still lets a client
browse. `tests/regression/validators.py` closes that gap.

**Five checks run on every case that gets a client on:**

| Check | Asserts |
|---|---|
| `negotiated encryption` | What the client negotiated matches the configured proto, and WPA3/PSK2/SAE never negotiate TKIP |
| `forwarding mode` | A bridged client is on the upstream network, a NATed one is behind the AP — and a bridged client is never on the management subnet |
| `radio settings` | The radio is on the configured channel, mode and width, not something it fell back to |
| `vlan placement` | An SSID on a tagged VLAN has a matching `bridge-vlan` rendered |
| `regulatory domain` | The country the config pins is the one the radio enforces |

An `ssh service` check also runs on every example carrying an SSH block —
losing management access on the WAN is the failure this framework exists to
avoid, so it is asserted everywhere.

**Examples that go further**, with a check written for the feature they exist to
exercise. The notable ones:

| Check | Method |
|---|---|
| `rate limit` | **Measured, not read back.** iperf3 from a wired peer on the client's own VLAN; fails if throughput exceeds 2.5× the cap |
| `qos dscp mapping` | Sends DSCP 0/32/48 from the wired peer and reads the client's **per-TID counters** — the TID that moved must map to the expected WMM access category |
| `rrm elements` | The station scans and reads the beacon; it must advertise the Radio Measurement capability |
| `dynamic vlan` | The VLAN the backend assigns at authentication time must be the one the client lands in |
| `radius accepted the client` | The lab server must have logged an `Access-Accept` **for this station's MAC** |
| `block rfc1918` | The one check where success means traffic must *fail* — a private destination unreachable **while the internet stays reachable** |
| `telemetry`, `ntp`, `lldp`, `igmp`, `admin ui`, … | The daemon that implements it is running *and* carries the configured value |

A check returns a one-line string of evidence when it passes, and that string is
what appears in the report. Where a check deliberately proves less than its name
suggests, it attaches a **scope note** saying so — telemetry *delivery* is not
observable with the agent disabled, so only local collection is checked.

The Bench Console renders this table **generated from the registries**, so it
cannot drift: `/docs/validation`.

## Safety mechanisms

Five guards exist because each one corresponds to a way this framework
previously broke a live bench.

**SSH is forced onto the WAN.** 71 of the 78 upstream interfaces in the corpus
list `ssh` only on the downstream LAN. Applying one tears down WAN management
and the AP disappears mid-run. Every applied config gets `ssh` added to its
upstream interface plus a top-level `services.ssh` block with
`idle-timeout: 0`. The array entry is the actual enable switch and emits the
firewall rule; the block makes the schema render `port` so that rule is
port-scoped rather than wide open.

**Commit-confirmed rollback.** Before each apply the AP is told to
factory-reset itself in `rollback_seconds` unless cancelled, and the framework
only cancels once it has proven management access still works. A config that
cuts the AP off the network therefore recovers by itself instead of needing a
physical power cycle.

**The station's management path is pinned.** A bridged test SSID hands the
client an address on the *same subnet* as the station's own management LAN, so
the DHCP lease installs a competing default route and the SSH session dies. A
source rule (`ip rule from <mgmt_ip> lookup 100`) keeps management traffic on
its own interface, the lease's default route is removed, and
`arp_ignore`/`arp_announce`/`rp_filter` are set — routing alone does not fix
the ARP flux that two interfaces on one subnet cause.

**The apply is detached.** `ucentral.uc` restarts dropbear, which can kill the
session running it. The apply runs under `setsid nohup` and its result is
polled from a file, so a dropped session no longer looks like a failure.

**The agent is held down for the whole apply window.** It otherwise restarts
itself mid-render and races the renderer — the cause of eight apparent
"renderer hangs" that were nothing of the kind.

## Config normalization

The upstream examples are schema illustrations, not runnable lab configs. All of
the following are applied before an apply, and every change is recorded per test
and attached to the report:

| Problem | Fix |
|---|---|
| `"country": "CA"` (about 90 of 112 radio entries) | Forced to `US` (configurable) |
| 80 MHz on a 2.4 GHz radio (33 examples) | Clamped to 20 MHz |
| Channel outside its declared band (21 examples) | Superseded by a fixed channel plan — every radio is pinned to `{2G:1, 5G:36, 6G:37}`, avoiding DFS |
| **VHT requested on 2.4 GHz** | Downgraded to HT — 802.11ac is not defined there, and asking for it made 19 cases fail as "2G config rejected" |
| Modes the AP cannot do | Clamped to its advertised `capabilities.json` (`HE` → `VHT`/`HT`), width and channel too |
| Bands the AP does not have | Radios, `wifi-bands` and SSIDs for absent bands dropped |
| `roaming` on a pre-WPA2 SSID | Stripped — `maverick` puts 802.11r on an open SSID |
| `fingerprint.mode: "raw-data"` | Corrected to `"raw"` — the schema does not accept the former |
| Duplicate SSID names within one config | Made unique — collisions hung the renderer and stranded the AP |
| SSID names and passphrases | Renamed `<ap-name>-<proto>` with the bench passphrase, capped at 32 octets, so two benches never collide on the air |
| Forwarding mode | Forced to bridge (default) or NAT so each matrix cell means one thing |
| Bridged SSIDs on the untagged upstream | Moved onto a tagged twin — otherwise clients are bridged onto the *management* subnet. Dynamic-VLAN SSIDs are deliberately left untagged |
| VLAN ids from the corpus | Substituted onto the lab's VLANs; `vlan-awareness` enabled on upstreams hosting dynamic-VLAN SSIDs |
| RADIUS servers pointing at nonexistent hosts | Re-pointed at the lab server |

That channel rule is easy to miss: `crypto-psk.json` asks for `band: 2G` with
`channel: 32`, and `telemetry.json` asks for `band: 2G` with `channel: 36`.

**Why this matters more than it looks.** The renderer does not reject 80 MHz on
2.4 GHz — it *clamps* the width and then **deletes your pinned channel**, so the
radio silently lands on auto-select and the apply still reports success. A test
would be validating a configuration nobody asked for. The framework therefore
also sets `"strict": true`, which makes the renderer reject on any warning
instead of clamping, so "applied" means "applied as requested".

## Handing the AP back

`ap.cleanup` in testbed.yaml controls the end state:

| Value | Behaviour |
|---|---|
| `factory_reset` *(default)* | `jffs2reset -y && reboot` — clean baseline, re-onboards to the controller by itself |
| `restore_agent` | re-enable the agent, leaving the last applied config committed |
| `none` | leave the AP exactly as the tests left it |

## Running it against a different AP

Nothing is hardcoded per model. The AP's radios, supported modes and channels
are probed from its own `capabilities.json` at session start, and every example
is normalized to fit before it is applied — so a Wi-Fi 5 dual-band AP and a
Wi-Fi 7 tri-band AP each get a config they can actually run.

Switching APs is one line — `ap.host` in `config/testbed.yaml` — or a field in
the Bench Console.

```bash
make setup                     # asks for the new AP's IP/credentials, VLANs, RADIUS
make plan                      # probes it and prints which examples are feasible
python -m framework.preflight  # proves the bench is fit
make regression                # run them
make watch                     # (second terminal) follow progress live
make report                    # build and open the Allure report
```

`make setup` backs up any existing `config/testbed.yaml` and offers current
values as defaults, so switching between APs is just re-running it — or keep a
file per AP and pass `CONFIG=`:

```bash
make plan       CONFIG=config/ap-lab2.yaml
make regression CONFIG=config/ap-lab2.yaml
```

**Always run `make plan` first on a new AP.** It stops the uCentral agent, reads
the capabilities, and shows exactly what will run and what will skip and why —
before anything is applied. Nothing is written to the AP by `plan`.

What to expect to differ on another AP:

| | Effect |
|---|---|
| Fewer bands | 6 GHz / Wi-Fi 7 examples skip; a 6 GHz radio in a config is dropped |
| Older radios | `HE` is clamped to `VHT`/`HT`; without this, strict mode rejects everything |
| Switch fabric | Set `external.has_switch_hw` to unlock the `switch-*` examples |

## Quickstart

```bash
make install                                   # venv + dependencies
cp config/profiles/example_minimal.yaml config/testbed.yaml
$EDITOR config/testbed.yaml                    # AP host, RPi5 host, credentials

make check                                     # offline — validates corpus and rules, no hardware
make infra-up                                  # RADIUS + the bench PKI on the station host
python -m framework.preflight                  # station, radio, scan, RADIUS, AP
make regression                                # full sweep
make report                                    # build and open the Allure report
```

Run a single feature area, or a single example:

```bash
make sweep AREA=security
pytest tests/regression -k crypto-psk -v --testbed-config config/testbed.yaml
```

`make check` needs no hardware and runs in seconds. It asserts the whole corpus
parses, the catalog matches what is on disk, the normalization rules still hold,
and the console's own logic (run indexing, comparison, redaction) behaves.

**Never interrupt a sweep to fix reporting.** Results are written per case as
the run proceeds; regenerating the report is a separate, cheap, repeatable step.

Other targets: `make help`, `serve` (ephemeral Allure), `infra-down`,
`sync-examples` (re-vendor from upstream), `clean`.

## The Bench Console

`benchd/` is a web UI that runs on the station host, so a sweep is a browser
action rather than a laptop ritual. It **drives** this framework rather than
duplicating it: it spawns the same pytest command, and imports the existing
probe, plan, catalog and config APIs.

```bash
pip install -e ".[console]"
sh benchd/deploy/install.sh        # on the station: venv, systemd unit, podman-restart
```

Then `http://<station>:8080`. One shared password, hashed in a gitignored
`benchd.env`.

What it adds over `make`:

- **Probe an AP read-only** before committing to a run — model, firmware,
  serial, radios, and the feasible/skipped split.
- **Preflight as a gate.** A failing bench blocks the run behind an explicit
  override, and an overridden run is flagged for ever, so nobody later quotes
  its numbers without knowing.
- **Runs keep their AP identity** in `runs/<id>/meta.json`, recorded at run
  time. Results directory names never carried it, which has cost real time.
- **Comparison** of two runs — AP against AP, or firmware against firmware —
  keyed on `(example_name, band)`, which contains no AP identity so cases line
  up across devices. It never reports a bare regression count: regressions are
  classified by the new failure and bench artefacts are separated out, because a
  case that failed this time only because the harness lost SSH says nothing
  about the device.
- **Generated documentation** at `/docs` — the validation table is derived from
  the catalog and the validator registries, so registering a check makes it
  appear and removing one stops it being claimed.

Storage is one directory per run and a `meta.json`; there is no database.

## Reading the report

Allure is a static site and must be **served** — opening `index.html` from the
filesystem gives a blank page. Do not use `--single-file`: it looks complete and
silently drops the attachments and step detail that carry the evidence. `make
report` generates and opens it; the console serves one per run.

```bash
cp allure-categories/categories.json allure-results/
allure generate allure-results -o allure-report --clean
allure open -p 8899 allure-report
```

Go to **Categories** first. It buckets failures by *cause*, not by test, so one
defect hitting twenty cases collapses into one row. The bench defines its own
buckets in `allure-categories/categories.json`, including
`Testbed lacks the hardware`, `AP rejected the config`,
`Renderer hung on the AP`, `SSID configured but never on the air` and
`AP advertised encryption it never describes`.

A standalone HTML report is also written to `reports/` (and `latest.html`) by
`framework/reporting/html_report.py`, and can be re-rendered from its JSON
sidecar with `python -m framework.report_rebuild`. Allure is the one to reach
for; the HTML is a fallback that needs no Java.

Report directory names do **not** record which AP a run came from. Identify a
run by its `environment.properties`, its JSON sidecar, or — in the console — its
`meta.json`.

## Sharing results

**An Allure results directory is not safe to hand to anyone.** Every case
attaches the config that was applied, verbatim, so it contains WPA passphrases
and RADIUS shared secrets.

```bash
python tools/share_report.py allure-results-<run> payload.json
```

This flattens a run into one redacted payload — every case, step tree and
attachment — with every credential-shaped field stripped, ready to embed in a
single self-contained page. Its leak check fails the build rather than warning,
because the vendored examples ship secrets of their own that no list of *your*
credentials would catch. Lab RFC1918 addresses are deliberately kept: they are
not routable, and half the failure messages are unreadable without them.

Do not publish a report to GitHub Pages from a private repo: Pages is public on
every plan below Enterprise.

## Project structure

```
80211_testing_framework/
├── config/
│   ├── testbed.yaml            # your bench (gitignored — credentials)
│   └── profiles/               # example_minimal.yaml, example_full_lab.yaml
├── configs/
│   ├── examples/upstream/      # 71 vendored uCentral examples (tracked)
│   └── ap/                     # your own AP configs (tracked)
├── framework/                  # core — not modified when adding coverage
│   ├── config.py               # pydantic testbed schema; constructing it IS the validation
│   ├── ap/
│   │   ├── ap_client.py        # SSH control: agent, apply, readback, identity, radio caps
│   │   └── config_loader.py
│   ├── clients/
│   │   ├── ssh.py              # shared session (password auth, sudo, sbin on PATH)
│   │   └── rpi5_station.py     # associate, DHCP, scan, captive portal, netns VLAN peer
│   ├── examples/
│   │   ├── loader.py           # tolerant parser for the malformed examples
│   │   ├── normalize.py        # every rewrite in the table above
│   │   ├── catalog.py          # feature area + hardware requirements
│   │   └── inspect.py          # read SSIDs/modes back out of a config
│   ├── capability/             # probe the bench (models.py, registry.py)
│   ├── preflight.py            # refuse to sweep a bench that is not fit
│   ├── plan.py                 # what would run, and why the rest would not
│   ├── setup.py                # interactive testbed.yaml builder
│   ├── infra_deploy.py         # push infra/ to the station host
│   ├── markers.py
│   ├── allure_import.py        # convert an old JSON sidecar into Allure results
│   ├── report_rebuild.py       # re-render the HTML report from its sidecar
│   └── reporting/              # html_report.py, console.py, allure_helper.py
├── benchd/                     # the Bench Console (web UI) + deploy/
├── infra/                      # FreeRADIUS container + the bench PKI
├── tools/
│   └── share_report.py         # redact a results directory for sharing
├── allure-categories/          # failure buckets by cause
├── tests/
│   ├── unit/                   # offline checks — no hardware
│   ├── regression/
│   │   ├── test_examples.py    # the sweep
│   │   ├── validators.py       # the feature checks
│   │   └── test_connectivity.py, test_network_mode.py, test_vlan.py
│   ├── superseded/             # older suites, not collected
│   └── _template.py
├── Makefile · pytest.ini · pyproject.toml
└── conftest.py                 # fixtures, capability gating, report collection
```

`runs/`, `reports/`, `benchd.env`, `config/*.yaml` and `infra/pki/out/` are
gitignored — they hold results or credentials.

## Example categories

| Area | Examples | Needs beyond AP + station |
|---|---|---|
| `security` | crypto-psk, crypto-enterprise, owe, owe-transition, multi-psk, eap_local, radius\*, ieee8021x-\* | RADIUS for enterprise modes |
| `network_mode` | default, maverick, block-rfc1918, strict-forwarding, data-plane, dhcpsnoop, igmp, loop-detect | — |
| `rate_limit` / `qos` | rate-limit, qos, qos-class | VLAN trunk, for the wired peer |
| `roaming` | steering, rrm, quality-threshold, roaming-psk2-radius | peer AP for an actual roam |
| `captive` | captive, captive-click, captive-credentials, captive-webroot, captive-multiple, captive-radius, captive-uam | UAM backend for external portals |
| `vlan` | vlan, switch-vlan, dhcp-relay, big | VLAN trunk |
| `tunnel` | gre, gre6, vxlan, mesh, wds-ap, wds-sta | peer AP / tunnel endpoint |
| `wifi_gen` | wifi-6e, wifi-6e-afc, wifi-7, wifi-6e-mpsk\* | 6 GHz or Wi-Fi 7 on both ends |
| `services` | ssh, lldp, ntp, online-check, unit, admin_ui, gps | internet for NTP |
| `telemetry` | metrics, telemetry, fingerprint-\*, tip-oui | — |
| `switch` / `wwan` | switch-ports, switch-fabric, wwan | switch fabric / modem |

`crypto-psk` is the highest-value single config in the corpus: six SSIDs on one
radio covering open, `psk`, `psk2`, `psk-mixed`, `sae` and `sae-mixed`, so one
apply exercises six association paths. It is also where the WPA1 defect shows
up — the AP beacons with the Privacy bit set but no WPA or RSN element, which
has reproduced on every AP tested so far.

## Adding coverage

**Adding an upstream example to the sweep** — add an entry to
`EXAMPLES` in `framework/examples/catalog.py` naming its area, forwarding mode
and requirements. It is picked up by the parametrized suites automatically.
`make check` will tell you if the declared mode disagrees with the config.

**Proving the feature actually works** — write a check in
`tests/regression/validators.py` and register it in `PER_SSID` (runs while a
client is associated, so it can measure or probe from the station) or `AP_SIDE`
(runs once per case, for things with no client-visible signature). Raise
`AssertionError` to fail; return a one-line string of evidence to pass. Add a
note for it in `benchd/docsgen.py` — a test asserts every registered check has
one, so an undocumented check fails `make check`.

**Adding a bespoke assertion** — copy `tests/_template.py` into
`tests/regression/`. Use the `apply_example` fixture and derive SSIDs from the
config you applied rather than hardcoding names. Zero framework files change.

## Notes on the RPi5 station

**OS.** Debian 13 (trixie). `/sbin` is not on a non-login shell's `PATH`, so
every command the framework runs is prefixed with it.

**Interface.** The BE200 comes up as `wlan1` when the Pi's onboard radio is
enabled and as `wlan0` when it is not. `config.py` and the shipped profiles
default to `wlan1`; `make setup` offers `wlan0`. Set `station.iface` to whichever
applies — this bench disables the onboard radio, so it is `wlan0`.

> Editing `/boot/firmware/config.txt` without `sync` before rebooting has
> bricked the boot on this hardware. Change one thing at a time, sync, and
> prefer a USB adapter over the onboard radio if you need a second station.

**Kernel.** Kernel **6.18.39** runs the BE200 fine, on the `iwlmld` driver with
firmware 101. Only the 6.18.34 point release was broken — it failed to probe
with `No config found for PCI dev 272b/00f4`, which is why 6.12 was pinned for a
while. Do not pin 6.12 on a new bench. **Verify the staged boot images by
md5sum before rebooting** — installing a kernel does not reliably restage them,
and a mismatch is unbootable.

**NetworkManager** manages every wireless interface by default. The framework
hands the BE200 out of its control (`nmcli device set <iface> managed no`) before
driving `wpa_supplicant` directly, and gives it back at teardown. Fighting
NetworkManager otherwise looks exactly like an association failure. This also
means a reboot returns the radio to NetworkManager, which is why preflight
prepares the interface before judging whether it can scan.

**DHCP.** There is no guaranteed standalone DHCP client — the station probes for
`dhclient`, `dhcpcd` and `udhcpc` in turn and names the package to install if
none exist.

**Captive portals** are passed by driving whatever form the portal actually
serves: the station probes `generate_204` both by name and by IP (silence means
it is still intercepted), finds the portal at the gateway's `/hotspot`, parses
the page with a stdlib HTML parser, echoes back the hidden fields and posts the
click or the credentials.

**Throughput measurement.** Where the SSID is on a tagged VLAN, the station
raises a wired peer for itself on that VLAN **inside a network namespace**. Both
ends are the same host, but the namespace has no route to the wireless address,
so the kernel cannot short-circuit the transfer — packets leave on `eth0`
tagged, cross the switch, and come back over the air through the AP. Without
that, a "throughput over Wi-Fi" test would pass without a frame being
transmitted. Where no peer can be raised, it falls back to an HTTP download
bound to the wireless source address.
