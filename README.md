# 80211 Testing Framework

Regression testing for OpenWiFi APs, driven **directly over SSH** — no uCentral
cloud SDK, no controller, no gateway. The framework logs into the AP, stops the
uCentral agent, and applies configs locally with
`/usr/share/ucentral/ucentral.uc`.

Test material comes from the [wlan-ap uCentral schema
examples](https://github.com/Telecominfraproject/wlan-ap/tree/main/feeds/ucentral/ucentral-schema/files/etc/ucentral/examples):
71 configs covering every security method, bridge and NAT forwarding, VLANs,
tunnels, captive portals, QoS, telemetry and 6 GHz/Wi-Fi 7. They are vendored,
categorized and normalized, then applied one at a time.

## Key design principles

- **Core is immutable** — most new coverage is a catalog entry, not a new file.
  Nothing in `framework/` changes when you extend the sweep.
- **Capability-aware** — the bench is probed once at session start. An example
  needing hardware you do not have skips with a reason that names it
  ("testbed lacks a RADIUS server"), rather than failing.
- **No SDK** — the AP is managed entirely over SSH as `root`. The uCentral
  agent is stopped and disabled for the run so nothing reverts a config
  mid-test, then restored afterwards.
- **One station** — an RPi5 with an Intel BE200 PCIe card, running Raspberry Pi
  OS, acts as the client for every association, DHCP, ping and iperf3 check.
- **Upstream examples are normalized, visibly** — every change is recorded and
  printed in the report. See [Config normalization](#config-normalization).
- **Two reports** — a standalone HTML file for humans, and Allure for
  interactive drilldown.

## Hardware

| Role | Hardware | Notes |
|---|---|---|
| DUT | Any OpenWiFi AP | Reached over SSH, default `root` / `openwifi` |
| Station | RPi5 + Intel BE200 (PCIe hat) | Raspberry Pi OS, normally `wlan1` |
| Optional | RADIUS, VLAN trunk, peer AP, iperf3 server | Each unlocks a group of tests |

A bare AP plus one RPi5 runs **34 of the 71** catalogued examples end to end.
The other 37 declare what they need — most commonly RADIUS (16), a peer AP (8)
or a VLAN trunk (7) — and skip cleanly without it.

## The run workflow

```
make plan          →  log in, stop the uCentral agent, read capabilities,
                      print which examples are feasible and why the rest are not
make regression    →  run them, write the report, hand the AP back
```

Per test:

1. Load the upstream example and normalize it — regulatory domain, channel
   width, channel, **and clamp mode/width/channel to what this AP advertises**.
2. Force `ssh` onto the upstream interface (see below), set `strict`.
3. **Arm a rollback**, upload, and apply with `ucentral.uc` detached.
4. Parse the result. **`ucentral.uc` exits 0 whether it succeeded or failed**
   on a custom config path, so success comes from whether it rendered a UCI
   batch — never from the exit code.
5. Confirm management access still works and cancel the rollback.
6. **Re-stop the agent** — every apply ends in `reload_config`, which fires
   procd's reload trigger and restarts the agent, which then reconnects to the
   controller and pushes its config over the one under test.
7. Read back live state (`iwinfo`, hostapd) to prove the config took effect,
   polling because hostapd brings each BSS up after the radios settle.
8. Where the example has an SSID a station can reach, associate, take a DHCP
   lease, and assert the behaviour under test.

## Safety mechanisms

Four guards exist because each one corresponds to a way this framework
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

## Handing the AP back

`ap.cleanup` in testbed.yaml controls the end state:

| Value | Behaviour |
|---|---|
| `factory_reset` *(default)* | `jffs2reset -y && reboot` — clean baseline, re-onboards to the controller by itself |
| `restore_agent` | re-enable the agent, leaving the last applied config committed |
| `none` | leave the AP exactly as the tests left it |

## Config normalization

The upstream examples are schema illustrations, not runnable lab configs. Three
problems affect most of the corpus, and all three are fixed before an apply:

| Problem | Scale | Fix |
|---|---|---|
| `"country": "CA"` | 86 of 108 radio entries | Forced to `US` (configurable) |
| 80 MHz on a 2.4 GHz radio | 32 examples | Clamped to 20 MHz |
| Channel outside its declared band | 22 examples | Moved into band |

That last one is easy to miss: `crypto-psk.json` asks for `band: 2G` with
`channel: 32`, and `telemetry.json` asks for `band: 2G` with `channel: 36`.

**Why this matters more than it looks.** The renderer does not reject 80 MHz on
2.4 GHz — it *clamps* the width and then **deletes your pinned channel**, so the
radio silently lands on auto-select and the apply still reports success. A test
would be validating a configuration nobody asked for. The framework therefore
also sets `"strict": true`, which makes the renderer reject on any warning
instead of clamping, so "applied" means "applied as requested".

Every normalization is listed per test in the HTML report.

## Running it against a different AP

Nothing is hardcoded per model. The AP's radios, supported modes, channels and
port names are probed from its own `capabilities.json` at session start, and
every example is normalized to fit before it is applied — so a Wi-Fi 5
dual-band AP and a Wi-Fi 7 tri-band AP each get a config they can actually run.

```bash
make setup            # asks for the new AP's IP/credentials, VLANs, RADIUS
make plan             # probes it and prints which examples are feasible
make regression       # run them
make watch            # (second terminal) follow progress live
make report           # open the HTML report
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
| Different ports | `select-ports` is matched against the AP's own `wan`/`lan` names |
| Switch fabric | Set `external.has_switch_hw` to unlock the `switch-*` examples |

## Quickstart

```bash
make install                                   # venv + dependencies
cp config/profiles/example_minimal.yaml config/testbed.yaml
$EDITOR config/testbed.yaml                    # AP host, RPi5 host, credentials

make check                                     # offline — validates corpus and rules, no hardware
make regression                                # full sweep
make report                                    # open the HTML report
```

Run a single feature area, or a single example:

```bash
make sweep AREA=security
pytest tests/regression -k crypto-psk -v --testbed-config config/testbed.yaml
```

`make check` needs no hardware and runs in CI. It asserts the whole corpus
parses, the catalog matches what is on disk, and the normalization rules above
still hold.

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
│   ├── ap/ap_client.py         # SSH control: agent, apply, readback, identity
│   ├── clients/
│   │   ├── ssh.py              # shared session (password auth, sudo)
│   │   └── rpi5_station.py     # BE200 station: associate, DHCP, ping, iperf3
│   ├── examples/
│   │   ├── loader.py           # tolerant parser for the malformed examples
│   │   ├── normalize.py        # CA→US, 2.4 GHz width, out-of-band channels
│   │   ├── catalog.py          # feature area + hardware requirements
│   │   └── inspect.py          # read SSIDs/modes back out of a config
│   ├── capability/             # probe the bench, gate tests on what it has
│   └── reporting/
│       ├── html_report.py      # standalone HTML + JSON
│       └── allure_helper.py
├── tests/
│   ├── unit/                   # offline checks — no hardware
│   ├── regression/             # the sweep
│   └── _template.py
└── conftest.py                 # fixtures, capability gating, report collection
```

## Example categories

| Area | Examples | Needs beyond AP + station |
|---|---|---|
| `security` | crypto-psk, crypto-enterprise, owe, owe-transition, multi-psk, radius\* | RADIUS for enterprise modes |
| `network_mode` | default, maverick, block-rfc1918, dual-stack, strict-forwarding | — |
| `rate_limit` / `qos` | rate-limit, qos, qos-class | iperf3 server for enforcement |
| `roaming` | steering, rrm, quality-threshold, roaming-psk2-radius | peer AP for roaming |
| `captive` | captive, captive-click, captive-credentials, captive-uam | UAM backend for external portals |
| `vlan` | vlan, switch-vlan, dhcp-relay, big | VLAN trunk |
| `tunnel` | gre, gre6, vxlan, mesh, wds-ap, wds-sta | peer AP / tunnel endpoint |
| `wifi_gen` | wifi-6e, wifi-6e-afc, wifi-7, wifi-6e-mpsk | 6 GHz or Wi-Fi 7 on both ends |
| `services` / `telemetry` | ssh, lldp, ntp, metrics, fingerprint-\* | internet for NTP |
| `switch` / `wwan` | switch-ports, switch-fabric, wwan | switch fabric / modem |

`crypto-psk` is the highest-value single config in the corpus: six SSIDs on one
radio covering open, `psk`, `psk2`, `psk-mixed`, `sae` and `sae-mixed`, so one
apply exercises six association paths.

## Adding coverage

**Adding an upstream example to the sweep** — add an entry to
`EXAMPLES` in `framework/examples/catalog.py` naming its area, forwarding mode
and requirements. It is picked up by the parametrized suites automatically.
`make check` will tell you if the declared mode disagrees with the config.

**Adding a bespoke assertion** — copy `tests/_template.py` into
`tests/regression/`. Use the `apply_example` fixture and derive SSIDs from the
config you applied rather than hardcoding names. Zero framework files change.

## Notes on the RPi5 station

Raspberry Pi OS (Bookworm) has NetworkManager managing every wireless interface.
The framework hands the BE200 out of NetworkManager's control
(`nmcli device set wlan1 managed no`) before driving `wpa_supplicant` directly,
and gives it back at teardown. Fighting NetworkManager otherwise looks exactly
like an association failure.

Bookworm also has no guaranteed standalone DHCP client — it relies on
NetworkManager's internal one, which is unavailable once the interface is
unmanaged. The station probes for `dhclient`, `dhcpcd` and `udhcpc` in turn; if
none exist it says so and names the package to install.
