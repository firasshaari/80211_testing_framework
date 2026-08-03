# Self-contained lab services

The regression suite needs a RADIUS server and a traffic peer. Rather than
depending on lab infrastructure that differs from bench to bench, these run as
containers on the RPi5 station host, so a checkout of this repo plus the
hardware below reproduces the same testbed anywhere.

Bringing these up takes the runnable share of the catalog from **38 to 52 of 71
examples** — RADIUS alone unlocks 12, and it is the only way to test dynamic
VLAN assignment, because that test needs a server configured to return a known
VLAN.

## Hardware this assumes

| Role | Hardware |
|---|---|
| Station host | Raspberry Pi 5, Raspberry Pi OS / Debian 13, kernel **6.12** |
| Station radio | Intel BE200 on a PCIe hat (**not** the onboard radio) |
| DUT | Any OpenWiFi AP reachable over SSH |
| Switch | One port trunking the test VLANs tagged to the AP |

The 6.12 kernel matters: the BE200 fails to probe on 6.18 with
`No config found for PCI dev 272b/00f4`. See the main README.

## Why macvlan and not host networking

The services get their **own address on the wired LAN**, separate from the Pi's.
This is a correctness requirement, not tidiness.

With host networking the iperf3 server would answer on the Pi's own address. The
station would then reach it over loopback and a "throughput over Wi-Fi" test
would pass without a single frame being transmitted. Giving the services a
distinct L2 endpoint forces station traffic out `wlan0`, through the AP, down
the trunk and back — the path the test claims to measure.

A macvlan child interface is also unreachable from its parent host's own
namespace, so the isolation is enforced by the network stack rather than by
remembering to be careful.

```
  RPi5 host ── eth0 ──┬── 10.0.127.77   station management (SSH)
                      └── macvlan ──── 10.0.127.90  radius
                                       10.0.127.91  iperf3
       wlan0 (BE200) ─── VLAN 1000 ─── via the AP, over the air
```

## Setup

```bash
cp infra/infra.env.example infra/infra.env
$EDITOR infra/infra.env          # pick FREE addresses on your wired LAN
make infra-up
```

`INFRA_IP` and `INFRA_IP2` must be free — they are static and will collide with
anything else holding them, including a DHCP pool.

Then point the framework at them:

```yaml
external:
  radius:
    host: 10.0.127.90
    secret: testing123
    identity: testuser
    password: testpass
    dynamic_vlan: 1000      # the VLAN this server returns for `identity`
  iperf_server: 10.0.127.91
```

`make plan` will now show the RADIUS-dependent examples as runnable.

## Test accounts

| User | Password | VLAN returned |
|---|---|---|
| `testuser` | `testpass` | 1000 |
| `vlan2000` | `testpass` | 2000 |
| `plainuser` | `testpass` | none |

Two VLANs on purpose: with one, a dynamic-assignment test cannot tell a correct
assignment from everything landing in the same place.

## Notes

FreeRADIUS is **built locally** rather than pulled. The upstream
`freeradius/freeradius-server` images are amd64-only and fail on ARM with
`Exec format error`, so `infra/freeradius/Containerfile` builds the equivalent
from the Debian package for arm64.

Podman is used rather than Docker: no daemon, and it does not install the NAT
and FORWARD rules that would interact with the policy routing the wireless tests
depend on.

## What containers cannot provide

19 examples need real hardware and will still skip: a second AP for
mesh/WDS/GRE/roaming (8), 6 GHz radios (5), a managed switch fabric (3), Wi-Fi 7
(1), GPS (1), WWAN (1). A second AP is the highest-value addition.
