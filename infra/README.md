# Self-contained lab services

The regression suite needs a RADIUS server and a certificate chain. Rather than
depending on lab infrastructure that differs from bench to bench, these run on
the RPi5 station host, so a checkout of this repo reproduces the same testbed
anywhere.

Bringing them up takes the runnable share of the catalog from **33 to 45 of 71
examples** — RADIUS alone unlocks 12, and it is the only way to test dynamic
VLAN assignment, because that test needs a server configured to return a known
VLAN. (A VLAN trunk takes it to 47, and internet access for NTP, online-check
and AFC to 49.)

## Hardware this assumes

| Role | Hardware |
|---|---|
| Station host | Raspberry Pi 5, Debian 13 (trixie) |
| Station radio | Intel BE200 on a PCIe hat (**not** the onboard radio) |
| DUT | Any OpenWiFi AP reachable over SSH |
| Switch | One port trunking the test VLANs tagged to the AP |

Kernel **6.18.39** runs the BE200 fine — driver `iwlmld`, firmware 101. Only the
6.18.34 point release was broken, failing to probe with `No config found for PCI
dev 272b/00f4`, which is why 6.12 was pinned for a while. **Do not pin 6.12 on a
new bench.** Nothing in the code asserts a kernel version; it is read with
`uname -r` for the report header only.

## What actually runs here

**FreeRADIUS**, in podman, on **host networking**. Its client is the AP, not the
station, so the AP reaches it at the Pi's own address over the wire. There is no
second container and no second address.

> An earlier revision put it on a macvlan child of `eth0` to isolate a local
> iperf3 peer from the station. **That peer is gone** — throughput is now
> measured against a wired peer the station raises for itself in a network
> namespace (see the main README), which crosses the air by construction, and
> internet throughput with a plain bound download. Since the only reason for
> macvlan was the local peer, and a macvlan child on the management NIC is a
> plausible cause of the station dropping off the network mid-sweep, it is not
> worth the risk.

**The restart policy must be `always`, not `unless-stopped`.**
`podman-restart.service` — the thing that actually starts containers after a
reboot — runs `podman start --all --filter restart-policy=always`, so an
`unless-stopped` container is skipped at boot and stays down. That was measured
on this bench: after a reboot the container sat in `Exited (0)` with
podman-restart both enabled and active, and every enterprise case in the next
sweep would have failed with the client associating and finding no
authentication server. Enable the service on the host:

```bash
systemctl enable --now podman-restart
```

`benchd/deploy/install.sh` does this for you.

**The container is rootless**, run as the station user, so its store is
`/run/user/1000/containers`. Asking `podman ps` over sudo returns an empty list —
which is how preflight once reported RADIUS down while it was up and answering.

## The bench PKI

`make infra-up` generates it on first run, if `pki/out/server.pem` is absent, by
calling `pki/make-pki.sh`. Output is gitignored — key material never belongs in
the repo.

| File | What it is |
|---|---|
| `ca.pem` / `ca.key` | the bench root CA, "80211 Bench Root CA" (key `chmod 600`) |
| `server.pem` / `server.key` | what FreeRADIUS presents. CN `radius.bench.local`, **`serverAuth` EKU plus a SAN** — wpa_supplicant rejects a server cert without them. Key is `chmod 644` so the `freerad` user can read it |
| `client.pem` / `client.key` | the station's EAP-TLS identity. CN `testuser`, `clientAuth` EKU |
| `client.p12` | the same as a PKCS#12 bundle, password `whatever` |
| `dh` | 2048-bit DH parameters, which FreeRADIUS insists on |

Overridable with `PKI_DAYS`, `PKI_SUBJ_BASE`, `PKI_CLIENT_CN`, `PKI_SERVER_CN`
and `PKI_P12_PASS`. Certificates are valid 825 days.

This is what makes enterprise SSIDs joinable. Without it the RADIUS examples
only ever exercise their companion PSK SSID, and every 802.1X exchange stalls
after association — which reads as an AP fault and is not one.

> Not every enterprise example uses this chain. Where the AP terminates EAP
> itself (`radius.local`, presenting its own vendor certificate) the lab server
> is never consulted, and the method is **EAP-PWD**, not PEAP.

## Setup

```bash
cp infra/infra.env.example infra/infra.env
$EDITOR infra/infra.env          # just RADIUS_SECRET
make infra-up                    # copies infra/ to the station and runs up.sh there
```

`make infra-down` stops it; `python -m framework.infra_deploy --testbed-config
<cfg> status` reports what is running.

Then point the framework at it:

```yaml
external:
  radius:
    host: 10.0.127.77         # the station host's own address
    secret: <your secret>
    identity: testuser
    password: testpass
    dynamic_vlan: 1000        # the VLAN this server returns for `identity`
    eap_method: PEAP          # or TLS, using the certs below
    ca_cert:     infra/pki/out/ca.pem
    client_cert: infra/pki/out/client.pem
    private_key: infra/pki/out/client.key
```

`make plan` will now show the RADIUS-dependent examples as runnable, and
`python -m framework.preflight` will confirm the container is actually up.

## Test accounts

Configured in `freeradius/authorize`; anything else is rejected by default.

| User | Password | VLAN returned |
|---|---|---|
| `testuser` | `testpass` | 1000 |
| `vlan2000` | `testpass` | 2000 |
| `plainuser` | `testpass` | none |

Two VLANs on purpose: with one, a dynamic-assignment test cannot tell a correct
assignment from everything landing in the same place.

`freeradius/clients.conf.tmpl` permits the AP under test plus the whole
`10.0.0.0/16` lab, so a re-addressed AP still works. The shared secret is
substituted in from `infra.env` at deploy time; `infra.env` is gitignored.

## Notes

**FreeRADIUS is built locally** rather than pulled. The upstream
`freeradius/freeradius-server` images are amd64-only and fail on ARM with
`Exec format error`, so `freeradius/Containerfile` builds the equivalent from
the Debian package on `debian:trixie-slim`. The build also flips `auth = no` to
`auth = yes` in `radiusd.conf` — without it the server authenticates correctly
but logs nothing, and the `radius accepted the client` check has nothing to read.

`freeradius/eap` sets `default_eap_type = tls` with PEAP and TTLS also enabled
(MSCHAPv2 inner), TLS 1.2–1.3, `SECLEVEL=1`.

**Podman rather than Docker**: no daemon, and it does not install the NAT and
FORWARD rules that would interact with the policy routing the wireless tests
depend on.

## What containers cannot provide

22 examples need real hardware and will still skip: a second AP for
mesh/WDS/GRE/roaming (8), 6 GHz radios (5), a managed switch fabric (3), an
external captive backend (2), and one each of Wi-Fi 7, GPS, WWAN and an external
DHCP server. **A second AP is the highest-value addition** — it would also
unlock strict forwarding, client isolation and steering, which cannot be tested
with one station.
