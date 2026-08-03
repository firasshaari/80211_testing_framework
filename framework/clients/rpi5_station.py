"""
RPi5 + Intel BE200 station client.

Target platform is Raspberry Pi OS (Bookworm), which brings two constraints
that shape this module:

* **NetworkManager owns every wireless interface by default.** Running
  ``wpa_supplicant`` underneath it produces a connect/disconnect fight that
  looks exactly like an association failure. The interface is therefore handed
  out of NetworkManager's control before any test drives it.
* **There is no single guaranteed DHCP client.** Bookworm dropped ``dhcpcd`` in
  favour of NetworkManager's internal client, so ``dhclient``/``dhcpcd``/
  ``udhcpc`` are each present only sometimes. :meth:`Station.request_dhcp`
  probes for whichever exists and reports a clear error naming the package to
  install if none do.

``wpa_supplicant`` is driven directly rather than through ``nmcli`` because the
regression matrix covers security modes — OWE transition, SAE mixed, per-SSID
802.1X — whose knobs are far more directly expressed as supplicant network
blocks.
"""
from __future__ import annotations

import logging
import re
import shlex
import textwrap
import time
from dataclasses import dataclass, field

from framework.clients.ssh import SSHError, SSHSession

log = logging.getLogger(__name__)

WPA_CONF_PATH = "/tmp/regression_wpa.conf"
WPA_CTRL_DIR = "/var/run/wpa_supplicant"
WPA_DEBUG_LOG = "/tmp/regression_wpa.log"
DHCP_CLIENTS = ("dhclient", "dhcpcd", "udhcpc")

# Lines from `wpa_supplicant -dd` that evidence what actually happened on air:
# which BSS was chosen, the auth/assoc exchange, the 4-way handshake, EAP for
# enterprise, and the cipher suite finally in use. Everything else is noise.
_EVIDENCE_PATTERNS = (
    "CTRL-EVENT-", "SME:", "Trying to associate", "Associated with",
    "WPA: Key negotiation completed", "WPA: 4-Way Handshake",
    "RSN: ", "EAP-", "EAPOL: ", "SAE:", "OWE:", "PMKSA",
    "auth_alg", "pairwise cipher", "group cipher", "key_mgmt",
    "Authentication with", "deauthenticat", "reason=",
)


class StationError(RuntimeError):
    pass


@dataclass
class Association:
    """Result of a successful association."""

    ssid: str
    bssid: str = ""
    mac: str = ""
    ip: str = ""
    freq_mhz: int = 0
    band: str = ""
    rssi_dbm: float | None = None
    # STA-side evidence that the link really formed the way it was meant to.
    supplicant_log: str = ""
    link_detail: str = ""
    pairwise_cipher: str = ""
    key_mgmt: str = ""

    @property
    def has_ip(self) -> bool:
        return bool(self.ip)

    def evidence(self) -> str:
        """Human-readable proof block for the report."""
        parts = [
            f"SSID           {self.ssid}",
            f"BSSID          {self.bssid}",
            f"Station MAC    {self.mac}",
            f"Band/Frequency {self.band} / {self.freq_mhz} MHz",
            f"RSSI           {self.rssi_dbm} dBm",
            f"IP address     {self.ip or 'none'}",
            f"key_mgmt       {self.key_mgmt or 'n/a'}",
            f"pairwise       {self.pairwise_cipher or 'n/a'}",
        ]
        if self.link_detail:
            parts += ["", "--- iw dev link ---", self.link_detail]
        if self.supplicant_log:
            parts += ["", "--- wpa_supplicant -dd (key lines) ---", self.supplicant_log]
        return "\n".join(parts)


@dataclass
class ScanResult:
    ssid: str
    bssid: str
    freq_mhz: int
    signal_dbm: float
    flags: str = ""

    @property
    def band(self) -> str:
        return _band_for_freq(self.freq_mhz)


@dataclass
class PingResult:
    transmitted: int = 0
    received: int = 0
    loss_pct: float = 100.0
    rtt_avg_ms: float | None = None

    @property
    def ok(self) -> bool:
        return self.received > 0


@dataclass
class ThroughputResult:
    mbps: float = 0.0
    direction: str = "downstream"
    protocol: str = "tcp"
    duration_s: int = 0
    retransmits: int | None = None
    raw: dict = field(default_factory=dict)


def _band_for_freq(freq: int) -> str:
    if freq >= 5925:
        return "6G"
    if freq >= 4900:
        return "5G"
    if freq >= 2400:
        return "2G"
    return "unknown"


# ── Security mode → wpa_supplicant network block ─────────────────────────────
# Keys are the uCentral schema's encryption "proto" values, so a test can pass
# the proto straight from the example config it applied.

def build_network_block(
    ssid: str,
    proto: str,
    *,
    passphrase: str | None = None,
    identity: str | None = None,
    eap_password: str | None = None,
    eap_method: str = "PEAP",
    phase2: str = "auth=MSCHAPV2",
    bssid: str | None = None,
) -> str:
    """Render the ``network={...}`` block for a uCentral encryption proto."""
    proto = (proto or "none").lower()
    lines = [f'ssid="{ssid}"', "scan_ssid=1"]
    if bssid:
        lines.append(f"bssid={bssid}")

    def psk() -> None:
        if not passphrase:
            raise StationError(f"proto {proto!r} needs a passphrase")
        lines.append(f'psk="{passphrase}"')

    if proto in ("none", "open"):
        lines.append("key_mgmt=NONE")

    elif proto == "owe":
        lines += ["key_mgmt=OWE", "ieee80211w=2"]

    elif proto == "owe-transition":
        # The transition BSS is advertised as open; the supplicant upgrades to
        # OWE on its own when the AP offers the transition element.
        lines += ["key_mgmt=OWE NONE", "ieee80211w=1"]

    elif proto == "psk":                       # WPA1 personal
        lines += ["key_mgmt=WPA-PSK", "proto=WPA", "pairwise=TKIP", "group=TKIP"]
        psk()

    elif proto in ("psk2", "psk2-radius", "mpsk", "mpsk-radius"):   # WPA2 personal
        lines += ["key_mgmt=WPA-PSK", "proto=RSN", "pairwise=CCMP", "group=CCMP"]
        psk()

    elif proto in ("psk-mixed", "psk2-mixed"):
        lines += ["key_mgmt=WPA-PSK", "proto=WPA RSN", "pairwise=CCMP TKIP"]
        psk()

    elif proto == "sae":                       # WPA3 personal
        lines += ["key_mgmt=SAE", "proto=RSN", "pairwise=CCMP", "ieee80211w=2"]
        psk()

    elif proto in ("sae-mixed", "wpa3-mixed"):  # WPA2/WPA3 transition
        lines += ["key_mgmt=SAE WPA-PSK", "proto=RSN", "pairwise=CCMP", "ieee80211w=1"]
        psk()

    elif proto in ("wpa", "wpa-mixed", "wpa2", "wpa2-radius", "wpa3"):  # enterprise
        if not identity or eap_password is None:
            raise StationError(f"proto {proto!r} needs identity and eap_password")
        mgmt = "WPA-EAP-SHA256 WPA-EAP" if proto == "wpa3" else "WPA-EAP"
        lines += [f"key_mgmt={mgmt}", f"eap={eap_method}"]
        lines += [f'identity="{identity}"', f'password="{eap_password}"']
        if eap_method.upper() in ("PEAP", "TTLS"):
            lines.append(f'phase2="{phase2}"')
        if proto == "wpa3":
            lines.append("ieee80211w=2")
        elif proto == "wpa":
            lines += ["proto=WPA", "pairwise=TKIP"]

    else:
        raise StationError(
            f"Unsupported encryption proto {proto!r}. "
            f"Extend build_network_block() in {__name__} if the AP supports it."
        )

    body = "\n    ".join(lines)
    return f"network={{\n    {body}\n}}"


class Station:
    """A single RPi5 acting as the wireless client under test."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        *,
        iface: str = "wlan1",
        root_password: str | None = None,
        country: str = "US",
        port: int = 22,
    ) -> None:
        self.host = host
        self.iface = iface
        self.country = country
        self.ssh = SSHSession(
            host,
            user,
            password,
            port=port,
            sudo_password=root_password or password,
            label=f"STA:{host}",
        )
        self._nm_released = False
        self._current: Association | None = None
        self._mgmt: dict[str, str] = {}

    # ── Setup ────────────────────────────────────────────────────────────────

    def prepare(self) -> None:
        """Take the interface off NetworkManager and set the regulatory domain."""
        if not self.ssh.run(f"test -d /sys/class/net/{self.iface}").ok:
            raise StationError(
                f"Interface {self.iface!r} does not exist on {self.host}. "
                f"Available: {self.list_interfaces()}"
            )

        # A soft rfkill block survives reboots via systemd-rfkill's saved state,
        # and makes `ip link set <iface> up` fail with the distinctly unhelpful
        # "Operation not possible due to RF-kill". Clear it before anything else.
        # NetworkManager can also hold the radio off independently of rfkill.
        if self.ssh.run("command -v nmcli").ok:
            self.ssh.run("nmcli radio wifi on", sudo=True)
        self.ssh.run("rfkill unblock wifi", sudo=True)

        # Only meaningful if NetworkManager is actually installed and running.
        if self.ssh.run("command -v nmcli").ok:
            res = self.ssh.run(f"nmcli device set {self.iface} managed no", sudo=True)
            if res.ok:
                self._nm_released = True
                log.info("Released %s from NetworkManager", self.iface)
            else:
                log.warning("Could not release %s from NetworkManager: %s",
                            self.iface, res.stderr.strip())

        self._protect_management_route()

        self.ssh.run(f"iw reg set {self.country}", sudo=True)
        up = self.ssh.run(f"ip link set {self.iface} up", sudo=True)
        if not up.ok:
            raise StationError(
                f"Could not bring {self.iface} up on {self.host}: "
                f"{up.stderr.strip() or up.stdout.strip()}"
            )

    # Routing table id used to pin management traffic to its own interface.
    MGMT_TABLE = 100

    def _protect_management_route(self) -> None:
        """
        Pin the management path to its own interface before any association.

        Without this the framework can lock itself out of the station. A
        bridged test SSID hands the client an address on the *same* subnet as
        the station's own management LAN — observed live: `wlan0` got
        10.0.127.76 while management sits on 10.0.127.77 — so the DHCP lease
        installs a competing default route, replies to the SSH session start
        leaving via the wireless interface, and the session dies mid-test.

        A source-based rule keeps anything sent from the management address on
        the management interface, whatever the wireless side does.
        """
        addr = self.ssh.run(
            f"ip -4 -o addr show | grep -w {self.host} | head -1"
        ).stdout.strip()
        if not addr:
            log.warning("Could not identify the management interface for %s; "
                        "association may interrupt this session", self.host)
            return

        mgmt_if = addr.split()[1]
        if mgmt_if == self.iface:
            log.warning(
                "Management address %s is on the test interface %s itself — "
                "cannot protect the session from association", self.host, mgmt_if
            )
            return

        gw = self.ssh.run(
            f"ip route show default dev {mgmt_if} | head -1"
        ).stdout.strip()
        gateway = gw.split()[2] if len(gw.split()) > 2 else ""
        self._mgmt = {"iface": mgmt_if, "ip": self.host, "gateway": gateway}

        t = self.MGMT_TABLE
        # Idempotent: drop any previous rule/table first.
        self.ssh.run(f"ip rule del from {self.host} lookup {t} || true", sudo=True)
        self.ssh.run(f"ip route flush table {t} || true", sudo=True)

        # Copy the kernel's connected route, not the interface address — the
        # address carries host bits (10.0.127.77/16) and `ip route add` rejects
        # it, silently leaving the table without an on-link entry.
        onlink = self.ssh.run(
            f"ip -4 route show dev {mgmt_if} scope link | head -1"
        ).stdout.strip()
        if onlink:
            self.ssh.run(
                f"ip route add {onlink.split()[0]} dev {mgmt_if} scope link "
                f"src {self.host} table {t} || true",
                sudo=True,
            )
        if gateway:
            self.ssh.run(
                f"ip route add default via {gateway} dev {mgmt_if} table {t} || true", sudo=True
            )
        self.ssh.run(f"ip rule add from {self.host} lookup {t} || true", sudo=True)

        # Routing alone is not enough when both interfaces land on one subnet.
        # By default Linux answers ARP for any local address on any interface
        # ("ARP flux"), so the upstream switch can learn the management IP on
        # the wireless MAC and blackhole the session. arp_ignore=1 answers only
        # for addresses on the receiving interface; arp_announce=2 always
        # sources ARP from the correct interface. rp_filter=2 (loose) stops
        # reverse-path checks dropping the deliberately asymmetric paths.
        for knob, value in (
            ("arp_ignore", 1),
            ("arp_announce", 2),
            ("rp_filter", 2),
        ):
            self.ssh.run(f"sysctl -qw net.ipv4.conf.all.{knob}={value}", sudo=True)
            self.ssh.run(f"sysctl -qw net.ipv4.conf.{mgmt_if}.{knob}={value}", sudo=True)
            self.ssh.run(f"sysctl -qw net.ipv4.conf.{self.iface}.{knob}={value}", sudo=True)

        log.info(
            "Management pinned: %s via %s (table %s), ARP flux protection on",
            self.host, mgmt_if, t,
        )

    # Routing table for traffic sourced from the wireless address.
    WIFI_TABLE = 200

    def _pin_wireless_route(self) -> None:
        """
        Give the wireless side its own default route, in its own table.

        Simply deleting the lease's default route — the first attempt at
        protecting management — also removed the only path a NAT-mode client
        has to the internet, so every "can this client reach google.com" check
        failed for a reason that had nothing to do with the AP.

        Instead the wireless default is moved into a dedicated table selected by
        source address. ``ping -I wlan0`` sources from the wireless address, so
        it follows the AP's gateway, while the system default and the management
        session stay on the wired interface.
        """
        default = self.ssh.run(
            f"ip -4 route show default dev {self.iface} | head -1"
        ).stdout.strip()
        ip = self.current_ip()
        if not ip:
            return

        gateway = default.split()[2] if len(default.split()) > 2 else ""
        t = self.WIFI_TABLE

        self.ssh.run(f"ip rule del from {ip} lookup {t} || true", sudo=True)
        self.ssh.run(f"ip route flush table {t} || true", sudo=True)

        onlink = self.ssh.run(
            f"ip -4 route show dev {self.iface} scope link | head -1"
        ).stdout.strip()
        if onlink:
            self.ssh.run(
                f"ip route add {onlink.split()[0]} dev {self.iface} scope link "
                f"src {ip} table {t} || true", sudo=True
            )
        if gateway:
            self.ssh.run(
                f"ip route add default via {gateway} dev {self.iface} table {t} || true",
                sudo=True,
            )
        self.ssh.run(f"ip rule add from {ip} lookup {t} || true", sudo=True)

        # Keep the *system* default on the wired side so the management session
        # and anything not explicitly bound to wlan0 is unaffected.
        self.ssh.run(f"ip route del default dev {self.iface} || true", sudo=True)

        log.info("Wireless route pinned: %s via %s (table %s)",
                 ip, gateway or "on-link", t)

    def release_to_networkmanager(self) -> None:
        """Give the interface back, so the Pi is usable after a run."""
        if self._nm_released:
            self.ssh.run(f"nmcli device set {self.iface} managed yes", sudo=True)
            self._nm_released = False

    def list_interfaces(self) -> list[str]:
        out = self.ssh.run("ls /sys/class/net").stdout
        return [i for i in out.split() if i != "lo"]

    def driver_info(self) -> dict:
        """Client-side hardware detail for the report header."""
        info = {"interface": self.iface}
        info["mac"] = self.ssh.run(
            f"cat /sys/class/net/{self.iface}/address"
        ).stdout.strip()
        driver = self.ssh.run(
            f"basename $(readlink /sys/class/net/{self.iface}/device/driver)"
        ).stdout.strip()
        info["driver"] = driver or "unknown"
        info["kernel"] = self.ssh.run("uname -r").stdout.strip()
        info["os"] = self.ssh.run(
            "grep PRETTY_NAME /etc/os-release | cut -d'\"' -f2"
        ).stdout.strip()
        # Model name of the PCIe card, e.g. the BE200 itself.
        lspci = self.ssh.run("lspci | grep -i network").stdout.strip()
        info["adapter"] = lspci.split(": ", 1)[-1] if lspci else "unknown"
        info["regdomain"] = self._current_regdomain()
        return info

    def _current_regdomain(self) -> str:
        out = self.ssh.run("iw reg get").stdout
        m = re.search(r"country (\w{2}):", out)
        return m.group(1) if m else "unknown"

    # ── Association ──────────────────────────────────────────────────────────

    def connect(
        self,
        ssid: str,
        proto: str = "psk2",
        *,
        passphrase: str | None = None,
        identity: str | None = None,
        eap_password: str | None = None,
        eap_method: str = "PEAP",
        timeout: int = 45,
        dhcp: bool = True,
    ) -> Association:
        """
        Associate to *ssid* using the uCentral encryption *proto*.

        Raises :class:`StationError` with the supplicant's own state if the
        association does not complete inside *timeout*.
        """
        self.disconnect()

        block = build_network_block(
            ssid,
            proto,
            passphrase=passphrase,
            identity=identity,
            eap_password=eap_password,
            eap_method=eap_method,
        )
        conf = textwrap.dedent(
            f"""\
            ctrl_interface=DIR={WPA_CTRL_DIR} GROUP=netdev
            update_config=0
            country={self.country}
            # 6 GHz and WPA3 both require management frame protection support.
            pmf=1
            """
        ) + block + "\n"
        self.ssh.put_text(conf, WPA_CONF_PATH)

        self.ssh.run(f"ip link set {self.iface} up", sudo=True)
        # -dd gives the full association story: chosen BSS, auth/assoc frames,
        # the 4-way handshake and the negotiated ciphers. That log is the
        # evidence the feature actually worked, rather than "we got an IP".
        self.ssh.run(f"rm -f {WPA_DEBUG_LOG}", sudo=True)
        start = self.ssh.run(
            f"wpa_supplicant -B -i {self.iface} -c {WPA_CONF_PATH} -D nl80211 "
            f"-dd -t -f {WPA_DEBUG_LOG}",
            sudo=True,
            timeout=30,
        )
        if not start.ok:
            raise StationError(
                f"wpa_supplicant failed to start on {self.iface}: "
                f"{start.stderr.strip() or start.stdout.strip()}"
            )

        try:
            assoc = self._wait_for_association(ssid, timeout=timeout)
        except StationError as exc:
            # Attach the supplicant's own account of the failure.
            raise StationError(f"{exc}\n{self.supplicant_evidence()}") from None

        if dhcp:
            assoc.ip = self.request_dhcp()

        assoc.supplicant_log = self.supplicant_evidence()
        assoc.link_detail = self.ssh.run(f"iw dev {self.iface} link").stdout.strip()
        status = self.wpa_status()
        assoc.pairwise_cipher = status.get("pairwise_cipher", "")
        assoc.key_mgmt = status.get("key_mgmt", "")

        self._current = assoc
        log.info(
            "Associated to %s (%s) on %s ch=%s — bssid=%s ip=%s key_mgmt=%s pairwise=%s",
            ssid, proto, assoc.band or "?", assoc.freq_mhz, assoc.bssid,
            assoc.ip or "none", assoc.key_mgmt, assoc.pairwise_cipher,
        )
        return assoc

    def supplicant_evidence(self, max_lines: int = 80) -> str:
        """The load-bearing lines of the verbose supplicant log."""
        try:
            raw = self.ssh.run(
                f"grep -E {shlex.quote('|'.join(_EVIDENCE_PATTERNS))} {WPA_DEBUG_LOG} "
                f"2>/dev/null | tail -n {max_lines}",
                sudo=True, timeout=45,
            ).stdout
        except SSHError:
            return "(supplicant log unavailable)"
        return raw.strip() or "(no matching lines in supplicant log)"

    def _wait_for_association(self, ssid: str, timeout: int) -> Association:
        deadline = time.monotonic() + timeout
        last_state = "UNKNOWN"
        while time.monotonic() < deadline:
            status = self.wpa_status()
            last_state = status.get("wpa_state", "UNKNOWN")
            if last_state == "COMPLETED":
                freq = int(status.get("freq", 0) or 0)
                return Association(
                    ssid=status.get("ssid", ssid),
                    bssid=status.get("bssid", ""),
                    mac=status.get("address", ""),
                    freq_mhz=freq,
                    band=_band_for_freq(freq),
                    rssi_dbm=self._current_rssi(),
                )
            time.sleep(2)

        detail = self._association_failure_detail()
        self.disconnect()
        raise StationError(
            f"Did not associate to {ssid!r} within {timeout}s "
            f"(last wpa_state={last_state}). {detail}"
        )

    def _association_failure_detail(self) -> str:
        """Explain *why* association failed, rather than just that it did."""
        seen = [s.ssid for s in self.scan()]
        if not seen:
            return "No SSIDs visible at all — check the radio came up on the AP."
        return f"Visible SSIDs: {sorted(set(seen))}"

    def wpa_status(self) -> dict:
        out = self.ssh.run(f"wpa_cli -i {self.iface} status", sudo=True).stdout
        status = {}
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                status[k.strip()] = v.strip()
        return status

    def _current_rssi(self) -> float | None:
        out = self.ssh.run(f"iw dev {self.iface} link").stdout
        m = re.search(r"signal:\s*(-?\d+)", out)
        return float(m.group(1)) if m else None

    def disconnect(self) -> None:
        self.ssh.run("pkill -f 'wpa_supplicant.*regression_wpa' || true", sudo=True)
        self.ssh.run("pkill -f 'wpa_supplicant.*regression' || true", sudo=True)
        for client in DHCP_CLIENTS:
            self.ssh.run(f"pkill -f '{client}.*{self.iface}' || true", sudo=True)
        self.ssh.run(f"ip addr flush dev {self.iface} || true", sudo=True)
        self._current = None
        time.sleep(1)

    # ── Addressing ───────────────────────────────────────────────────────────

    def request_dhcp(self, timeout: int = 30) -> str:
        """Obtain a lease with whichever DHCP client this image actually has."""
        client = self._find_dhcp_client()

        # Drop any lease held from a previous test before asking for a new one.
        # dhclient replays a cached lease first: after a NAT-mode case it spends
        # two DHCPREQUEST rounds trying to reclaim 192.168.1.x on a VLAN where
        # that address does not exist, and only then falls back to DISCOVER.
        # That easily outlasts the wait and looks like "no DHCP server", which
        # is what made every bridged case fail while a phone on the same SSID
        # got an address instantly.
        if client == "dhclient":
            self.ssh.run(f"dhclient -r {self.iface} >/dev/null 2>&1 || true",
                         sudo=True, timeout=30)
            self.ssh.run("rm -f /var/lib/dhcp/dhclient*.leases", sudo=True)
        elif client == "dhcpcd":
            self.ssh.run(f"dhcpcd -k {self.iface} >/dev/null 2>&1 || true",
                         sudo=True, timeout=30)
        self.ssh.run(f"ip addr flush dev {self.iface} || true", sudo=True)

        if client == "dhclient":
            cmd = f"dhclient -1 {self.iface}"
        elif client == "dhcpcd":
            cmd = f"dhcpcd -4 -t {timeout} {self.iface}"
        else:
            cmd = f"udhcpc -i {self.iface} -n -q -t 5"

        # Detached, not foreground. Acquiring a lease briefly reshuffles routes
        # and resolv.conf, and a foreground client streaming over the SSH
        # channel takes the management session down with it — which surfaced as
        # "command transport failed: dhclient" and failed every bridged case.
        # Detaching means a blip costs at most a poll, not the whole test.
        # Must go through `sh -c`: sudo cannot execute a subshell, so
        # `sudo (setsid ... ) &` is a bash syntax error and the client never
        # runs at all — which presented as "no DHCP server" with an empty log.
        inner = f"setsid {cmd} >/tmp/regression_dhcp.log 2>&1 || " \
                f"{cmd} >>/tmp/regression_dhcp.log 2>&1"
        self.ssh.run(
            f"sh -c {shlex.quote(inner + ' &')}", sudo=True, timeout=30
        )
        ip = self.wait_for_ip(timeout=timeout)
        if not ip:
            # Surface what the client actually said rather than just "no IP".
            tail = self.ssh.run(
                "tail -12 /tmp/regression_dhcp.log 2>/dev/null", sudo=True
            ).stdout.strip()
            if tail:
                log.warning("DHCP failed on %s; client output:\n%s", self.iface, tail)
        if ip:
            # Move the lease's default route into a source-selected table so it
            # serves wireless traffic without hijacking the management session.
            self._pin_wireless_route()
        return ip

    def _find_dhcp_client(self) -> str:
        for candidate in DHCP_CLIENTS:
            if self.ssh.run(f"command -v {candidate}").ok:
                return candidate
        raise StationError(
            f"No DHCP client on {self.host}. Raspberry Pi OS Bookworm relies on "
            f"NetworkManager's internal client, which is unavailable once the "
            f"interface is unmanaged. Install one with: "
            f"sudo apt install isc-dhcp-client"
        )

    def wait_for_ip(self, timeout: int = 30) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                ip = self.current_ip()
            except SSHError:
                # The lease can briefly disturb the management path; reconnect
                # and keep waiting rather than failing the test.
                self.ssh.close()
                time.sleep(2)
                continue
            if ip:
                return ip
            time.sleep(2)
        return ""

    def current_ip(self) -> str:
        out = self.ssh.run(f"ip -4 -o addr show {self.iface}").stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""

    def current_ipv6(self) -> str:
        out = self.ssh.run(f"ip -6 -o addr show {self.iface} scope global").stdout
        m = re.search(r"inet6 ([0-9a-f:]+)", out)
        return m.group(1) if m else ""

    # ── Verification helpers ─────────────────────────────────────────────────

    def scan(self, timeout: int = 30) -> list[ScanResult]:
        self.ssh.run(f"ip link set {self.iface} up", sudo=True)
        out = self.ssh.run(f"iw dev {self.iface} scan", sudo=True, timeout=timeout).stdout
        return _parse_iw_scan(out)

    def scan_for(self, ssid: str, *, retries: int = 3) -> list[ScanResult]:
        """Scan repeatedly for one SSID — a single scan often misses a new BSS."""
        for attempt in range(retries):
            hits = [r for r in self.scan() if r.ssid == ssid]
            if hits:
                return hits
            if attempt < retries - 1:
                time.sleep(3)
        return []

    def ping(self, target: str, count: int = 10, timeout: int = 30) -> PingResult:
        """
        Ping *target* from the wireless interface.

        Binds to the interface's **source address**, not its device name.
        ``ping -I wlan0`` uses SO_BINDTODEVICE, and the source address is chosen
        after the routing decision — so the ``from <wlan-ip> lookup 200`` rule
        that carries the wireless default route never matches, the lookup falls
        through to the main table which deliberately has no wireless default,
        and every ping fails with "No route to host" on a link that works
        perfectly. Binding by source address matches the rule.
        """
        source = self.current_ip() or self.iface
        res = self.ssh.run(
            f"ping -c {count} -W 2 -I {source} {shlex.quote(target)}",
            timeout=timeout,
        )
        return _parse_ping(res.stdout)

    def diagnose_path(self, host: str = "google.com") -> str:
        """
        Work out *why* the internet is unreachable, so a failure is actionable.

        "cannot reach google.com" has at least four causes that need different
        fixes: no default route, a gateway that does not answer, no forwarding
        or NAT past the gateway, and working routing with broken DNS. This walks
        outward — gateway, then a public IP, then the name — and reports the
        first hop that fails.
        """
        lines: list[str] = []
        route = self.ssh.run(f"ip route show dev {self.iface}").stdout.strip()
        lines.append(f"routes on {self.iface}:\n{route or '  (none)'}")

        if not self.current_ip():
            lines.append(
                "no address at all — the client associated but DHCP never answered.\n"
                "If the SSID is on a tagged VLAN, the usual cause is the AP's switch\n"
                "port not trunking that VLAN tagged. Confirm from the AP itself with:\n"
                "  udhcpc -i up<N>v<vlan>   (its own VLAN interface on the bridge)\n"
                "A client on an access port for the same VLAN proves nothing — that\n"
                "path is untagged and does not exercise the trunk."
            )
            return "\n".join(lines)

        gw = ""
        for line in route.splitlines():
            if line.startswith("default via"):
                gw = line.split()[2]
                break
        if not gw:
            # NAT mode: the AP is the gateway, derived from the client subnet.
            addr = self.ssh.run(
                f"ip -4 -o addr show {self.iface} | awk '{{print $4}}'"
            ).stdout.strip()
            if addr:
                lines.append(f"no default route via {self.iface}; address is {addr}")

        if gw:
            r = self.ping(gw, count=3)
            lines.append(f"gateway {gw}: {r.received}/{r.transmitted} replies")
            if not r.ok:
                lines.append("-> the gateway itself does not answer")
                return "\n".join(lines)

        r8 = self.ping("8.8.8.8", count=3)
        lines.append(f"8.8.8.8 (raw IP): {r8.received}/{r8.transmitted} replies")

        resolved = self.ssh.run(f"getent hosts {shlex.quote(host)}").stdout.strip()
        lines.append(f"DNS for {host}: {resolved or 'FAILED to resolve'}")

        if r8.ok and not resolved:
            lines.append("-> routing works, DNS is broken")
        elif not r8.ok and resolved:
            lines.append("-> DNS works, but packets are not being forwarded/NATed upstream")
        elif not r8.ok:
            lines.append("-> no upstream path at all past the gateway")
        return "\n".join(lines)

    def verify_internet(self, host: str = "google.com", count: int = 5,
                        timeout: int = 40) -> PingResult:
        """
        Prove the link carries real traffic by pinging *host* over the test
        interface.

        Association plus a DHCP lease only shows the client reached the AP.
        Reaching a name on the internet additionally exercises DNS, the AP's
        forwarding or NAT path, and the upstream route — which is what a user
        of the SSID actually cares about.

        Pinned to the wireless interface with ``-I`` so a working ethernet path
        cannot make a broken wireless one look healthy.
        """
        # Resolve first, so a DNS failure is distinguishable from no route.
        resolved = self.ssh.run(
            f"getent hosts {shlex.quote(host)} | head -1", timeout=20
        ).stdout.strip()
        result = self.ping(host, count=count, timeout=timeout)
        if not result.ok and not resolved:
            log.warning("%s did not resolve from the station — DNS may be the fault, "
                        "not connectivity", host)
        return result

    def iperf3(
        self,
        server: str,
        *,
        direction: str = "downstream",
        protocol: str = "tcp",
        duration_s: int = 10,
        target_mbps: float | None = None,
        port: int = 5201,
    ) -> ThroughputResult:
        """
        Run iperf3 against *server*.

        ``downstream`` means traffic toward the station, which iperf3 expresses
        as reverse mode.
        """
        import json as _json

        flags = [f"-c {shlex.quote(server)}", f"-p {port}", f"-t {duration_s}", "-J"]
        if direction == "downstream":
            flags.append("-R")
        if protocol == "udp":
            flags.append("-u")
            flags.append(f"-b {target_mbps or 100}M")
        elif target_mbps:
            flags.append(f"-b {target_mbps}M")

        res = self.ssh.run(
            f"iperf3 {' '.join(flags)}", timeout=duration_s + 45
        )
        if not res.stdout.strip():
            raise StationError(
                f"iperf3 produced no output against {server}: {res.stderr.strip()}"
            )
        try:
            data = _json.loads(res.stdout)
        except ValueError as exc:
            raise StationError(f"iperf3 output was not JSON: {res.stdout[:200]}") from exc

        if "error" in data:
            raise StationError(f"iperf3 error: {data['error']}")

        end = data.get("end", {})
        if protocol == "udp":
            summary = end.get("sum", {})
            bps = summary.get("bits_per_second", 0)
            retrans = None
        else:
            key = "sum_received" if direction == "downstream" else "sum_sent"
            summary = end.get(key, {})
            bps = summary.get("bits_per_second", 0)
            retrans = end.get("sum_sent", {}).get("retransmits")

        return ThroughputResult(
            mbps=bps / 1e6,
            direction=direction,
            protocol=protocol,
            duration_s=duration_s,
            retransmits=retrans,
            raw=data,
        )

    def http_get(self, url: str, *, timeout: int = 15) -> tuple[int, str]:
        """Fetch a URL from the station — used to prove captive portal redirects."""
        res = self.ssh.run(
            f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
            f"--interface {self.iface} --max-time {timeout} {shlex.quote(url)}",
            timeout=timeout + 10,
        )
        parts = res.stdout.strip().split(None, 1)
        code = int(parts[0]) if parts and parts[0].isdigit() else 0
        return code, (parts[1] if len(parts) > 1 else "")

    def teardown(self) -> None:
        try:
            self.disconnect()
            self.release_to_networkmanager()
        except SSHError as exc:
            log.warning("Station teardown incomplete: %s", exc)
        finally:
            self.ssh.close()


# ── Output parsers ───────────────────────────────────────────────────────────

def _parse_iw_scan(raw: str) -> list[ScanResult]:
    results: list[ScanResult] = []
    bssid = ""
    ssid = ""
    freq = 0
    signal = 0.0
    flags: list[str] = []

    def flush() -> None:
        if bssid and ssid:
            results.append(
                ScanResult(ssid=ssid, bssid=bssid, freq_mhz=freq,
                           signal_dbm=signal, flags=",".join(flags))
            )

    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            flush()
            bssid = stripped.split()[1].split("(")[0]
            ssid, freq, signal, flags = "", 0, 0.0, []
        elif stripped.startswith("SSID:"):
            ssid = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("freq:"):
            try:
                freq = int(float(stripped.split(":", 1)[1].strip()))
            except ValueError:
                freq = 0
        elif stripped.startswith("signal:"):
            try:
                signal = float(stripped.split(":", 1)[1].strip().split()[0])
            except (ValueError, IndexError):
                signal = 0.0
        elif stripped.startswith("RSN:") or stripped.startswith("WPA:"):
            flags.append(stripped.split(":", 1)[0])
    flush()
    return results


def _parse_ping(raw: str) -> PingResult:
    result = PingResult()
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", raw)
    if m:
        result.transmitted = int(m.group(1))
        result.received = int(m.group(2))
        if result.transmitted:
            result.loss_pct = 100.0 * (1 - result.received / result.transmitted)
    m = re.search(r"= [\d.]+/([\d.]+)/", raw)
    if m:
        result.rtt_avg_ms = float(m.group(1))
    return result
