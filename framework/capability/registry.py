"""
CapabilityRegistry — probes the bench once per session.

Probing is deliberately cheap and non-destructive: it reads identity and radio
capability from both ends and checks liveness of anything declared under
``external:``. Declaring a resource in the config is treated as intent; the
probe decides whether it is actually usable, so a stale entry produces a skip
rather than a confusing mid-test failure.
"""
from __future__ import annotations

import logging
import re

from framework.capability.models import RadioCapability, TestbedCapabilities

log = logging.getLogger(__name__)

# Frequencies that identify a band in `iw phy` output.
_BAND_MARKERS = (("2G", 2400, 2500), ("5G", 4900, 5895), ("6G", 5925, 7125))


class CapabilityRegistry:
    def __init__(self, config, ap_client=None, station=None) -> None:
        self._config = config
        self._ap = ap_client
        self._station = station

    def probe(self) -> TestbedCapabilities:
        caps = TestbedCapabilities()

        self._probe_ap(caps)
        self._probe_station(caps)
        self._probe_external(caps)

        log.info(
            "Capabilities — ap=%s sta=%s usable_bands=%s wifi7=%s radius=%s vlan=%s",
            caps.ap_reachable, caps.station_reachable,
            sorted(caps.usable_bands) or "none", caps.has_wifi7,
            caps.has_radius, caps.has_vlan,
        )
        return caps

    # ── AP ───────────────────────────────────────────────────────────────────

    def _probe_ap(self, caps: TestbedCapabilities) -> None:
        if self._ap is None:
            caps.notes.append("No AP client constructed — every test will skip.")
            return
        if not self._ap.ssh.is_reachable():
            caps.notes.append(f"AP {self._ap.host} did not answer SSH.")
            return

        caps.ap_reachable = True
        try:
            info = self._ap.device_info()
        except Exception as exc:
            caps.notes.append(f"AP identity probe failed: {exc}")
            return

        for radio in info.radios:
            bands = frozenset(_normalize_band(b) for b in radio.get("bands", []))
            caps.ap_radios.append(
                RadioCapability(
                    name=radio.get("phy", "?"),
                    bands=bands - {""},
                    wifi_gen=self._ap_radio_generation(radio),
                    owner="ap",
                )
            )
        if not caps.ap_radios:
            caps.notes.append(
                "AP reported no radios in capabilities.json — band-specific tests will skip."
            )

    def _ap_radio_generation(self, radio: dict) -> int:
        """Infer the Wi-Fi generation from the capability keys the AP advertises."""
        keys = " ".join(radio.keys()).lower() + " " + str(radio).lower()
        if "eht" in keys:
            return 7
        if "he_" in keys or "he_capa" in keys or "hemac" in keys:
            return 6
        if "vht" in keys:
            return 5
        return 0

    # ── Station ──────────────────────────────────────────────────────────────

    def _probe_station(self, caps: TestbedCapabilities) -> None:
        if self._station is None:
            caps.notes.append("No station configured — association tests will skip.")
            return
        if not self._station.ssh.is_reachable():
            caps.notes.append(f"Station {self._station.host} did not answer SSH.")
            return

        caps.station_reachable = True
        iface = self._station.iface
        if not self._station.ssh.run(f"test -d /sys/class/net/{iface}").ok:
            caps.station_reachable = False
            available = self._station.list_interfaces()
            caps.notes.append(
                f"Station has no interface {iface!r} (found: {', '.join(available)}). "
                f"Set station.iface in testbed.yaml to the BE200's interface."
            )
            return

        phy = self._station_phy(iface)
        info = self._station.ssh.run(f"iw phy {phy} info", sudo=True).stdout if phy else ""
        bands, gen = _parse_iw_phy(info)
        caps.station_radios.append(
            RadioCapability(name=phy or iface, bands=bands, wifi_gen=gen, owner="station")
        )
        if "6G" not in bands:
            caps.notes.append(
                "Station reports no 6 GHz channels. On a BE200 this is usually the "
                "regulatory domain — check 'iw reg get' and the country setting."
            )

    def _station_phy(self, iface: str) -> str:
        out = self._station.ssh.run(
            f"cat /sys/class/net/{iface}/phy80211/name"
        ).stdout.strip()
        return out or ""

    # ── External resources ───────────────────────────────────────────────────

    def _probe_external(self, caps: TestbedCapabilities) -> None:
        ext = self._config.external

        caps.has_switch_hw = ext.has_switch_hw
        caps.has_gps_hw = ext.has_gps_hw
        caps.has_wwan_hw = ext.has_wwan_hw
        caps.has_vlan = bool(ext.vlan and ext.vlan.ids)
        caps.has_captive_backend = bool(ext.captive_backend)
        caps.has_dhcp_server = bool(ext.dhcp_server)

        if ext.radius:
            caps.has_radius = self._reachable(ext.radius.host)
            if not caps.has_radius:
                caps.notes.append(
                    f"RADIUS host {ext.radius.host} is configured but not pingable."
                )
        if ext.peer_ap_host:
            caps.has_peer_ap = self._reachable(ext.peer_ap_host)
            if not caps.has_peer_ap:
                caps.notes.append(f"Peer AP {ext.peer_ap_host} is configured but unreachable.")
        if ext.iperf_server:
            caps.has_iperf_server = self._iperf_listening(ext.iperf_server)
            if not caps.has_iperf_server:
                caps.notes.append(
                    f"No iperf3 server answering on {ext.iperf_server}:5201 — "
                    f"throughput assertions will be skipped."
                )
        if ext.has_internet:
            caps.has_internet = self._reachable("8.8.8.8")
            if not caps.has_internet:
                caps.notes.append("Internet declared available but 8.8.8.8 is unreachable.")

    def _reachable(self, host: str) -> bool:
        """Ping from the AP, since that is the vantage point that matters."""
        prober = self._ap or self._station
        if prober is None:
            return False
        try:
            return prober.ssh.run(f"ping -c 2 -W 2 {host}", timeout=20).ok
        except Exception:
            return False

    def _iperf_listening(self, host: str, port: int = 5201) -> bool:
        if self._station is None:
            return False
        try:
            # -z exits 0 when the port accepts a connection, without sending data.
            res = self._station.ssh.run(f"nc -z -w 3 {host} {port}", timeout=15)
            return res.ok
        except Exception:
            return False


def _normalize_band(band: str) -> str:
    """Map the several band spellings in the wild onto 2G / 5G / 6G."""
    b = str(band).strip().lower()
    if b in ("2g", "2.4g", "2.4ghz", "2ghz"):
        return "2G"
    if b in ("5g", "5ghz"):
        return "5G"
    if b in ("6g", "6ghz"):
        return "6G"
    return ""


def _parse_iw_phy(info: str) -> tuple[frozenset[str], int]:
    """Extract supported bands and Wi-Fi generation from `iw phy <phy> info`."""
    bands: set[str] = set()
    for match in re.finditer(r"^\s*\*\s*(\d{4})(?:\.\d+)? MHz", info, re.MULTILINE):
        freq = int(match.group(1))
        # A channel listed as disabled is not usable in the current regdomain.
        line_end = info[match.end(): match.end() + 60]
        if "disabled" in line_end:
            continue
        for name, low, high in _BAND_MARKERS:
            if low <= freq <= high:
                bands.add(name)

    upper = info.upper()
    if "EHT" in upper:
        gen = 7
    elif "HE " in upper or "HE_" in upper or "HE PHY" in upper:
        gen = 6
    elif "VHT" in upper:
        gen = 5
    else:
        gen = 0

    return frozenset(bands), gen
