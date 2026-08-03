"""
Capability model — what this bench can actually do.

A requirement in :mod:`framework.examples.catalog` is satisfied only when both
ends support it. 6 GHz is the clearest case: the AP having a 6 GHz radio is
useless if the BE200 is under a regulatory domain that forbids it, so the check
is an intersection, not a union.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from framework.examples.catalog import Example, Requirement


@dataclass
class RadioCapability:
    """One radio, on either end of the link."""

    name: str
    bands: frozenset[str] = frozenset()
    wifi_gen: int = 0          # 4, 5, 6, 7 — 0 when undetermined
    owner: str = "ap"          # "ap" or "station"


@dataclass
class TestbedCapabilities:
    """A snapshot taken once per session, before any test runs."""

    ap_reachable: bool = False
    station_reachable: bool = False

    ap_radios: list[RadioCapability] = field(default_factory=list)
    station_radios: list[RadioCapability] = field(default_factory=list)

    # External resources, from the `external:` config block plus liveness probes.
    has_radius: bool = False
    has_vlan: bool = False
    has_peer_ap: bool = False
    has_captive_backend: bool = False
    has_dhcp_server: bool = False
    has_iperf_server: bool = False
    has_switch_hw: bool = False
    has_gps_hw: bool = False
    has_wwan_hw: bool = False
    has_internet: bool = False

    # Notes shown in the report — why a probe concluded what it did.
    notes: list[str] = field(default_factory=list)

    # ── Derived ──────────────────────────────────────────────────────────────

    @property
    def ap_bands(self) -> frozenset[str]:
        if not self.ap_radios:
            return frozenset()
        return frozenset().union(*(r.bands for r in self.ap_radios))

    @property
    def station_bands(self) -> frozenset[str]:
        if not self.station_radios:
            return frozenset()
        return frozenset().union(*(r.bands for r in self.station_radios))

    @property
    def usable_bands(self) -> frozenset[str]:
        """Bands both ends can use — the only ones a link test can exercise."""
        return self.ap_bands & self.station_bands

    @property
    def has_sixghz(self) -> bool:
        return "6G" in self.usable_bands

    @property
    def has_wifi7(self) -> bool:
        ap7 = any(r.wifi_gen >= 7 for r in self.ap_radios)
        sta7 = any(r.wifi_gen >= 7 for r in self.station_radios)
        return ap7 and sta7

    @property
    def has_station(self) -> bool:
        return self.station_reachable

    # ── Requirement checking ─────────────────────────────────────────────────

    def satisfies(self, req: Requirement) -> bool:
        return {
            Requirement.STATION: self.has_station,
            Requirement.RADIUS: self.has_radius,
            Requirement.VLAN: self.has_vlan,
            Requirement.PEER_AP: self.has_peer_ap,
            Requirement.CAPTIVE_BACKEND: self.has_captive_backend,
            Requirement.SWITCH_HW: self.has_switch_hw,
            Requirement.GPS_HW: self.has_gps_hw,
            Requirement.WWAN_HW: self.has_wwan_hw,
            Requirement.DHCP_SERVER: self.has_dhcp_server,
            Requirement.INTERNET: self.has_internet,
            Requirement.SIXGHZ: self.has_sixghz,
            Requirement.WIFI7: self.has_wifi7,
        }[req]

    def unmet(self, example: Example) -> list[Requirement]:
        return [
            r for r in sorted(example.requires, key=lambda r: r.value)
            if not self.satisfies(r)
        ]

    def skip_reason(self, example: Example) -> str | None:
        """A sentence naming what the bench is missing, or None if runnable."""
        missing = self.unmet(example)
        if not missing:
            return None
        return f"testbed lacks {_describe(missing)}"

    # ── Reporting ────────────────────────────────────────────────────────────

    def as_rows(self) -> list[tuple[str, str]]:
        return [
            ("AP reachable", _yn(self.ap_reachable)),
            ("Station reachable", _yn(self.station_reachable)),
            ("AP bands", ", ".join(sorted(self.ap_bands)) or "none detected"),
            ("Station bands", ", ".join(sorted(self.station_bands)) or "none detected"),
            ("Usable bands", ", ".join(sorted(self.usable_bands)) or "none"),
            ("Wi-Fi 7 link", _yn(self.has_wifi7)),
            ("RADIUS", _yn(self.has_radius)),
            ("VLAN trunk", _yn(self.has_vlan)),
            ("Peer AP", _yn(self.has_peer_ap)),
            ("iperf3 server", _yn(self.has_iperf_server)),
            ("Internet", _yn(self.has_internet)),
        ]


_HUMAN = {
    Requirement.STATION: "a reachable RPi5 station",
    Requirement.RADIUS: "a RADIUS server",
    Requirement.VLAN: "a VLAN-trunked upstream switch",
    Requirement.PEER_AP: "a second AP or tunnel endpoint",
    Requirement.CAPTIVE_BACKEND: "an external captive-portal backend",
    Requirement.SWITCH_HW: "an AP with a managed switch fabric",
    Requirement.GPS_HW: "GPS hardware",
    Requirement.WWAN_HW: "a WWAN modem",
    Requirement.DHCP_SERVER: "an external DHCP server",
    Requirement.INTERNET: "internet reachability",
    Requirement.SIXGHZ: "6 GHz support on both AP and station",
    Requirement.WIFI7: "Wi-Fi 7 support on both AP and station",
}


def _describe(reqs: list[Requirement]) -> str:
    parts = [_HUMAN[r] for r in reqs]
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + f" and {parts[-1]}"


def _yn(value: bool) -> str:
    return "yes" if value else "no"
