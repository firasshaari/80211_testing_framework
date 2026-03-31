"""
Capability models — hardware inventory and testbed capability representation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from framework.config import VLANEntry, StaticRadiusServer


class RadioType(Enum):
    MULTI_STA        = "multi_sta"         # MT7915, MT7996 — up to 19 STAs per radio
    SINGLE_STA_WIFI7 = "single_sta_wifi7"  # BE200 — 1 STA per radio, WiFi 7
    GENERIC          = "generic"           # Everything else — 1 STA per radio


@dataclass
class RadioInfo:
    name: str                        # e.g. "1.1.wiphy0"
    chipset: str                     # e.g. "MT7915", "BE200", "unknown"
    radio_type: RadioType
    max_stations: int
    wifi_gen: int                    # 5, 6, 7
    supported_bands: list[str] = field(default_factory=list)  # ["2.4GHz","5GHz","6GHz"]


@dataclass
class TestbedCapabilities:
    # Presence flags
    has_lanforge: bool = False
    has_rpi5: bool     = False
    has_infra: bool    = False        # managed infra box (SSH + dnsmasq/freeradius)

    # Radio inventory (populated by LANforge probe)
    radios: list[RadioInfo] = field(default_factory=list)

    # Managed infrastructure flags (set when infra box is reachable and services are active)
    has_radius: bool     = False
    has_vlan_infra: bool = False

    # Pre-configured (static) network resources declared in testbed.yaml network: block
    # These are available even when there is no managed infra box.
    vlans: list["VLANEntry"]                   = field(default_factory=list)
    static_radius: "StaticRadiusServer | None" = None

    # Derived — computed in __post_init__
    has_multi_sta_radio: bool  = field(init=False, default=False)
    has_wifi7_radio: bool      = field(init=False, default=False)
    has_sixghz_radio: bool     = field(init=False, default=False)
    total_sta_capacity: int    = field(init=False, default=0)
    best_engine: str           = field(init=False, default="none")

    # Derived presence flags that merge both managed and static sources
    radius_available: bool    = field(init=False, default=False)  # managed OR static
    vlans_available: bool     = field(init=False, default=False)  # managed OR static

    def __post_init__(self) -> None:
        self.has_multi_sta_radio  = any(r.radio_type == RadioType.MULTI_STA for r in self.radios)
        self.has_wifi7_radio      = any(r.radio_type == RadioType.SINGLE_STA_WIFI7 for r in self.radios)
        self.has_sixghz_radio     = any("6GHz" in r.supported_bands for r in self.radios)
        self.total_sta_capacity   = sum(r.max_stations for r in self.radios)

        if self.has_lanforge:
            self.best_engine = "lanforge"
        elif self.has_rpi5:
            self.best_engine = "rpi5"
        else:
            self.best_engine = "none"

        # Merge managed + static sources into unified "available" flags.
        # Tests that need RADIUS/VLANs can check these without caring whether
        # the resource is dynamically managed or pre-configured.
        self.radius_available = self.has_radius or (self.static_radius is not None)
        self.vlans_available  = self.has_vlan_infra or len(self.vlans) > 0

    # ── Convenience helpers ───────────────────────────────────────────────────

    def get_vlan(self, *, id: int | None = None, name: str | None = None) -> "VLANEntry":
        """
        Look up a pre-configured VLAN by tag ID or name.

        Raises ValueError if no match is found or no static VLANs are configured.
        """
        for v in self.vlans:
            if id is not None and v.id == id:
                return v
            if name is not None and v.name == name:
                return v
        criteria = f"id={id}" if id is not None else f"name={name!r}"
        raise ValueError(f"No pre-configured VLAN with {criteria}")
