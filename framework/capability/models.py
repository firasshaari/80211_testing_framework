"""
Capability models — hardware inventory and testbed capability representation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


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
    has_infra: bool    = False

    # Radio inventory (populated by LANforge probe)
    radios: list[RadioInfo] = field(default_factory=list)

    # Infrastructure flags
    has_radius: bool    = False
    has_vlan_infra: bool = False

    # Derived — computed in __post_init__
    has_multi_sta_radio: bool  = field(init=False, default=False)
    has_wifi7_radio: bool      = field(init=False, default=False)
    has_sixghz_radio: bool     = field(init=False, default=False)
    total_sta_capacity: int    = field(init=False, default=0)
    best_engine: str           = field(init=False, default="none")

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
