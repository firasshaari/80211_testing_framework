"""
Chipset classification table.
Add new chipsets here — no other file needs changing.
"""
from __future__ import annotations
from dataclasses import dataclass
from framework.capability.models import RadioType


@dataclass(frozen=True)
class RadioProfile:
    type: RadioType
    max_stations: int
    wifi_gen: int


CHIPSET_PROFILES: dict[str, RadioProfile] = {
    # ── Multi-STA radios ─────────────────────────────────────────────────────
    "MT7915": RadioProfile(type=RadioType.MULTI_STA,        max_stations=19, wifi_gen=6),
    "MT7996": RadioProfile(type=RadioType.MULTI_STA,        max_stations=19, wifi_gen=7),

    # ── 1:1 high-throughput radios ────────────────────────────────────────────
    "BE200":  RadioProfile(type=RadioType.SINGLE_STA_WIFI7, max_stations=1,  wifi_gen=7),

    # ── Generic single-STA ────────────────────────────────────────────────────
    "AX210":  RadioProfile(type=RadioType.GENERIC,          max_stations=1,  wifi_gen=6),
    "AX200":  RadioProfile(type=RadioType.GENERIC,          max_stations=1,  wifi_gen=6),
    "AX411":  RadioProfile(type=RadioType.GENERIC,          max_stations=1,  wifi_gen=6),
}

DEFAULT_PROFILE = RadioProfile(type=RadioType.GENERIC, max_stations=1, wifi_gen=5)


def classify(chipset_string: str) -> RadioProfile:
    """
    Match a chipset string (from LANforge or manual override) against the table.
    Case-insensitive prefix match — e.g. "MT7915 2x2" → MT7915 profile.
    Falls back to DEFAULT_PROFILE if no match.
    """
    upper = chipset_string.upper()
    for key, profile in CHIPSET_PROFILES.items():
        if key in upper:
            return profile
    return DEFAULT_PROFILE
