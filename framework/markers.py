"""
Capability requirement markers.
Test authors import these — no direct pytest knowledge needed.
"""
import pytest

# ── Traffic engine ────────────────────────────────────────────────────────────
requires_lanforge       = pytest.mark.requires_lanforge
requires_rpi5           = pytest.mark.requires_rpi5
requires_two_endpoints  = pytest.mark.requires_two_endpoints

# ── Radio type ────────────────────────────────────────────────────────────────
requires_multi_sta      = pytest.mark.requires_multi_sta
requires_wifi7          = pytest.mark.requires_wifi7
requires_sixghz         = pytest.mark.requires_sixghz


def requires_min_stations(n: int):
    """Skip if total testbed STA capacity is less than n."""
    return pytest.mark.requires_min_stations(n)


# ── Infrastructure ────────────────────────────────────────────────────────────
requires_radius         = pytest.mark.requires_radius
requires_vlan           = pytest.mark.requires_vlan
