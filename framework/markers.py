"""
Markers for selecting subsets of the regression sweep.

Feature-area markers mirror :class:`framework.examples.catalog.Area`, so
``pytest -m security`` and ``catalog.by_area(Area.SECURITY)`` always agree.

Hardware requirements are *not* markers. They are checked against the probed
capabilities at runtime, which lets a skip say "testbed lacks a RADIUS server"
instead of "did not match marker expression".
"""
from __future__ import annotations

import pytest

from framework.examples.catalog import Area

security = pytest.mark.security
network_mode = pytest.mark.network_mode
rate_limit = pytest.mark.rate_limit
qos = pytest.mark.qos
roaming = pytest.mark.roaming
captive = pytest.mark.captive
vlan = pytest.mark.vlan
tunnel = pytest.mark.tunnel
services = pytest.mark.services
telemetry = pytest.mark.telemetry
switch = pytest.mark.switch
wifi_gen = pytest.mark.wifi_gen
wwan = pytest.mark.wwan

regression = pytest.mark.regression
config_only = pytest.mark.config_only


def for_area(area: Area):
    """The marker matching a catalog area — used by parametrized suites."""
    return getattr(pytest.mark, area.value)
