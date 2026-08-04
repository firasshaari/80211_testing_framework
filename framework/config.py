"""
Pydantic models for ``testbed.yaml`` — validated at session start.

The minimum viable testbed is two boxes: the AP under test and one RPi5
station. Everything under ``external:`` describes lab resources that only some
examples need; leaving a block out makes the tests requiring it skip with a
readable reason rather than fail.

``${ENV_VAR}`` is expanded in string fields so credentials can stay out of the
file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator


def _expand_env(value: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), str(value))


class _EnvExpanding(BaseModel):
    """Base that expands ${ENV} references in every string field."""

    @field_validator("*", mode="before")
    @classmethod
    def _expand(cls, v):
        return _expand_env(v) if isinstance(v, str) else v


class TestbedMeta(BaseModel):
    name: str = "openwifi-regression"
    description: str = ""
    operator: str = ""


class APSettings(_EnvExpanding):
    """The device under test."""

    host: str
    user: str = "root"
    password: str = "openwifi"
    port: int = 22
    key_path: Optional[str] = None
    # Leave the agent running only when deliberately testing cloud-managed mode.
    disable_ucentral_agent: bool = True
    # How to hand the AP back when the session ends:
    #   factory_reset  jffs2reset -y && reboot — clean baseline, re-onboards
    #                  to the controller by itself (default, recommended)
    #   restore_agent  re-enable the uCentral agent, leaving the last applied
    #                  config committed in /etc/config
    #   none           leave the AP exactly as the tests left it
    cleanup: str = "factory_reset"

    @field_validator("cleanup")
    @classmethod
    def known_cleanup(cls, v):
        allowed = {"factory_reset", "restore_agent", "none"}
        if v not in allowed:
            raise ValueError(f"ap.cleanup must be one of {sorted(allowed)}, got {v!r}")
        return v


class StationSettings(_EnvExpanding):
    """The RPi5 + BE200 acting as the client."""

    host: str
    user: str = "pi"
    password: str
    root_password: Optional[str] = None
    # wlan0 is the Pi's onboard radio; the BE200 normally lands on wlan1.
    iface: str = "wlan1"
    country: str = "US"
    port: int = 22

    @field_validator("root_password")
    @classmethod
    def default_root_to_login_password(cls, v, info):
        return v or info.data.get("password")


class RadiusSettings(_EnvExpanding):
    host: str
    secret: str
    auth_port: int = 1812
    acct_port: int = 1813
    # A known-good account the station can authenticate with.
    identity: str = "testuser"
    password: str = "testpass"
    eap_method: str = "PEAP"
    # VLAN this server is configured to return for `identity` via
    # Tunnel-Private-Group-Id. Required to test dynamic VLAN assignment: without
    # it there is no way to know which VLAN a successful auth should land in,
    # so that test skips rather than asserting nothing.
    dynamic_vlan: Optional[int] = None


class LocalRadiusUser(_EnvExpanding):
    """One account served by the AP's own EAP server (the eap_local example)."""

    username: str
    password: str
    # VLAN the AP should assign this user. The upstream eap_local example
    # carries no VLAN at all, so dynamic assignment cannot be tested unless
    # this is supplied.
    vlan_id: Optional[int] = None


class VLANSettings(BaseModel):
    """VLANs the upstream switch already trunks to the AP."""

    ids: list[int] = Field(default_factory=list)
    # Optional per-VLAN gateway, used as a ping target to prove segmentation.
    gateways: dict[int, str] = Field(default_factory=dict)


class ExternalResources(BaseModel):
    """
    Optional lab resources. Each present block satisfies one requirement in
    :mod:`framework.examples.catalog`; absent blocks turn into test skips.
    """

    radius: Optional[RadiusSettings] = None
    # Accounts to inject into the AP's own EAP server for local-RADIUS tests.
    local_radius_users: list[LocalRadiusUser] = Field(default_factory=list)
    vlan: Optional[VLANSettings] = None
    # Host running `iperf3 -s`, reachable from the station's subnet.
    iperf_server: Optional[str] = None
    # Second AP or tunnel endpoint for mesh/WDS/GRE/VXLAN examples.
    peer_ap_host: Optional[str] = None
    dhcp_server: Optional[str] = None
    captive_backend: Optional[str] = None
    # Hardware the DUT itself may or may not have.
    has_switch_hw: bool = False
    has_gps_hw: bool = False
    has_wwan_hw: bool = False
    # Set false on an air-gapped bench so NTP/online-check/AFC tests skip.
    has_internet: bool = True


class NormalizationSettings(BaseModel):
    """
    How upstream examples are cleaned before they reach the AP.

    Defaults target a US bench that wants deterministic results — see
    :mod:`framework.examples.normalize` for why each one matters.
    """

    country: str = "US"
    avoid_dfs: bool = True
    force_2g_width: Optional[int] = 20
    # Fixed channel per band for the whole sweep, so a result on a given band
    # means the same thing every run. All are non-DFS; 6 GHz 37 is a PSC.
    channel_plan: dict[str, int] = Field(
        default_factory=lambda: {"2G": 1, "5G": 36, "6G": 37}
    )
    # Adds "strict": true so the renderer rejects instead of silently clamping.
    strict_apply: bool = True
    # Move bridged SSIDs onto the first VLAN in external.vlan.ids instead of
    # leaving them on the untagged upstream. Keeps test clients off the
    # management subnet — a bridged SSID sharing that subnet is what previously
    # locked the framework out of its own station. Needs external.vlan.ids.
    bridge_vlan_from_pool: bool = True
    # SSH idle timeout forced into every applied config, in seconds. 0 disables
    # the timeout (schema default is 60, maximum 600). Set to null to omit the
    # field. 'ssh' is always added to the upstream interface regardless — that
    # is what keeps the AP reachable mid-run.
    ssh_idle_timeout: Optional[int] = 0


class Settings(BaseModel):
    association_timeout: int = 45
    apply_timeout: int = 180
    # Commit-confirmed safety net. Before each apply the AP is told to
    # factory-reset itself after this many seconds unless the framework
    # cancels it, which it does as soon as management access is proven still
    # alive. Protects against a config that cuts the AP off the network. Must
    # comfortably exceed apply_timeout.
    rollback_seconds: int = 300
    wireless_settle_timeout: int = 90
    # How long a configured SSID gets to start beaconing. `wireless_settle`
    # only says the radios stopped reporting "pending"; hostapd still has to
    # bring each BSS up after that, and how long it takes is a property of the
    # AP, not of the test — a MediaTek MT7621 occasionally needs more than the
    # 60s this used to hard-code, and reported a healthy SSID as missing.
    ssid_up_timeout: int = 120
    traffic_duration_s: int = 10
    ping_count: int = 10
    report_dir: str = "reports"
    allure_results_dir: str = "allure-results"
    log_level: str = "INFO"
    # Passphrase used for SSIDs the framework substitutes a known key into.
    default_passphrase: str = "12345678"


class TestbedConfig(BaseModel):
    testbed: TestbedMeta = TestbedMeta()
    ap: APSettings
    station: StationSettings
    external: ExternalResources = ExternalResources()
    normalization: NormalizationSettings = NormalizationSettings()
    settings: Settings = Settings()


def load_testbed_config(path: str | Path) -> TestbedConfig:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Testbed config not found: {p}\n"
            f"Copy config/profiles/example_minimal.yaml to config/testbed.yaml "
            f"and fill in your AP and RPi5 details."
        )
    data = yaml.safe_load(p.read_text()) or {}
    return TestbedConfig(**data)
