"""
Pydantic models for testbed.yaml — validated at session start.

Network resources can be declared in two ways:

1. **Managed** (``infra:`` block present): the framework SSH-es into the
   infra box and creates/tears down VLANs, DHCP pools, RADIUS entries, etc.

2. **Pre-configured** (``network:`` block present): resources already exist
   on the network; the framework just reads their parameters and uses them.
   The ``infra:`` block is not required in this mode.

Both blocks may coexist — the framework merges them, with ``infra:`` used for
dynamic management and ``network:`` for static lookups.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, field_validator


def _expand_env(value: str) -> str:
    """Expand ${ENV_VAR} placeholders in string values."""
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), value)


class TestbedMeta(BaseModel):
    name: str
    description: str = ""


class APConfig(BaseModel):
    serial: str
    serial_port: Optional[str] = None


class ControllerConfig(BaseModel):
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False

    @field_validator("password", mode="before")
    @classmethod
    def expand_password(cls, v):
        return _expand_env(str(v))


class LANforgeConfig(BaseModel):
    host: str
    port: int = 8080
    radio_overrides: Optional[dict[str, str]] = None


class RPi5Host(BaseModel):
    host: str
    user: str
    key_path: str
    role: str          # "client" | "server"
    wifi_iface: str = "wlan0"


class RPi5Config(BaseModel):
    hosts: list[RPi5Host]


class InfraServices(BaseModel):
    dhcp: str = "dnsmasq"
    radius: str = "freeradius"


class InfraConfig(BaseModel):
    host: str
    user: str
    key_path: str
    parent_iface: str = "eth0"
    dnsmasq_conf_dir: str = "/etc/dnsmasq.d"
    freeradius_conf_dir: str = "/etc/freeradius/3.0"
    services: InfraServices = InfraServices()


# ── Pre-configured network resources ──────────────────────────────────────────

class VLANEntry(BaseModel):
    """Describes a VLAN that already exists on the network."""
    id: int                                  # 802.1Q tag
    name: str = ""                           # human label, e.g. "corp", "guest"
    subnet: str                              # CIDR, e.g. "192.168.10.0/24"
    gateway: str                             # default gateway IP
    dhcp_range: Optional[list[str]] = None  # [start, end] — purely informational
    dns: str = "8.8.8.8"
    interface: Optional[str] = None          # e.g. "eth0.10" on the infra/router box


class StaticRadiusServer(BaseModel):
    """Describes a RADIUS server that is already running and reachable."""
    host: str
    auth_port: int = 1812
    acct_port: int = 1813
    secret: str

    @field_validator("secret", mode="before")
    @classmethod
    def expand_secret(cls, v):
        return _expand_env(str(v))


class NetworkConfig(BaseModel):
    """
    Pre-configured network resources available to tests.

    When this section is present, tests can call
    ``testbed_config.network.get_vlan(id=10)`` (or iterate
    ``network.vlans``) instead of asking the framework to create VLANs
    dynamically.
    """
    vlans: list[VLANEntry] = []
    radius: Optional[StaticRadiusServer] = None
    management_subnet: Optional[str] = None   # subnet where AP mgmt lives

    # ── Convenience helpers ───────────────────────────────────────────────────

    def get_vlan(self, *, id: int | None = None, name: str | None = None) -> VLANEntry:
        """
        Look up a VLAN by tag ID or name.

        Raises ValueError if no match is found.
        """
        for v in self.vlans:
            if id is not None and v.id == id:
                return v
            if name is not None and v.name == name:
                return v
        criteria = f"id={id}" if id is not None else f"name={name!r}"
        raise ValueError(f"No pre-configured VLAN with {criteria}")

    def get_vlans_by_name(self, *names: str) -> list[VLANEntry]:
        """Return VLANs whose name is in *names*, preserving declaration order."""
        return [v for v in self.vlans if v.name in names]


# ── Settings ──────────────────────────────────────────────────────────────────

class Settings(BaseModel):
    association_timeout: int  = 30
    traffic_duration_s: int   = 30
    allure_results_dir: str   = "allure-results"
    log_level: str            = "INFO"


# ── Root config ───────────────────────────────────────────────────────────────

class TestbedConfig(BaseModel):
    testbed:    TestbedMeta
    ap:         APConfig
    controller: ControllerConfig
    lanforge:   Optional[LANforgeConfig] = None
    rpi5:       Optional[RPi5Config]     = None
    infra:      Optional[InfraConfig]    = None
    network:    Optional[NetworkConfig]  = None   # pre-configured resources
    settings:   Settings                 = Settings()


def load_testbed_config(path: str) -> TestbedConfig:
    data = yaml.safe_load(Path(path).read_text())
    return TestbedConfig(**data)
