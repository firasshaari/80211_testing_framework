"""
Pydantic models for testbed.yaml — validated at session start.
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


class Settings(BaseModel):
    association_timeout: int  = 30
    traffic_duration_s: int   = 30
    allure_results_dir: str   = "allure-results"
    log_level: str            = "INFO"


class TestbedConfig(BaseModel):
    testbed:    TestbedMeta
    ap:         APConfig
    controller: ControllerConfig
    lanforge:   Optional[LANforgeConfig] = None
    rpi5:       Optional[RPi5Config]     = None
    infra:      Optional[InfraConfig]    = None
    settings:   Settings                 = Settings()


def load_testbed_config(path: str) -> TestbedConfig:
    data = yaml.safe_load(Path(path).read_text())
    return TestbedConfig(**data)
