"""
Fluent builder for uCentral JSON AP configurations.
"""
from __future__ import annotations
from copy import deepcopy

_SECURITY_MAP = {
    "open":               "none",
    "wpa2":               "psk2",
    "psk2":               "psk2",
    "wpa3":               "sae",
    "sae":                "sae",
    "wpa3_personal_mixed": "sae-mixed",
    "sae-mixed":          "sae-mixed",
    "wpa2_enterprise":    "wpa2",
    "wpa3_enterprise":    "wpa3",
}

_BASE = {
    "uuid": 1,
    "radios": [],
    "interfaces": [
        {
            "name": "WAN",
            "role": "upstream",
            "services": ["ssh", "lldp", "dhcp-snooping"],
            "ethernet": [{"select-ports": ["WAN*"]}],
            "ipv4": {"addressing": "dynamic"},
            "ssids": [],
        },
        {
            "name": "LAN",
            "role": "downstream",
            "services": ["ssh", "lldp", "dhcp-snooping"],
            "ethernet": [{"select-ports": ["LAN*"]}],
            "ipv4": {
                "addressing": "static",
                "subnet": "192.168.1.1/16",
                "dhcp": {"lease-first": 10, "lease-count": 10000, "lease-time": "6h"},
            },
        },
    ],
    "metrics": {
        "statistics": {"interval": 60, "types": ["ssids", "lldp", "clients"]},
        "health": {"interval": 120},
        "wifi-frames": {"filters": ["probe", "auth", "assoc", "disassoc", "deauth",
                                     "local-deauth", "inactive-deauth", "key-mismatch",
                                     "beacon-report", "radar-detected"]},
        "dhcp-snooping": {"filters": ["ack", "discover", "offer", "request",
                                       "solicit", "reply", "renew"]},
    },
    "services": {
        "lldp": {"describe": "80211Networks", "location": "Lab"},
        "ssh":  {"port": 22},
    },
}


class ConfigBuilder:

    def __init__(self) -> None:
        self._config = deepcopy(_BASE)

    def mode(self, mode: str) -> "ConfigBuilder":
        """Set the AP operating mode: BRIDGE | NAT | VLAN."""
        self._mode = mode
        return self

    def radio(self, band: str, channel: int | str = "auto",
              channel_mode: str = "HE", channel_width: int = 80) -> "ConfigBuilder":
        """Add a radio definition."""
        entry: dict = {
            "band": band,
            "country": "US",
            "channel-mode": channel_mode,
            "channel": channel,
        }
        if band != "2G":
            entry["channel-width"] = channel_width
            if band == "5G":
                entry["allow-dfs"] = False
        self._config["radios"].append(entry)
        return self

    def ssid(
        self,
        name: str,
        band: str,
        security: str,
        password: str = "",
        downstream_rate_kbps: int | None = None,
        upstream_rate_kbps: int | None = None,
        vlan_id: int | None = None,
        ieee80211w: str = "optional",
    ) -> "ConfigBuilder":
        """Add an SSID to the WAN upstream interface."""
        proto = _SECURITY_MAP.get(security.lower(), security)

        ssid_entry: dict = {
            "name": name,
            "bss-mode": "ap",
            "wifi-bands": [band],
            "services": ["wifi-frames"],
        }

        if proto == "none":
            ssid_entry["encryption"] = {"proto": "none"}
        else:
            ssid_entry["encryption"] = {
                "proto": proto,
                "key": password,
                "ieee80211w": ieee80211w,
            }

        if downstream_rate_kbps or upstream_rate_kbps:
            ssid_entry["rate-limit"] = {}
            if downstream_rate_kbps:
                ssid_entry["rate-limit"]["egress-rate"]  = downstream_rate_kbps
            if upstream_rate_kbps:
                ssid_entry["rate-limit"]["ingress-rate"] = upstream_rate_kbps

        if vlan_id:
            ssid_entry["vlan-id"] = vlan_id

        # Attach to WAN interface
        wan = next(i for i in self._config["interfaces"] if i["name"] == "WAN")
        wan["ssids"].append(ssid_entry)
        return self

    def build(self) -> dict:
        return deepcopy(self._config)
