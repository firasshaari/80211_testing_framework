"""
Read structure back out of a uCentral config.

Tests derive what to associate to from the config they just applied rather than
from hardcoded strings, so an example that changes upstream does not silently
start testing nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Protos the RPi5 can associate to unaided. Enterprise and portal-backed modes
# need credentials or a backend supplied by the test.
STATION_READY_PROTOS = {
    "none", "open", "owe", "owe-transition",
    "psk", "psk2", "psk-mixed", "psk2-mixed", "sae", "sae-mixed",
}
ENTERPRISE_PROTOS = {"wpa", "wpa-mixed", "wpa2", "wpa3", "wpa3-mixed",
                     "psk2-radius", "mpsk-radius", "wpa2-radius"}


@dataclass
class SSIDSpec:
    name: str
    proto: str = "none"
    key: str | None = None
    bands: list[str] = field(default_factory=list)
    interface: str = ""
    role: str = ""              # upstream (bridged) | downstream (NATed)
    bss_mode: str = "ap"
    vlan_id: int | None = None
    has_radius: bool = False
    has_captive: bool = False
    has_multi_psk: bool = False

    @property
    def bridged(self) -> bool:
        return self.role == "upstream"

    @property
    def nated(self) -> bool:
        return self.role == "downstream"

    @property
    def station_ready(self) -> bool:
        """True when the station can associate with just the config's own key."""
        if self.has_radius or self.proto in ENTERPRISE_PROTOS:
            return False
        if self.proto in ("none", "open", "owe", "owe-transition"):
            return True
        return self.proto in STATION_READY_PROTOS and bool(self.key)

    @property
    def enterprise(self) -> bool:
        return self.proto in ENTERPRISE_PROTOS or self.has_radius


@dataclass
class InterfaceSpec:
    name: str
    role: str = ""
    addressing: str = ""
    subnet: str | None = None
    vlan_id: int | None = None
    has_dhcp_server: bool = False
    ssids: list[SSIDSpec] = field(default_factory=list)


def iter_interfaces(config: dict) -> list[InterfaceSpec]:
    specs: list[InterfaceSpec] = []
    for iface in config.get("interfaces") or []:
        ipv4 = iface.get("ipv4") or {}
        vlan = iface.get("vlan") or {}
        spec = InterfaceSpec(
            name=iface.get("name", ""),
            role=iface.get("role", ""),
            addressing=ipv4.get("addressing", ""),
            subnet=ipv4.get("subnet"),
            vlan_id=vlan.get("id"),
            has_dhcp_server=bool(ipv4.get("dhcp")),
        )
        for ssid in iface.get("ssids") or []:
            spec.ssids.append(_ssid_spec(ssid, spec))
        specs.append(spec)
    return specs


def _ssid_spec(ssid: dict, iface: InterfaceSpec) -> SSIDSpec:
    enc = ssid.get("encryption") or {}
    return SSIDSpec(
        name=ssid.get("name", ""),
        proto=(enc.get("proto") or "none").lower(),
        key=enc.get("key"),
        bands=list(ssid.get("wifi-bands") or []),
        interface=iface.name,
        role=iface.role,
        bss_mode=ssid.get("bss-mode", "ap"),
        vlan_id=iface.vlan_id,
        has_radius=bool(ssid.get("radius")),
        has_captive=bool(ssid.get("captive")),
        has_multi_psk=bool(ssid.get("multi-psk")),
    )


def iter_ssids(config: dict) -> list[SSIDSpec]:
    """Every SSID in the config, in declaration order."""
    return [s for iface in iter_interfaces(config) for s in iface.ssids]


def station_ready_ssids(config: dict, *, bands: frozenset[str] | None = None) -> list[SSIDSpec]:
    """
    SSIDs the station can associate to using only what the config declares.

    When *bands* is given, SSIDs whose bands are all unusable on this bench are
    dropped — associating to a 6 GHz-only SSID from a 5 GHz-capped station just
    produces a confusing timeout.
    """
    out = []
    for ssid in iter_ssids(config):
        if not ssid.station_ready or ssid.bss_mode != "ap":
            continue
        if bands is not None and ssid.bands and not (set(ssid.bands) & set(bands)):
            continue
        out.append(ssid)
    return out


def downstream_subnets(config: dict) -> list[str]:
    """Subnets the AP serves itself — a client in one of these is being NATed."""
    return [
        iface.subnet
        for iface in iter_interfaces(config)
        if iface.role == "downstream" and iface.subnet
    ]


def ip_in_subnet(ip: str, cidr: str) -> bool:
    """True if *ip* falls inside *cidr*. Returns False on malformed input."""
    import ipaddress

    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
