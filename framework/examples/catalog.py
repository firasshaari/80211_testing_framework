"""
Catalog of the vendored uCentral examples.

Each example is classified by *feature area* (what it exercises) and by
*requirements* (what the lab must physically have for the test to mean
anything).  The capability layer turns unmet requirements into skips with a
readable reason, so a minimal bench — one AP plus one RPi5 — still runs the
whole subset it can legitimately run.

Classification comes from reading each config's actual content:

* An SSID on an ``upstream``-role interface is **bridged** to the WAN.
* An SSID on a ``downstream``-role interface sits behind the AP's own subnet
  and is therefore **NAT**ed.
* An example with no SSIDs at all is **config-only** — apply it and verify the
  AP accepted it; there is nothing for a station to associate to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Requirement(Enum):
    """Physical lab resources an example needs beyond the AP itself."""

    STATION = "station"              # an RPi5 + BE200 that can associate
    RADIUS = "radius"                # reachable FreeRADIUS / auth server
    VLAN = "vlan"                    # VLAN-aware upstream switch
    PEER_AP = "peer_ap"              # second AP or tunnel endpoint
    CAPTIVE_BACKEND = "captive_backend"   # external UAM / RADIUS portal
    SWITCH_HW = "switch_hw"          # AP with a managed switch fabric
    GPS_HW = "gps_hw"
    WWAN_HW = "wwan_hw"
    DHCP_SERVER = "dhcp_server"      # external DHCP server (relay tests)
    INTERNET = "internet"            # NTP / online-check / AFC reachability
    SIXGHZ = "sixghz"                # 6 GHz capable radio on AP and station
    WIFI7 = "wifi7"                  # 802.11be capable radio


class Area(Enum):
    """Feature area — also the pytest marker name and report section."""

    SECURITY = "security"
    NETWORK_MODE = "network_mode"
    RATE_LIMIT = "rate_limit"
    QOS = "qos"
    ROAMING = "roaming"
    CAPTIVE = "captive"
    VLAN = "vlan"
    TUNNEL = "tunnel"
    SERVICES = "services"
    TELEMETRY = "telemetry"
    SWITCH = "switch"
    WIFI_GEN = "wifi_gen"
    WWAN = "wwan"


class Mode(Enum):
    """How the SSIDs are attached to the network."""

    BRIDGE = "bridge"        # SSID on the upstream interface
    NAT = "nat"              # SSID behind the AP's downstream subnet
    MIXED = "mixed"          # both present in one config
    # No AP-mode BSS for a station to associate to — either the config declares
    # no SSIDs at all, or only mesh/WDS BSSes that need a peer radio. Verified
    # by applying and reading back committed state.
    CONFIG_ONLY = "config_only"


@dataclass(frozen=True)
class Example:
    name: str
    area: Area
    mode: Mode
    summary: str
    requires: frozenset[Requirement] = field(default_factory=frozenset)
    bands: frozenset[str] = field(default_factory=frozenset)
    # Encryption protos the config declares, for security-coverage reporting.
    protos: frozenset[str] = field(default_factory=frozenset)

    @property
    def needs_station(self) -> bool:
        return Requirement.STATION in self.requires

    @property
    def external_hw(self) -> frozenset[Requirement]:
        """Requirements beyond 'AP plus one station'."""
        return frozenset(self.requires) - {Requirement.STATION}

    @property
    def ap_only(self) -> bool:
        """True when a bare AP + one RPi5 bench can run this."""
        return not self.external_hw


def _e(name, area, mode, summary, requires=(), bands=(), protos=()) -> Example:
    return Example(
        name=name,
        area=area,
        mode=mode,
        summary=summary,
        requires=frozenset(requires),
        bands=frozenset(bands),
        protos=frozenset(protos),
    )


R = Requirement
A = Area
M = Mode

# ── The catalog ───────────────────────────────────────────────────────────────
# Ordered by area so the report reads sensibly.

EXAMPLES: tuple[Example, ...] = (
    # ── Security: the core regression surface ────────────────────────────────
    _e("crypto-psk", A.SECURITY, M.BRIDGE,
       "Six SSIDs covering open, psk, psk2, psk-mixed, sae and sae-mixed on one radio",
       [R.STATION], ["2G"],
       ["none", "psk", "psk2", "psk-mixed", "sae", "sae-mixed"]),
    _e("crypto-enterprise", A.SECURITY, M.BRIDGE,
       "WPA/WPA2/WPA3 Enterprise and mixed modes against RADIUS",
       [R.STATION, R.RADIUS], ["2G"],
       ["wpa", "wpa-mixed", "wpa2", "wpa3", "wpa3-mixed"]),
    _e("owe", A.SECURITY, M.MIXED, "Opportunistic Wireless Encryption (WPA3 open)",
       [R.STATION], ["5G"], ["owe", "psk2"]),
    _e("owe-transition", A.SECURITY, M.MIXED,
       "OWE transition mode — open and OWE BSS pair",
       [R.STATION], ["5G"], ["owe-transition", "psk2"]),
    _e("multi-psk", A.SECURITY, M.BRIDGE,
       "Multiple pre-shared keys on one SSID, per-key VLAN assignment",
       [R.STATION, R.VLAN], ["2G", "5G"], ["psk2", "mpsk"]),
    _e("eap_local", A.SECURITY, M.BRIDGE, "EAP served locally by the AP (no external RADIUS)",
       [R.STATION], ["2G"], ["wpa2"]),
    _e("psk2-radius", A.SECURITY, M.BRIDGE, "PSK2 with RADIUS accounting",
       [R.STATION, R.RADIUS], ["2G"], ["psk2-radius"]),
    _e("wpa2-radius", A.SECURITY, M.MIXED,
       "WPA2 Enterprise with 802.11r fast transition and 802.11k neighbour reports",
       [R.STATION, R.RADIUS], ["5G"], ["wpa2", "psk2"]),
    _e("radius", A.SECURITY, M.BRIDGE, "Baseline WPA2 Enterprise against external RADIUS",
       [R.STATION, R.RADIUS], ["5G"], ["wpa2"]),
    _e("radius-secondary", A.SECURITY, M.BRIDGE, "RADIUS failover to a secondary server",
       [R.STATION, R.RADIUS], ["5G"], ["wpa2"]),
    _e("radius-proxy", A.SECURITY, M.MIXED, "RADIUS proxy / realm routing",
       [R.STATION, R.RADIUS], ["5G"], ["wpa2", "psk2"]),
    _e("radius-gw-proxy", A.SECURITY, M.BRIDGE, "RADIUS proxied through the uCentral gateway",
       [R.STATION, R.RADIUS], ["2G", "5G"], ["wpa2"]),
    _e("radius-request-attr", A.SECURITY, M.BRIDGE, "Custom RADIUS request attributes",
       [R.STATION, R.RADIUS], ["5G"], ["wpa2"]),
    _e("ieee8021x-radius", A.SECURITY, M.CONFIG_ONLY, "Wired 802.1X against RADIUS",
       [R.RADIUS]),
    _e("ieee8021x-mac-auth", A.SECURITY, M.CONFIG_ONLY, "Wired 802.1X MAC authentication bypass",
       [R.RADIUS]),
    _e("ieee8021x-nat", A.SECURITY, M.CONFIG_ONLY, "Wired 802.1X on a NATed port",
       [R.RADIUS]),
    _e("roaming-psk2-radius", A.ROAMING, M.BRIDGE,
       "802.11r fast roaming with PSK2 and RADIUS",
       [R.STATION, R.RADIUS, R.PEER_AP], ["2G", "5G"], ["psk2"]),

    # ── Network mode: bridge vs NAT ──────────────────────────────────────────
    _e("default", A.NETWORK_MODE, M.MIXED,
       "Stock config — bridged upstream SSID plus NATed downstream LAN",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("maverick", A.NETWORK_MODE, M.NAT, "Open SSID fully NATed behind the AP",
       [R.STATION], ["2G", "5G"], ["none"]),
    _e("block-rfc1918", A.NETWORK_MODE, M.NAT,
       "NAT mode with RFC1918 destinations blocked from the client subnet",
       [R.STATION], ["2G"], ["psk2"]),
    _e("dual-stack", A.NETWORK_MODE, M.MIXED, "IPv4 and IPv6 dual-stack addressing",
       [R.STATION], ["2G"], ["psk2"]),
    _e("strict-forwarding", A.NETWORK_MODE, M.BRIDGE,
       "Client isolation — station-to-station forwarding blocked",
       [R.STATION], ["2G"], ["psk2"]),
    _e("data-plane", A.NETWORK_MODE, M.MIXED, "Explicit data-plane forwarding rules",
       [R.STATION], ["2G"], ["psk2"]),
    _e("dhcpsnoop", A.NETWORK_MODE, M.CONFIG_ONLY, "DHCP snooping on the bridge"),
    _e("igmp", A.NETWORK_MODE, M.CONFIG_ONLY, "IGMP snooping for multicast"),
    _e("loop-detect", A.NETWORK_MODE, M.MIXED, "Bridge loop detection",
       [R.STATION], ["2G"], ["psk2"]),

    # ── Rate limiting and QoS ────────────────────────────────────────────────
    _e("rate-limit", A.RATE_LIMIT, M.NAT, "Per-SSID and per-client upstream/downstream shaping",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("qos", A.QOS, M.MIXED, "Quality-of-service bulk/critical classification",
       [R.STATION], ["2G"], ["psk2"]),
    _e("qos-class", A.QOS, M.MIXED, "DSCP-to-WMM class mapping",
       [R.STATION], ["2G"], ["psk2"]),

    # ── Roaming, steering, RRM ───────────────────────────────────────────────
    _e("steering", A.ROAMING, M.BRIDGE, "Band steering between 2.4 and 5 GHz",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("rrm", A.ROAMING, M.MIXED, "802.11k radio resource management",
       [R.STATION], ["2G"], ["psk2"]),
    _e("quality-threshold", A.ROAMING, M.BRIDGE, "Kick clients below an RSSI/quality threshold",
       [R.STATION], ["2G"], ["psk2"]),

    # ── Captive portal ───────────────────────────────────────────────────────
    _e("captive", A.CAPTIVE, M.MIXED, "Built-in click-through captive portal",
       [R.STATION], ["2G", "5G"], ["psk2", "none"]),
    _e("captive-click", A.CAPTIVE, M.BRIDGE, "Click-to-accept splash page",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("captive-credentials", A.CAPTIVE, M.BRIDGE, "Portal with local credential list",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("captive-webroot", A.CAPTIVE, M.BRIDGE, "Portal serving a custom embedded webroot",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    # One of its two portals is UAM, pointed at a commercial hosted service, so
    # the splash redirects off-box and no bench without that backend can clear
    # it. Same requirement as captive-uam rather than a guaranteed failure.
    _e("captive-multiple", A.CAPTIVE, M.BRIDGE, "Several portal-enabled SSIDs at once",
       [R.STATION, R.CAPTIVE_BACKEND], ["2G", "5G"], ["psk2"]),
    _e("captive-radius", A.CAPTIVE, M.BRIDGE, "Portal authenticating against RADIUS",
       [R.STATION, R.RADIUS], ["2G", "5G"], ["psk2"]),
    _e("captive-uam", A.CAPTIVE, M.BRIDGE, "External UAM portal redirect",
       [R.STATION, R.RADIUS, R.CAPTIVE_BACKEND], ["2G", "5G"], ["psk2"]),

    # ── VLAN ─────────────────────────────────────────────────────────────────
    _e("vlan", A.VLAN, M.BRIDGE, "SSID bridged onto a tagged VLAN",
       [R.STATION, R.VLAN], ["2G", "5G"], ["psk2"]),
    _e("switch-vlan", A.VLAN, M.CONFIG_ONLY, "VLAN assignment across switch ports",
       [R.VLAN, R.SWITCH_HW]),
    _e("dhcp-relay", A.VLAN, M.BRIDGE, "DHCP relay to an upstream server",
       [R.STATION, R.VLAN, R.DHCP_SERVER], ["2G"], ["psk2"]),
    _e("big", A.VLAN, M.MIXED, "Large composite config — many SSIDs, VLANs and a mesh link",
       [R.STATION, R.VLAN, R.PEER_AP], ["2G", "5G"], ["psk2"]),

    # ── Tunnels and mesh ─────────────────────────────────────────────────────
    _e("gre", A.TUNNEL, M.MIXED, "GRE tunnel to a remote endpoint",
       [R.STATION, R.VLAN, R.PEER_AP], ["2G"], ["psk2"]),
    _e("gre6", A.TUNNEL, M.BRIDGE, "GRE over IPv6",
       [R.STATION, R.PEER_AP], ["2G", "5G"], ["none"]),
    _e("vxlan", A.TUNNEL, M.MIXED, "VXLAN overlay",
       [R.STATION, R.VLAN, R.PEER_AP], ["2G"], ["psk2"]),
    # The next three declare only mesh/WDS BSSes. An ordinary station cannot
    # associate to those, so they are apply-and-verify against a peer radio.
    _e("mesh", A.TUNNEL, M.CONFIG_ONLY, "802.11s mesh backhaul",
       [R.PEER_AP], ["5G"], ["psk2"]),
    _e("wds-ap", A.TUNNEL, M.CONFIG_ONLY, "WDS access point side",
       [R.PEER_AP], ["2G", "5G"], ["psk2"]),
    _e("wds-sta", A.TUNNEL, M.CONFIG_ONLY, "WDS station side",
       [R.PEER_AP], ["5G"], ["psk2"]),

    # ── Wi-Fi generation ─────────────────────────────────────────────────────
    _e("wifi-6e", A.WIFI_GEN, M.BRIDGE, "6 GHz operation with WPA3",
       [R.STATION, R.SIXGHZ], ["2G", "5G", "6G"], ["psk2", "sae"]),
    _e("wifi-6e-afc", A.WIFI_GEN, M.BRIDGE, "6 GHz standard power under AFC control",
       [R.STATION, R.SIXGHZ, R.INTERNET], ["2G", "5G", "6G"], ["psk2", "sae"]),
    _e("wifi-6e-mpsk", A.WIFI_GEN, M.BRIDGE, "6 GHz with multi-PSK",
       [R.STATION, R.SIXGHZ], ["2G", "5G", "6G"], ["psk2", "sae", "mpsk"]),
    _e("wifi-6e-mpsk-radius", A.WIFI_GEN, M.BRIDGE, "6 GHz multi-PSK keyed from RADIUS",
       [R.STATION, R.SIXGHZ, R.RADIUS], ["2G", "5G", "6G"], ["mpsk-radius"]),
    _e("wifi-6e-psk2-radius", A.WIFI_GEN, M.BRIDGE, "6 GHz PSK2 with RADIUS",
       [R.STATION, R.SIXGHZ, R.RADIUS], ["2G", "5G", "6G"], ["psk2-radius", "sae"]),
    _e("wifi-7", A.WIFI_GEN, M.BRIDGE, "802.11be / Wi-Fi 7 operation",
       [R.STATION, R.WIFI7], ["2G", "5G", "6G"], ["psk2", "sae"]),

    # ── Telemetry and fingerprinting ─────────────────────────────────────────
    _e("metrics", A.TELEMETRY, M.NAT, "Statistics and health reporting intervals",
       [R.STATION], ["2G"], ["psk2"]),
    _e("telemetry", A.TELEMETRY, M.BRIDGE, "Real-time telemetry stream",
       [R.STATION], ["2G"], ["psk2"]),
    _e("fingerprint-raw", A.TELEMETRY, M.MIXED, "Raw client fingerprinting",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("fingerprint-final-always", A.TELEMETRY, M.MIXED, "Fingerprint reported on every change",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("fingerprint-final-periodic", A.TELEMETRY, M.MIXED, "Fingerprint reported periodically",
       [R.STATION], ["2G", "5G"], ["psk2"]),
    _e("tip-oui", A.TELEMETRY, M.MIXED, "OUI-based client identification",
       [R.STATION], ["2G"], ["psk2"]),

    # ── Services ─────────────────────────────────────────────────────────────
    _e("ssh", A.SERVICES, M.CONFIG_ONLY, "SSH server settings"),
    _e("lldp", A.SERVICES, M.CONFIG_ONLY, "LLDP neighbour advertisement"),
    _e("ntp", A.SERVICES, M.MIXED, "NTP client and server settings",
       [R.STATION, R.INTERNET], ["2G"], ["psk2"]),
    _e("online-check", A.SERVICES, M.MIXED, "Connectivity watchdog and recovery action",
       [R.STATION, R.INTERNET], ["2G"], ["psk2"]),
    _e("unit", A.SERVICES, M.CONFIG_ONLY, "Unit-level settings — name, location, timezone"),
    _e("admin_ui", A.SERVICES, M.MIXED, "Local admin web UI",
       [R.STATION], ["2G"], ["psk2"]),
    _e("gps", A.SERVICES, M.MIXED, "GPS location service",
       [R.STATION, R.GPS_HW], ["2G"], ["psk2"]),

    # ── Switch fabric ────────────────────────────────────────────────────────
    _e("switch-ports", A.SWITCH, M.CONFIG_ONLY, "Per-port switch configuration", [R.SWITCH_HW]),
    _e("switch-fabric", A.SWITCH, M.CONFIG_ONLY, "Switch fabric topology", [R.SWITCH_HW]),

    # ── WWAN ─────────────────────────────────────────────────────────────────
    _e("wwan", A.WWAN, M.NAT, "Cellular WWAN uplink failover",
       [R.STATION, R.WWAN_HW], ["5G"], ["psk2"]),
)

# Sub-groups within a feature area. "Security" spanning personal PSK, the AP's
# own EAP server and an external RADIUS is three different things to set up and
# three different things to debug, so the report should not lump them together.
GROUPS: dict[str, str] = {
    # ── Security ─────────────────────────────────────────────────────────────
    "crypto-psk": "Personal — PSK and SAE",
    "owe": "Open and OWE",
    "owe-transition": "Open and OWE",
    "multi-psk": "Personal — multi-PSK",
    "wifi-6e-mpsk": "Personal — multi-PSK",
    "eap_local": "Enterprise — RADIUS on the AP",
    "crypto-enterprise": "Enterprise — external RADIUS",
    "radius": "Enterprise — external RADIUS",
    "radius-secondary": "Enterprise — external RADIUS",
    "radius-proxy": "Enterprise — external RADIUS",
    "radius-gw-proxy": "Enterprise — external RADIUS",
    "radius-request-attr": "Enterprise — external RADIUS",
    "psk2-radius": "Enterprise — external RADIUS",
    "wpa2-radius": "Enterprise — external RADIUS",
    "wifi-6e-mpsk-radius": "Enterprise — external RADIUS",
    "wifi-6e-psk2-radius": "Enterprise — external RADIUS",
    "ieee8021x-radius": "Wired 802.1X",
    "ieee8021x-mac-auth": "Wired 802.1X",
    "ieee8021x-nat": "Wired 802.1X",
    "roaming-psk2-radius": "Roaming — 802.11r",
    # ── Forwarding ───────────────────────────────────────────────────────────
    "default": "Baseline",
    "maverick": "NAT",
    "block-rfc1918": "NAT with filtering",
    "strict-forwarding": "Client isolation",
    "data-plane": "Forwarding rules",
    "dual-stack": "IPv4 and IPv6",
    "dhcpsnoop": "DHCP snooping",
    "igmp": "Multicast",
    "loop-detect": "Loop detection",
    # ── Captive portal ───────────────────────────────────────────────────────
    "captive": "Built-in portal",
    "captive-click": "Built-in portal",
    "captive-credentials": "Built-in portal",
    "captive-webroot": "Built-in portal",
    "captive-multiple": "Built-in portal",
    "captive-radius": "Portal with RADIUS",
    "captive-uam": "External UAM portal",
    # ── VLAN ─────────────────────────────────────────────────────────────────
    "vlan": "Static SSID to VLAN",
    "switch-vlan": "Switch port VLANs",
    "dhcp-relay": "DHCP relay",
    "big": "Composite config",
    # ── Tunnels ──────────────────────────────────────────────────────────────
    "gre": "GRE", "gre6": "GRE", "vxlan": "VXLAN",
    "mesh": "Mesh backhaul", "wds-ap": "WDS", "wds-sta": "WDS",
    # ── Wi-Fi generation ─────────────────────────────────────────────────────
    "wifi-6e": "6 GHz", "wifi-6e-afc": "6 GHz with AFC", "wifi-7": "Wi-Fi 7",
    # ── Services and telemetry ───────────────────────────────────────────────
    "ssh": "Management access", "admin_ui": "Management access",
    "lldp": "Discovery", "ntp": "Time", "online-check": "Connectivity watchdog",
    "unit": "Unit settings", "gps": "Location",
    "metrics": "Statistics", "telemetry": "Statistics",
    "fingerprint-raw": "Client fingerprinting",
    "fingerprint-final-always": "Client fingerprinting",
    "fingerprint-final-periodic": "Client fingerprinting",
    "tip-oui": "Client identification",
    # ── Roaming / QoS / rate ─────────────────────────────────────────────────
    "steering": "Band steering", "rrm": "802.11k RRM",
    "quality-threshold": "Signal thresholds",
    "qos": "QoS classification", "qos-class": "QoS classification",
    "rate-limit": "Shaping",
    "switch-ports": "Switch ports", "switch-fabric": "Switch fabric",
    "wwan": "Cellular uplink",
}


def group_of(example: "Example | str") -> str:
    """Sub-group for the report; falls back to the area label."""
    name = example if isinstance(example, str) else example.name
    if name in GROUPS:
        return GROUPS[name]
    entry = BY_NAME.get(name)
    return entry.area.value.replace("_", " ").title() if entry else "Other"


BY_NAME: dict[str, Example] = {e.name: e for e in EXAMPLES}


def get(name: str) -> Example:
    try:
        return BY_NAME[name]
    except KeyError:
        raise KeyError(f"No catalog entry for example {name!r}") from None


def by_area(area: Area) -> list[Example]:
    return [e for e in EXAMPLES if e.area == area]


def ap_only_examples() -> list[Example]:
    """Examples runnable on a bare AP + one RPi5 station."""
    return [e for e in EXAMPLES if e.ap_only]


def requiring(req: Requirement) -> list[Example]:
    return [e for e in EXAMPLES if req in e.requires]
