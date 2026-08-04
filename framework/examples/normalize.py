"""
Normalizer for upstream uCentral example configs.

The examples in the wlan-ap tree are written as schema illustrations, not as
runnable lab configs, and several would be rejected or silently mangled by a US
AP.  Measured against the vendored corpus:

* 86 of 108 radio entries declare ``"country": "CA"``.
* 32 examples set ``channel-width: 80`` on a ``2G`` radio.
* 22 examples set a channel that does not exist in the band they declare —
  ``crypto-psk.json`` asks for ``band: 2G`` with ``channel: 32``, and
  ``telemetry.json`` asks for ``band: 2G`` with ``channel: 36``.

Every change is recorded in a :class:`NormalizationReport` and surfaced in the
HTML report, so a test never silently runs against a config different from the
one its name implies.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

DEFAULT_COUNTRY = "US"

# Channels legal in the US per band.
US_CHANNELS_2G = set(range(1, 12))          # 12-14 are not permitted in the US
US_CHANNELS_5G_NON_DFS = {36, 40, 44, 48, 149, 153, 157, 161, 165}
US_CHANNELS_5G_DFS = set(range(52, 65, 4)) | set(range(100, 145, 4))
US_CHANNELS_5G = US_CHANNELS_5G_NON_DFS | US_CHANNELS_5G_DFS
# 6 GHz preferred scanning channels — a STA finds these fastest.
US_CHANNELS_6G_PSC = {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229}

# Widths each band can actually run.
BAND_MAX_WIDTH = {"2G": 40, "5G": 160, "6G": 320}
BAND_VALID_WIDTHS = {
    "2G": {20, 40},
    "5G": {20, 40, 80, 160},
    "6G": {20, 40, 80, 160, 320},
}

# Fallbacks used when a declared channel is impossible for its band.
BAND_FALLBACK_CHANNEL = {"2G": 6, "5G": 36, "6G": 37}

# 2.4 GHz is crowded and 40 MHz there is a bad neighbour; regression runs want
# the boring, always-legal width.
DEFAULT_2G_WIDTH = 20

# Fixed channel per band for the whole sweep. Pinning them makes runs
# comparable — a result on "5 GHz" means the same thing every time — and keeps
# every band off DFS. 6 GHz channel 37 is a PSC, so a station finds it quickly.
DEFAULT_CHANNEL_PLAN: dict[str, int] = {"2G": 1, "5G": 36, "6G": 37}


@dataclass
class NormalizationReport:
    """What the normalizer changed, for reporting and assertions."""

    example: str = ""
    changes: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.changes)

    def record(self, msg: str) -> None:
        self.changes.append(msg)
        log.debug("normalize[%s]: %s", self.example, msg)

    def summary(self) -> str:
        if not self.changes:
            return "no changes"
        return "; ".join(self.changes)


def normalize_config(
    config: dict,
    *,
    example: str = "",
    country: str = DEFAULT_COUNTRY,
    avoid_dfs: bool = True,
    force_2g_width: int | None = DEFAULT_2G_WIDTH,
    radio_caps: dict | None = None,
    channel_plan: dict[str, int] | None = None,
) -> tuple[dict, NormalizationReport]:
    """
    Return a cleaned deep copy of *config* plus a report of what changed.

    Parameters
    ----------
    country:
        Regulatory domain forced onto every radio. Defaults to ``US``.
    avoid_dfs:
        Move 5 GHz DFS channels to a non-DFS channel. DFS forces a channel
        availability check of 60 s or more before the BSS comes up, and a radar
        event mid-run fails an unrelated test, so regression defaults to off.
    force_2g_width:
        Width forced onto every 2.4 GHz radio. ``None`` only clamps illegal
        widths instead of pinning a value.
    radio_caps:
        Band -> :class:`framework.ap.ap_client.RadioCaps` for the DUT. When
        given, ``channel-mode``, ``channel-width`` and ``channel`` are clamped
        to what this AP actually advertises.

        This matters more than it sounds. The examples are written against
        Wi-Fi 6E/7 flagships — 85 of the radio entries in the corpus ask for
        ``HE`` — so on, say, a Wi-Fi 5 IPQ4019 the renderer warns
        "does not support requested HT mode HE20, falling back to HT40" and
        carries on. Under ``strict`` that warning rejects the whole config, so
        without this clamping almost nothing applies on older hardware.
    """
    cfg = copy.deepcopy(config)
    report = NormalizationReport(example=example)

    plan = DEFAULT_CHANNEL_PLAN if channel_plan is None else channel_plan

    for idx, radio in enumerate(cfg.get("radios") or []):
        _normalize_radio(radio, idx, report, country, avoid_dfs, force_2g_width)
        # Pin the agreed channel for this band before clamping, so the clamp
        # only has to move it if this AP genuinely cannot use it.
        band = radio.get("band")
        if plan and band in plan and radio.get("channel") != plan[band]:
            was = radio.get("channel")
            radio["channel"] = plan[band]
            report.record(f"radio[{idx}] band={band}: channel {was} -> {plan[band]} (test plan)")
        if radio_caps:
            _clamp_to_radio_caps(radio, idx, report, radio_caps, avoid_dfs)

    if radio_caps:
        _drop_unsupported_bands(cfg, report, radio_caps)

    _drop_roaming_without_wpa2(cfg, report)
    _fix_known_bad_enums(cfg, report)

    return cfg, report


# Values the corpus uses that no uCentral schema accepts, and what they meant.
# Keyed by the path they appear at, so a value that is legal elsewhere is not
# rewritten by accident.
_ENUM_FIXUPS = {
    ("services", "fingerprint", "mode"): {"raw-data": "raw"},
}


def _fix_known_bad_enums(config: dict, report: NormalizationReport) -> None:
    """
    Correct example values this firmware's schema rejects outright.

    ``fingerprint-raw`` asks for ``mode: "raw-data"``; the schema allows only
    ``polled``, ``final`` or ``raw``, so the config is refused and the feature
    is never exercised at all. Rewriting it to the value it plainly meant keeps
    the case testing fingerprinting rather than testing a typo — the same
    treatment the corpus's ``CA`` country codes and 80 MHz 2.4 GHz radios get.
    """
    for path, mapping in _ENUM_FIXUPS.items():
        node = config
        for key in path[:-1]:
            node = node.get(key) if isinstance(node, dict) else None
            if not isinstance(node, dict):
                break
        else:
            leaf = path[-1]
            if isinstance(node, dict) and node.get(leaf) in mapping:
                was = node[leaf]
                node[leaf] = mapping[was]
                report.record(
                    f"{'/'.join(path)}: {was!r} -> {node[leaf]!r} "
                    f"(not a value the schema accepts)"
                )


# Roaming needs a PMK to hand between APs, so the schema requires WPA2 or
# later. These protos predate it (or have no key at all).
_PRE_WPA2_PROTOS = frozenset({"none", "open", "wep", "psk", "wpa"})


def _drop_roaming_without_wpa2(config: dict, report: NormalizationReport) -> None:
    """
    Strip ``roaming`` from SSIDs whose encryption cannot carry it.

    ``maverick`` puts 802.11r on an open SSID, which is meaningless — there is
    no pairwise key to hand over — and this firmware refuses the whole config
    with "Roaming requires wpa2 or later". Like the 80 MHz-on-2.4 GHz entries,
    it is an inconsistency in the example rather than something to test, so it
    is cleaned up instead of failing the case.
    """
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            if not ssid.get("roaming"):
                continue
            proto = ((ssid.get("encryption") or {}).get("proto") or "none").lower()
            if proto in _PRE_WPA2_PROTOS:
                ssid.pop("roaming")
                report.record(
                    f"dropped roaming from SSID {ssid.get('name', '?')!r} — "
                    f"proto {proto} predates WPA2 and the AP requires WPA2 or later"
                )


def _drop_unsupported_bands(config: dict, report: NormalizationReport, radio_caps: dict) -> None:
    """
    Remove radios, and SSID band references, for bands this AP does not have.

    Clamping mode and width is not enough. A config that declares a 6 GHz radio
    on a dual-band AP makes the renderer warn "Can't find any suitable radio phy
    for band 6G radio settings", and under ``strict`` that warning rejects the
    whole config — which is why every captive-portal example failed on a Wi-Fi 5
    AP even though the portal settings themselves were fine.
    """
    supported = set(radio_caps)
    if not supported:
        return

    radios = config.get("radios") or []
    kept = [r for r in radios if r.get("band") in supported]
    dropped = [r.get("band") for r in radios if r.get("band") not in supported]
    if dropped:
        config["radios"] = kept
        report.record(f"dropped radio(s) for band(s) {sorted(set(dropped))} — AP has "
                      f"{sorted(supported)}")

    # An SSID left advertising only an absent band would never come up, and the
    # test would report it missing rather than skipped.
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            bands = ssid.get("wifi-bands")
            if not bands:
                continue
            usable = [b for b in bands if b in supported]
            if usable == list(bands):
                continue
            if usable:
                ssid["wifi-bands"] = usable
                report.record(
                    f"SSID {ssid.get('name')!r}: wifi-bands {list(bands)} -> {usable}"
                )
            else:
                iface["ssids"] = [s for s in iface["ssids"] if s is not ssid]
                report.record(
                    f"removed SSID {ssid.get('name')!r} — only on absent band(s) {list(bands)}"
                )


# Ordered weakest to strongest — must match framework.ap.ap_client.MODE_ORDER.
_MODE_ORDER = ("HT", "VHT", "HE", "EHT")


def _clamp_to_radio_caps(
    radio: dict,
    idx: int,
    report: NormalizationReport,
    radio_caps: dict,
    avoid_dfs: bool,
) -> None:
    """Clamp one radio to what the DUT advertises for its band."""
    band = radio.get("band")
    caps = radio_caps.get(band)
    if caps is None or not caps.modes:
        return

    tag = f"radio[{idx}] band={band}"

    # ── Mode: drop to the strongest the radio actually has ───────────────────
    requested = str(radio.get("channel-mode") or "").upper()
    if requested in _MODE_ORDER and requested not in caps.modes:
        ceiling = _MODE_ORDER.index(requested)
        supported = [m for m in _MODE_ORDER[:ceiling] if m in caps.modes]
        if supported:
            best = supported[-1]
            radio["channel-mode"] = best
            report.record(f"{tag}: channel-mode {requested} -> {best} (AP lacks {requested})")
            requested = best

    # ── Width: clamp to what that mode supports ──────────────────────────────
    allowed = caps.widths_for(requested) if requested in caps.modes else frozenset()
    width = radio.get("channel-width")
    if allowed and width is not None and width not in allowed:
        clamped = max(w for w in allowed if w <= width) if any(
            w <= width for w in allowed
        ) else min(allowed)
        radio["channel-width"] = clamped
        report.record(f"{tag}: channel-width {width} -> {clamped} (AP supports {sorted(allowed)})")

    # ── Channel: must be one this radio actually offers ──────────────────────
    channel = radio.get("channel")
    if channel is None or not caps.channels:
        return

    usable = set(caps.channels)
    if avoid_dfs and caps.dfs_channels:
        non_dfs = usable - set(caps.dfs_channels)
        if non_dfs:
            usable = non_dfs

    if channel not in usable:
        replacement = min(usable)
        reason = "DFS avoided" if channel in caps.dfs_channels else "not offered by this radio"
        radio["channel"] = replacement
        report.record(f"{tag}: channel {channel} -> {replacement} ({reason})")


def _normalize_radio(
    radio: dict,
    idx: int,
    report: NormalizationReport,
    country: str,
    avoid_dfs: bool,
    force_2g_width: int | None,
) -> None:
    band = radio.get("band")
    tag = f"radio[{idx}] band={band}"

    # ── Regulatory domain ────────────────────────────────────────────────────
    current = radio.get("country")
    if current != country:
        radio["country"] = country
        report.record(f"{tag}: country {current!r} -> {country!r}")

    if band not in BAND_VALID_WIDTHS:
        return

    # ── Channel width ────────────────────────────────────────────────────────
    width = radio.get("channel-width")
    if band == "2G" and force_2g_width is not None:
        if width != force_2g_width:
            radio["channel-width"] = force_2g_width
            report.record(f"{tag}: channel-width {width} -> {force_2g_width} (2.4GHz)")
    elif width is not None and width not in BAND_VALID_WIDTHS[band]:
        clamped = BAND_MAX_WIDTH[band]
        radio["channel-width"] = clamped
        report.record(f"{tag}: channel-width {width} invalid -> {clamped}")

    # ── Channel ──────────────────────────────────────────────────────────────
    # A missing channel means "auto select", which is valid — leave it alone.
    channel = radio.get("channel")
    if channel is None:
        return

    fixed = _fix_channel(band, channel, avoid_dfs)
    if fixed != channel:
        reason = "not valid in band" if not _channel_in_band(band, channel) else "DFS avoided"
        radio["channel"] = fixed
        report.record(f"{tag}: channel {channel} -> {fixed} ({reason})")


def _channel_in_band(band: str, channel: int) -> bool:
    if band == "2G":
        return channel in US_CHANNELS_2G
    if band == "5G":
        return channel in US_CHANNELS_5G
    if band == "6G":
        return 1 <= channel <= 233
    return True


def _fix_channel(band: str, channel: int, avoid_dfs: bool) -> int:
    if not _channel_in_band(band, channel):
        return BAND_FALLBACK_CHANNEL[band]
    if band == "5G" and avoid_dfs and channel in US_CHANNELS_5G_DFS:
        return BAND_FALLBACK_CHANNEL["5G"]
    return channel


def assign_bridge_vlan(
    config: dict,
    vlan_id: int,
    *,
    report: NormalizationReport | None = None,
) -> dict:
    """
    Move bridged SSIDs onto a tagged upstream interface, in place.

    A bridged SSID on an *untagged* upstream drops its clients straight onto the
    management LAN. That is how the framework previously locked itself out of
    the station: the client was handed an address on the same subnet as the
    station's own management interface. Putting test traffic on its own VLAN
    keeps it clearly separated from management.

    The shape follows the upstream ``vlan`` example: leave the untagged upstream
    alone so the AP keeps its own management address, and add a tagged twin that
    carries the SSIDs. Tagging the existing upstream instead would move the AP
    itself onto the VLAN and strand it.

    Does nothing to SSIDs already on a tagged interface, or to NATed SSIDs on a
    downstream interface — those are already off the management path.
    """
    interfaces = config.get("interfaces") or []
    moved: list[str] = []
    left_dynamic: list[str] = []
    # Reuse a tagged twin if one is already here. This runs a second time after
    # bridge-forcing, which is what catches SSIDs that started on a downstream
    # interface and would otherwise be bridged onto the untagged management
    # interface — and a second pass must not build a duplicate interface.
    existing = {
        (i.get("vlan") or {}).get("id"): i
        for i in interfaces if i.get("role") == "upstream" and i.get("vlan")
    }

    for iface in list(interfaces):
        if iface.get("role") != "upstream" or iface.get("vlan"):
            continue
        all_ssids = iface.get("ssids") or []
        if not all_ssids:
            continue

        # SSIDs that get their VLAN assigned at authentication time must stay
        # on the untagged interface: the AP creates the VLAN interface on the
        # fly from what RADIUS returns, or from the matched multi-PSK key.
        # Pre-tagging them would pin every client to one VLAN and defeat the
        # very behaviour under test.
        ssids = [s for s in all_ssids if not _has_dynamic_vlan(s)]
        left_dynamic.extend(
            s.get("name", "?") for s in all_ssids if _has_dynamic_vlan(s)
        )
        if not ssids:
            continue
        iface["ssids"] = [s for s in all_ssids if _has_dynamic_vlan(s)]

        if vlan_id in existing:
            existing[vlan_id].setdefault("ssids", []).extend(ssids)
            moved.extend(s.get("name", "?") for s in ssids)
            continue

        tagged = {
            "name": f"{iface.get('name', 'WAN')}{vlan_id}",
            "role": "upstream",
            "vlan": {"id": vlan_id},
            "ethernet": copy.deepcopy(iface.get("ethernet"))
            or [{"select-ports": ["WAN*"]}],
            # Always dynamic, never a copy of the source interface's ipv4: a
            # static block without subnet/gateway/use-dns makes the renderer
            # die with "invalid static interface settings". Ports on a tagged
            # upstream render as ':t', so sharing WAN* with the untagged
            # interface is fine — only two *untagged* users of a port collide.
            "ipv4": {"addressing": "dynamic"},
            "ssids": ssids,
        }
        interfaces.append(tagged)
        moved.extend(s.get("name", "?") for s in ssids)

    if report is not None:
        if moved:
            report.record(
                f"moved bridged SSID(s) {', '.join(moved)} onto VLAN {vlan_id} "
                f"(untagged upstream kept for AP management)"
            )
        if left_dynamic:
            report.record(
                f"left SSID(s) {', '.join(left_dynamic)} untagged — VLAN is assigned "
                f"dynamically and the AP creates the interface on the fly"
            )
    return config


def name_ssids_for_test(
    config: dict,
    ap_name: str,
    *,
    password: str = "12345678",
    report: NormalizationReport | None = None,
) -> dict:
    """
    Rename every SSID to ``<ap-name>-<use-case>`` and set a known password.

    The upstream names (``OpenWifi-psk2``, ``Maverick``) say nothing about which
    AP is broadcasting, so on a bench with several APs up at once a scan is
    ambiguous and a client can silently associate to the wrong one. Naming each
    SSID after the AP and the case under test makes every result traceable to
    the device that produced it.

    The use-case suffix comes from the encryption proto, which is what
    distinguishes the SSIDs within a config. SSID names are capped at the 32
    octets 802.11 allows.

    Names must stay unique. Several examples carry two SSIDs sharing one proto —
    ``captive-multiple`` has a UAM portal and a click-to-continue portal both on
    psk2 — and naming by proto alone collapses them onto one name. Two BSSes
    with the same name on one radio is not a configuration the renderer can
    make sense of: on this DUT it hangs ``ucentral.uc`` until it is killed and
    leaves the AP without its management path, which then fails the next test
    too. A collision is disambiguated by what actually differs between them.
    """
    renamed: list[str] = []
    taken: set[str] = set()
    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            enc = ssid.setdefault("encryption", {})
            proto = (enc.get("proto") or "open").lower()
            new = _unique_ssid_name(f"{ap_name}-{proto}", ssid, taken)
            taken.add(new)
            if ssid.get("name") != new:
                renamed.append(f"{ssid.get('name')} -> {new}")
                ssid["name"] = new
            # Open and OWE networks take no key.
            if proto not in ("none", "open", "owe", "owe-transition"):
                enc["key"] = password

    if renamed and report is not None:
        report.record(f"SSIDs named for this AP and case: {', '.join(renamed)}")
    return config


def _unique_ssid_name(base: str, ssid: dict, taken: set[str]) -> str:
    """
    ``base``, or ``base`` plus whatever distinguishes this SSID from its twin.

    Prefers a suffix that means something to a reader watching a scan list — the
    portal's auth mode, "radius", "mpsk" — and only falls back to a counter when
    nothing else sets the two apart. Always trimmed to the 32 octets 802.11
    allows, and trimmed on the *base* so the distinguishing suffix survives.
    """
    def fit(name: str) -> str:
        if len(name) <= 32:
            return name
        head, _, tail = name.rpartition("-")
        return f"{head[:32 - len(tail) - 1]}-{tail}"

    if fit(base) not in taken:
        return fit(base)

    captive = ssid.get("captive") or {}
    hints = []
    if captive.get("auth-mode"):
        hints.append(str(captive["auth-mode"]).replace("-to-continue", ""))
    elif captive:
        hints.append("captive")
    if ssid.get("radius"):
        hints.append("radius")
    if ssid.get("multi-psk"):
        hints.append("mpsk")

    for hint in hints:
        candidate = fit(f"{base}-{hint}")
        if candidate not in taken:
            return candidate

    for n in range(2, 100):
        candidate = fit(f"{base}-{n}")
        if candidate not in taken:
            return candidate
    return fit(base)


def restrict_to_band(
    config: dict,
    band: str,
    *,
    channel_plan: dict[str, int] | None = None,
    radio_caps: dict | None = None,
    report: NormalizationReport | None = None,
) -> dict:
    """
    Reduce the config to a single band, on the agreed channel.

    Running the same feature on each band separately is the only way to tell
    "WPA3 works" from "WPA3 works on 5 GHz and is broken on 2.4". With every
    band live at once a station picks whichever it likes and the result says
    nothing about the others.

    *radio_caps* must be passed whenever it is known. This step runs after the
    clamping in :func:`normalize_config`, and it can introduce a radio that step
    never saw — most examples declare no 2.4 GHz radio, so one is synthesised
    here. Left unclamped it asked for VHT20 on a radio that only does HT, and
    ``strict`` mode correctly rejected the whole config. That single omission
    accounted for the great majority of the 2 GHz "config was rejected"
    failures in a full sweep.
    """
    plan = DEFAULT_CHANNEL_PLAN if channel_plan is None else channel_plan
    radios = config.get("radios") or []

    kept = [r for r in radios if r.get("band") == band]
    if not kept:
        # The example may not declare this band at all; synthesise a radio for
        # it rather than skipping the combination entirely.
        kept = [{"band": band, "country": DEFAULT_COUNTRY,
                 "channel-mode": "HE" if band == "6G" else "VHT",
                 "channel-width": DEFAULT_2G_WIDTH if band == "2G" else 80}]
        if report is not None:
            report.record(f"example declares no {band} radio — added one for this case")
    for radio in kept:
        if band in plan:
            radio["channel"] = plan[band]
        if band == "2G":
            radio["channel-width"] = min(radio.get("channel-width") or 20, 20)
    config["radios"] = kept

    if radio_caps:
        for idx, radio in enumerate(kept):
            _clamp_to_radio_caps(
                radio, idx, report or NormalizationReport(example="restrict"),
                radio_caps, False,
            )

    for iface in config.get("interfaces") or []:
        for ssid in iface.get("ssids") or []:
            if ssid.get("wifi-bands") != [band]:
                ssid["wifi-bands"] = [band]

    if report is not None:
        report.record(
            f"restricted to {band} on channel {plan.get(band, 'auto')} for this case"
        )
    return config


def force_forwarding_mode(
    config: dict,
    mode: str,
    *,
    report: NormalizationReport | None = None,
    nat_subnet: str = "192.168.150.1/24",
) -> dict:
    """
    Put every AP-mode SSID on the bridged or the NATed path.

    The two paths exercise genuinely different code on the AP — bridging hands
    the client to the upstream network, NAT makes the AP a router with its own
    DHCP pool and masquerade. A feature can work on one and fail on the other,
    so each is tested explicitly rather than accepting whatever the example
    happened to ship.

    ``bridge`` leaves SSIDs on the upstream interfaces; ``nat`` moves them to a
    downstream interface serving its own subnet, creating one if the example has
    none.
    """
    interfaces = config.get("interfaces") or []
    ap_ssids: list[dict] = []
    for iface in interfaces:
        keep, move = [], []
        for ssid in iface.get("ssids") or []:
            (move if ssid.get("bss-mode", "ap") == "ap" else keep).append(ssid)
        iface["ssids"] = keep
        ap_ssids.extend(move)

    if not ap_ssids:
        return config

    if mode == "nat":
        target = next((i for i in interfaces if i.get("role") == "downstream"), None)
        if target is None:
            target = {
                "name": "LAN",
                "role": "downstream",
                "services": ["ssh"],
                "ethernet": [{"select-ports": ["LAN*"]}],
                "ipv4": {
                    "addressing": "static",
                    "subnet": nat_subnet,
                    "dhcp": {"lease-first": 10, "lease-count": 100, "lease-time": "6h"},
                },
                "ssids": [],
            }
            interfaces.append(target)
            if report is not None:
                report.record(f"added a downstream interface ({nat_subnet}) for NAT mode")
        else:
            ipv4 = target.setdefault("ipv4", {})
            ipv4.setdefault("addressing", "static")
            ipv4.setdefault("subnet", nat_subnet)
            ipv4.setdefault(
                "dhcp", {"lease-first": 10, "lease-count": 100, "lease-time": "6h"}
            )
    else:
        target = next(
            (i for i in interfaces if i.get("role") == "upstream" and i.get("vlan")),
            None,
        ) or next((i for i in interfaces if i.get("role") == "upstream"), None)
        if target is None:
            raise ValueError("config has no upstream interface to bridge onto")

    target.setdefault("ssids", []).extend(ap_ssids)

    if report is not None:
        names = ", ".join(s.get("name", "?") for s in ap_ssids)
        report.record(
            f"forced {mode} mode: SSID(s) {names} placed on "
            f"{target.get('name')} ({target.get('role')})"
        )
    return config


def enable_vlan_awareness(
    config: dict,
    vlan_ids: list[int],
    *,
    report: NormalizationReport | None = None,
) -> dict:
    """
    Pre-authorise a VLAN range on interfaces hosting dynamic-VLAN SSIDs.

    For RADIUS- or multi-PSK-assigned VLANs the AP builds the VLAN netdev at
    authentication time, but the bridge still has to be told which VIDs may
    egress tagged on the wired ports. That is ``vlan-awareness {first, last}``
    on the **interface** — the per-SSID key of the same name is only honoured in
    station mode, so it does nothing for an AP.
    """
    if not vlan_ids:
        return config

    first, last = min(vlan_ids), max(vlan_ids)
    touched: list[str] = []
    for iface in config.get("interfaces") or []:
        if iface.get("role") != "upstream":
            continue
        if not any(_has_dynamic_vlan(s) for s in iface.get("ssids") or []):
            continue
        if iface.get("vlan-awareness"):
            continue
        iface["vlan-awareness"] = {"first": first, "last": last}
        touched.append(iface.get("name") or "upstream")

    if touched and report is not None:
        report.record(
            f"enabled vlan-awareness {first}-{last} on {', '.join(touched)} so "
            f"dynamically assigned VLANs can egress tagged"
        )
    return config


def _has_dynamic_vlan(ssid: dict) -> bool:
    """True when this SSID's VLAN is decided per-client at auth time."""
    if ssid.get("radius"):
        return True
    return any(entry.get("vlan-id") for entry in ssid.get("multi-psk") or [])


def ensure_management_access(
    config: dict,
    *,
    report: NormalizationReport | None = None,
    ssh_port: int = 22,
    idle_timeout: int | None = 0,
) -> dict:
    """
    Guarantee the config keeps SSH reachable on the WAN, in place.

    This is the single most important safety rule in the framework. The DUT is
    managed over its upstream/WAN address, but **71 of the 78 upstream
    interfaces in the corpus do not list ``ssh`` as a service** — they put it on
    the downstream LAN instead. Applying one of those configs tears down SSH on
    the WAN and the AP becomes unreachable mid-run, with no way back except a
    physical console or a controller push.

    ``idle-timeout`` is set to 0 — the schema's documented "disable" value, in
    seconds, default 60, max 600 — so a long apply-and-observe cycle cannot have
    its session dropped underneath it. Pass ``None`` to omit the field.

    The top-level ``services.ssh`` block is written as well as the interface's
    ``services`` entry, and both are needed for different reasons. The array
    entry is the actual enable switch: the renderer skips SSH entirely unless
    some interface lists it, and it is what emits the firewall ACCEPT rule for
    that zone. The block is what makes the schema fill in its defaults — without
    it ``port`` is null and the firewall rule is written with no ``dest_port``,
    opening SSH wider than intended.

    Note that ``schemareader.validate()`` silently drops properties it does not
    recognise rather than failing, so a misspelled key here would quietly do
    nothing instead of raising. Changes to this function want testing against a
    real AP.
    """
    touched: list[str] = []

    upstreams = [i for i in (config.get("interfaces") or []) if i.get("role") == "upstream"]
    # Prefer the untagged upstream: that is the one carrying the AP's own
    # management address. Opening SSH on a VLAN-tagged interface as well would
    # expose it on the test VLAN for no benefit.
    untagged = [i for i in upstreams if not i.get("vlan")]
    for iface in (untagged or upstreams):
        services = iface.setdefault("services", [])
        if not any(str(s).lower() == "ssh" for s in services):
            services.append("ssh")
            touched.append(iface.get("name") or "upstream")

    services_block = config.setdefault("services", {})
    ssh = services_block.setdefault("ssh", {})
    if ssh.get("port") != ssh_port:
        ssh["port"] = ssh_port
    if idle_timeout is not None and ssh.get("idle-timeout") != idle_timeout:
        ssh["idle-timeout"] = idle_timeout

    if report is not None and touched:
        report.record(
            f"added 'ssh' to upstream interface(s) {', '.join(touched)} "
            f"to keep WAN management access"
        )
    return config


def collect_vlan_ids(config: dict) -> list[int]:
    """Every VLAN id the config references, in order of first appearance."""
    found: list[int] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("vlan-id",) and isinstance(value, int):
                    if value not in found:
                        found.append(value)
                elif key == "vlan" and isinstance(value, dict) and isinstance(value.get("id"), int):
                    if value["id"] not in found:
                        found.append(value["id"])
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(config)
    return found


def substitute_vlans(
    config: dict,
    available: list[int],
    *,
    report: NormalizationReport | None = None,
) -> dict:
    """
    Rewrite the example's hardcoded VLAN ids onto ones this lab actually has.

    The examples pin specific ids — ``vlan`` uses 100, ``dhcp-relay`` uses 10,
    ``multi-psk`` maps one of its keys to 100. Those numbers are illustrative.
    Applying them unchanged against a lab whose DHCP server serves, say, 20 and
    30 produces an AP that is configured perfectly and a client that never gets
    a lease — an environmental failure indistinguishable from an AP bug.

    Ids are mapped in order of first appearance onto *available*, so a config
    using two distinct VLANs gets two distinct lab VLANs. Returns the config
    unchanged when *available* is empty; the caller is expected to have skipped
    the test in that case.
    """
    if not available:
        return config

    used = collect_vlan_ids(config)
    if not used:
        return config

    mapping = {old: available[i % len(available)] for i, old in enumerate(used)}
    if len(used) > len(available) and report is not None:
        report.record(
            f"config uses {len(used)} VLANs but only {len(available)} are available "
            f"({available}); ids were reused, so segmentation between them is not tested"
        )

    def rewrite(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "vlan-id" and isinstance(value, int) and value in mapping:
                    node[key] = mapping[value]
                elif key == "vlan" and isinstance(value, dict) and value.get("id") in mapping:
                    value["id"] = mapping[value["id"]]
                else:
                    rewrite(value)
        elif isinstance(node, list):
            for item in node:
                rewrite(item)

    rewrite(config)

    changed = {o: n for o, n in mapping.items() if o != n}
    if changed and report is not None:
        pairs = ", ".join(f"{o}->{n}" for o, n in sorted(changed.items()))
        report.record(f"VLAN ids remapped to this lab's VLANs: {pairs}")
    return config


def point_radius_at(
    config: dict,
    host: str,
    secret: str,
    *,
    auth_port: int = 1812,
    acct_port: int = 1813,
    report: NormalizationReport | None = None,
) -> dict:
    """
    Rewrite every RADIUS server reference onto this lab's server, in place.

    The corpus points at ``10.0.0.1`` for enterprise SSIDs and at a public
    address for the RADIUS-backed captive portal. Neither exists on a test
    bench, so authentication is attempted against a black hole: the AP is
    configured exactly as the example intends and the client still never gets
    on, which reads as an AP defect when it is purely environmental — the same
    trap :func:`substitute_vlans` exists to avoid.

    Covers both shapes the schema uses: the ``radius`` block on an SSID, with
    its ``authentication`` / ``accounting`` sub-objects, and the flat
    ``auth-server`` / ``auth-secret`` keys on the captive service.
    """
    touched: list[str] = []

    def rewrite(node, where: str) -> None:
        if isinstance(node, dict):
            for role, port in (("authentication", auth_port), ("accounting", acct_port)):
                block = node.get(role)
                if isinstance(block, dict) and "host" in block:
                    block["host"], block["secret"] = host, secret
                    block.setdefault("port", port)
                    block["port"] = port
                    touched.append(f"{where}/{role}")
            if "auth-server" in node:
                node["auth-server"], node["auth-secret"] = host, secret
                node["auth-port"] = auth_port
                touched.append(f"{where}/captive-auth")
            if "acct-server" in node:
                node["acct-server"], node["acct-secret"] = host, secret
                node["acct-port"] = acct_port
                touched.append(f"{where}/captive-acct")
            for key, value in node.items():
                rewrite(value, key if isinstance(key, str) else where)
        elif isinstance(node, list):
            for item in node:
                rewrite(item, where)

    rewrite(config, "config")

    if touched and report is not None:
        report.record(
            f"RADIUS pointed at this lab's server {host}:{auth_port} "
            f"({len(touched)} reference(s): {', '.join(sorted(set(touched)))})"
        )
    return config


def set_strict(config: dict, strict: bool = True) -> dict:
    """
    Set the top-level ``strict`` flag in place and return the config.

    Without it the renderer *clamps* an unsupported request and carries on: ask
    for 80 MHz on a 2.4 GHz radio and ``match_htmode()`` silently falls back to
    HE40 **and deletes the pinned channel**, so the radio lands on ACS/auto.
    The apply still reports success and the test would then be validating a
    configuration nobody asked for.

    With ``strict`` set, any renderer warning rejects the apply outright, so
    "applied" means "applied as requested". The normalizer already removes the
    known-bad combinations; this catches the ones specific to the DUT's own
    radio capabilities, which cannot be known ahead of time.
    """
    config["strict"] = strict
    return config


# NOTE: the config ``uuid`` is deliberately left alone. It only drives the ubus
# result report and the /etc/ucentral/ucentral.cfg.* rotation, both of which are
# gated on the config being applied from the agent's own path. Applying from a
# custom path re-renders and re-applies in full every time regardless of uuid,
# so there is no staleness to defeat.
