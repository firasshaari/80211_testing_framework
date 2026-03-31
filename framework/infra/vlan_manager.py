"""
VLAN manager — creates and tears down 802.1Q sub-interfaces on the
external infra Linux box.

Usage:
    from framework.infra.vlan_manager import VLANManager
    mgr = VLANManager(infra_client, parent_iface="eth0")
    mgr.create_vlan(10, ip="192.168.10.1/24")
    mgr.delete_vlan(10)
"""
from __future__ import annotations
import logging
from framework.clients.infra_client import InfraClient

log = logging.getLogger(__name__)


class VLANManager:
    """
    Manages 802.1Q VLAN sub-interfaces on the infra box using `ip` commands.

    Changes are not persistent across reboots by design — tests create the
    VLANs they need at setup and tear them down at teardown.
    """

    def __init__(self, client: InfraClient, parent_iface: str = "eth0"):
        self._client       = client
        self._parent_iface = parent_iface

    # ── Public API ────────────────────────────────────────────────────────────

    def create_vlan(
        self,
        vlan_id: int,
        ip: str,
        *,
        parent: str | None = None,
        mtu: int = 1500,
    ) -> str:
        """
        Create a VLAN sub-interface and assign an IP address.

        Parameters
        ----------
        vlan_id : 802.1Q VLAN tag (1-4094).
        ip      : IP address with prefix length (e.g. "192.168.10.1/24").
        parent  : Parent interface; defaults to the one set at __init__.
        mtu     : MTU for the sub-interface (default 1500).

        Returns
        -------
        The sub-interface name, e.g. "eth0.10".
        """
        iface  = self._sub_iface(vlan_id, parent)
        log.info("Creating VLAN %d on %s → %s ip=%s", vlan_id, parent or self._parent_iface, iface, ip)

        cmds = [
            f"ip link add link {parent or self._parent_iface} name {iface} type vlan id {vlan_id}",
            f"ip link set {iface} mtu {mtu}",
            f"ip addr add {ip} dev {iface}",
            f"ip link set {iface} up",
        ]
        for cmd in cmds:
            stdout, stderr, rc = self._client.exec(cmd)
            if rc != 0:
                log.warning("cmd failed (rc=%d) cmd=%r stderr=%s", rc, cmd, stderr)
        return iface

    def delete_vlan(self, vlan_id: int, *, parent: str | None = None) -> None:
        """Bring down and delete the VLAN sub-interface."""
        iface = self._sub_iface(vlan_id, parent)
        log.info("Deleting VLAN %d (%s)", vlan_id, iface)
        cmds = [
            f"ip link set {iface} down",
            f"ip link delete {iface}",
        ]
        for cmd in cmds:
            stdout, stderr, rc = self._client.exec(cmd)
            if rc != 0:
                log.warning("cmd failed (rc=%d) cmd=%r stderr=%s", rc, cmd, stderr)

    def list_vlans(self, *, parent: str | None = None) -> list[dict]:
        """
        Return active VLAN sub-interfaces on *parent* as a list of dicts
        with keys: iface, vlan_id, ip.
        """
        p = parent or self._parent_iface
        stdout, _, rc = self._client.exec(
            f"ip -d -o link show | grep '{p}\\.' | grep 'vlan'"
        )
        if rc != 0 or not stdout.strip():
            return []
        vlans = []
        for line in stdout.splitlines():
            parts = line.split()
            iface = parts[1].rstrip("@" + p) if len(parts) > 1 else ""
            # extract vlan id from "vlan id <N>"
            try:
                idx = parts.index("id")
                vid = int(parts[idx + 1])
            except (ValueError, IndexError):
                vid = -1
            vlans.append({"iface": iface, "vlan_id": vid})
        return vlans

    def vlan_exists(self, vlan_id: int, *, parent: str | None = None) -> bool:
        """Return True if the VLAN sub-interface currently exists."""
        iface = self._sub_iface(vlan_id, parent)
        _, _, rc = self._client.exec(f"ip link show {iface}")
        return rc == 0

    # ── Internal ──────────────────────────────────────────────────────────────

    def _sub_iface(self, vlan_id: int, parent: str | None) -> str:
        return f"{parent or self._parent_iface}.{vlan_id}"
