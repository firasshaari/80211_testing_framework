"""
DHCP manager — manages dnsmasq leases and DHCP pool configuration
on the external infra Linux box.

Usage:
    from framework.infra.dhcp_manager import DHCPManager
    mgr = DHCPManager(infra_client)
    mgr.add_pool("vlan10", "192.168.10.100", "192.168.10.200", "255.255.255.0",
                 gateway="192.168.10.1", dns="8.8.8.8", lease_time="1h")
    mgr.reload()
    mgr.remove_pool("vlan10")
"""
from __future__ import annotations
import logging
from pathlib import PurePosixPath
from framework.clients.infra_client import InfraClient

log = logging.getLogger(__name__)


class DHCPManager:
    """
    Manages per-VLAN dnsmasq DHCP pool configuration files.

    Each pool gets its own drop-in file under dnsmasq_conf_dir so that
    pools can be added/removed independently without touching global config.
    """

    def __init__(self, client: InfraClient):
        self._client = client

    # ── Public API ────────────────────────────────────────────────────────────

    def add_pool(
        self,
        name: str,
        range_start: str,
        range_end: str,
        netmask: str,
        *,
        gateway: str,
        dns: str = "8.8.8.8",
        lease_time: str = "1h",
        interface: str | None = None,
    ) -> None:
        """
        Write a dnsmasq conf snippet that enables a DHCP pool for *name*.

        Parameters
        ----------
        name        : Unique pool name, becomes the filename (e.g. "vlan10").
        range_start : First IP in the pool.
        range_end   : Last IP in the pool.
        netmask     : Subnet mask for the pool (e.g. "255.255.255.0").
        gateway     : Default gateway option sent to clients.
        dns         : DNS server option sent to clients.
        lease_time  : dnsmasq lease duration string (e.g. "1h", "24h").
        interface   : Bind pool to this interface (e.g. "eth0.10"). If None,
                      dnsmasq serves the pool on whichever interface is in range.
        """
        lines = []
        if interface:
            lines.append(f"interface={interface}")
        lines += [
            f"dhcp-range={range_start},{range_end},{netmask},{lease_time}",
            f"dhcp-option=3,{gateway}",   # option 3 = router
            f"dhcp-option=6,{dns}",        # option 6 = DNS
        ]
        content = "\n".join(lines) + "\n"
        dest = self._conf_path(name)
        log.info("Writing DHCP pool '%s' → %s", name, dest)
        self._client.put_file_content(content, dest)

    def remove_pool(self, name: str) -> None:
        """Delete the dnsmasq conf snippet for *name* and reload."""
        dest = self._conf_path(name)
        log.info("Removing DHCP pool '%s' (%s)", name, dest)
        stdout, stderr, rc = self._client.exec(f"rm -f {dest}")
        if rc != 0:
            log.warning("rm failed (rc=%d): %s", rc, stderr)

    def reload(self) -> None:
        """Reload dnsmasq without dropping existing leases (SIGHUP)."""
        log.info("Reloading dnsmasq")
        self._client.reload_service("dnsmasq")

    def flush_leases(self) -> None:
        """Stop dnsmasq, clear the lease database, and restart."""
        log.info("Flushing dnsmasq leases")
        stdout, stderr, rc = self._client.exec(
            "systemctl stop dnsmasq && "
            "rm -f /var/lib/misc/dnsmasq.leases && "
            "systemctl start dnsmasq"
        )
        if rc != 0:
            log.warning("flush_leases error (rc=%d): %s", rc, stderr)

    def get_leases(self) -> list[dict]:
        """
        Return the current lease table as a list of dicts with keys:
        expire, mac, ip, hostname, client_id.
        """
        stdout, _, rc = self._client.exec("cat /var/lib/misc/dnsmasq.leases")
        if rc != 0:
            return []
        leases = []
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                leases.append({
                    "expire":    parts[0],
                    "mac":       parts[1],
                    "ip":        parts[2],
                    "hostname":  parts[3],
                    "client_id": parts[4] if len(parts) > 4 else "",
                })
        return leases

    # ── Internal ──────────────────────────────────────────────────────────────

    def _conf_path(self, name: str) -> str:
        base = self._client.dnsmasq_conf_dir
        return str(PurePosixPath(base) / f"test-pool-{name}.conf")
