"""
RADIUS manager — manages FreeRADIUS client and user entries
on the external infra Linux box.

Usage:
    from framework.infra.radius_manager import RADIUSManager
    mgr = RADIUSManager(infra_client)
    mgr.add_client("192.168.1.1", secret="testing123", shortname="ap1")
    mgr.add_user("testuser", "testpass")
    mgr.reload()
    mgr.remove_user("testuser")
    mgr.remove_client("192.168.1.1")
"""
from __future__ import annotations
import logging
from pathlib import PurePosixPath
from framework.clients.infra_client import InfraClient

log = logging.getLogger(__name__)

# Drop-in directories relative to freeradius_conf_dir
_CLIENTS_D  = "clients.d"
_USERS_FILE = "mods-config/files/authorize"


class RADIUSManager:
    """
    Thin manager for FreeRADIUS 3.x running on the infra box.

    * NAS clients are written as individual files under clients.d/
    * Test users are appended/removed from the authorize flat-file
    """

    def __init__(self, client: InfraClient):
        self._client = client

    # ── NAS clients ───────────────────────────────────────────────────────────

    def add_client(
        self,
        ip_or_cidr: str,
        *,
        secret: str,
        shortname: str | None = None,
        nastype: str = "other",
    ) -> None:
        """
        Create a FreeRADIUS client entry for *ip_or_cidr*.

        Parameters
        ----------
        ip_or_cidr : AP management IP or CIDR block (e.g. "192.168.1.1" or "10.0.0.0/24").
        secret     : Shared secret.
        shortname  : Human-readable label; defaults to ip_or_cidr with '/' replaced by '_'.
        nastype    : NAS type string (default "other").
        """
        name = shortname or ip_or_cidr.replace("/", "_").replace(".", "_")
        content = (
            f"client {name} {{\n"
            f"    ipaddr      = {ip_or_cidr}\n"
            f"    secret      = {secret}\n"
            f"    shortname   = {name}\n"
            f"    nas_type    = {nastype}\n"
            f"}}\n"
        )
        dest = self._client_conf_path(name)
        log.info("Writing RADIUS client '%s' → %s", name, dest)
        self._client.put_file_content(content, dest)

    def remove_client(self, ip_or_cidr: str, shortname: str | None = None) -> None:
        """Remove the client conf file for *ip_or_cidr*."""
        name = shortname or ip_or_cidr.replace("/", "_").replace(".", "_")
        dest = self._client_conf_path(name)
        log.info("Removing RADIUS client '%s' (%s)", name, dest)
        stdout, stderr, rc = self._client.exec(f"rm -f {dest}")
        if rc != 0:
            log.warning("rm failed (rc=%d): %s", rc, stderr)

    # ── Users ─────────────────────────────────────────────────────────────────

    def add_user(
        self,
        username: str,
        password: str,
        *,
        vlan_id: int | None = None,
    ) -> None:
        """
        Append a Cleartext-Password user entry to the FreeRADIUS authorize file.

        Optionally set a Tunnel-Private-Group-Id for VLAN assignment.
        """
        reply = ""
        if vlan_id is not None:
            reply = (
                f",\n\tTunnel-Type = VLAN,\n"
                f"\tTunnel-Medium-Type = IEEE-802,\n"
                f"\tTunnel-Private-Group-Id = \"{vlan_id}\""
            )
        entry = (
            f"\n# test-user:{username}\n"
            f"{username}    Cleartext-Password := \"{password}\"{reply}\n"
        )
        users_file = self._users_path()
        log.info("Appending RADIUS user '%s'", username)
        # Escape single quotes in entry for shell
        escaped = entry.replace("'", "'\\''")
        cmd = f"printf '%s' '{escaped}' >> {users_file}"
        stdout, stderr, rc = self._client.exec(cmd)
        if rc != 0:
            log.warning("add_user failed (rc=%d): %s", rc, stderr)

    def remove_user(self, username: str) -> None:
        """
        Remove all lines associated with *username* from the authorize file.
        Uses sed to delete the comment marker line and the entry line.
        """
        users_file = self._users_path()
        log.info("Removing RADIUS user '%s'", username)
        # Delete comment line + following entry line
        cmd = (
            f"sed -i '/^# test-user:{username}/,+1d' {users_file}"
        )
        stdout, stderr, rc = self._client.exec(cmd)
        if rc != 0:
            log.warning("remove_user failed (rc=%d): %s", rc, stderr)

    # ── Service control ───────────────────────────────────────────────────────

    def reload(self) -> None:
        """Reload FreeRADIUS (HUP — rereads config without dropping connections)."""
        log.info("Reloading freeradius")
        self._client.reload_service("freeradius")

    def test_auth(self, username: str, password: str, server: str = "127.0.0.1") -> bool:
        """
        Quick smoke-test using radtest.  Returns True if Access-Accept received.
        Requires radtest to be installed on the infra box.
        """
        cmd = f"radtest {username} {password} {server} 0 testing123"
        stdout, _, rc = self._client.exec(cmd)
        accepted = "Access-Accept" in stdout
        log.info("radtest %s → %s", username, "ACCEPT" if accepted else "REJECT/FAIL")
        return accepted

    # ── Internal ──────────────────────────────────────────────────────────────

    def _client_conf_path(self, name: str) -> str:
        base = self._client.freeradius_conf_dir
        return str(PurePosixPath(base) / _CLIENTS_D / f"test-{name}.conf")

    def _users_path(self) -> str:
        base = self._client.freeradius_conf_dir
        return str(PurePosixPath(base) / _USERS_FILE)
