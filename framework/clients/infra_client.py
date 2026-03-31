"""
SSH client for the external Linux infrastructure box (DHCP / RADIUS / router).
Also used for RPi5 hosts.
"""
from __future__ import annotations
import logging
import paramiko

log = logging.getLogger(__name__)


class InfraClient:

    def __init__(self, host: str, user: str, key_path: str | None = None,
                 password: str | None = None, port: int = 22) -> None:
        self.host = host
        self._user = user
        self._key_path = key_path
        self._password = password
        self._port = port
        self._client: paramiko.SSHClient | None = None

    # ── Connection ────────────────────────────────────────────────────────────

    def _connect(self) -> paramiko.SSHClient:
        if self._client and self._client.get_transport() and \
                self._client.get_transport().is_active():
            return self._client
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {"hostname": self.host, "port": self._port,
                        "username": self._user, "timeout": 10}
        if self._key_path:
            kwargs["key_filename"] = self._key_path
        if self._password:
            kwargs["password"] = self._password
        client.connect(**kwargs)
        self._client = client
        return client

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    # ── Commands ──────────────────────────────────────────────────────────────

    def exec(self, cmd: str, timeout: int = 60) -> tuple[str, str, int]:
        """Run a command and return (stdout, stderr, returncode)."""
        client = self._connect()
        log.debug(f"[{self.host}] $ {cmd}")
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        rc  = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if rc != 0:
            log.debug(f"[{self.host}] rc={rc} stderr={err.strip()}")
        return out, err, rc

    def put_file(self, local_path: str, remote_path: str) -> None:
        """Upload a local file to the remote host via SFTP."""
        client = self._connect()
        with client.open_sftp() as sftp:
            sftp.put(local_path, remote_path)
        log.debug(f"[{self.host}] uploaded {local_path} → {remote_path}")

    def put_file_content(self, content: str, remote_path: str) -> None:
        """Write a string directly to a remote file via SFTP."""
        client = self._connect()
        with client.open_sftp() as sftp:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
        log.debug(f"[{self.host}] wrote {len(content)} bytes → {remote_path}")

    def reload_service(self, name: str) -> None:
        """Reload a systemd service on the remote host."""
        _, err, rc = self.exec(f"systemctl reload {name}")
        if rc != 0:
            raise RuntimeError(f"Failed to reload {name}: {err}")
