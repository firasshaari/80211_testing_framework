"""
Shared SSH session.

Both endpoints in this testbed are reached by password rather than key: the AP
ships with root/openwifi, and the RPi5 is a stock RPi OS install whose user
needs a password for ``sudo``. Key auth is still supported and preferred when a
``key_path`` is given.
"""
from __future__ import annotations

import logging
import shlex
import socket
import time
from dataclasses import dataclass

import paramiko

log = logging.getLogger(__name__)

# A non-login SSH shell on Debian/RPi OS gets a PATH without the sbin
# directories, so `iw`, `wpa_supplicant`, `rfkill` and `dhcpcd` are installed
# but unfindable. sudo is unaffected (sudoers `secure_path` covers them), which
# makes the failure look intermittent: the same tool works with sudo=True and
# reports "command not found" without it. Every command gets the sbin
# directories appended.
_SBIN_PATH = "/usr/local/sbin:/usr/sbin:/sbin"


class SSHError(RuntimeError):
    pass


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    rc: int

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def check(self) -> "CommandResult":
        if not self.ok:
            raise SSHError(
                f"Command failed (rc={self.rc}): {self.command}\n"
                f"stdout: {self.stdout.strip()}\nstderr: {self.stderr.strip()}"
            )
        return self


class SSHSession:
    """A lazily-connected, auto-reconnecting SSH session."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str | None = None,
        *,
        key_path: str | None = None,
        port: int = 22,
        sudo_password: str | None = None,
        connect_timeout: int = 15,
        label: str = "",
    ) -> None:
        self.host = host
        self.user = user
        self.label = label or host
        self._password = password
        self._key_path = key_path
        self._port = port
        # Falls back to the login password, which is the common RPi OS case.
        self._sudo_password = sudo_password or password
        self._connect_timeout = connect_timeout
        self._client: paramiko.SSHClient | None = None

    # ── Connection ───────────────────────────────────────────────────────────

    def connect(self) -> paramiko.SSHClient:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.host,
            "username": self.user,
            "port": self._port,
            "timeout": self._connect_timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self._key_path:
            kwargs["key_filename"] = self._key_path
        else:
            kwargs["password"] = self._password

        try:
            client.connect(**kwargs)
        except (paramiko.SSHException, socket.error, OSError) as exc:
            raise SSHError(f"Cannot SSH to {self.label} ({self.user}@{self.host}): {exc}") from exc

        transport = client.get_transport()
        if transport is not None:
            # A test spends long stretches idle — an AP apply takes 45-60s with
            # nothing on the station's session — and an idle connection gets
            # reaped somewhere in between, leaving a socket that still reports
            # active and then fails on the next command. Keepalives stop the
            # connection going quiet for long enough to be collected.
            transport.set_keepalive(15)

        self._client = client
        log.debug("SSH connected to %s", self.label)
        return client

    def is_reachable(self) -> bool:
        try:
            return self.run("echo ok", timeout=10).stdout.strip() == "ok"
        except SSHError:
            return False

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self) -> "SSHSession":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── Execution ────────────────────────────────────────────────────────────

    def run(self, command: str, *, timeout: int = 60, sudo: bool = False) -> CommandResult:
        """
        Run *command* and return its result. Never raises on a non-zero exit —
        call :meth:`CommandResult.check` when the caller wants that.
        """
        client = self.connect()
        actual = command
        if sudo:
            # -S reads the password from stdin; -p '' keeps the prompt out of stderr.
            actual = f"sudo -S -p '' {command}"
        actual = f'export PATH="$PATH:{_SBIN_PATH}"; {actual}'

        try:
            stdin, stdout, stderr = self._open_channel(client, actual, timeout)
            if sudo and self._sudo_password:
                stdin.write(self._sudo_password + "\n")
                stdin.flush()
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, socket.error, OSError) as exc:
            raise SSHError(f"{self.label}: command transport failed: {command}: {exc}") from exc

        if rc != 0:
            log.debug("%s: rc=%s for %s", self.label, rc, command)
        return CommandResult(command=command, stdout=out, stderr=err, rc=rc)

    def _open_channel(self, client, command: str, timeout: int):
        """
        Start *command*, reconnecting once if the session died while idle.

        The retry is deliberately confined to opening the channel. Failing here
        means the command was never delivered, so running it again is safe;
        once output is being read the command *has* run, and a blind retry could
        apply a config or start a DHCP client twice.
        """
        try:
            return client.exec_command(command, timeout=timeout, get_pty=False)
        except (paramiko.SSHException, socket.error, OSError) as exc:
            log.warning("%s: session went stale (%s); reconnecting", self.label, exc)
            self.close()
            client = self.connect()
            return client.exec_command(command, timeout=timeout, get_pty=False)

    def run_checked(self, command: str, *, timeout: int = 60, sudo: bool = False) -> str:
        return self.run(command, timeout=timeout, sudo=sudo).check().stdout

    # ── File transfer ────────────────────────────────────────────────────────

    def put_text(self, content: str, remote_path: str, *, retries: int = 2) -> None:
        """
        Write *content* to *remote_path*, creating parent directories.

        SFTP is tried first and retried, because a transient failure here used
        to fall straight through to the shell fallback and then die on large
        payloads — surfacing as "Connection reset by peer" with the heredoc
        marker in the traceback rather than anything resembling the real cause.
        """
        parent = remote_path.rsplit("/", 1)[0]
        if parent:
            self.run(f"mkdir -p {shlex.quote(parent)}")

        last: Exception | None = None
        for attempt in range(retries + 1):
            try:
                client = self.connect()
                sftp = client.open_sftp()
                try:
                    with sftp.open(remote_path, "w") as fh:
                        fh.write(content)
                    return
                finally:
                    sftp.close()
            except (paramiko.SSHException, OSError) as exc:
                last = exc
                log.debug("SFTP upload attempt %s failed: %s", attempt + 1, exc)
                self.close()
                time.sleep(1)

        log.warning(
            "SFTP unavailable after %s attempts (%s); falling back to a chunked "
            "shell upload", retries + 1, last
        )
        self._put_text_via_shell(content, remote_path)

    # dropbear's command line is limited, so large files go up in pieces.
    # Chunks are shell-quoted before sending, which costs a few characters per
    # quote in the content, so this leaves generous headroom under the buffer.
    _CHUNK_BYTES = 4096

    def _put_text_via_shell(self, content: str, remote_path: str) -> None:
        """
        Fallback upload for images whose dropbear has no SFTP subsystem.

        Sent in chunks and appended, because a single command carrying a whole
        config — ``captive-webroot`` is over 250 KB — overruns the remote
        command buffer and the connection is reset mid-transfer.

        Each chunk goes through ``printf '%s'``, which writes exactly the bytes
        it is given. The obvious alternative, a quoted heredoc, silently appends
        a newline per chunk: harmless between JSON tokens, but a raw newline
        inside a string literal is invalid JSON, so a config whose 8 KB boundary
        landed mid-string was corrupted the same way on every retry.
        ``data-plane`` and ``captive-webroot`` both did. ``base64`` is not
        available on this firmware, so it is not an option here.
        """
        quoted = shlex.quote(remote_path)
        self.run(f": > {quoted}").check()
        for start in range(0, len(content), self._CHUNK_BYTES):
            chunk = content[start:start + self._CHUNK_BYTES]
            # Only the format string interprets escapes; the argument is
            # written verbatim, so JSON backslashes and % survive intact.
            self.run(
                f"printf '%s' {shlex.quote(chunk)} >> {quoted}", timeout=120
            ).check()

        # A truncated config is worse than a failed upload — it may still parse.
        size = self.run(f"wc -c < {quoted}").stdout.strip()
        expected = len(content.encode())
        if size.isdigit() and int(size) != expected:
            raise SSHError(
                f"Upload of {remote_path} is {size} bytes, expected {expected}"
            )

    def read_text(self, remote_path: str) -> str:
        return self.run(f"cat {shlex.quote(remote_path)}").check().stdout

    def exists(self, remote_path: str) -> bool:
        return self.run(f"test -e {shlex.quote(remote_path)}").ok

    # ── Waiting ──────────────────────────────────────────────────────────────

    def wait_until_reachable(self, timeout: int = 180, interval: int = 5) -> bool:
        """Poll until the host answers, e.g. across a reboot."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.close()
            if self.is_reachable():
                return True
            time.sleep(interval)
        return False
