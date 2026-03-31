"""
AP client — SSH and serial console access to the AP.
Wraps openwrt_ctl.py pattern with proper session state management.
"""
from __future__ import annotations
import json
import logging
import time
import paramiko

log = logging.getLogger(__name__)


class APClient:

    def __init__(self, serial: str, gateway_host: str | None = None,
                 gateway_user: str = "lanforge",
                 gateway_pass: str = "lanforge",
                 serial_port: str | None = "/dev/ttyUSB0",
                 ap_user: str = "root",
                 ap_pass: str = "openwifi") -> None:
        self.serial        = serial
        self._gw_host      = gateway_host
        self._gw_user      = gateway_user
        self._gw_pass      = gateway_pass
        self._serial_port  = serial_port
        self._ap_user      = ap_user
        self._ap_pass      = ap_pass
        self._ssh: paramiko.SSHClient | None = None

    # ── SSH helpers ───────────────────────────────────────────────────────────

    def _gw_connect(self) -> paramiko.SSHClient:
        if self._ssh and self._ssh.get_transport() and \
                self._ssh.get_transport().is_active():
            return self._ssh
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self._gw_host, username=self._gw_user,
                       password=self._gw_pass, timeout=10)
        self._ssh = client
        return client

    def _serial_cmd(self, cmd: str, timeout: int = 30) -> str:
        """Run a command on the AP via serial console through the gateway."""
        if not self._gw_host or not self._serial_port:
            raise RuntimeError("No gateway host or serial port configured")
        client = self._gw_connect()
        openwrt_cmd = (
            f"cd ~/cicd-git/ && ./openwrt_ctl.py "
            f"--prompt root@{self.serial} -s serial --log stdout "
            f"--user {self._ap_user} --passwd {self._ap_pass} "
            f"-t {self._serial_port} --action cmd --value \"{cmd}\""
        )
        _, stdout, stderr = client.exec_command(openwrt_cmd, timeout=timeout + 5)
        rc  = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        if rc != 0:
            log.warning(f"Serial cmd '{cmd}' rc={rc}: {stderr.read().decode()}")
        # Extract output after the "Output for command:" marker
        if "Output for command:" in out:
            out = out.split("Output for command:", 1)[1]
            out = out.split("\n", 1)[1] if "\n" in out else out
        return out.strip()

    # ── AP commands ───────────────────────────────────────────────────────────

    def ubus_call_ucentral_status(self, retries: int = 3) -> dict:
        """Return parsed output of `ubus call ucentral status`."""
        for attempt in range(retries):
            try:
                raw = self._serial_cmd("ubus call ucentral status", timeout=30)
                return json.loads(raw)
            except (json.JSONDecodeError, RuntimeError) as e:
                log.warning(f"ubus status attempt {attempt + 1}/{retries} failed: {e}")
                time.sleep(5)
        raise RuntimeError(f"ubus call ucentral status failed after {retries} attempts")

    def get_wifi_status(self) -> dict:
        raw = self._serial_cmd("wifi status", timeout=30)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    def get_connected_clients(self) -> list[dict]:
        raw = self._serial_cmd("ubus call hostapd get_clients 2>/dev/null || echo '{}'")
        try:
            return json.loads(raw).get("clients", [])
        except json.JSONDecodeError:
            return []

    def get_firmware_version(self) -> str | None:
        out = self._serial_cmd("cat /tmp/ucentral.version 2>/dev/null || echo ''")
        return out.strip() or None

    def logread(self, lines: int = 200) -> str:
        return self._serial_cmd(f"logread | tail -n {lines}")

    def restart_ucentral(self) -> None:
        self._serial_cmd("/etc/init.d/ucentral restart", timeout=15)
        time.sleep(5)

    def close(self) -> None:
        if self._ssh:
            self._ssh.close()
            self._ssh = None
