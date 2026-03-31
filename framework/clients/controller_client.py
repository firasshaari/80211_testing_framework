"""
uCentral controller REST API client.
Handles authentication, config push, device status queries.
"""
from __future__ import annotations
import logging
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


class ControllerClient:

    def __init__(self, base_url: str, username: str, password: str,
                 verify_ssl: bool = False) -> None:
        self._base    = base_url.rstrip("/")
        self._user    = username
        self._pass    = password
        self._verify  = verify_ssl
        self._token: str | None = None
        self._session = requests.Session()

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _authenticate(self) -> None:
        resp = self._session.post(
            f"{self._base}/api/v1/oauth2",
            json={"userId": self._user, "password": self._pass},
            verify=self._verify, timeout=15,
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        self._session.headers.update({"Authorization": f"Bearer {self._token}"})
        log.debug("uCentral authentication successful")

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json"}

    # ── Device operations ─────────────────────────────────────────────────────

    def push_config(self, serial: str, config: dict) -> dict:
        """Push a uCentral JSON configuration to the AP."""
        payload = {"configuration": config, "serialNumber": serial, "UUID": 1}
        resp = self._session.post(
            f"{self._base}/api/v1/device/{serial}/configure",
            json=payload, headers=self._headers(),
            verify=self._verify, timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("errorCode", 0) != 0:
            log.warning(f"Config push returned errorCode={result['errorCode']}: "
                        f"{result.get('errorText')}")
        return result

    def get_device_status(self, serial: str) -> dict:
        """Return the latest device status from the controller."""
        resp = self._session.get(
            f"{self._base}/api/v1/device/{serial}/status",
            headers=self._headers(), verify=self._verify, timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def get_device_info(self, serial: str) -> dict:
        """Return device record (firmware, model, etc.)."""
        resp = self._session.get(
            f"{self._base}/api/v1/device/{serial}",
            headers=self._headers(), verify=self._verify, timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def wait_for_state(self, serial: str, state: str = "connected",
                       timeout: int = 60) -> dict:
        """Poll device status until it reaches the expected state."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status = self.get_device_status(serial)
                if status.get("connected"):
                    return status
            except Exception as e:
                log.debug(f"Status poll error: {e}")
            time.sleep(3)
        raise TimeoutError(
            f"AP {serial} did not reach state '{state}' within {timeout}s"
        )

    def reboot(self, serial: str) -> None:
        self._session.post(
            f"{self._base}/api/v1/device/{serial}/reboot",
            headers=self._headers(), verify=self._verify, timeout=15,
        ).raise_for_status()
