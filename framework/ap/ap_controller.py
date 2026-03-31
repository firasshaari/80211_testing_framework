"""
High-level AP controller — combines uCentral push with AP-side verification.
"""
from __future__ import annotations
import logging

from framework.clients.controller_client import ControllerClient
from framework.clients.ap_client         import APClient

log = logging.getLogger(__name__)


class APController:

    def __init__(self, controller: ControllerClient, ap: APClient,
                 serial: str) -> None:
        self._ctrl   = controller
        self._ap     = ap
        self._serial = serial

    def push_config(self, config: dict, wait_timeout: int = 60) -> dict:
        """Push config and wait for AP to confirm it's applied and connected."""
        log.info(f"Pushing config to AP {self._serial}")
        result = self._ctrl.push_config(self._serial, config)
        status = self._ctrl.wait_for_state(self._serial, "connected",
                                           timeout=wait_timeout)
        log.info(f"AP {self._serial} connected after config push")
        return status

    def wait_for_state(self, state: str = "connected",
                       timeout: int = 60) -> dict:
        return self._ctrl.wait_for_state(self._serial, state, timeout)

    def get_ucentral_status(self) -> dict:
        return self._ap.ubus_call_ucentral_status()

    def get_wifi_status(self) -> dict:
        return self._ap.get_wifi_status()

    def get_firmware(self) -> str | None:
        return self._ap.get_firmware_version()

    def get_connected_clients(self) -> list[dict]:
        return self._ap.get_connected_clients()

    def logread(self, lines: int = 200) -> str:
        return self._ap.logread(lines=lines)
