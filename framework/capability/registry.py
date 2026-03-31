"""
CapabilityRegistry — probes all hardware at session start and builds
a TestbedCapabilities snapshot used by the skip hook and engine factory.
"""
from __future__ import annotations
import logging

from framework.capability.models   import TestbedCapabilities, RadioInfo
from framework.capability.profiles import classify

log = logging.getLogger(__name__)


class CapabilityRegistry:
    def __init__(self, config) -> None:
        self._config = config

    def probe(self) -> TestbedCapabilities:
        caps = TestbedCapabilities()

        caps.radios       = self._probe_lanforge()
        caps.has_lanforge = len(caps.radios) > 0 or self._lanforge_reachable()
        caps.has_rpi5     = self._probe_rpi5()
        caps.has_infra    = self._probe_infra()

        if caps.has_infra:
            caps.has_radius    = self._check_service("freeradius")
            caps.has_vlan_infra = True

        # Recompute derived fields after setting radios
        caps.__post_init__()

        log.info(
            f"Capabilities probed — engine={caps.best_engine} "
            f"radios={len(caps.radios)} total_sta={caps.total_sta_capacity} "
            f"radius={caps.has_radius} vlan={caps.has_vlan_infra}"
        )
        return caps

    # ── Private probe methods ─────────────────────────────────────────────────

    def _probe_lanforge(self) -> list[RadioInfo]:
        """Query LANforge for radio ports and classify each chipset."""
        if not self._config.lanforge:
            return []
        try:
            from framework.clients.lanforge_client import LanforgeClient
            client = LanforgeClient(
                host=self._config.lanforge.host,
                port=self._config.lanforge.port,
            )
            overrides = getattr(self._config.lanforge, "radio_overrides", {}) or {}
            return client.get_radio_inventory(overrides)
        except Exception as e:
            log.warning(f"LANforge probe failed: {e}")
            return []

    def _lanforge_reachable(self) -> bool:
        """Return True if LANforge host responds (even if no radios found)."""
        if not self._config.lanforge:
            return False
        try:
            import requests
            r = requests.get(
                f"http://{self._config.lanforge.host}:{self._config.lanforge.port}/",
                timeout=5,
            )
            return r.status_code < 500
        except Exception:
            return False

    def _probe_rpi5(self) -> bool:
        """Return True if all configured RPi5 hosts are SSH-reachable."""
        if not self._config.rpi5:
            return False
        try:
            from framework.clients.infra_client import InfraClient
            for h in self._config.rpi5.hosts:
                client = InfraClient(host=h.host, user=h.user, key_path=h.key_path)
                stdout, _, rc = client.exec("echo ok")
                if rc != 0 or "ok" not in stdout:
                    log.warning(f"RPi5 host {h.host} unreachable")
                    return False
            return True
        except Exception as e:
            log.warning(f"RPi5 probe failed: {e}")
            return False

    def _probe_infra(self) -> bool:
        """Return True if the infra (DHCP/RADIUS) box is SSH-reachable."""
        if not self._config.infra:
            return False
        try:
            from framework.clients.infra_client import InfraClient
            client = InfraClient(
                host=self._config.infra.host,
                user=self._config.infra.user,
                key_path=self._config.infra.key_path,
            )
            _, _, rc = client.exec("echo ok")
            return rc == 0
        except Exception as e:
            log.warning(f"Infra probe failed: {e}")
            return False

    def _check_service(self, service: str) -> bool:
        """Return True if a systemd service is active on the infra box."""
        if not self._config.infra:
            return False
        try:
            from framework.clients.infra_client import InfraClient
            client = InfraClient(
                host=self._config.infra.host,
                user=self._config.infra.user,
                key_path=self._config.infra.key_path,
            )
            _, _, rc = client.exec(f"systemctl is-active {service}")
            return rc == 0
        except Exception:
            return False

    def select_traffic_engine(self, capabilities: TestbedCapabilities):
        """Factory — returns the best available TrafficEngine instance."""
        if capabilities.has_lanforge and self._config.lanforge:
            from framework.clients.lanforge_client import LanforgeClient
            from framework.traffic.lanforge_engine  import LANforgeEngine
            client = LanforgeClient(
                host=self._config.lanforge.host,
                port=self._config.lanforge.port,
            )
            return LANforgeEngine(client, capabilities)

        if capabilities.has_rpi5 and self._config.rpi5:
            from framework.traffic.rpi5_engine import RPi5Engine
            return RPi5Engine(self._config.rpi5.hosts)

        return None
