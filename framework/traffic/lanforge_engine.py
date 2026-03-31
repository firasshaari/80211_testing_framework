"""
LANforge traffic engine implementation.
Translates TrafficEngine calls into LANforge REST API operations.
"""
from __future__ import annotations
import logging
import time

from framework.traffic.base import TrafficEngine, ClientHandle, TrafficResult, SSIDInfo

log = logging.getLogger(__name__)


class LANforgeEngine(TrafficEngine):

    def __init__(self, client, capabilities) -> None:
        self._client = client
        self._caps   = capabilities
        self._stations: list[str] = []
        self._cxs: list[str]      = []

    def connect_client(self, ssid, password, band, security) -> ClientHandle:
        radio = self._pick_radio(band)
        sta_name = self._client.create_station(radio, ssid, password, security)
        self._stations.append(sta_name)
        ip = self._client.wait_for_ip(sta_name, timeout=30)
        mac = self._client.get_port_mac(sta_name)
        log.info(f"LANforge station {sta_name} connected — IP {ip}")
        return ClientHandle(id=sta_name, ip=ip, mac=mac,
                            band=band, ssid=ssid, engine="lanforge")

    def run_traffic(self, handle, direction, protocol, duration_s,
                    target_rate_mbps) -> TrafficResult:
        cx_type = "lf_udp" if protocol == "udp" else "lf_tcp"
        upstream = self._client.get_upstream_port()
        cx_name = self._client.create_layer3_cx(
            port_a=handle.id, port_b=upstream, cx_type=cx_type,
        )
        self._cxs.append(cx_name)

        self._client.start_cx(cx_name)
        time.sleep(duration_s)
        stats = self._client.get_cx_stats(cx_name)
        self._client.stop_cx(cx_name)

        rx_bps = stats.get("rx-bps", 0)
        tx_bps = stats.get("tx-bps", 0)
        return TrafficResult(
            rx_throughput_mbps=rx_bps / 1e6,
            tx_throughput_mbps=tx_bps / 1e6,
            lost_packets=stats.get("dropped", 0),
            duration_s=duration_s,
            raw=stats,
        )

    def disconnect_client(self, handle: ClientHandle) -> None:
        self._client.delete_station(handle.id)
        if handle.id in self._stations:
            self._stations.remove(handle.id)

    def scan_ssids(self) -> list[SSIDInfo]:
        return self._client.scan_ssids()

    def teardown(self) -> None:
        for cx in self._cxs:
            try:
                self._client.stop_cx(cx)
                self._client.delete_cx(cx)
            except Exception:
                pass
        for sta in self._stations:
            try:
                self._client.delete_station(sta)
            except Exception:
                pass
        self._cxs.clear()
        self._stations.clear()

    def _pick_radio(self, band: str) -> str:
        """Select the first LANforge radio that supports the requested band."""
        band_map = {"2G": "2.4GHz", "5G": "5GHz", "6G": "6GHz"}
        target = band_map.get(band.upper(), band)
        for radio in self._caps.radios:
            if target in radio.supported_bands:
                return radio.name
        raise RuntimeError(f"No LANforge radio found for band {band}")
