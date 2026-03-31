"""
LANforge REST API client (port 8080).
"""
from __future__ import annotations
import logging
import time
import requests

from framework.capability.models    import RadioInfo
from framework.capability.profiles  import classify
from framework.traffic.base         import SSIDInfo

log = logging.getLogger(__name__)


class LanforgeClient:

    def __init__(self, host: str, port: int = 8080) -> None:
        self._base = f"http://{host}:{port}"
        self._session = requests.Session()

    def _get(self, path: str, **kwargs) -> dict:
        resp = self._session.get(f"{self._base}{path}", timeout=15, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = self._session.post(f"{self._base}{path}", json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    # ── Inventory ─────────────────────────────────────────────────────────────

    def get_radio_inventory(self, overrides: dict | None = None) -> list[RadioInfo]:
        """Return a list of RadioInfo for all WIFI-RADIO ports on LANforge."""
        overrides = overrides or {}
        ports = self._get("/port/list").get("interface", [])
        radios: list[RadioInfo] = []
        for p in ports:
            alias = p.get("alias", "")
            if p.get("port_type") != "WIFI-RADIO":
                continue
            chipset_raw = overrides.get(alias) or p.get("driver", "") or "unknown"
            profile = classify(chipset_raw)
            bands = self._get_radio_bands(alias)
            radios.append(RadioInfo(
                name=alias,
                chipset=chipset_raw,
                radio_type=profile.type,
                max_stations=profile.max_stations,
                wifi_gen=profile.wifi_gen,
                supported_bands=bands,
            ))
        log.info(f"LANforge radio inventory: {[r.name for r in radios]}")
        return radios

    def _get_radio_bands(self, radio_name: str) -> list[str]:
        try:
            info = self._get(f"/radio/1/1/{radio_name.split('.')[-1]}")
            bands = []
            hw = info.get("radio", {}).get("capabilities", "")
            if "2" in hw or "2.4" in hw:
                bands.append("2.4GHz")
            if "5" in hw:
                bands.append("5GHz")
            if "6" in hw:
                bands.append("6GHz")
            return bands or ["2.4GHz", "5GHz"]
        except Exception:
            return ["2.4GHz", "5GHz"]

    def get_upstream_port(self) -> str:
        ports = self._get("/port/list").get("interface", [])
        for p in ports:
            if p.get("port_type") == "ETHERNET-STA" or "eth" in p.get("alias", ""):
                return p["alias"]
        raise RuntimeError("No upstream port found on LANforge")

    # ── Stations ──────────────────────────────────────────────────────────────

    def create_station(self, radio: str, ssid: str, password: str,
                       security: str) -> str:
        resource = radio.split(".")[1] if "." in radio else "1"
        sta_name = f"sta{int(time.time()) % 100000:05d}"
        self._post("/cli-json/add_sta", {
            "shelf": 1, "resource": resource,
            "radio": radio.split(".")[-1],
            "sta_name": sta_name,
            "ssid": ssid,
            "passwd": password,
            "mode": 0,
            "flags": 0x400,       # admin-up
        })
        return f"1.{resource}.{sta_name}"

    def wait_for_ip(self, port_name: str, timeout: int = 30) -> str | None:
        deadline = time.time() + timeout
        parts = port_name.split(".")
        path = f"/port/{parts[0]}/{parts[1]}/{parts[2]}"
        while time.time() < deadline:
            try:
                info = self._get(path)
                ip = info.get("interface", {}).get("ip", "")
                if ip and ip != "0.0.0.0":
                    return ip
            except Exception:
                pass
            time.sleep(2)
        return None

    def get_port_mac(self, port_name: str) -> str:
        parts = port_name.split(".")
        info = self._get(f"/port/{parts[0]}/{parts[1]}/{parts[2]}")
        return info.get("interface", {}).get("mac", "")

    def delete_station(self, port_name: str) -> None:
        parts = port_name.split(".")
        self._post("/cli-json/rm_vlan", {
            "shelf": parts[0], "resource": parts[1], "port": parts[2],
        })

    # ── Layer-3 connections ───────────────────────────────────────────────────

    def create_layer3_cx(self, port_a: str, port_b: str, cx_type: str) -> str:
        cx_name = f"cx{int(time.time()) % 100000:05d}"
        self._post("/cli-json/add_cx", {
            "alias": cx_name, "test_mgr": "default_tm",
            "tx_endp": port_a, "rx_endp": port_b,
            "cx_type": cx_type,
        })
        return cx_name

    def start_cx(self, cx_name: str) -> None:
        self._post("/cli-json/set_cx_state", {
            "test_mgr": "default_tm", "cx_name": cx_name, "cx_state": "RUNNING",
        })

    def stop_cx(self, cx_name: str) -> None:
        self._post("/cli-json/set_cx_state", {
            "test_mgr": "default_tm", "cx_name": cx_name, "cx_state": "STOPPED",
        })

    def get_cx_stats(self, cx_name: str) -> dict:
        return self._get(f"/cx/{cx_name}").get(cx_name, {})

    def delete_cx(self, cx_name: str) -> None:
        self._post("/cli-json/rm_cx", {
            "test_mgr": "default_tm", "cx_name": cx_name,
        })

    # ── SSID scan ─────────────────────────────────────────────────────────────

    def scan_ssids(self) -> list[SSIDInfo]:
        try:
            data = self._get("/scanresults/1/1/wiphy0")
            results = []
            for entry in data.get("scan-results", []):
                results.append(SSIDInfo(
                    ssid=entry.get("ssid", ""),
                    bssid=entry.get("bss", ""),
                    band="5GHz" if int(entry.get("frequency", 0)) > 3000 else "2.4GHz",
                    channel=int(entry.get("channel", 0)),
                    security=entry.get("auth", "unknown"),
                    signal_dbm=float(entry.get("signal", 0)),
                ))
            return results
        except Exception as e:
            log.warning(f"SSID scan failed: {e}")
            return []
