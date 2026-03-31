"""
RPi5 + iperf3 traffic engine implementation.
Uses wpa_supplicant on the client RPi5 and iperf3 for traffic generation.
"""
from __future__ import annotations
import json
import logging
import time
import textwrap

from framework.traffic.base import TrafficEngine, ClientHandle, TrafficResult, SSIDInfo
from framework.clients.infra_client import InfraClient

log = logging.getLogger(__name__)

# Security proto → wpa_supplicant key_mgmt mapping
_KEY_MGMT = {
    "open":               "NONE",
    "wpa2":               "WPA-PSK",
    "psk2":               "WPA-PSK",
    "wpa3":               "SAE",
    "sae":                "SAE",
    "wpa3_personal_mixed": "WPA-PSK SAE",
    "sae-mixed":          "WPA-PSK SAE",
}


class RPi5Engine(TrafficEngine):

    def __init__(self, rpi5_hosts: list) -> None:
        client_host = next(h for h in rpi5_hosts if h.role == "client")
        server_host = next(h for h in rpi5_hosts if h.role == "server")

        self._client_ssh  = InfraClient(client_host.host, client_host.user, client_host.key_path)
        self._server_ssh  = InfraClient(server_host.host, server_host.user, server_host.key_path)
        self._server_host = server_host.host
        self._wifi_iface  = client_host.wifi_iface
        self._active_handle: ClientHandle | None = None

    # ── TrafficEngine implementation ──────────────────────────────────────────

    def connect_client(self, ssid, password, band, security) -> ClientHandle:
        key_mgmt = _KEY_MGMT.get(security.lower(), "WPA-PSK")
        conf = self._build_wpa_conf(ssid, password, key_mgmt)

        self._client_ssh.exec("pkill wpa_supplicant || true")
        self._client_ssh.exec("pkill dhclient || true")
        time.sleep(1)

        self._client_ssh.put_file_content(conf, "/tmp/wpa_test.conf")
        self._client_ssh.exec(f"ip link set {self._wifi_iface} down")
        self._client_ssh.exec(f"ip link set {self._wifi_iface} up")
        self._client_ssh.exec(
            f"wpa_supplicant -B -i {self._wifi_iface} -c /tmp/wpa_test.conf"
        )

        ip  = self._wait_for_ip(timeout=30)
        mac = self._get_mac()
        log.info(f"RPi5 client connected to {ssid} — IP {ip} MAC {mac}")

        self._active_handle = ClientHandle(
            id=self._client_ssh.host, ip=ip, mac=mac,
            band=band, ssid=ssid, engine="rpi5",
        )
        return self._active_handle

    def run_traffic(self, handle, direction, protocol, duration_s,
                    target_rate_mbps) -> TrafficResult:
        # Start iperf3 server
        self._server_ssh.exec("pkill iperf3 || true")
        time.sleep(0.5)
        self._server_ssh.exec("iperf3 -s -D --foregroud")

        flag_r = "-R" if direction == "downstream" else ""
        flag_u = "-u" if protocol == "udp" else ""
        flag_b = f"-b {target_rate_mbps}M"

        stdout, stderr, rc = self._client_ssh.exec(
            f"iperf3 -c {self._server_host} -t {duration_s} "
            f"{flag_b} {flag_r} {flag_u} -J"
        )
        if rc != 0 or not stdout.strip():
            raise RuntimeError(f"iperf3 failed (rc={rc}): {stderr}")

        data = json.loads(stdout)
        key = "sum_received" if direction == "downstream" else "sum_sent"
        bps  = data["end"][key]["bits_per_second"]
        lost = data["end"].get("sum", {}).get("lost_packets", 0)

        return TrafficResult(
            rx_throughput_mbps=bps / 1e6,
            tx_throughput_mbps=bps / 1e6,
            lost_packets=lost,
            duration_s=duration_s,
            raw=data,
        )

    def disconnect_client(self, handle: ClientHandle) -> None:
        self._client_ssh.exec("pkill wpa_supplicant || true")
        self._client_ssh.exec("pkill dhclient || true")
        self._client_ssh.exec(f"ip link set {self._wifi_iface} down")
        self._active_handle = None

    def scan_ssids(self) -> list[SSIDInfo]:
        stdout, _, _ = self._client_ssh.exec(
            f"iw dev {self._wifi_iface} scan 2>/dev/null"
        )
        return _parse_iw_scan(stdout)

    def teardown(self) -> None:
        try:
            self._client_ssh.exec("pkill wpa_supplicant || true")
            self._client_ssh.exec("pkill iperf3 || true")
            self._server_ssh.exec("pkill iperf3 || true")
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_wpa_conf(self, ssid: str, password: str, key_mgmt: str) -> str:
        if key_mgmt == "NONE":
            network = f'ssid="{ssid}"\n    key_mgmt=NONE'
        else:
            network = (
                f'ssid="{ssid}"\n'
                f'    key_mgmt={key_mgmt}\n'
                f'    psk="{password}"'
            )
        return textwrap.dedent(f"""\
            ctrl_interface=/var/run/wpa_supplicant
            update_config=1

            network={{
                {network}
            }}
        """)

    def _wait_for_ip(self, timeout: int = 30) -> str:
        self._client_ssh.exec(f"dhclient -v {self._wifi_iface} &")
        deadline = time.time() + timeout
        while time.time() < deadline:
            stdout, _, _ = self._client_ssh.exec(
                f"ip -4 addr show {self._wifi_iface} | grep 'inet '"
            )
            if stdout.strip():
                ip = stdout.strip().split()[1].split("/")[0]
                return ip
            time.sleep(2)
        raise TimeoutError(f"Client did not get an IP within {timeout}s")

    def _get_mac(self) -> str:
        stdout, _, _ = self._client_ssh.exec(
            f"cat /sys/class/net/{self._wifi_iface}/address"
        )
        return stdout.strip()


def _parse_iw_scan(raw: str) -> list[SSIDInfo]:
    """Minimal parser for `iw dev scan` output."""
    ssids = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if current.get("ssid"):
                ssids.append(_make_ssid_info(current))
            current = {"bssid": line.split()[1].split("(")[0]}
        elif line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("freq:"):
            freq = int(line.split(":")[1].strip())
            current["freq"] = freq
            current["band"] = "6GHz" if freq > 5900 else ("5GHz" if freq > 3000 else "2.4GHz")
        elif "DS Parameter set: channel" in line:
            current["channel"] = int(line.split("channel")[1].strip())
        elif line.startswith("signal:"):
            current["signal"] = float(line.split(":")[1].strip().split()[0])
        elif "capability:" in line.lower():
            current["security"] = "open" if "Privacy" not in line else "wpa2"
    if current.get("ssid"):
        ssids.append(_make_ssid_info(current))
    return ssids


def _make_ssid_info(d: dict) -> SSIDInfo:
    return SSIDInfo(
        ssid=d.get("ssid", ""),
        bssid=d.get("bssid", ""),
        band=d.get("band", ""),
        channel=d.get("channel", 0),
        security=d.get("security", "unknown"),
        signal_dbm=d.get("signal", 0.0),
    )
