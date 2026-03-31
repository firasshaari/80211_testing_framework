"""
Traffic engine abstraction — ABC and shared data classes.
Both LANforgeEngine and RPi5Engine implement this interface.
Tests only ever see this interface — never the concrete implementation.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ClientHandle:
    id: str              # LANforge port name OR RPi5 hostname
    ip: str | None
    mac: str | None
    band: str
    ssid: str
    engine: str          # "lanforge" | "rpi5"


@dataclass
class TrafficResult:
    rx_throughput_mbps: float
    tx_throughput_mbps: float
    lost_packets: int
    duration_s: float
    passed_threshold: bool | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class SSIDInfo:
    ssid: str
    bssid: str
    band: str
    channel: int
    security: str
    signal_dbm: float


class TrafficEngine(ABC):

    @abstractmethod
    def connect_client(
        self,
        ssid: str,
        password: str,
        band: str,
        security: str,
    ) -> ClientHandle:
        """Associate a client to the target SSID and return a handle with IP."""
        ...

    @abstractmethod
    def run_traffic(
        self,
        handle: ClientHandle,
        direction: str,          # "upstream" | "downstream" | "bidirectional"
        protocol: str,           # "tcp" | "udp"
        duration_s: int,
        target_rate_mbps: float,
    ) -> TrafficResult:
        """Generate traffic and return measured throughput."""
        ...

    @abstractmethod
    def disconnect_client(self, handle: ClientHandle) -> None:
        """Disassociate client and clean up."""
        ...

    @abstractmethod
    def scan_ssids(self) -> list[SSIDInfo]:
        """Return list of SSIDs visible from the client radio."""
        ...

    @abstractmethod
    def teardown(self) -> None:
        """Called by fixture finalizer — clean up all resources."""
        ...
