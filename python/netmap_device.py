"""
NetMap Device — dataclasses for network scanning.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    state: str = "open"


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    device_type: str = "unknown"
    status: str = "online"
    ports: list = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @property
    def id(self):
        return self.mac or self.ip


@dataclass
class Edge:
    source: str
    target: str
    edge_type: str = "direct"
    latency_ms: Optional[float] = None


@dataclass
class NetworkInfo:
    interface: str
    ip: str
    prefix: int
    gateway: str
    cidr: str
    description: str


@dataclass
class ScanResult:
    scan_time: str
    network: str
    devices: list
    edges: list


class ScanCallbacks:
    def on_device_found(self, device: Device): pass
    def on_progress(self, msg: str, pct: int): pass
    def on_complete(self, result: ScanResult): pass
    def on_error(self, msg: str): pass
