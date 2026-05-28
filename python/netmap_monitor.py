"""
NetMap Monitor — diff engine and serialization for ScanResult.
"""
import json
from dataclasses import asdict

try:
    from .netmap_device import Device, Port, Edge, ScanResult
except ImportError:
    from netmap_device import Device, Port, Edge, ScanResult


def monitor_diff(previous: ScanResult, current: ScanResult) -> dict:
    prev_ips = {d.ip: d for d in previous.devices}
    curr_ips = {d.ip: d for d in current.devices}

    appeared = [d for ip, d in curr_ips.items() if ip not in prev_ips]
    disappeared = [d for ip, d in prev_ips.items() if ip not in curr_ips]
    changed = []
    for ip in prev_ips.keys() & curr_ips.keys():
        prev_ports = {p.port for p in prev_ips[ip].ports}
        curr_set = {p.port for p in curr_ips[ip].ports}
        if prev_ports != curr_set:
            changed.append({"ip": ip, "prev": sorted(prev_ports), "curr": sorted(curr_set)})

    return {
        "appeared": [asdict(d) for d in appeared],
        "disappeared": [asdict(d) for d in disappeared],
        "changed": changed,
        "previous_count": len(previous.devices),
        "current_count": len(current.devices),
    }


def save_result(result: ScanResult, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, indent=2, ensure_ascii=False)


def load_result(path: str) -> ScanResult:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    devices = []
    for d in data.get("devices", []):
        dev = Device(
            ip=d.get("ip", ""), mac=d.get("mac", ""),
            hostname=d.get("hostname"), vendor=d.get("vendor"),
            os=d.get("os"), device_type=d.get("device_type", "unknown"),
            status=d.get("status", "online"),
            first_seen=d.get("first_seen"), last_seen=d.get("last_seen"),
        )
        dev.ports = [Port(**p) for p in d.get("ports", [])]
        devices.append(dev)
    edges = [Edge(**e) for e in data.get("edges", [])]
    return ScanResult(scan_time=data.get("scan_time", ""),
                      network=data.get("network", ""),
                      devices=devices, edges=edges)
