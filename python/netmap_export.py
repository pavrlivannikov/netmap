#!/usr/bin/env python3
"""
NetMap Export — save scan results to various formats.
No external dependencies; JSON (stdlib json), CSV (stdlib csv.writer).
"""
import json
import csv
import os
from dataclasses import asdict
from typing import Optional

from netmap_device import ScanResult, Device, Edge, Port


# ── Helpers ──────────────────────────────────────────────────────

def _ensure_dir(path: str) -> str:
    """Create parent directories if needed and return absolute path."""
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    return os.path.abspath(path)


def _sanitize(s) -> str:
    """Convert None/empty to empty string."""
    if s is None:
        return ""
    return str(s)


# ── JSON ─────────────────────────────────────────────────────────

def export_json(result: ScanResult, path: str) -> str:
    """Save ScanResult to a human-readable JSON file.

    Args:
        result: Completed scan result.
        path:   Destination file path.

    Returns:
        Absolute path to the written file.
    """
    path = _ensure_dir(path)

    data = {
        "scan_time": result.scan_time,
        "network": result.network,
        "devices": [
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.hostname,
                "vendor": d.vendor,
                "os": d.os,
                "device_type": d.device_type,
                "status": d.status,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "state": p.state,
                    }
                    for p in (d.ports or [])
                ],
            }
            for d in result.devices
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "edge_type": e.edge_type,
                "latency_ms": e.latency_ms,
            }
            for e in result.edges
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return path


# ── CSV ──────────────────────────────────────────────────────────

def export_csv(result: ScanResult, path: str) -> str:
    """Save device table to CSV using only stdlib csv.writer.

    Args:
        result: Completed scan result.
        path:   Destination file path (.csv).

    Returns:
        Absolute path to the written file.
    """
    path = _ensure_dir(path)

    fieldnames = [
        "ip", "mac", "hostname", "vendor", "os",
        "device_type", "status", "open_ports", "first_seen", "last_seen",
    ]

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)

        for d in result.devices:
            ports_str = ", ".join(
                f"{p.port}/{p.protocol}" + (f"({p.service})" if p.service else "")
                for p in (d.ports or [])
            )
            writer.writerow([
                d.ip,
                d.mac,
                _sanitize(d.hostname),
                _sanitize(d.vendor),
                _sanitize(d.os),
                d.device_type,
                d.status,
                ports_str,
                _sanitize(d.first_seen),
                _sanitize(d.last_seen),
            ])

    return path


# ── Graphviz DOT ─────────────────────────────────────────────────

def export_topology_dot(result: ScanResult, path: str) -> str:
    """Generate a Graphviz DOT file for the network topology graph.

    Devices become nodes; edges become connections.
    Use: dot -Tpng topology.dot -o topology.png

    Args:
        result: Completed scan result (must have devices + edges).
        path:   Destination file path (.dot).

    Returns:
        Absolute path to the written file.
    """
    path = _ensure_dir(path)

    # Build a lookup for device labels
    device_labels: dict = {}
    for d in result.devices:
        node_id = d.mac or d.ip
        label_parts = [d.ip]
        if d.hostname:
            label_parts.append(d.hostname)
        if d.vendor:
            label_parts.append(d.vendor)
        device_labels[node_id] = "\\n".join(label_parts)

    # Determine shape/color by device_type
    def node_attrs(d: Device) -> str:
        if d.device_type in ("switch", "router", "network-device"):
            return 'shape=box, style=filled, fillcolor="#d4e6ff"'
        return 'shape=ellipse, style=filled, fillcolor="#e6ffe6"'

    lines = [
        "// NetMap Topology Graph",
        f'// Scan: {result.scan_time}  Network: {result.network}',
        "digraph NetMapTopology {",
        "  rankdir=LR;",
        '  node [fontname="Helvetica", fontsize=10];',
        '  edge [fontname="Helvetica", fontsize=8, color="#666666"];',
        "",
        "  // ── Devices ──",
    ]

    for d in result.devices:
        node_id = d.mac or d.ip
        label = device_labels.get(node_id, d.ip).replace('"', '\\"')
        attrs = node_attrs(d)
        lines.append(f'  "{node_id}" [{attrs}, label="{label}"];')

    lines.append("")
    lines.append("  // ── Connections ──")

    for e in result.edges:
        src_label = device_labels.get(e.source, e.source).replace('"', '\\"').split("\\n")[0]
        tgt_label = device_labels.get(e.target, e.target).replace('"', '\\"').split("\\n")[0]
        attrs = []
        if e.edge_type == "wireless":
            attrs.append('style=dashed')
        if e.latency_ms is not None:
            attrs.append(f'label="{e.latency_ms:.1f}ms"')
        attr_str = ", ".join(attrs) if attrs else ""
        lines.append(f'  "{e.source}" -> "{e.target}" [{attr_str}];')

    lines.append("}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return path


# ── Markdown ─────────────────────────────────────────────────────

def export_markdown(result: ScanResult, path: str) -> str:
    """Export device list as a Markdown table.

    Args:
        result: Completed scan result.
        path:   Destination file path (.md).

    Returns:
        Absolute path to the written file.
    """
    path = _ensure_dir(path)

    lines = [
        f"# NetMap Scan Report",
        "",
        f"**Scan time:** {result.scan_time}",
        f"**Network:** {result.network}",
        f"**Devices:** {len(result.devices)}",
        f"**Edges:** {len(result.edges)}",
        "",
        "## Devices",
        "",
    ]

    # Table header
    headers = ["IP", "MAC", "Hostname", "Vendor", "OS", "Type", "Status", "Open Ports"]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join([" --- "] * len(headers)) + "|")

    # Table rows
    for d in result.devices:
        ports_str = ", ".join(
            f"{p.port}/{p.protocol}" + (f" ({p.service})" if p.service else "")
            for p in (d.ports or [])
        )
        row = [
            d.ip,
            d.mac or "—",
            d.hostname or "—",
            d.vendor or "—",
            d.os or "—",
            d.device_type,
            d.status,
            ports_str or "—",
        ]
        lines.append("| " + " | ".join(row) + " |")

    # Edges section (if topology data present)
    if result.edges:
        lines.append("")
        lines.append("## Topology")
        lines.append("")
        lines.append("| Source | Target | Type | Latency |")
        lines.append("| --- | --- | --- | --- |")
        for e in result.edges:
            latency = f"{e.latency_ms:.1f} ms" if e.latency_ms is not None else "—"
            lines.append(f"| {e.source} | {e.target} | {e.edge_type} | {latency} |")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return path
