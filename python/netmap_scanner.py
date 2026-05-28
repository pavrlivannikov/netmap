"""
NetMap Scanner — high-level scan scenarios (quick, discover, deep, topology).

This module is the backward-compatible entry point. All public symbols from
sub-modules are re-exported here so that existing imports like:

    from netmap_scanner import Device, scan_quick, discover_networks

continue to work.
"""
from datetime import datetime

# ── Re-export dataclasses ────────────────────────────────────────
try:
    from .netmap_device import (
        Device, Port, Edge, NetworkInfo, ScanResult, ScanCallbacks,
    )
except ImportError:
    from netmap_device import (
        Device, Port, Edge, NetworkInfo, ScanResult, ScanCallbacks,
    )

# ── Re-export utilities ─────────────────────────────────────────
try:
    from .netmap_utils import (
        COMMON_PORTS, SERVICE_MAP,
        _is_windows, _run, _check_output, _is_valid_ip, _is_valid_mac,
        _count_dots, _mask_to_prefix, expand_subnet, is_ip_in_subnet,
        _guess_gw, _get_gateway, _resolve_hostname,
        _find_gateway_linux, _find_gateway_win, _find_gateway_for_iface_win,
        _sort_networks,
        oui_lookup, guess_device_type,
        check_port, scan_ports, guess_os_by_ttl,
        _parse_arp_win, _parse_arp_linux, _parse_ip_neigh,
        _run_ps_arp, _nmap_scan, _find_device_by_name,
    )
except ImportError:
    from netmap_utils import (
        COMMON_PORTS, SERVICE_MAP,
        _is_windows, _run, _check_output, _is_valid_ip, _is_valid_mac,
        _count_dots, _mask_to_prefix, expand_subnet, is_ip_in_subnet,
        _guess_gw, _get_gateway, _resolve_hostname,
        _find_gateway_linux, _find_gateway_win, _find_gateway_for_iface_win,
        _sort_networks,
        oui_lookup, guess_device_type,
        check_port, scan_ports, guess_os_by_ttl,
        _parse_arp_win, _parse_arp_linux, _parse_ip_neigh,
        _run_ps_arp, _nmap_scan, _find_device_by_name,
    )

# ── Re-export discovery ─────────────────────────────────────────
try:
    from .netmap_discovery import (
        discover_networks, arp_scan, arp_scan_subnet,
        ping_host, ping_sweep,
        _win32_get_adapters, _win32_get_arp_table,
        _discover_windows, _discover_windows_netsh, _discover_windows_ipconfig,
        _discover_linux,
    )
except ImportError:
    from netmap_discovery import (
        discover_networks, arp_scan, arp_scan_subnet,
        ping_host, ping_sweep,
        _win32_get_adapters, _win32_get_arp_table,
        _discover_windows, _discover_windows_netsh, _discover_windows_ipconfig,
        _discover_linux,
    )

# ── Re-export monitor ───────────────────────────────────────────
try:
    from .netmap_monitor import monitor_diff, save_result, load_result
except ImportError:
    from netmap_monitor import monitor_diff, save_result, load_result


# ── High-level scan scenarios ───────────────────────────────────

def scan_quick(subnet: str, callbacks=None) -> ScanResult:
    """Быстрый: только ARP."""
    if callbacks:
        callbacks.on_progress("ARP scan...", 10)
    devices = arp_scan_subnet(subnet, callbacks)
    if callbacks:
        callbacks.on_progress(f"Found {len(devices)} devices", 100)

    gw = _get_gateway(subnet)
    edges = [Edge(source=d.id, target=gw, edge_type="direct")
             for d in devices if gw and d.ip != gw]

    return ScanResult(scan_time=datetime.now().isoformat(), network=subnet,
                      devices=devices, edges=edges)


def scan_discover(subnet: str, callbacks=None) -> ScanResult:
    """Обзор: ARP + ICMP sweep + порты + OS guess."""
    if callbacks:
        callbacks.on_progress("ARP scan...", 5)

    devices = arp_scan_subnet(subnet, callbacks)
    known_ips = {d.ip for d in devices}

    if callbacks:
        callbacks.on_progress(f"ARP: {len(devices)} devices", 15)

    # ICMP sweep for remaining
    all_ips = expand_subnet(subnet)
    remaining = [ip for ip in all_ips if ip not in known_ips
                 and "169.254." not in ip]
    if remaining:
        if callbacks:
            callbacks.on_progress(f"ICMP sweep {len(remaining)} hosts...", 20)
        new_devices = ping_sweep(remaining, callbacks, workers=5)
        devices.extend(new_devices)

    if callbacks:
        callbacks.on_progress(f"Total: {len(devices)}. Ports...", 50)

    # Port scan + OS
    last_pct = [50]
    for i, d in enumerate(devices):
        d.ports = scan_ports(d.ip, COMMON_PORTS, timeout=0.3)
        if not d.os:
            d.os = guess_os_by_ttl(d.ip)
        if d.device_type == "unknown" and d.ports:
            d.device_type = guess_device_type(d.hostname or "", d.ports)
        if callbacks:
            pct = 50 + (i + 1) * 45 // max(len(devices), 1)
            if pct > last_pct[0]:
                last_pct[0] = pct
                callbacks.on_progress(f"Ports: {d.ip} ({len(d.ports)} open)", pct)

    gw = _get_gateway(subnet)
    edges = [Edge(source=d.id, target=gw, edge_type="direct")
             for d in devices if gw and d.ip != gw]

    if callbacks:
        callbacks.on_progress(f"Done: {len(devices)} devices", 100)

    return ScanResult(scan_time=datetime.now().isoformat(), network=subnet,
                      devices=devices, edges=edges)


def scan_deep(subnet: str, callbacks=None) -> ScanResult:
    """Глубокое: discover + nmap OS (если доступен)."""
    if callbacks:
        callbacks.on_progress("Deep scan...", 10)

    result = scan_discover(subnet, callbacks)

    for i, d in enumerate(result.devices):
        os_info, ports = _nmap_scan(d.ip)
        if os_info:
            d.os = os_info
        if ports:
            known = {p.port for p in d.ports}
            for p in ports:
                if p.port not in known:
                    d.ports.append(p)
            d.ports.sort(key=lambda p: p.port)
        if callbacks:
            callbacks.on_progress(
                f"Deep: {d.ip}",
                60 + (i + 1) * 35 // max(len(result.devices), 1))

    gw = _get_gateway(subnet)
    result.edges = [Edge(source=d.id, target=gw, edge_type="direct")
                    for d in result.devices if d.ip != gw]

    if callbacks:
        callbacks.on_progress(f"Deep: {len(result.devices)} devices", 100)

    return result


def scan_topology(subnet: str, callbacks=None, community: str = "public") -> ScanResult:
    """Топология: ARP + SNMP (LLDP + FDB) → реальные связи."""
    if callbacks:
        callbacks.on_progress("ARP scan...", 5)

    devices = arp_scan_subnet(subnet, callbacks)
    if callbacks:
        callbacks.on_progress(f"ARP: {len(devices)} devices, probing SNMP...", 15)

    edges = []
    snmp_client = None
    mac_to_ip = {d.mac: d.ip for d in devices if d.mac}
    ip_to_mac = {d.ip: d.mac for d in devices if d.mac}

    for i, d in enumerate(devices):
        try:
            if snmp_client is None:
                from netmap_snmp import SnmpClient
                snmp_client = SnmpClient(community=community, timeout=0.5)
            if snmp_client.probe(d.ip):
                info = snmp_client.discover(d.ip)
                if info.sys_name:
                    d.hostname = d.hostname or info.sys_name
                if info.sys_descr:
                    d.os = d.os or info.sys_descr[:60]
                if info.sys_location:
                    d.vendor = d.vendor or info.sys_location
                if info.interfaces:
                    for iface in info.interfaces[:12]:
                        d.ports.append(Port(
                            port=iface.index, protocol="snmp",
                            service=f"{iface.name} ({iface.status})"
                        ))
                d.device_type = "network-device"

                # LLDP → реальные связи между устройствами
                if callbacks:
                    callbacks.on_progress(
                        f"LLDP: {d.ip}...",
                        25 + i * 60 // max(len(devices), 1))
                lldp = snmp_client.get_lldp_neighbors(d.ip)
                for local_port, rem_name, rem_port in lldp:
                    target_id = _find_device_by_name(devices, rem_name)
                    if not target_id:
                        target_id = _get_gateway(subnet)
                    edges.append(Edge(
                        source=d.id, target=target_id,
                        edge_type=f"LLDP port {local_port}"
                    ))

                # FDB → MAC-to-port mapping
                fdb = snmp_client.get_fdb(d.ip)
                if callbacks:
                    callbacks.on_progress(
                        f"FDB: {d.ip} ({len(fdb)} entries)...",
                        25 + (i + 1) * 60 // max(len(devices), 1))
                for vlan, mac, port in fdb:
                    if mac in mac_to_ip:
                        edges.append(Edge(
                            source=d.id, target=mac_to_ip[mac],
                            edge_type=f"FDB port {port} vlan {vlan}"
                        ))
        except Exception:
            pass

        # If no SNMP, quick port scan
        if not d.ports and d.device_type != "network-device":
            d.ports = scan_ports(d.ip, COMMON_PORTS, timeout=0.3)

        if callbacks:
            pct = 25 + (i + 1) * 60 // max(len(devices), 1)
            callbacks.on_progress(
                f"Topo {d.ip}: SNMP={d.device_type == 'network-device'}", pct)

    # Fallback: connect all non-linked devices to gateway
    linked_ids = {e.source for e in edges} | {e.target for e in edges}
    gw = _get_gateway(subnet)
    for d in devices:
        if d.id not in linked_ids and d.ip != gw:
            edges.append(Edge(source=d.id, target=gw, edge_type="direct"))

    if callbacks:
        callbacks.on_progress(
            f"Topology: {len(devices)} devices, {len(edges)} edges", 100)

    return ScanResult(scan_time=datetime.now().isoformat(), network=subnet,
                      devices=devices, edges=edges)
