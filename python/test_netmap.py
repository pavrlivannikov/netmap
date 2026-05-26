#!/usr/bin/env python3
"""
NetMap — автоматическое тестирование всех функций.
Запуск: python3 test_netmap.py
"""
import sys
import os
import unittest
import json
import tempfile
import socket
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_scanner import (
    Device, Port, Edge, ScanResult, NetworkInfo,
    ScanCallbacks, discover_networks, arp_scan, arp_scan_subnet,
    ping_host, ping_sweep, check_port, scan_ports,
    oui_lookup, expand_subnet, is_ip_in_subnet,
    guess_device_type, guess_os_by_ttl, save_result, load_result,
    monitor_diff, scan_quick, scan_discover,
    _is_windows, _is_valid_ip, _is_valid_mac, _mask_to_prefix,
    _count_dots, _run, _check_output,
    COMMON_PORTS, SERVICE_MAP,
)
from netmap_snmp import (
    SnmpClient, SnmpDevice, SnmpInterface, LldpNeighbor, MacEntry,
    SnmpTopology,
)


class TestDataClasses(unittest.TestCase):
    """Проверка dataclass-ов."""

    def test_device_id_mac(self):
        d = Device(ip="1.2.3.4", mac="aa:bb:cc:dd:ee:ff")
        self.assertEqual(d.id, "aa:bb:cc:dd:ee:ff")

    def test_device_id_no_mac(self):
        d = Device(ip="1.2.3.4")
        self.assertEqual(d.id, "1.2.3.4")

    def test_port_defaults(self):
        p = Port(port=80)
        self.assertEqual(p.port, 80)
        self.assertEqual(p.protocol, "tcp")
        self.assertEqual(p.state, "open")

    def test_edge(self):
        e = Edge(source="aa:bb", target="cc:dd", edge_type="LLDP port 5")
        self.assertEqual(e.edge_type, "LLDP port 5")

    def test_device_defaults(self):
        d = Device(ip="10.0.0.1")
        self.assertEqual(d.status, "online")
        self.assertEqual(d.device_type, "unknown")
        self.assertEqual(d.ports, [])

    def test_scan_result_dict(self):
        sr = ScanResult(scan_time="t", network="n", devices=[], edges=[])
        from dataclasses import asdict
        d = asdict(sr)
        self.assertEqual(d["network"], "n")


class TestHelpers(unittest.TestCase):
    """Вспомогательные функции."""

    def test_is_valid_ip(self):
        self.assertTrue(_is_valid_ip("192.168.1.1"))
        self.assertTrue(_is_valid_ip("8.8.8.8"))
        self.assertFalse(_is_valid_ip("999.999.999.999"))
        self.assertFalse(_is_valid_ip("not-an-ip"))

    def test_is_valid_mac(self):
        self.assertTrue(_is_valid_mac("aa:bb:cc:dd:ee:ff"))
        self.assertTrue(_is_valid_mac("AA-BB-CC-DD-EE-FF"))
        self.assertFalse(_is_valid_mac("aa:bb:cc"))
        self.assertFalse(_is_valid_mac(""))

    def test_mask_to_prefix(self):
        self.assertEqual(_mask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(_mask_to_prefix("255.255.0.0"), 16)
        self.assertEqual(_mask_to_prefix("255.0.0.0"), 8)

    def test_count_dots(self):
        self.assertEqual(_count_dots("192.168.1.1"), 3)
        self.assertEqual(_count_dots("hello"), 0)

    def test_expand_subnet(self):
        ips = expand_subnet("10.0.0.0/30")
        self.assertEqual(len(ips), 2)
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)

    def test_is_ip_in_subnet(self):
        self.assertTrue(is_ip_in_subnet("192.168.1.5", "192.168.1.0/24"))
        self.assertFalse(is_ip_in_subnet("10.0.0.1", "192.168.1.0/24"))

    def test_service_map(self):
        self.assertEqual(SERVICE_MAP[22], "SSH")
        self.assertEqual(SERVICE_MAP[80], "HTTP")
        self.assertEqual(SERVICE_MAP[443], "HTTPS")
        self.assertEqual(SERVICE_MAP[3389], "RDP")


class TestOUI(unittest.TestCase):
    """OUI-база вендоров."""

    def test_known_vendors(self):
        self.assertEqual(oui_lookup("F0-9F-C5-00-00-00"), "Dell")
        self.assertIsNotNone(oui_lookup("0017F2112233"))
        self.assertIsNotNone(oui_lookup("38-10-D5-00-00-00"))
        self.assertIsNotNone(oui_lookup("00-E0-4C-00-00-00"))  # Cisco

    def test_unknown_oui(self):
        result = oui_lookup("de:ad:be:ef:ca:fe")
        self.assertTrue(result is None or isinstance(result, str))

    def test_external_db_fallback(self):
        """Even without oui_data.py, built-in prefixes work."""
        result = oui_lookup("84:00:00:00:00:01")  # TP-Link prefix
        self.assertIsNotNone(result)


class TestDeviceType(unittest.TestCase):
    """Угадывание типа устройства."""

    def test_router_by_hostname(self):
        self.assertEqual(guess_device_type("gateway-01", []), "router")

    def test_switch_by_hostname(self):
        self.assertEqual(guess_device_type("core-switch-01", []), "switch")

    def test_server_by_ports(self):
        self.assertEqual(guess_device_type("", [Port(22)]), "server")
        self.assertEqual(guess_device_type("", [Port(3389)]), "server")

    def test_workstation_default(self):
        self.assertEqual(guess_device_type("pc-01", []), "workstation")


class TestPing(unittest.TestCase):
    """ICMP ping."""

    def test_ping_localhost(self):
        alive, lat = ping_host("127.0.0.1", timeout=1.0)
        self.assertTrue(alive)
        self.assertIsNotNone(lat)

    def test_ping_unreachable(self):
        alive, lat = ping_host("192.0.2.1", timeout=0.5)
        self.assertFalse(alive)

    def test_ping_sweep(self):
        ips = ["127.0.0.1", "127.0.0.2"]
        devices = ping_sweep(ips, workers=2)
        self.assertGreaterEqual(len(devices), 1)


class TestPorts(unittest.TestCase):
    """TCP port scan."""

    def test_check_port_localhost(self):
        """localhost should have no common ports open in test env."""
        result = check_port("127.0.0.1", 9999, timeout=0.2)
        self.assertIsNone(result)

    def test_scan_ports(self):
        ports = scan_ports("127.0.0.1", [9998, 9999], timeout=0.2)
        self.assertIsInstance(ports, list)

    def test_scan_ports_default_list(self):
        ports = scan_ports("127.0.0.1", timeout=0.2)
        self.assertIsInstance(ports, list)


class TestNetworkDiscovery(unittest.TestCase):
    """Обнаружение сетей."""

    def test_discover_networks(self):
        nets = discover_networks()
        self.assertIsInstance(nets, list)
        for n in nets:
            self.assertIsInstance(n, NetworkInfo)
            self.assertTrue(n.ip)
            self.assertTrue(n.cidr)
            self.assertTrue("/" in n.cidr)


class TestARPScan(unittest.TestCase):
    """ARP-сканирование."""

    def test_arp_scan(self):
        devices = arp_scan()
        self.assertIsInstance(devices, list)

    def test_arp_scan_subnet(self):
        nets = discover_networks()
        if nets:
            devices = arp_scan_subnet(nets[0].cidr)
            self.assertIsInstance(devices, list)
            for d in devices:
                self.assertIsInstance(d, Device)
                self.assertTrue(d.ip)
                self.assertEqual(d.status, "online")


class TestScanModes(unittest.TestCase):
    """Режимы сканирования."""

    def test_scan_quick(self):
        nets = discover_networks()
        if nets:
            result = scan_quick(nets[0].cidr)
            self.assertIsInstance(result, ScanResult)
            self.assertIsNotNone(result.scan_time)
            self.assertIsInstance(result.devices, list)

    def test_scan_discover(self):
        nets = discover_networks()
        if nets:
            result = scan_discover(nets[0].cidr)
            self.assertIsInstance(result, ScanResult)
            for d in result.devices:
                self.assertIsInstance(d, Device)
                self.assertEqual(d.status, "online")


class TestMonitorDiff(unittest.TestCase):
    """Мониторинг diff."""

    def test_no_changes(self):
        prev = ScanResult("t1", "n", devices=[Device(ip="1.2.3.4")], edges=[])
        curr = ScanResult("t2", "n", devices=[Device(ip="1.2.3.4")], edges=[])
        diff = monitor_diff(prev, curr)
        self.assertEqual(len(diff["appeared"]), 0)
        self.assertEqual(len(diff["disappeared"]), 0)

    def test_appeared(self):
        prev = ScanResult("t1", "n", devices=[], edges=[])
        curr = ScanResult("t2", "n", devices=[Device(ip="1.2.3.4")], edges=[])
        diff = monitor_diff(prev, curr)
        self.assertEqual(len(diff["appeared"]), 1)

    def test_disappeared(self):
        prev = ScanResult("t1", "n", devices=[Device(ip="1.2.3.4")], edges=[])
        curr = ScanResult("t2", "n", devices=[], edges=[])
        diff = monitor_diff(prev, curr)
        self.assertEqual(len(diff["disappeared"]), 1)

    def test_ports_changed(self):
        prev = ScanResult("t1", "n", devices=[Device(ip="1.2.3.4", ports=[Port(80)])], edges=[])
        curr = ScanResult("t2", "n", devices=[Device(ip="1.2.3.4", ports=[Port(443)])], edges=[])
        diff = monitor_diff(prev, curr)
        self.assertEqual(len(diff["changed"]), 1)


class TestSerialization(unittest.TestCase):
    """Сохранение и загрузка."""

    def test_save_load_roundtrip(self):
        result = ScanResult(
            scan_time="2026-05-26", network="10.0.0.0/24",
            devices=[
                Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff",
                       hostname="gw", vendor="Cisco", device_type="router",
                       ports=[Port(port=22, service="SSH")]),
                Device(ip="10.0.0.2", mac="11:22:33:44:55:66",
                       hostname="pc1", vendor="Dell", device_type="workstation"),
            ],
            edges=[Edge(source="aa:bb:cc:dd:ee:ff", target="11:22:33:44:55:66",
                        edge_type="direct")]
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            fname = f.name
        save_result(result, fname)
        loaded = load_result(fname)
        self.assertEqual(len(loaded.devices), 2)
        self.assertEqual(loaded.devices[0].ip, "10.0.0.1")
        self.assertEqual(loaded.devices[0].vendor, "Cisco")
        self.assertEqual(len(loaded.devices[0].ports), 1)
        self.assertEqual(loaded.devices[0].ports[0].service, "SSH")
        self.assertEqual(len(loaded.edges), 1)
        os.unlink(fname)


class TestSNMP(unittest.TestCase):
    """SNMP клиент (pysnmp)."""

    def test_probe_no_device(self):
        client = SnmpClient(timeout=0.3)
        result = client.probe("192.0.2.1")
        self.assertFalse(result)

    def test_snmp_device_dataclass(self):
        dev = SnmpDevice(sys_name="test-switch", sys_descr="Cisco IOS")
        self.assertEqual(dev.sys_name, "test-switch")

    def test_snmp_topology_dataclass(self):
        topo = SnmpTopology(
            device=SnmpDevice(sys_name="sw1"),
            lldp_neighbors=[LldpNeighbor(local_port=1, remote_name="sw2", remote_port="Gi0/1")],
            mac_table=[MacEntry(mac="aa:bb:cc:dd:ee:ff", port=1, vlan=100)]
        )
        self.assertEqual(len(topo.lldp_neighbors), 1)
        self.assertEqual(len(topo.mac_table), 1)

    def test_discover_no_device(self):
        client = SnmpClient(timeout=0.3)
        dev = client.discover("192.0.2.1")
        self.assertIsInstance(dev, SnmpDevice)
        self.assertIsNone(dev.sys_name)

    def test_walk_no_device(self):
        client = SnmpClient(timeout=0.3)
        results = client.walk("192.0.2.1", "1.3.6.1.2.1.1")
        self.assertIsInstance(results, list)


class TestSubprocessWrappers(unittest.TestCase):
    """Обёртки subprocess (дымовые тесты)."""

    def test_run_no_window(self):
        if _is_windows():
            result = _run(["cmd", "/c", "echo", "test"], capture_output=True, text=True)
        else:
            result = _run(["echo", "test"], capture_output=True, text=True, shell=True)
        self.assertEqual(result.returncode, 0)

    def test_check_output(self):
        if _is_windows():
            out = _check_output(["cmd", "/c", "echo", "hello"], text=True)
        else:
            out = _check_output(["printf", "hello"], text=True)
        self.assertIn("hello", out)


class TestCallbacks(unittest.TestCase):
    """Callback-механизм."""

    def test_callbacks_base(self):
        cb = ScanCallbacks()
        cb.on_device_found(Device(ip="1.2.3.4"))
        cb.on_progress("test", 50)
        cb.on_error("test error")
        # Base class methods do nothing — no crash is pass


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap — Автоматическое тестирование")
    print("=" * 60)
    # Run tests
    unittest.main(verbosity=2, argv=[sys.argv[0]])
