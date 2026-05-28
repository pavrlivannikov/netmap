#!/usr/bin/env python3
"""
NetMap DB — тесты SQLite базы данных (ScanDB, миграция).
Запуск: python -m pytest test_netmap_db.py -v
       python -m unittest test_netmap_db.py
"""
import sys
import os
import unittest
import json
import tempfile
import glob
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_db import ScanDB, migrate_json_to_sqlite
from netmap_device import Device, Port, Edge, ScanResult


# ------------------------------------------------------------------
# Helpers — build realistic ScanResult objects
# ------------------------------------------------------------------

def _make_scan_1():
    """Scan with 3 devices and 2 edges."""
    devices = [
        Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01",
               hostname="router.home", vendor="MikroTik",
               device_type="router", os="RouterOS 7",
               first_seen="2026-01-01", last_seen="2026-05-28",
               ports=[Port(port=22, protocol="tcp", service="SSH"),
                      Port(port=8291, protocol="tcp", service="Winbox")]),
        Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:02",
               hostname="desktop-pavel", vendor="Dell",
               device_type="desktop", status="online",
               ports=[Port(port=3389, protocol="tcp", service="RDP")]),
        Device(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:03",
               hostname="printer-office", vendor="HP",
               device_type="printer", status="online",
               ports=[Port(port=9100, protocol="tcp")]),
    ]
    edges = [
        Edge(source="aa:bb:cc:dd:ee:01", target="aa:bb:cc:dd:ee:02",
             edge_type="direct", latency_ms=1.5),
        Edge(source="aa:bb:cc:dd:ee:01", target="aa:bb:cc:dd:ee:03",
             edge_type="direct", latency_ms=2.0),
    ]
    return ScanResult(scan_time="2026-05-28T18:00:00", network="192.168.1.0/24",
                      devices=devices, edges=edges)


def _make_scan_2():
    """Scan with different devices — one new, one gone, one changed."""
    devices = [
        # Same router but ports changed
        Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01",
               hostname="router.home", vendor="MikroTik",
               device_type="router",
               ports=[Port(port=22, protocol="tcp", service="SSH"),
                      Port(port=443, protocol="tcp", service="HTTPS"),  # added
                      Port(port=8291, protocol="tcp", service="Winbox")]),
        # desktop disappeared; new IoT device appeared
        Device(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:04",
               hostname="camera-garage", vendor="Hikvision",
               device_type="camera", status="online",
               ports=[Port(port=554, protocol="tcp", service="RTSP")]),
    ]
    edges = []
    return ScanResult(scan_time="2026-05-28T19:00:00", network="192.168.1.0/24",
                      devices=devices, edges=edges)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestScanDBSaveGet(unittest.TestCase):
    """Сохранение и загрузка одного скана."""

    def test_create_in_memory(self):
        db = ScanDB(":memory:")
        self.assertIsNotNone(db.conn)
        # Tables should exist
        tables = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {r["name"] for r in tables}
        for t in ("scans", "devices", "ports", "edges"):
            self.assertIn(t, table_names)
        db.close()

    def test_save_and_get_scan(self):
        db = ScanDB(":memory:")
        result = _make_scan_1()
        scan_id = db.save_scan(result)
        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

        loaded = db.get_scan(scan_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.scan_time, result.scan_time)
        self.assertEqual(loaded.network, "192.168.1.0/24")
        self.assertEqual(len(loaded.devices), 3)
        self.assertEqual(len(loaded.edges), 2)

        db.close()

    def test_get_scan_nonexistent(self):
        db = ScanDB(":memory:")
        loaded = db.get_scan(99999)
        self.assertIsNone(loaded)
        db.close()

    def test_save_scan_device_count(self):
        db = ScanDB(":memory:")
        result = _make_scan_1()
        scan_id = db.save_scan(result)
        row = db.conn.execute(
            "SELECT device_count FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        self.assertEqual(row["device_count"], 3)
        db.close()

    def test_save_scan_empty(self):
        db = ScanDB(":memory:")
        result = ScanResult(scan_time="now", network="10.0.0.0/24",
                            devices=[], edges=[])
        scan_id = db.save_scan(result)
        loaded = db.get_scan(scan_id)
        self.assertEqual(len(loaded.devices), 0)
        self.assertEqual(len(loaded.edges), 0)
        db.close()

    def test_ports_persisted(self):
        db = ScanDB(":memory:")
        result = _make_scan_1()
        scan_id = db.save_scan(result)
        loaded = db.get_scan(scan_id)
        router = next(d for d in loaded.devices if d.hostname == "router.home")
        self.assertEqual(len(router.ports), 2)
        port_services = {p.service for p in router.ports}
        self.assertIn("SSH", port_services)
        self.assertIn("Winbox", port_services)
        db.close()

    def test_device_id_persisted(self):
        db = ScanDB(":memory:")
        d = Device(ip="10.0.0.1", mac="11:22:33:44:55:66",
                   hostname="test-host", vendor="TestCo")
        result = ScanResult(scan_time="now", network="10.0.0.0/24",
                            devices=[d], edges=[])
        scan_id = db.save_scan(result)
        loaded = db.get_scan(scan_id)
        self.assertEqual(loaded.devices[0].id, "11:22:33:44:55:66")
        db.close()

    def test_context_manager(self):
        with ScanDB(":memory:") as db:
            scan_id = db.save_scan(_make_scan_1())
            self.assertGreater(scan_id, 0)
        # Should be closed after with-block — no crash is pass


class TestScanDBList(unittest.TestCase):
    """list_scans."""

    def test_list_scans_empty(self):
        db = ScanDB(":memory:")
        scans = db.list_scans()
        self.assertEqual(len(scans), 0)
        db.close()

    def test_list_scans_multiple(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1(), scan_type="full")
        db.save_scan(_make_scan_2(), scan_type="quick")
        scans = db.list_scans()
        self.assertEqual(len(scans), 2)
        # Most recent first
        self.assertEqual(scans[0]["scan_type"], "quick")
        self.assertEqual(scans[1]["scan_type"], "full")
        db.close()

    def test_list_scans_limit(self):
        db = ScanDB(":memory:")
        for i in range(5):
            result = ScanResult(scan_time=f"t{i}", network="n",
                                devices=[], edges=[])
            db.save_scan(result)
        scans = db.list_scans(limit=3)
        self.assertEqual(len(scans), 3)
        db.close()

    def test_list_scans_structure(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())
        scans = db.list_scans()
        self.assertEqual(len(scans), 1)
        s = scans[0]
        self.assertIn("id", s)
        self.assertIn("scan_time", s)
        self.assertIn("network", s)
        self.assertIn("scan_type", s)
        self.assertIn("device_count", s)
        db.close()


class TestScanDBDeviceHistory(unittest.TestCase):
    """get_device_history."""

    def test_history_by_ip(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())  # scan_id=1
        db.save_scan(_make_scan_2())  # scan_id=2
        history = db.get_device_history("192.168.1.1")
        # Router appears in both scans
        self.assertGreaterEqual(len(history), 2)
        self.assertEqual(history[0]["hostname"], "router.home")
        db.close()

    def test_history_by_mac(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())
        db.save_scan(_make_scan_2())
        history = db.get_device_history("aa:bb:cc:dd:ee:01")
        self.assertGreaterEqual(len(history), 2)
        db.close()

    def test_history_nonexistent(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())
        history = db.get_device_history("10.0.0.99")
        self.assertEqual(len(history), 0)
        db.close()

    def test_history_order_desc(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())  # older
        db.save_scan(_make_scan_2())  # newer
        history = db.get_device_history("192.168.1.1")
        # Newest first
        self.assertEqual(history[0]["scan_time"],
                         _make_scan_2().scan_time)
        db.close()


class TestScanDBDiff(unittest.TestCase):
    """diff_scans."""

    def test_no_difference(self):
        db = ScanDB(":memory:")
        result = _make_scan_1()
        id1 = db.save_scan(result)
        id2 = db.save_scan(result)
        diff = db.diff_scans(id1, id2)
        self.assertEqual(len(diff["appeared"]), 0)
        self.assertEqual(len(diff["disappeared"]), 0)
        self.assertEqual(len(diff["changed"]), 0)
        db.close()

    def test_appeared_device(self):
        db = ScanDB(":memory:")
        id1 = db.save_scan(_make_scan_1())
        id2 = db.save_scan(_make_scan_2())
        diff = db.diff_scans(id1, id2)
        appeared_ips = {d["ip"] for d in diff["appeared"]}
        self.assertIn("192.168.1.30", appeared_ips)
        db.close()

    def test_disappeared_device(self):
        db = ScanDB(":memory:")
        id1 = db.save_scan(_make_scan_1())
        id2 = db.save_scan(_make_scan_2())
        diff = db.diff_scans(id1, id2)
        disappeared_ips = {d["ip"] for d in diff["disappeared"]}
        self.assertIn("192.168.1.10", disappeared_ips)
        self.assertIn("192.168.1.20", disappeared_ips)
        db.close()

    def test_changed_device(self):
        db = ScanDB(":memory:")
        id1 = db.save_scan(_make_scan_1())
        id2 = db.save_scan(_make_scan_2())
        diff = db.diff_scans(id1, id2)
        # Router ports changed
        changed_ips = {c["ip"] for c in diff["changed"]}
        self.assertIn("192.168.1.1", changed_ips)
        db.close()

    def test_diff_counts(self):
        db = ScanDB(":memory:")
        id1 = db.save_scan(_make_scan_1())
        id2 = db.save_scan(_make_scan_2())
        diff = db.diff_scans(id1, id2)
        self.assertEqual(diff["previous_count"], 3)
        self.assertEqual(diff["current_count"], 2)
        db.close()


class TestScanDBStats(unittest.TestCase):
    """get_stats."""

    def test_stats_empty(self):
        db = ScanDB(":memory:")
        stats = db.get_stats()
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["total_unique_devices"], 0)
        self.assertIsNone(stats["last_scan_time"])
        db.close()

    def test_stats_with_data(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())
        db.save_scan(_make_scan_2())
        stats = db.get_stats()
        self.assertEqual(stats["total_scans"], 2)
        self.assertGreaterEqual(stats["total_unique_devices"], 3)
        self.assertIsNotNone(stats["last_scan_time"])
        # OUI distribution
        self.assertIn("MikroTik", stats["oui_distribution"])
        db.close()


class TestScanDBMaintenance(unittest.TestCase):
    """delete_scan, vacuum."""

    def test_delete_scan(self):
        db = ScanDB(":memory:")
        scan_id = db.save_scan(_make_scan_1())
        self.assertIsNotNone(db.get_scan(scan_id))
        db.delete_scan(scan_id)
        self.assertIsNone(db.get_scan(scan_id))
        # Devices and edges should cascade-delete
        count = db.conn.execute(
            "SELECT COUNT(*) FROM devices WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
        self.assertEqual(count, 0)
        db.close()

    def test_vacuum(self):
        db = ScanDB(":memory:")
        db.save_scan(_make_scan_1())
        db.vacuum()  # Should not raise
        db.close()


class TestMigration(unittest.TestCase):
    """migrate_json_to_sqlite."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_migrate_single_file(self):
        # Write a JSON file
        data = {
            "scan_time": "2026-05-28T18:00:00",
            "network": "192.168.1.0/24",
            "devices": [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "hostname": "router.home",
                    "vendor": "MikroTik",
                    "device_type": "router",
                    "status": "online",
                    "ports": [
                        {"port": 22, "protocol": "tcp", "service": "SSH", "state": "open"},
                    ],
                },
            ],
            "edges": [],
        }
        json_path = os.path.join(self.tmpdir, "scan_001.json")
        with open(json_path, "w") as f:
            json.dump(data, f)

        db_path = os.path.join(self.tmpdir, "migrated.db")
        count = migrate_json_to_sqlite(self.tmpdir, db_path)
        self.assertEqual(count, 1)

        # Verify
        db = ScanDB(db_path)
        scans = db.list_scans()
        self.assertEqual(len(scans), 1)
        loaded = db.get_scan(scans[0]["id"])
        self.assertEqual(len(loaded.devices), 1)
        self.assertEqual(loaded.devices[0].hostname, "router.home")
        db.close()

    def test_migrate_empty_dir(self):
        db_path = os.path.join(self.tmpdir, "empty.db")
        count = migrate_json_to_sqlite(self.tmpdir, db_path)
        self.assertEqual(count, 0)

    def test_migrate_with_edges(self):
        data = {
            "scan_time": "2026-05-28T19:00:00",
            "network": "10.0.0.0/24",
            "devices": [
                {"ip": "10.0.0.1", "mac": "11:11:11:11:11:01", "hostname": "sw1", "vendor": "Cisco", "device_type": "switch", "status": "online", "ports": []},
                {"ip": "10.0.0.2", "mac": "22:22:22:22:22:02", "hostname": "sw2", "vendor": "Cisco", "device_type": "switch", "status": "online", "ports": []},
            ],
            "edges": [
                {"source": "11:11:11:11:11:01", "target": "22:22:22:22:22:02", "edge_type": "LLDP", "latency_ms": 0.8},
            ],
        }
        json_path = os.path.join(self.tmpdir, "scan_002.json")
        with open(json_path, "w") as f:
            json.dump(data, f)

        db_path = os.path.join(self.tmpdir, "migrated_edges.db")
        count = migrate_json_to_sqlite(self.tmpdir, db_path)
        self.assertEqual(count, 1)

        db = ScanDB(db_path)
        scans = db.list_scans()
        loaded = db.get_scan(scans[0]["id"])
        self.assertEqual(len(loaded.edges), 1)
        self.assertEqual(loaded.edges[0].edge_type, "LLDP")
        self.assertAlmostEqual(loaded.edges[0].latency_ms, 0.8)
        db.close()

    def test_migrate_corrupted_skipped(self):
        # Corrupted JSON file should be skipped
        bad_path = os.path.join(self.tmpdir, "bad.json")
        with open(bad_path, "w") as f:
            f.write("this is not json {")

        # Valid file
        data = {"scan_time": "t", "network": "n", "devices": [], "edges": []}
        good_path = os.path.join(self.tmpdir, "good.json")
        with open(good_path, "w") as f:
            json.dump(data, f)

        db_path = os.path.join(self.tmpdir, "migrated_skip.db")
        count = migrate_json_to_sqlite(self.tmpdir, db_path)
        # Bad file skipped, good file migrated
        self.assertEqual(count, 1)

        db = ScanDB(db_path)
        self.assertEqual(len(db.list_scans()), 1)
        db.close()


class TestScanDBSaveEdge(unittest.TestCase):
    """Проверка корректного сохранения edges."""

    def test_edges_saved_and_loaded(self):
        db = ScanDB(":memory:")
        result = ScanResult(
            scan_time="2026-05-28T20:00:00",
            network="10.1.0.0/16",
            devices=[
                Device(ip="10.1.1.1", mac="aa:11:22:33:44:01"),
                Device(ip="10.1.1.2", mac="aa:11:22:33:44:02"),
            ],
            edges=[
                Edge(source="aa:11:22:33:44:01", target="aa:11:22:33:44:02",
                     edge_type="LLDP Gi0/1", latency_ms=0.5),
                Edge(source="aa:11:22:33:44:01", target="aa:11:22:33:44:02",
                     edge_type="wireless", latency_ms=3.2),
            ],
        )
        scan_id = db.save_scan(result)
        loaded = db.get_scan(scan_id)
        self.assertEqual(len(loaded.edges), 2)
        edge_types = {e.edge_type for e in loaded.edges}
        self.assertIn("LLDP Gi0/1", edge_types)
        self.assertIn("wireless", edge_types)
        db.close()


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap DB — SQLite Tests")
    print("=" * 60)
    unittest.main(verbosity=2, argv=[sys.argv[0]])
