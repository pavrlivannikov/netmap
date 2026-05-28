#!/usr/bin/env python3
"""
NetMap Export — тесты экспорта: JSON, CSV, DOT, Markdown.
Запуск: python -m pytest test_netmap_export.py -v
       python -m unittest test_netmap_export.py
"""
import sys
import os
import unittest
import json
import csv
import tempfile
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_export import (
    export_json, export_csv, export_topology_dot, export_markdown,
    _sanitize, _ensure_dir,
)
from netmap_device import Device, Port, Edge, ScanResult


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_rich_scan():
    """Scan with diverse devices and topology edges."""
    devices = [
        Device(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01",
               hostname="router-home", vendor="MikroTik",
               device_type="router", os="RouterOS 7", status="online",
               first_seen="2026-01-01", last_seen="2026-05-28",
               ports=[Port(port=22, service="SSH"),
                      Port(port=443, service="HTTPS"),
                      Port(port=8291, service="Winbox")]),
        Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:02",
               hostname="desktop-pavel", vendor="Dell",
               device_type="desktop", status="online",
               ports=[Port(port=3389, service="RDP")]),
        Device(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:03",
               hostname=None, vendor="HP",
               device_type="printer", status="offline",
               ports=[Port(port=9100, protocol="tcp")]),
        Device(ip="192.168.1.30", mac="", hostname=None, vendor=None,
               device_type="unknown", status="online", ports=[]),
    ]
    edges = [
        Edge(source="aa:bb:cc:dd:ee:01", target="aa:bb:cc:dd:ee:02",
             edge_type="direct", latency_ms=1.5),
        Edge(source="aa:bb:cc:dd:ee:01", target="aa:bb:cc:dd:ee:03",
             edge_type="wireless", latency_ms=3.0),
    ]
    return ScanResult(scan_time="2026-05-28T20:00:00",
                      network="192.168.1.0/24",
                      devices=devices, edges=edges)


def _make_empty_scan():
    """Scan with no devices or edges."""
    return ScanResult(scan_time="2026-05-28T20:00:00",
                      network="10.0.0.0/8",
                      devices=[], edges=[])


# ------------------------------------------------------------------
# Helpers tests
# ------------------------------------------------------------------

class TestHelpers(unittest.TestCase):
    """Вспомогательные функции экспорта."""

    def test_sanitize_string(self):
        self.assertEqual(_sanitize("hello"), "hello")

    def test_sanitize_none(self):
        self.assertEqual(_sanitize(None), "")

    def test_sanitize_number(self):
        self.assertEqual(_sanitize(42), "42")

    def test_sanitize_empty_string(self):
        self.assertEqual(_sanitize(""), "")

    def test_ensure_dir_creates(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "sub1", "sub2", "file.json")
            result = _ensure_dir(path)
            self.assertTrue(os.path.isdir(os.path.dirname(result)))

    def test_ensure_dir_returns_absolute(self):
        result = _ensure_dir("test.json")
        self.assertTrue(os.path.isabs(result))


# ------------------------------------------------------------------
# JSON export
# ------------------------------------------------------------------

class TestExportJSON(unittest.TestCase):
    """JSON экспорт и round-trip проверка."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_json_writes_file(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.json")
        out_path = export_json(result, path)
        self.assertTrue(os.path.isfile(out_path))
        self.assertTrue(out_path.endswith("scan.json"))

    def test_export_json_roundtrip(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["scan_time"], "2026-05-28T20:00:00")
        self.assertEqual(data["network"], "192.168.1.0/24")
        self.assertEqual(len(data["devices"]), 4)
        self.assertEqual(len(data["edges"]), 2)

    def test_export_json_device_fields(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        d = data["devices"][0]
        self.assertIn("ip", d)
        self.assertIn("mac", d)
        self.assertIn("hostname", d)
        self.assertIn("vendor", d)
        self.assertIn("os", d)
        self.assertIn("device_type", d)
        self.assertIn("status", d)
        self.assertIn("first_seen", d)
        self.assertIn("last_seen", d)
        self.assertIn("ports", d)

    def test_export_json_ports(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        router = data["devices"][0]
        self.assertEqual(len(router["ports"]), 3)
        port_services = {p["service"] for p in router["ports"]}
        self.assertIn("SSH", port_services)
        self.assertIn("HTTPS", port_services)

    def test_export_json_edges(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        e = data["edges"][0]
        self.assertIn("source", e)
        self.assertIn("target", e)
        self.assertIn("edge_type", e)
        self.assertIn("latency_ms", e)

    def test_export_json_empty_scan(self):
        result = _make_empty_scan()
        path = os.path.join(self.tmpdir, "empty.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data["devices"]), 0)
        self.assertEqual(len(data["edges"]), 0)

    def test_export_json_unicode(self):
        """Test that non-ASCII characters are preserved (ensure_ascii=False)."""
        d = Device(ip="10.0.0.1", mac="aa:bb:cc:dd:ee:01",
                   hostname="сеть-роутер", vendor="МикроТик")
        d.ports = []
        result = ScanResult(scan_time="t", network="n",
                            devices=[d], edges=[])
        path = os.path.join(self.tmpdir, "unicode.json")
        export_json(result, path)

        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        self.assertIn("сеть-роутер", raw)
        self.assertIn("МикроТик", raw)


# ------------------------------------------------------------------
# CSV export
# ------------------------------------------------------------------

class TestExportCSV(unittest.TestCase):
    """CSV экспорт."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_csv_writes_file(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.csv")
        out_path = export_csv(result, path)
        self.assertTrue(os.path.isfile(out_path))

    def test_csv_has_correct_headers(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)
            expected = ["ip", "mac", "hostname", "vendor", "os",
                        "device_type", "status", "open_ports",
                        "first_seen", "last_seen"]
            self.assertEqual(headers, expected)

    def test_csv_row_count(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # header
            rows = list(reader)
        self.assertEqual(len(rows), 4)  # 4 devices

    def test_csv_row_values(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # header
            rows = list(reader)

        # First row: router
        self.assertEqual(rows[0][0], "192.168.1.1")
        self.assertEqual(rows[0][2], "router-home")   # hostname
        self.assertEqual(rows[0][3], "MikroTik")       # vendor
        self.assertEqual(rows[0][5], "router")          # device_type
        self.assertEqual(rows[0][6], "online")          # status

    def test_csv_ports_column(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "scan.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # header
            rows = list(reader)

        # Router has 3 ports: SSH, HTTPS, Winbox
        ports_str = rows[0][7]
        self.assertIn("22/tcp", ports_str)
        self.assertIn("SSH", ports_str)
        self.assertIn("443/tcp", ports_str)
        self.assertIn("HTTPS", ports_str)

    def test_csv_empty_scan(self):
        result = _make_empty_scan()
        path = os.path.join(self.tmpdir, "empty.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # header
            rows = list(reader)
        self.assertEqual(len(rows), 0)

    def test_csv_none_fields_sanitized(self):
        # Device with null hostname/vendor should have empty strings
        d = Device(ip="10.0.0.1", mac="", hostname=None, vendor=None, os=None)
        d.ports = []
        result = ScanResult(scan_time="t", network="n",
                            devices=[d], edges=[])
        path = os.path.join(self.tmpdir, "none.csv")
        export_csv(result, path)

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            row = next(reader)
        self.assertEqual(row[2], "")  # hostname
        self.assertEqual(row[3], "")  # vendor
        self.assertEqual(row[4], "")  # os


# ------------------------------------------------------------------
# DOT (Graphviz) export
# ------------------------------------------------------------------

class TestExportDOT(unittest.TestCase):
    """Graphviz DOT экспорт."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_dot_writes_file(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        out_path = export_topology_dot(result, path)
        self.assertTrue(os.path.isfile(out_path))

    def test_dot_starts_with_digraph(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("digraph NetMapTopology", content)

    def test_dot_has_nodes(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Each device should have a node
        for mac in ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]:
            self.assertIn(f'"{mac}"', content)

    def test_dot_has_edges(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("->", content)
        self.assertIn("aa:bb:cc:dd:ee:01", content)
        self.assertIn("aa:bb:cc:dd:ee:02", content)
        self.assertIn("aa:bb:cc:dd:ee:03", content)

    def test_dot_edge_types(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Wireless edge should have style=dashed
        self.assertIn("dashed", content)

    def test_dot_latency_label(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Direct edge has 1.5ms latency
        self.assertIn("1.5ms", content)

    def test_dot_closing_brace(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "topology.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertTrue(content.rstrip().endswith("}"))

    def test_dot_empty_scan(self):
        result = _make_empty_scan()
        path = os.path.join(self.tmpdir, "empty.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("digraph NetMapTopology", content)
        self.assertIn("}", content)

    def test_dot_device_no_mac_uses_ip(self):
        """Device without MAC uses IP as node id."""
        d = Device(ip="10.0.0.1", mac="")
        d.ports = []
        result = ScanResult(scan_time="t", network="n",
                            devices=[d], edges=[])
        path = os.path.join(self.tmpdir, "no_mac.dot")
        export_topology_dot(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('"10.0.0.1"', content)


# ------------------------------------------------------------------
# Markdown export
# ------------------------------------------------------------------

class TestExportMarkdown(unittest.TestCase):
    """Markdown экспорт."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_markdown_writes_file(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        out_path = export_markdown(result, path)
        self.assertTrue(os.path.isfile(out_path))

    def test_markdown_has_title(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("# NetMap Scan Report", content)

    def test_markdown_has_scan_meta(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("2026-05-28T20:00:00", content)
        self.assertIn("192.168.1.0/24", content)
        self.assertIn("**Devices:** 4", content)
        self.assertIn("**Edges:** 2", content)

    def test_markdown_has_table_headers(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("| IP | MAC | Hostname | Vendor | OS | Type | Status | Open Ports |",
                       content)
        self.assertIn("| ---", content)  # separator row

    def test_markdown_table_rows(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        lines = content.split("\n")
        table_rows = [l for l in lines if l.startswith("| 192.") or l.startswith("| 10.")]
        self.assertEqual(len(table_rows), 4)  # 4 devices

    def test_markdown_table_content(self):
        result = _make_rich_scan()
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Router row should have correct values
        self.assertIn("192.168.1.1", content)
        self.assertIn("router-home", content)
        self.assertIn("MikroTik", content)
        self.assertIn("router", content)
        self.assertIn("online", content)

    def test_markdown_topology_section(self):
        result = _make_rich_scan()  # has edges
        path = os.path.join(self.tmpdir, "report.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("## Topology", content)
        self.assertIn("| Source | Target | Type | Latency |", content)

    def test_markdown_no_topology_when_no_edges(self):
        result = _make_empty_scan()
        path = os.path.join(self.tmpdir, "empty.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("## Topology", content)

    def test_markdown_empty_fields_rendered_as_dash(self):
        d = Device(ip="10.0.0.1", mac="", hostname=None, vendor=None, os=None)
        d.ports = []
        result = ScanResult(scan_time="t", network="n",
                            devices=[d], edges=[])
        path = os.path.join(self.tmpdir, "empty_fields.md")
        export_markdown(result, path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Empty MAC should show "—"
        self.assertIn("—", content)


# ------------------------------------------------------------------
# Export path handling
# ------------------------------------------------------------------

class TestExportPathHandling(unittest.TestCase):
    """Проверка создания директорий."""

    def test_nested_dirs_created(self):
        with tempfile.TemporaryDirectory() as td:
            nested = os.path.join(td, "reports", "2026", "05", "scan.json")
            path = export_json(_make_empty_scan(), nested)
            self.assertTrue(os.path.isfile(path))

    def test_csv_nested_dirs_created(self):
        with tempfile.TemporaryDirectory() as td:
            nested = os.path.join(td, "exports", "data.csv")
            path = export_csv(_make_empty_scan(), nested)
            self.assertTrue(os.path.isfile(path))


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap Export — Format Export Tests")
    print("=" * 60)
    unittest.main(verbosity=2, argv=[sys.argv[0]])
