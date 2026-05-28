#!/usr/bin/env python3
"""
NetMap Tree — тесты построения дерева и статистики.
Запуск: python -m pytest test_netmap_tree.py -v
       python -m unittest test_netmap_tree.py
"""
import sys
import os
import unittest
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_tree import (
    NetNode,
    build_tree,
    tree_to_dict,
    get_stats,
    _subnet_key,
    _guess_subnet_prefix,
    _short_subnet_label,
    _get_device_icon,
    _get_status_icon,
    _extract_ip,
    _extract_field,
)


# ------------------------------------------------------------------
# Helpers — device factories
# ------------------------------------------------------------------

def _dict_dev(ip, mac="", hostname=None, vendor=None, device_type="unknown",
              status="online", ports=None):
    """Create a dict-style device (as used in monitors)."""
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "device_type": device_type,
        "status": status,
        "ports": ports or [],
        "os": None,
    }


def _flat_devices():
    """A flat list of devices across multiple /24 subnets."""
    return [
        _dict_dev("192.168.1.1", "aa:bb:cc:dd:ee:01",
                  "router-home", "MikroTik", "router", "online"),
        _dict_dev("192.168.1.10", "aa:bb:cc:dd:ee:02",
                  "desktop-pavel", "Dell", "desktop", "online"),
        _dict_dev("192.168.1.20", "aa:bb:cc:dd:ee:03",
                  "printer-office", "HP", "printer", "offline"),
        _dict_dev("192.168.2.5", "aa:bb:cc:dd:ee:04",
                  "camera-garage", "Hikvision", "camera", "online"),
        _dict_dev("192.168.2.10", "aa:bb:cc:dd:ee:05",
                  "switch-garage", "TP-Link", "switch", "online"),
        _dict_dev("10.0.0.1", "aa:bb:cc:dd:ee:06",
                  "server-vpn", "Supermicro", "server", "online"),
    ]


# ------------------------------------------------------------------
# IP helpers
# ------------------------------------------------------------------

class TestIPHelpers(unittest.TestCase):
    """IP-хелперы."""

    def test_extract_ip_from_dict(self):
        self.assertEqual(_extract_ip({"ip": "1.2.3.4"}), "1.2.3.4")

    def test_extract_ip_from_string(self):
        self.assertEqual(_extract_ip("10.0.0.1"), "10.0.0.1")

    def test_extract_ip_from_object(self):
        class FakeDevice:
            ip = "192.168.1.1"
        self.assertEqual(_extract_ip(FakeDevice()), "192.168.1.1")

    def test_extract_ip_none(self):
        self.assertIsNone(_extract_ip({}))
        self.assertIsNone(_extract_ip(None))

    def test_extract_field_from_dict(self):
        d = {"hostname": "test", "extra": 42}
        self.assertEqual(_extract_field(d, "hostname"), "test")
        self.assertEqual(_extract_field(d, "extra"), 42)
        self.assertEqual(_extract_field(d, "missing", "default"), "default")

    def test_extract_field_from_object(self):
        class FakeDevice:
            hostname = "my-device"
            vendor = "Acme"
        self.assertEqual(_extract_field(FakeDevice(), "hostname"), "my-device")
        self.assertEqual(_extract_field(FakeDevice(), "vendor"), "Acme")
        self.assertEqual(_extract_field(FakeDevice(), "missing", "n/a"), "n/a")

    def test_subnet_key(self):
        self.assertEqual(_subnet_key("192.168.1.5", 24), "192.168.1.0/24")
        self.assertEqual(_subnet_key("192.168.2.100", 24), "192.168.2.0/24")

    def test_subnet_key_invalid_ip(self):
        self.assertEqual(_subnet_key("not-an-ip", 24), "not-an-ip")

    def test_guess_subnet_prefix_24(self):
        self.assertEqual(_guess_subnet_prefix("192.168.1.0/24"), 24)

    def test_guess_subnet_prefix_16(self):
        self.assertEqual(_guess_subnet_prefix("192.168.0.0/16"), 24)

    def test_guess_subnet_prefix_8(self):
        self.assertEqual(_guess_subnet_prefix("10.0.0.0/8"), 16)

    def test_guess_subnet_prefix_28(self):
        """For /28 and smaller: use 24 for grouping."""
        self.assertEqual(_guess_subnet_prefix("10.0.0.0/28"), 24)

    def test_short_subnet_label_24(self):
        self.assertEqual(_short_subnet_label("192.168.1.0/24"), "192.168.1.x")

    def test_short_subnet_label_16(self):
        self.assertEqual(_short_subnet_label("192.168.0.0/16"), "192.168.x.x")

    def test_short_subnet_label_8(self):
        self.assertEqual(_short_subnet_label("10.0.0.0/8"), "10.x.x.x")

    def test_short_subnet_label_unknown(self):
        self.assertEqual(_short_subnet_label("nonsense"), "nonsense")


# ------------------------------------------------------------------
# Icons
# ------------------------------------------------------------------

class TestIcons(unittest.TestCase):
    """Иконки типов устройств."""

    def test_known_device_icons(self):
        self.assertEqual(_get_device_icon("router"), "📡")
        self.assertEqual(_get_device_icon("switch"), "🔀")
        self.assertEqual(_get_device_icon("printer"), "🖨️")
        self.assertEqual(_get_device_icon("server"), "🗄️")
        self.assertEqual(_get_device_icon("phone"), "📱")

    def test_unknown_device_icon(self):
        self.assertEqual(_get_device_icon("something-else"), "❓")
        self.assertEqual(_get_device_icon(None), "❓")
        self.assertEqual(_get_device_icon(""), "❓")

    def test_case_insensitive_icons(self):
        self.assertEqual(_get_device_icon("ROUTER"), "📡")
        self.assertEqual(_get_device_icon("Switch"), "🔀")

    def test_status_icons(self):
        self.assertEqual(_get_status_icon("online"), "🟢")
        self.assertEqual(_get_status_icon("offline"), "🔴")

    def test_status_icon_default(self):
        self.assertEqual(_get_status_icon("unknown"), "⚪")
        self.assertEqual(_get_status_icon(None), "🟢")  # default is online


# ------------------------------------------------------------------
# NetNode
# ------------------------------------------------------------------

class TestNetNode(unittest.TestCase):
    """NetNode dataclass."""

    def test_node_creation(self):
        n = NetNode("test", node_type="network")
        self.assertEqual(n.name, "test")
        self.assertEqual(n.node_type, "network")
        self.assertEqual(len(n.children), 0)
        self.assertEqual(n.data, {})

    def test_node_with_data(self):
        n = NetNode("sub", node_type="subnet", data={"cidr": "10.0.0.0/8"})
        self.assertEqual(n.data["cidr"], "10.0.0.0/8")

    def test_add_child(self):
        root = NetNode("root")
        child = NetNode("child")
        root.add_child(child)
        self.assertEqual(len(root.children), 1)
        self.assertIs(root.children[0], child)

    def test_to_dict_recursive(self):
        root = NetNode("root", node_type="network")
        subnet = NetNode("10.0.0.0/24", node_type="subnet",
                         data={"online": 2, "offline": 0})
        dev = NetNode("my-host", node_type="device",
                      data={"ip": "10.0.0.1", "status": "online"})
        subnet.add_child(dev)
        root.add_child(subnet)

        d = root.to_dict()
        self.assertEqual(d["name"], "root")
        self.assertEqual(d["type"], "network")
        self.assertEqual(len(d["children"]), 1)
        self.assertEqual(d["children"][0]["name"], "10.0.0.0/24")
        self.assertEqual(len(d["children"][0]["children"]), 1)
        self.assertEqual(d["children"][0]["children"][0]["data"]["ip"], "10.0.0.1")

    def test_repr(self):
        n = NetNode("test", node_type="subnet", data={"online": 5})
        r = repr(n)
        self.assertIn("test", r)
        self.assertIn("subnet", r)


# ------------------------------------------------------------------
# build_tree
# ------------------------------------------------------------------

class TestBuildTree(unittest.TestCase):
    """Построение дерева."""

    def test_build_tree_flat_list(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        self.assertIsInstance(root, NetNode)
        self.assertEqual(root.node_type, "network")

    def test_tree_root_data(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        self.assertEqual(root.data["cidr"], "192.168.0.0/16")
        self.assertEqual(root.data["total_devices"], len(devices))

    def test_tree_grouping_by_24(self):
        """Devices in 192.168.1.x and 192.168.2.x get separate subnet nodes."""
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        subnet_names = {c.name for c in root.children}
        self.assertIn("192.168.1.0/24", subnet_names)
        self.assertIn("192.168.2.0/24", subnet_names)

    def test_tree_subnet_child_count(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        for child in root.children:
            if child.name == "192.168.1.0/24":
                # 3 devices in 192.168.1.x
                self.assertEqual(len(child.children), 3)
            elif child.name == "192.168.2.0/24":
                # 2 devices in 192.168.2.x
                self.assertEqual(len(child.children), 2)

    def test_tree_subnet_data(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        for child in root.children:
            if child.name == "192.168.1.0/24":
                self.assertEqual(child.data["total_devices"], 3)
                self.assertEqual(child.data["online"], 2)
                self.assertEqual(child.data["offline"], 1)

    def test_tree_device_node_data(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        # Find the router
        subnet_1 = next(c for c in root.children if c.name == "192.168.1.0/24")
        router_node = next(c for c in subnet_1.children
                           if c.data.get("hostname") == "router-home")
        self.assertEqual(router_node.data["ip"], "192.168.1.1")
        self.assertEqual(router_node.data["vendor"], "MikroTik")
        self.assertEqual(router_node.data["device_type"], "router")
        self.assertEqual(router_node.data["icon"], "📡")
        self.assertEqual(router_node.data["status_icon"], "🟢")

    def test_tree_device_labels(self):
        """Devices with hostnames should have combined label."""
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        subnet_1 = next(c for c in root.children if c.name == "192.168.1.0/24")
        router = next(c for c in subnet_1.children
                      if c.data.get("hostname") == "router-home")
        self.assertIn("router-home", router.name)
        self.assertIn("192.168.1.1", router.name)

    def test_tree_device_no_hostname(self):
        """Device without hostname uses IP as label."""
        devs = [_dict_dev("10.0.0.5", hostname=None)]
        root = build_tree(devs, "10.0.0.0/8")
        device_node = root.children[0].children[0]
        self.assertEqual(device_node.name, "10.0.0.5")

    def test_tree_ungrouped_devices(self):
        """Devices without IP go into 'Other' node."""
        devs = [{"no_ip": True}]
        root = build_tree(devs, "192.168.0.0/16")
        # Should have the "Other" node
        other_names = {c.name for c in root.children}
        self.assertIn("Other", other_names)

    def test_tree_empty_list(self):
        root = build_tree([], "192.168.0.0/16")
        self.assertEqual(root.data["total_devices"], 0)
        self.assertEqual(len(root.children), 0)

    def test_tree_different_prefix(self):
        """10.0.0.0/8 devices grouped by /16."""
        devices = [
            _dict_dev("10.1.1.1", hostname="a"),
            _dict_dev("10.1.1.2", hostname="b"),
            _dict_dev("10.2.1.1", hostname="c"),
        ]
        root = build_tree(devices, "10.0.0.0/8")
        subnet_names = {c.name for c in root.children}
        self.assertIn("10.1.0.0/16", subnet_names)
        self.assertIn("10.2.0.0/16", subnet_names)


# ------------------------------------------------------------------
# tree_to_dict
# ------------------------------------------------------------------

class TestTreeToDict(unittest.TestCase):
    """Сериализация дерева в dict."""

    def test_tree_to_dict_valid_json(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        d = tree_to_dict(root)
        # Must be JSON-serializable
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 0)
        # Round-trip
        loaded = json.loads(json_str)
        self.assertEqual(loaded["name"], "192.168.0.0/16")
        self.assertEqual(loaded["type"], "network")

    def test_tree_to_dict_children(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        d = tree_to_dict(root)
        self.assertIn("children", d)
        self.assertGreater(len(d["children"]), 0)

    def test_tree_to_dict_device_data(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        d = tree_to_dict(root)
        json_str = json.dumps(d)
        self.assertIn("router-home", json_str)
        self.assertIn("MikroTik", json_str)


# ------------------------------------------------------------------
# get_stats
# ------------------------------------------------------------------

class TestGetStats(unittest.TestCase):
    """Сбор статистики."""

    def test_get_stats_total_devices(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        stats = get_stats(root)
        self.assertEqual(stats["total_devices"], 6)

    def test_get_stats_online_offline(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        stats = get_stats(root)
        # 5 online, 1 offline ("printer-office")
        self.assertEqual(stats["online"], 5)
        self.assertEqual(stats["offline"], 1)

    def test_get_stats_by_type(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        stats = get_stats(root)
        by_type = stats["by_type"]
        self.assertEqual(by_type["router"], 1)
        self.assertEqual(by_type["desktop"], 1)
        self.assertEqual(by_type["printer"], 1)
        self.assertEqual(by_type["switch"], 1)
        self.assertEqual(by_type["camera"], 1)
        self.assertEqual(by_type["server"], 1)

    def test_get_stats_by_type_sorted(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        stats = get_stats(root)
        by_type = stats["by_type"]
        # All count 1, sorted alphabetically (by name)
        keys = list(by_type.keys())
        self.assertEqual(keys, sorted(keys))

    def test_get_stats_empty_tree(self):
        root = build_tree([], "0.0.0.0/0")
        stats = get_stats(root)
        self.assertEqual(stats["total_devices"], 0)
        self.assertEqual(stats["online"], 0)
        self.assertEqual(stats["offline"], 0)
        self.assertEqual(stats["by_type"], {})

    def test_get_stats_with_mixed_types(self):
        """Multiple devices of same type."""
        devices = [
            _dict_dev("10.0.0.1", device_type="router"),
            _dict_dev("10.0.0.2", device_type="router"),
            _dict_dev("10.0.0.3", device_type="switch"),
        ]
        root = build_tree(devices, "10.0.0.0/8")
        stats = get_stats(root)
        self.assertEqual(stats["by_type"]["router"], 2)
        self.assertEqual(stats["by_type"]["switch"], 1)

    def test_get_stats_returns_all_keys(self):
        devices = _flat_devices()
        root = build_tree(devices, "192.168.0.0/16")
        stats = get_stats(root)
        self.assertIn("total_devices", stats)
        self.assertIn("online", stats)
        self.assertIn("offline", stats)
        self.assertIn("by_type", stats)


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap Tree — Tree Builder Tests")
    print("=" * 60)
    unittest.main(verbosity=2, argv=[sys.argv[0]])
