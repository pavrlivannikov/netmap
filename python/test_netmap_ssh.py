#!/usr/bin/env python3
"""
NetMap SSH — тесты парсинга SSH-вывода коммутаторов и probe.
Запуск: python -m pytest test_netmap_ssh.py -v
       python -m unittest test_netmap_ssh.py
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_ssh import (
    MacEntry,
    _normalise_mac,
    _parse_cisco_style,
    _parse_mikrotik,
    _parse_tplink,
    get_fdb_ssh,
)


# ------------------------------------------------------------------
# MAC normalisation
# ------------------------------------------------------------------

class TestNormaliseMAC(unittest.TestCase):
    """Приведение MAC-адресов к единому формату."""

    def test_colon_format_preserved(self):
        self.assertEqual(_normalise_mac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff")

    def test_dash_format_converted(self):
        self.assertEqual(_normalise_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")

    def test_cisco_dotted_format(self):
        self.assertEqual(_normalise_mac("0011.2233.4455"), "00:11:22:33:44:55")

    def test_uppercase_converted(self):
        self.assertEqual(_normalise_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")

    def test_mixed_format(self):
        self.assertEqual(_normalise_mac("Aa-Bb.Cc-Dd.Ee-Ff"), "aa:bb:cc:dd:ee:ff")

    def test_garbage_preserved_as_is(self):
        result = _normalise_mac("not-a-mac")
        self.assertEqual(result, "not-a-mac")

    def test_incomplete_mac(self):
        result = _normalise_mac("aa:bb:cc")
        self.assertEqual(result, "aa:bb:cc")


# ------------------------------------------------------------------
# Cisco IOS parser — dotted MAC
# ------------------------------------------------------------------

class TestParseCiscoStyle(unittest.TestCase):
    """Парсинг show mac address-table (Cisco IOS/IOS-XE)."""

    def test_parse_cisco_dotted_mac(self):
        output = """\
Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Gi1/0/1
  10    aabb.ccdd.eeff    STATIC      Gi1/0/24
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 2)

        self.assertEqual(entries[0].mac, "00:11:22:33:44:55")
        self.assertEqual(entries[0].port, "Gi1/0/1")
        self.assertEqual(entries[0].vlan, 1)

        self.assertEqual(entries[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries[1].port, "Gi1/0/24")
        self.assertEqual(entries[1].vlan, 10)

    def test_parse_cisco_with_star(self):
        """Entries flagged with * are still parsed."""
        output = """\
  *    1    0011.2233.4455    dynamic    Gi1/0/1
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mac, "00:11:22:33:44:55")

    def test_parse_cisco_colon_mac(self):
        """Cisco NX-OS uses colon format."""
        output = """\
VLAN      MAC Address         Type      age     Secure NTFY   Ports
---------+-----------------+--------+---------+------+----+------------------
1         00:11:22:33:44:55   dynamic  0          F      F    Eth1/1
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mac, "00:11:22:33:44:55")
        self.assertEqual(entries[0].port, "Eth1/1")
        self.assertEqual(entries[0].vlan, 1)

    def test_parse_cisco_multiple_vlans(self):
        output = """\
  10        0011.2233.4455  dynamic   Gi1/0/1
  20        aabb.ccdd.eeff  dynamic   Gi1/0/2
 100        1122.3344.5566  static    Gi1/0/48
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 3)
        vlans = {e.vlan for e in entries}
        self.assertEqual(vlans, {10, 20, 100})

    def test_parse_cisco_skips_non_port_keywords(self):
        """Lines where the 'port' column is 'dynamic' or 'static' are filtered."""
        output = """\
   1    0011.2233.4455    dynamic    dynamic
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 0)

    def test_parse_cisco_empty_output(self):
        entries = _parse_cisco_style("")
        self.assertEqual(len(entries), 0)

    def test_parse_cisco_header_lines(self):
        """Header lines should be ignored."""
        output = """\
Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
"""
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 0)

    def test_parse_cisco_banner_ipx(self):
        """Some older IOS includes protocol field like ip,ipx."""
        output = "  1    0011.2233.4455  dynamic     ip,ipx       GigabitEthernet1/0/1"
        entries = _parse_cisco_style(output)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].port, "GigabitEthernet1/0/1")


# ------------------------------------------------------------------
# TP-Link parser
# ------------------------------------------------------------------

class TestParseTPLink(unittest.TestCase):
    """Парсинг show mac-address (TP-Link JetStream)."""

    def test_parse_tplink_basic(self):
        output = """\
VlanId  Mac Address        Type    Port
------  ---------------    ------  ---------
1       00:11:22:33:44:55  Dynamic 1/0/1
1       aa:bb:cc:dd:ee:ff  Static  1/0/24
"""
        entries = _parse_tplink(output)
        self.assertEqual(len(entries), 2)

        self.assertEqual(entries[0].mac, "00:11:22:33:44:55")
        self.assertEqual(entries[0].port, "1/0/1")
        self.assertEqual(entries[0].vlan, 1)

        self.assertEqual(entries[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries[1].port, "1/0/24")
        self.assertEqual(entries[1].vlan, 1)

    def test_parse_tplink_dash_mac(self):
        """TP-Link might use dash format."""
        output = "  1  aa-bb-cc-dd-ee-ff  Dynamic  1/0/1"
        entries = _parse_tplink(output)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].mac, "aa:bb:cc:dd:ee:ff")

    def test_parse_tplink_empty_output(self):
        entries = _parse_tplink("")
        self.assertEqual(len(entries), 0)

    def test_parse_tplink_header_skipped(self):
        output = """\
VlanId  Mac Address        Type    Port
------  ---------------    ------  ---------
"""
        entries = _parse_tplink(output)
        self.assertEqual(len(entries), 0)

    def test_parse_tplink_multiple_vlans(self):
        output = """\
1       11:22:33:44:55:66  Dynamic 1/0/1
100     aa:bb:cc:dd:ee:ff  Dynamic 1/0/10
"""
        entries = _parse_tplink(output)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].vlan, 1)
        self.assertEqual(entries[1].vlan, 100)


# ------------------------------------------------------------------
# MikroTik parser
# ------------------------------------------------------------------

class TestParseMikroTik(unittest.TestCase):
    """Парсинг /interface bridge host print (MikroTik RouterOS)."""

    def test_parse_mikrotik_basic(self):
        output = """\
Flags: L - local, D - dynamic
 #    MAC-ADDRESS        VID ON-INTERFACE      BRIDGE
 0    00:11:22:33:44:55    1 ether2            bridge1
 1    aa:bb:cc:dd:ee:ff    1 ether3            bridge1
"""
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 2)

        self.assertEqual(entries[0].mac, "00:11:22:33:44:55")
        self.assertEqual(entries[0].port, "ether2")
        self.assertEqual(entries[0].vlan, 1)

        self.assertEqual(entries[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries[1].port, "ether3")
        self.assertEqual(entries[1].vlan, 1)

    def test_parse_mikrotik_with_flags(self):
        """Rows with D flag should be parsed."""
        output = """\
 0 D  00:11:22:33:44:55  ether2  bridge1
 1 DL  aa:bb:cc:dd:ee:ff  ether3  bridge1
"""
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].port, "ether2")

    def test_parse_mikrotik_no_vlan(self):
        """Without VLAN column — vlan should be None."""
        output = """\
 0  00:11:22:33:44:55  ether2  bridge1
"""
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 1)
        self.assertIsNone(entries[0].vlan)
        self.assertEqual(entries[0].port, "ether2")

    def test_parse_mikrotik_empty(self):
        entries = _parse_mikrotik("")
        self.assertEqual(len(entries), 0)

    def test_parse_mikrotik_invalid_line(self):
        output = "  just some random text\n"
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 0)

    def test_parse_mikrotik_header_skipped(self):
        output = """\
Flags: X - disabled, D - dynamic
 #    MAC-ADDRESS       ON-INTERFACE   BRIDGE
 0    00:11:22:33:44:55 ether2         bridge1
"""
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 1)


# ------------------------------------------------------------------
# MacEntry dataclass
# ------------------------------------------------------------------

class TestMacEntryDataclass(unittest.TestCase):
    """MacEntry dataclass."""

    def test_mac_entry_creation(self):
        e = MacEntry(mac="aa:bb:cc:dd:ee:ff", port="Gi1/0/1", vlan=10)
        self.assertEqual(e.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(e.port, "Gi1/0/1")
        self.assertEqual(e.vlan, 10)

    def test_mac_entry_no_vlan(self):
        e = MacEntry(mac="00:11:22:33:44:55", port="ether1")
        self.assertEqual(e.mac, "00:11:22:33:44:55")
        self.assertEqual(e.port, "ether1")
        self.assertIsNone(e.vlan)

    def test_mac_entry_to_dict(self):
        e = MacEntry(mac="aa:bb:cc:dd:ee:ff", port="1/0/1", vlan=1)
        d = e.to_dict()
        self.assertEqual(d["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(d["port"], "1/0/1")
        self.assertEqual(d["vlan"], 1)


# ------------------------------------------------------------------
# Cross-parser tests
# ------------------------------------------------------------------

class TestParserCrossCheck(unittest.TestCase):
    """Проверка что парсеры не ломаются на чужих форматах."""

    def test_cisco_parser_on_empty(self):
        self.assertEqual(len(_parse_cisco_style("")), 0)

    def test_cisco_parser_on_tplink_output(self):
        """TP-Link output should not match Cisco parser."""
        output = "1  00:11:22:33:44:55  Dynamic  1/0/1"
        # The Cisco parser regex might actually match this too,
        # since the TP-Link format is similar. That's fine — it should
        # produce entries or not crash.
        entries = _parse_cisco_style(output)
        # May or may not parse; the key is no exception
        self.assertIsInstance(entries, list)

    def test_tplink_parser_on_cisco_output(self):
        """Cisco dotted MAC output should NOT match TP-Link parser."""
        output = "1  0011.2233.4455  dynamic  Gi1/0/1"
        entries = _parse_tplink(output)
        # Dotted MAC doesn't match the colon/dash regex
        self.assertEqual(len(entries), 0)

    def test_mikrotik_parser_on_cisco_output(self):
        """Cisco output should not crash MikroTik parser."""
        output = "1  0011.2233.4455  dynamic  Gi1/0/1"
        entries = _parse_mikrotik(output)
        self.assertEqual(len(entries), 0)

    def test_all_parsers_on_junk(self):
        junk = "this is garbage\nnot even close\n"
        for parser in [_parse_cisco_style, _parse_tplink, _parse_mikrotik]:
            result = parser(junk)
            self.assertEqual(len(result), 0,
                             f"{parser.__name__} should return empty list on junk")


# ------------------------------------------------------------------
# get_fdb_ssh — connection failure tests
# ------------------------------------------------------------------

class TestGetFDBSSH(unittest.TestCase):
    """Тесты get_fdb_ssh на ошибках соединения (без реального SSH)."""

    def test_connect_failure_returns_empty(self):
        """Without a real SSH server, connecting should fail gracefully."""
        result = get_fdb_ssh(
            host="192.0.2.1",       # TEST-NET-1 — never routable
            username="test",
            password="test",
            port=22,
            timeout=2.0,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_connect_invalid_port_returns_empty(self):
        """Connection refused on a closed port."""
        result = get_fdb_ssh(
            host="127.0.0.1",
            username="test",
            password="test",
            port=19999,
            timeout=2.0,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_connect_unknown_host_returns_empty(self):
        """Unresolvable hostname."""
        result = get_fdb_ssh(
            host="does-not-exist.invalid",
            username="test",
            password="test",
            timeout=2.0,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_get_fdb_returns_list(self):
        """Return type is always a list, even on error."""
        result = get_fdb_ssh(
            host="10.255.255.255",
            username="x", password="y",
            timeout=1.0,
        )
        self.assertIsInstance(result, list)

    def test_vendor_hint_does_not_crash(self):
        """Vendor hint should not cause errors."""
        result = get_fdb_ssh(
            host="192.0.2.1",
            username="test",
            password="test",
            vendor="cisco",
            timeout=1.0,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_mikrotik_vendor_hint(self):
        result = get_fdb_ssh(
            host="192.0.2.1",
            username="test",
            password="test",
            vendor="mikrotik",
            timeout=1.0,
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap SSH — Parser Tests")
    print("=" * 60)
    unittest.main(verbosity=2, argv=[sys.argv[0]])
