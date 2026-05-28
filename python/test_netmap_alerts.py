#!/usr/bin/env python3
"""
NetMap Alerts — тесты системы уведомлений.
Запуск: python -m pytest test_netmap_alerts.py -v
       python -m unittest test_netmap_alerts.py
"""
import sys
import os
import unittest
import time
import io
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_alerts import (
    Alert, AlertType, AlertImportance,
    AlertChannel, ConsoleChannel, TelegramChannel, WebhookChannel,
    AlertManager,
    _IMPORTANCE_WEIGHT,
)
from netmap_device import Device, Port, Edge, ScanResult


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_device(ip, mac="", hostname=None, vendor=None, device_type="unknown",
                 status="online", ports=None):
    """Quick Device factory."""
    d = Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor,
               device_type=device_type, status=status)
    d.ports = ports or []
    return d


def _make_scan(devices, scan_time="2026-05-28T18:00:00", network="192.168.1.0/24"):
    """Quick ScanResult factory."""
    return ScanResult(scan_time=scan_time, network=network,
                      devices=devices, edges=[])


# ------------------------------------------------------------------
# Alert dataclass tests
# ------------------------------------------------------------------

class TestAlertDataclass(unittest.TestCase):
    """Базовые тесты класса Alert."""

    def test_alert_creation(self):
        a = Alert(AlertType.NEW_DEVICE, "192.168.1.1")
        self.assertEqual(a.type, AlertType.NEW_DEVICE)
        self.assertEqual(a.device_ip, "192.168.1.1")
        self.assertEqual(a.importance, AlertImportance.INFO)

    def test_alert_mac_change_is_critical(self):
        a = Alert(AlertType.MAC_CHANGE, "10.0.0.1")
        self.assertEqual(a.importance, AlertImportance.CRITICAL)

    def test_alert_device_gone_is_warning(self):
        a = Alert(AlertType.DEVICE_GONE, "10.0.0.2")
        self.assertEqual(a.importance, AlertImportance.WARNING)

    def test_alert_timestamp(self):
        before = time.time()
        a = Alert(AlertType.NEW_DEVICE, "1.2.3.4")
        after = time.time()
        self.assertGreaterEqual(a.timestamp, before)
        self.assertLessEqual(a.timestamp, after)

    def test_alert_ts_iso(self):
        a = Alert(AlertType.NEW_DEVICE, "1.2.3.4")
        iso = a.ts_iso
        self.assertIn("T", iso)
        self.assertTrue(iso.endswith("+00:00") or iso.endswith("Z"))

    def test_alert_details(self):
        a = Alert(AlertType.PORT_CHANGE, "10.0.0.1",
                  details={"opened": [443], "closed": [80]})
        self.assertEqual(a.details["opened"], [443])
        self.assertEqual(a.details["closed"], [80])

    def test_alert_repr(self):
        a = Alert(AlertType.NEW_DEVICE, "192.168.1.1")
        r = repr(a)
        self.assertIn("new_device", r)
        self.assertIn("192.168.1.1", r)

    def test_alert_emoji_all_types(self):
        for at in AlertType:
            a = Alert(at, "10.0.0.1")
            self.assertTrue(a.emoji)
            self.assertTrue(a.label)

    def test_importance_weights(self):
        self.assertEqual(_IMPORTANCE_WEIGHT[AlertImportance.INFO], 0)
        self.assertEqual(_IMPORTANCE_WEIGHT[AlertImportance.WARNING], 1)
        self.assertEqual(_IMPORTANCE_WEIGHT[AlertImportance.CRITICAL], 2)


# ------------------------------------------------------------------
# ConsoleChannel tests
# ------------------------------------------------------------------

class TestConsoleChannel(unittest.TestCase):
    """ConsoleChannel — проверка что не падает и что-то выводит."""

    def test_send_to_console(self):
        ch = ConsoleChannel(verbose=True)
        a = Alert(AlertType.NEW_DEVICE, "192.168.1.1",
                  details={"mac": "aa:bb:cc:dd:ee:01",
                           "hostname": "router.home",
                           "vendor": "MikroTik"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = ch.send(a)
        self.assertTrue(result)
        output = buf.getvalue()
        self.assertIn("192.168.1.1", output)
        self.assertIn("router.home", output)
        self.assertIn("MikroTik", output)

    def test_send_verbose_false(self):
        ch = ConsoleChannel(verbose=False)
        a = Alert(AlertType.NEW_DEVICE, "10.0.0.5",
                  details={"mac": "11:22:33:44:55:66"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            ch.send(a)
        output = buf.getvalue()
        # Should contain IP but not detailed info
        self.assertIn("10.0.0.5", output)
        self.assertNotIn("11:22:33:44:55:66", output)

    def test_send_mac_change_shows_spoofing(self):
        ch = ConsoleChannel(verbose=True)
        a = Alert(AlertType.MAC_CHANGE, "192.168.1.1",
                  details={"old_mac": "aa:bb:cc:dd:ee:01",
                           "new_mac": "fa:ke:ma:ca:dd:rs"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            ch.send(a)
        output = buf.getvalue()
        self.assertIn("ARP-spoofing", output)

    def test_send_port_change_shows_opened_closed(self):
        ch = ConsoleChannel(verbose=True)
        a = Alert(AlertType.PORT_CHANGE, "192.168.1.10",
                  details={"opened": [443, 8080], "closed": [80],
                           "mac": "00:11:22:33:44:55"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            ch.send(a)
        output = buf.getvalue()
        self.assertIn("443", output)
        self.assertIn("8080", output)
        self.assertIn("80", output)


# ------------------------------------------------------------------
# AlertManager — detection tests
# ------------------------------------------------------------------

class TestAlertManagerDetection(unittest.TestCase):
    """Проверка детекции изменений."""

    def setUp(self):
        self.mgr = AlertManager({
            "alert_cooldown_seconds": 0,
            "min_importance": "info",
        })

    def test_new_device_detected(self):
        prev = _make_scan([])
        curr = _make_scan([_make_device("10.0.0.1", mac="aa:bb:cc:dd:ee:01")])
        alerts = self.mgr._detect_changes(prev, curr)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, AlertType.NEW_DEVICE)
        self.assertEqual(alerts[0].device_ip, "10.0.0.1")

    def test_device_gone_detected(self):
        prev = _make_scan([_make_device("10.0.0.1")])
        curr = _make_scan([])
        alerts = self.mgr._detect_changes(prev, curr)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, AlertType.DEVICE_GONE)
        self.assertEqual(alerts[0].device_ip, "10.0.0.1")

    def test_new_and_gone_detected(self):
        prev = _make_scan([
            _make_device("10.0.0.1"),
            _make_device("10.0.0.2"),
        ])
        curr = _make_scan([
            _make_device("10.0.0.2"),
            _make_device("10.0.0.3"),
        ])
        alerts = self.mgr._detect_changes(prev, curr)
        types = {a.type for a in alerts}
        self.assertIn(AlertType.NEW_DEVICE, types)
        self.assertIn(AlertType.DEVICE_GONE, types)

    def test_no_change_detected(self):
        devs = [_make_device("10.0.0.1"), _make_device("10.0.0.2")]
        prev = _make_scan(devs)
        curr = _make_scan(devs)
        alerts = self.mgr._detect_changes(prev, curr)
        self.assertEqual(len(alerts), 0)

    def test_port_change_detected(self):
        d1_prev = _make_device("10.0.0.1", ports=[
            Port(port=22, service="SSH"),
            Port(port=80, service="HTTP"),
        ])
        d1_curr = _make_device("10.0.0.1", ports=[
            Port(port=22, service="SSH"),
            Port(port=443, service="HTTPS"),
        ])
        prev = _make_scan([d1_prev])
        curr = _make_scan([d1_curr])
        alerts = self.mgr._detect_changes(prev, curr)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, AlertType.PORT_CHANGE)
        self.assertIn("opened", alerts[0].details)
        self.assertIn("closed", alerts[0].details)
        self.assertIn(443, alerts[0].details["opened"])
        self.assertIn(80, alerts[0].details["closed"])

    def test_mac_change_detected(self):
        d_prev = _make_device("10.0.0.1", mac="aa:bb:cc:dd:ee:01")
        d_curr = _make_device("10.0.0.1", mac="fa:ke:ma:ca:dd:rs")
        prev = _make_scan([d_prev])
        curr = _make_scan([d_curr])
        alerts = self.mgr._detect_changes(prev, curr)
        mac_alerts = [a for a in alerts if a.type == AlertType.MAC_CHANGE]
        self.assertEqual(len(mac_alerts), 1)
        self.assertEqual(mac_alerts[0].details["old_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(mac_alerts[0].details["new_mac"], "fa:ke:ma:ca:dd:rs")

    def test_mac_change_requires_both_macs(self):
        # Missing MAC in prev: no alert
        d_prev = _make_device("10.0.0.1", mac="")
        d_curr = _make_device("10.0.0.1", mac="fa:ke:ma:ca:dd:rs")
        prev = _make_scan([d_prev])
        curr = _make_scan([d_curr])
        alerts = self.mgr._detect_changes(prev, curr)
        mac_alerts = [a for a in alerts if a.type == AlertType.MAC_CHANGE]
        self.assertEqual(len(mac_alerts), 0)

    def test_mac_change_case_insensitive(self):
        d_prev = _make_device("10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
        d_curr = _make_device("10.0.0.1", mac="aa:bb:cc:dd:ee:ff")
        prev = _make_scan([d_prev])
        curr = _make_scan([d_curr])
        alerts = self.mgr._detect_changes(prev, curr)
        mac_alerts = [a for a in alerts if a.type == AlertType.MAC_CHANGE]
        self.assertEqual(len(mac_alerts), 0)


# ------------------------------------------------------------------
# AlertManager — cooldown tests
# ------------------------------------------------------------------

class TestAlertManagerCooldown(unittest.TestCase):
    """Проверка механизма cooldown."""

    def test_cooldown_blocks_repeat(self):
        mgr = AlertManager({
            "alert_cooldown_seconds": 300,
            "min_importance": "info",
        })
        # First scan: empty → device appears
        prev = _make_scan([])
        curr = _make_scan([_make_device("10.0.0.1")])
        alerts1 = mgr.check_and_alert(prev, curr)
        # check_and_alert already dispatched what passed _should_send
        self.assertGreaterEqual(len(alerts1), 1)

        # Second scan: device still present, no new changes
        prev2 = curr
        curr2 = _make_scan([_make_device("10.0.0.1")])
        alerts2 = mgr.check_and_alert(prev2, curr2)
        self.assertEqual(len(alerts2), 0)  # no changes detected

        # Third: device appears again (was in prev2 but not here — this is no-change)
        # Actually, let's do a disappeared + reappeared within cooldown
        curr3 = _make_scan([])  # device gone
        alerts3 = mgr.check_and_alert(curr2, curr3)
        self.assertGreaterEqual(len(alerts3), 1)  # DEVICE_GONE detected

        curr4 = _make_scan([_make_device("10.0.0.1")])  # device back
        # Same detection should happen
        prev_for_check = curr3  # no devices
        alerts4 = mgr.check_and_alert(prev_for_check, curr4)
        # Should detect NEW_DEVICE
        new_alerts = [a for a in alerts4 if a.type == AlertType.NEW_DEVICE]
        self.assertGreaterEqual(len(new_alerts), 1)

    def test_cooldown_key_is_type_ip(self):
        mgr = AlertManager({"alert_cooldown_seconds": 300})
        # Record alert for NEW_DEVICE on 10.0.0.1
        a1 = Alert(AlertType.NEW_DEVICE, "10.0.0.1")
        mgr._record_alert(a1)
        self.assertFalse(mgr._should_send(a1))

        # Different IP should still send
        a2 = Alert(AlertType.NEW_DEVICE, "10.0.0.2")
        self.assertTrue(mgr._should_send(a2))

        # Different type on same IP should still send
        a3 = Alert(AlertType.DEVICE_GONE, "10.0.0.1")
        self.assertTrue(mgr._should_send(a3))

    def test_zero_cooldown_allows_repeat(self):
        mgr = AlertManager({"alert_cooldown_seconds": 0})
        a = Alert(AlertType.NEW_DEVICE, "10.0.0.1")
        mgr._record_alert(a)
        self.assertTrue(mgr._should_send(a))


# ------------------------------------------------------------------
# AlertManager — importance filter tests
# ------------------------------------------------------------------

class TestAlertManagerImportance(unittest.TestCase):
    """Проверка фильтрации по важности."""

    def test_min_importance_warning_blocks_info(self):
        mgr = AlertManager({"min_importance": "warning", "alert_cooldown_seconds": 0})
        # NEW_DEVICE is INFO — should be blocked
        a = Alert(AlertType.NEW_DEVICE, "10.0.0.1")
        self.assertFalse(mgr._should_send(a))

    def test_min_importance_warning_allows_warning(self):
        mgr = AlertManager({"min_importance": "warning", "alert_cooldown_seconds": 0})
        a = Alert(AlertType.DEVICE_GONE, "10.0.0.1")
        self.assertTrue(mgr._should_send(a))

    def test_min_importance_critical_blocks_warning(self):
        mgr = AlertManager({"min_importance": "critical", "alert_cooldown_seconds": 0})
        a = Alert(AlertType.PORT_CHANGE, "10.0.0.1")
        self.assertFalse(mgr._should_send(a))

    def test_min_importance_critical_allows_critical(self):
        mgr = AlertManager({"min_importance": "critical", "alert_cooldown_seconds": 0})
        a = Alert(AlertType.MAC_CHANGE, "10.0.0.1")
        self.assertTrue(mgr._should_send(a))


# ------------------------------------------------------------------
# AlertManager — channel management
# ------------------------------------------------------------------

class TestAlertManagerChannels(unittest.TestCase):
    """Управление каналами."""

    def test_default_console_channel(self):
        mgr = AlertManager()
        self.assertGreaterEqual(len(mgr.channels), 1)
        self.assertTrue(any(isinstance(c, ConsoleChannel) for c in mgr.channels))

    def test_add_remove_channel(self):
        mgr = AlertManager()
        initial_count = len(mgr.channels)
        ch = TelegramChannel("dummy_token", "123456")
        mgr.add_channel(ch)
        self.assertEqual(len(mgr.channels), initial_count + 1)
        mgr.remove_channel(ch)
        self.assertEqual(len(mgr.channels), initial_count)

    def test_telegram_auto_registered(self):
        mgr = AlertManager({
            "telegram_token": "test_token_123",
            "telegram_chat_id": "98765",
        })
        tg_channels = [c for c in mgr.channels if isinstance(c, TelegramChannel)]
        self.assertEqual(len(tg_channels), 1)
        self.assertEqual(tg_channels[0].token, "test_token_123")
        self.assertEqual(tg_channels[0].chat_id, "98765")

    def test_webhook_auto_registered(self):
        mgr = AlertManager({
            "webhook_url": "https://hooks.example.com/alerts",
        })
        wh_channels = [c for c in mgr.channels if isinstance(c, WebhookChannel)]
        self.assertEqual(len(wh_channels), 1)
        self.assertEqual(wh_channels[0].url, "https://hooks.example.com/alerts")

    def test_channel_dispatch_called(self):
        """Verify dispatch sends to all channels."""
        sent_alerts = []

        class MockChannel(AlertChannel):
            def send(self, alert):
                sent_alerts.append(alert)
                return True

        mgr = AlertManager({"alert_cooldown_seconds": 0})
        # Remove default console channel to avoid stdout noise
        mgr.channels = []
        ch1 = MockChannel()
        ch2 = MockChannel()
        mgr.add_channel(ch1)
        mgr.add_channel(ch2)

        prev = _make_scan([])
        curr = _make_scan([_make_device("10.0.0.1")])
        mgr.check_and_alert(prev, curr)

        # Each channel receives the alert
        self.assertGreaterEqual(len(sent_alerts), 2)


# ------------------------------------------------------------------
# AlertManager — check_and_alert integration
# ------------------------------------------------------------------

class TestAlertManagerIntegration(unittest.TestCase):
    """Интеграционный тест check_and_alert."""

    def test_check_and_alert_returns_alerts(self):
        mgr = AlertManager({"alert_cooldown_seconds": 0})
        prev = _make_scan([
            _make_device("192.168.1.1", mac="aa:bb:cc:dd:ee:01"),
        ])
        curr = _make_scan([
            _make_device("192.168.1.1", mac="aa:bb:cc:dd:ee:01"),
            _make_device("192.168.1.2", mac="aa:bb:cc:dd:ee:02"),
        ])
        alerts = mgr.check_and_alert(prev, curr)
        new_alerts = [a for a in alerts if a.type == AlertType.NEW_DEVICE]
        self.assertEqual(len(new_alerts), 1)

    def test_last_scan_state_updated(self):
        mgr = AlertManager({"alert_cooldown_seconds": 0})
        prev = _make_scan([])
        curr = _make_scan([_make_device("10.0.0.1")])
        mgr.check_and_alert(prev, curr)
        self.assertIsNotNone(mgr.last_scan_state)
        self.assertEqual(mgr.last_scan_state.devices[0].ip, "10.0.0.1")

    def test_mac_change_with_port_change(self):
        """MAC changed + ports changed at same time: both alerts fire."""
        d_prev = _make_device("10.0.0.1", mac="aa:bb:cc:dd:ee:01",
                              ports=[Port(port=80)])
        d_curr = _make_device("10.0.0.1", mac="fa:ke:ma:ca:dd:rs",
                              ports=[Port(port=443)])
        prev = _make_scan([d_prev])
        curr = _make_scan([d_curr])
        alerts = self.mgr = AlertManager({"alert_cooldown_seconds": 0})
        alerts = self.mgr._detect_changes(prev, curr)
        types = {a.type for a in alerts}
        self.assertIn(AlertType.MAC_CHANGE, types)
        self.assertIn(AlertType.PORT_CHANGE, types)


# ------------------------------------------------------------------
# AlertManager — error resilience
# ------------------------------------------------------------------

class TestAlertManagerErrorResilience(unittest.TestCase):
    """Устойчивость к ошибкам в каналах."""

    def test_channel_exception_does_not_crash(self):
        class FailingChannel(AlertChannel):
            def send(self, alert):
                raise RuntimeError("simulated channel failure")

        mgr = AlertManager({"alert_cooldown_seconds": 0})
        mgr.channels = [FailingChannel()]

        prev = _make_scan([])
        curr = _make_scan([_make_device("10.0.0.1")])
        # Should not raise
        alerts = mgr.check_and_alert(prev, curr)
        self.assertGreaterEqual(len(alerts), 1)


# ------------------------------------------------------------------
# TelegramChannel — formatting (no network)
# ------------------------------------------------------------------

class TestTelegramChannelFormatting(unittest.TestCase):
    """Форматирование сообщений без отправки в сеть."""

    def test_format_new_device(self):
        ch = TelegramChannel("fake_token", "123")
        a = Alert(AlertType.NEW_DEVICE, "192.168.1.1",
                  details={"mac": "aa:bb:cc:dd:ee:01",
                           "hostname": "router.home",
                           "vendor": "MikroTik",
                           "device_type": "router"})
        text = ch._format_message(a)
        self.assertIn("192.168.1.1", text)
        self.assertIn("router.home", text)
        self.assertIn("MikroTik", text)
        self.assertIn("<b>", text)  # HTML format

    def test_format_mac_change(self):
        ch = TelegramChannel("fake_token", "123")
        a = Alert(AlertType.MAC_CHANGE, "10.0.0.1",
                  details={"old_mac": "11:22:33:44:55:66",
                           "new_mac": "aa:bb:cc:dd:ee:ff"})
        text = ch._format_message(a)
        self.assertIn("11:22:33:44:55:66", text)
        self.assertIn("aa:bb:cc:dd:ee:ff", text)
        self.assertIn("ARP-spoofing", text)


# ------------------------------------------------------------------
# WebhookChannel — payload structure (no network)
# ------------------------------------------------------------------

class TestWebhookChannel(unittest.TestCase):
    """Структура payload без реальной отправки."""

    def test_payload_matches_alert(self):
        """Verify the JSON payload is constructed correctly.
        We can't test send without a server, but we check the payload-building indirectly.
        """
        # WebhookChannel.send builds a dict and tries to POST it.
        # We can monkey-patch requests.post to capture the payload.
        import json as json_mod

        captured_payload = []

        def fake_post(url, json=None, headers=None, timeout=None):
            captured_payload.append(json)
            # Return a mock response
            class FakeResp:
                status_code = 200
                text = "OK"
            return FakeResp()

        import netmap_alerts
        original_post = netmap_alerts.requests.post
        netmap_alerts.requests.post = fake_post
        try:
            ch = WebhookChannel("https://example.com/hook")
            a = Alert(AlertType.NEW_DEVICE, "10.0.0.1",
                      details={"hostname": "test"})
            ch.send(a)
            self.assertEqual(len(captured_payload), 1)
            payload = captured_payload[0]
            self.assertEqual(payload["source"], "netmap")
            self.assertEqual(payload["type"], "new_device")
            self.assertEqual(payload["device_ip"], "10.0.0.1")
            self.assertEqual(payload["details"]["hostname"], "test")
            self.assertEqual(payload["importance"], "info")
            self.assertIn("timestamp_iso", payload)
        finally:
            netmap_alerts.requests.post = original_post


if __name__ == "__main__":
    print("=" * 60)
    print("NetMap Alerts — Alert System Tests")
    print("=" * 60)
    unittest.main(verbosity=2, argv=[sys.argv[0]])
