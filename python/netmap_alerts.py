"""
NetMap Alerts — notification system for network changes.

Detects:
  - NEW_DEVICE:   device appeared on the network
  - DEVICE_GONE:  device disappeared
  - PORT_CHANGE:  open ports changed
  - MAC_CHANGE:   MAC address changed (possible ARP-spoofing!)

Channels (plug-in via AlertChannel ABC):
  - ConsoleChannel  — print to stdout (testing / debugging)
  - TelegramChannel — send via Telegram Bot API
  - WebhookChannel — POST JSON to an HTTP endpoint

Usage:
    from netmap_alerts import AlertManager
    from netmap_monitor import load_result

    mgr = AlertManager({
        "telegram_token": "...",
        "telegram_chat_id": "...",
        "webhook_url": "https://hooks.example.com/alerts",
        "alert_cooldown_seconds": 300,
        "min_importance": "warning",
    })

    prev = load_result("scan_prev.json")
    curr = load_result("scan_curr.json")
    alerts = mgr.check_and_alert(prev, curr)
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# Graceful import: works both as package module and standalone
try:
    from .netmap_device import Device, ScanResult
except ImportError:
    from netmap_device import Device, ScanResult  # type: ignore[no-redef]


# ──────────────────────────────────────────────
#  Enums
# ──────────────────────────────────────────────

class AlertType(Enum):
    NEW_DEVICE  = "new_device"
    DEVICE_GONE = "device_gone"
    PORT_CHANGE = "port_change"
    MAC_CHANGE  = "mac_change"


class AlertImportance(Enum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"


# ──────────────────────────────────────────────
#  Alert metadata
# ──────────────────────────────────────────────

_ALERT_META = {
    AlertType.NEW_DEVICE:  {"emoji": "🟢", "label": "Новое устройство",    "importance": AlertImportance.INFO},
    AlertType.DEVICE_GONE: {"emoji": "🔴", "label": "Устройство пропало",   "importance": AlertImportance.WARNING},
    AlertType.PORT_CHANGE: {"emoji": "🟡", "label": "Изменение портов",     "importance": AlertImportance.WARNING},
    AlertType.MAC_CHANGE:  {"emoji": "🚨", "label": "Смена MAC-адреса",     "importance": AlertImportance.CRITICAL},
}

_IMPORTANCE_WEIGHT = {
    AlertImportance.INFO:     0,
    AlertImportance.WARNING:  1,
    AlertImportance.CRITICAL: 2,
}


# ──────────────────────────────────────────────
#  Alert
# ──────────────────────────────────────────────

class Alert:
    """Single alert event."""

    __slots__ = ("type", "timestamp", "device_ip", "details",
                 "emoji", "label", "importance")

    def __init__(self, alert_type: AlertType, device_ip: str,
                 details: Optional[Dict[str, Any]] = None) -> None:
        self.type = alert_type
        self.timestamp = time.time()
        self.device_ip = device_ip
        self.details = details or {}
        meta = _ALERT_META[alert_type]
        self.emoji = meta["emoji"]
        self.label = meta["label"]
        self.importance = meta["importance"]

    @property
    def ts_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    def __repr__(self) -> str:
        return (f"<Alert {self.type.value} ip={self.device_ip!r} "
                f"importance={self.importance.value}>")


# ──────────────────────────────────────────────
#  Channel interface
# ──────────────────────────────────────────────

class AlertChannel(ABC):
    """Abstract notification channel."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Deliver alert. Return True on success."""
        ...


# ──────────────────────────────────────────────
#  ConsoleChannel
# ──────────────────────────────────────────────

class ConsoleChannel(AlertChannel):
    """Print alerts to stdout — useful for testing and debugging."""

    def __init__(self, verbose: bool = True) -> None:
        self.verbose = verbose

    def send(self, alert: Alert) -> bool:
        ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        header = f"[{ts}] {alert.emoji} {alert.label}: {alert.device_ip}"
        lines = [header]

        if self.verbose:
            d = alert.details
            if d.get("mac"):
                lines.append(f"       MAC     : {d['mac']}")
            if d.get("hostname"):
                lines.append(f"       Hostname: {d['hostname']}")
            if d.get("vendor"):
                lines.append(f"       Vendor  : {d['vendor']}")
            if d.get("os"):
                lines.append(f"       OS      : {d['os']}")
            if d.get("device_type"):
                lines.append(f"       Type    : {d['device_type']}")

            if alert.type == AlertType.PORT_CHANGE:
                if d.get("opened"):
                    lines.append(f"       🟢 Opened : {', '.join(map(str, d['opened']))}")
                if d.get("closed"):
                    lines.append(f"       🔴 Closed : {', '.join(map(str, d['closed']))}")

            if alert.type == AlertType.MAC_CHANGE:
                if d.get("old_mac"):
                    lines.append(f"       Old MAC: {d['old_mac']}")
                if d.get("new_mac"):
                    lines.append(f"       New MAC: {d['new_mac']}")
                lines.append("       ⚠️  Possible ARP-spoofing!")

        print("\n".join(lines))
        print("-" * 50)
        return True


# ──────────────────────────────────────────────
#  TelegramChannel
# ──────────────────────────────────────────────

class TelegramChannel(AlertChannel):
    """Send alerts via Telegram Bot API.

    Uses synchronous requests (no aiohttp).
    Message format: HTML (parse_mode=HTML).
    """

    def __init__(self, token: str, chat_id: str,
                 timeout: float = 10.0) -> None:
        self.token = token
        self.chat_id = chat_id
        self.timeout = timeout
        self.base_url = f"https://api.telegram.org/bot{token}"

    def send(self, alert: Alert) -> bool:
        text = self._format_message(alert)
        url = f"{self.base_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            ok = resp.status_code == 200
            if not ok:
                print(f"[TelegramChannel] HTTP {resp.status_code}: {resp.text[:200]}")
            return ok
        except requests.RequestException as exc:
            print(f"[TelegramChannel] Request failed: {exc}")
            return False

    def _format_message(self, alert: Alert) -> str:
        d = alert.details
        lines: List[str] = []

        # Header
        lines.append("🔔 <b>NetMap Alert</b>")
        lines.append("")

        # Main line
        lines.append(f"{alert.emoji} <b>{alert.label}</b>: <code>{alert.device_ip}</code>")

        # Device info block
        info_parts: List[str] = []
        if d.get("mac"):
            info_parts.append(f"🖧 MAC: <code>{d['mac']}</code>")
        if d.get("hostname"):
            info_parts.append(f"🖥 Hostname: <b>{d['hostname']}</b>")
        if d.get("vendor"):
            info_parts.append(f"🏷 {d['vendor']}")
        if d.get("os"):
            info_parts.append(f"💿 OS: {d['os']}")
        if d.get("device_type") and d["device_type"] != "unknown":
            type_labels = {
                "router":      "📡 Маршрутизатор",
                "switch":      "🔀 Коммутатор",
                "access_point": "📶 Точка доступа",
                "printer":     "🖨 Принтер",
                "camera":      "📷 Камера",
                "server":      "🖥 Сервер",
                "workstation": "💻 Рабочая станция",
                "phone":       "📱 Телефон",
                "iot":         "🔌 IoT-устройство",
            }
            label = type_labels.get(d["device_type"], d["device_type"])
            info_parts.append(f"📦 Тип: {label}")
        lines.extend(info_parts)

        # Type-specific details
        if alert.type == AlertType.PORT_CHANGE:
            lines.append("")
            if d.get("opened"):
                lines.append(
                    f"🟢 <b>Открыты:</b> <code>{', '.join(map(str, d['opened']))}</code>"
                )
            if d.get("closed"):
                lines.append(
                    f"🔴 <b>Закрыты:</b> <code>{', '.join(map(str, d['closed']))}</code>"
                )
            if d.get("prev_ports") is not None and d.get("curr_ports") is not None:
                lines.append(
                    f"📋 <i>Было: {', '.join(map(str, d['prev_ports']))}</i>"
                )
                lines.append(
                    f"📋 <i>Стало: {', '.join(map(str, d['curr_ports']))}</i>"
                )

        elif alert.type == AlertType.MAC_CHANGE:
            lines.append("")
            if d.get("old_mac"):
                lines.append(f"⬅️ Старый MAC: <code>{d['old_mac']}</code>")
            if d.get("new_mac"):
                lines.append(f"➡️ Новый MAC: <code>{d['new_mac']}</code>")
            lines.append("")
            lines.append("⚠️ <b>Возможный ARP-spoofing!</b>")

        return "\n".join(lines)


# ──────────────────────────────────────────────
#  WebhookChannel
# ──────────────────────────────────────────────

class WebhookChannel(AlertChannel):
    """POST alert JSON to an HTTP webhook URL."""

    def __init__(self, url: str, timeout: float = 10.0,
                 headers: Optional[Dict[str, str]] = None) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, alert: Alert) -> bool:
        payload = {
            "source": "netmap",
            "type": alert.type.value,
            "importance": alert.importance.value,
            "timestamp": alert.timestamp,
            "timestamp_iso": alert.ts_iso,
            "device_ip": alert.device_ip,
            "details": alert.details,
        }
        try:
            resp = requests.post(self.url, json=payload,
                                 headers=self.headers, timeout=self.timeout)
            ok = resp.status_code in (200, 201, 202, 204)
            if not ok:
                print(f"[WebhookChannel] HTTP {resp.status_code}: {resp.text[:200]}")
            return ok
        except requests.RequestException as exc:
            print(f"[WebhookChannel] Request failed: {exc}")
            return False


# ──────────────────────────────────────────────
#  AlertManager
# ──────────────────────────────────────────────

class AlertManager:
    """Orchestrates detection → filtering → dispatch.

    Parameters
    ----------
    config : dict
        telegram_token          — Telegram Bot API token
        telegram_chat_id        — target chat / channel ID
        webhook_url             — HTTP endpoint for webhook alerts
        alert_cooldown_seconds  — minimum seconds between same (type, ip) alert (default 300)
        min_importance          — "info" | "warning" | "critical" (default "info")
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        config = config or {}

        self.channels: List[AlertChannel] = []
        self.last_scan_state: Optional[ScanResult] = None

        # Configuration
        self.alert_cooldown: float = float(config.get("alert_cooldown_seconds", 300))
        min_imp_str: str = config.get("min_importance", "info")
        self.min_importance: AlertImportance = AlertImportance(min_imp_str)

        # Cooldown tracker:  key = "type:ip"  →  last alert timestamp
        self._last_alert: Dict[str, float] = {}

        # Auto-register channels from config
        token = config.get("telegram_token")
        chat_id = config.get("telegram_chat_id")
        if token and chat_id:
            self.add_channel(TelegramChannel(token, str(chat_id)))

        webhook = config.get("webhook_url")
        if webhook:
            self.add_channel(WebhookChannel(webhook))

        # Console is always registered for visibility
        self.add_channel(ConsoleChannel())

    # ── Channel management ────────────────────────

    def add_channel(self, channel: AlertChannel) -> None:
        """Register a notification channel."""
        self.channels.append(channel)

    def remove_channel(self, channel: AlertChannel) -> None:
        """Remove a previously registered channel."""
        self.channels = [ch for ch in self.channels if ch is not channel]

    # ── Main entry point ─────────────────────────

    def check_and_alert(self, previous_scan: ScanResult,
                        current_scan: ScanResult) -> List[Alert]:
        """Compare two scans and dispatch alerts for detected changes.

        Returns the list of generated alerts (sent or suppressed by cooldown).
        Updates `self.last_scan_state` to `current_scan` after processing.
        """
        alerts = self._detect_changes(previous_scan, current_scan)

        sent_count = 0
        for alert in alerts:
            if self._should_send(alert):
                self._dispatch(alert)
                self._record_alert(alert)
                sent_count += 1

        if sent_count:
            print(f"[AlertManager] Sent {sent_count}/{len(alerts)} alerts "
                  f"(cooldown={self.alert_cooldown}s, "
                  f"min_importance={self.min_importance.value})")

        self.last_scan_state = current_scan
        return alerts

    # ── Diff engine ──────────────────────────────

    def _detect_changes(self, previous: ScanResult,
                        current: ScanResult) -> List[Alert]:
        alerts: List[Alert] = []

        prev_map: Dict[str, Device] = {d.ip: d for d in previous.devices}
        curr_map: Dict[str, Device] = {d.ip: d for d in current.devices}

        # ── NEW_DEVICE ──
        for ip, dev in curr_map.items():
            if ip not in prev_map:
                alerts.append(Alert(
                    AlertType.NEW_DEVICE, ip,
                    self._device_details(dev),
                ))

        # ── DEVICE_GONE ──
        for ip, dev in prev_map.items():
            if ip not in curr_map:
                alerts.append(Alert(
                    AlertType.DEVICE_GONE, ip,
                    self._device_details(dev),
                ))

        # ── PORT_CHANGE + MAC_CHANGE ──
        common_ips = prev_map.keys() & curr_map.keys()
        for ip in common_ips:
            prev_dev = prev_map[ip]
            curr_dev = curr_map[ip]

            # MAC_CHANGE — only if both MACs are known and differ
            if (prev_dev.mac and curr_dev.mac
                    and prev_dev.mac.lower() != curr_dev.mac.lower()):
                alerts.append(Alert(
                    AlertType.MAC_CHANGE, ip,
                    {
                        "old_mac": prev_dev.mac,
                        "new_mac": curr_dev.mac,
                        "hostname": curr_dev.hostname,
                        "vendor": curr_dev.vendor,
                    },
                ))

            # PORT_CHANGE
            prev_ports = {p.port for p in prev_dev.ports}
            curr_ports = {p.port for p in curr_dev.ports}
            if prev_ports != curr_ports:
                opened = sorted(curr_ports - prev_ports)
                closed = sorted(prev_ports - curr_ports)
                alerts.append(Alert(
                    AlertType.PORT_CHANGE, ip,
                    {
                        "opened": opened,
                        "closed": closed,
                        "prev_ports": sorted(prev_ports),
                        "curr_ports": sorted(curr_ports),
                        "hostname": curr_dev.hostname,
                        "vendor": curr_dev.vendor,
                        "mac": curr_dev.mac,
                    },
                ))

        return alerts

    # ── Helpers ──────────────────────────────────

    @staticmethod
    def _device_details(dev: Device) -> Dict[str, Any]:
        """Extract alert-worthy fields from a Device into a plain dict."""
        return {
            "mac":         dev.mac,
            "hostname":    dev.hostname,
            "vendor":      dev.vendor,
            "os":          dev.os,
            "device_type": dev.device_type,
            "ports":       [p.port for p in dev.ports],
        }

    def _should_send(self, alert: Alert) -> bool:
        """Apply importance filter + per-(type,ip) cooldown."""
        if _IMPORTANCE_WEIGHT[alert.importance] < _IMPORTANCE_WEIGHT[self.min_importance]:
            return False

        key = f"{alert.type.value}:{alert.device_ip}"
        last_ts = self._last_alert.get(key, 0.0)
        if (time.time() - last_ts) < self.alert_cooldown:
            return False

        return True

    def _dispatch(self, alert: Alert) -> None:
        """Send alert through every registered channel."""
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as exc:
                print(f"[AlertManager] Channel {type(channel).__name__} "
                      f"raised: {exc}")

    def _record_alert(self, alert: Alert) -> None:
        """Update cooldown tracker."""
        key = f"{alert.type.value}:{alert.device_ip}"
        self._last_alert[key] = time.time()


# ──────────────────────────────────────────────
#  Self-test (run with: python netmap_alerts.py)
# ──────────────────────────────────────────────

def _demo() -> None:
    """Quick smoke test — no real network traffic, no real messages."""
    from dataclasses import replace

    print("=" * 60)
    print(" NetMap Alerts — smoke test")
    print("=" * 60)

    # Build two fake ScanResults
    dev_a = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01",
                   hostname="router.local", vendor="MikroTik",
                   device_type="router", ports=[
                       type("Port", (), {"port": 22, "protocol": "tcp"})(),
                       type("Port", (), {"port": 80, "protocol": "tcp"})(),
                   ])
    dev_b = Device(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:02",
                   hostname="printer.local", vendor="HP",
                   device_type="printer", ports=[
                       type("Port", (), {"port": 9100, "protocol": "tcp"})(),
                   ])
    dev_c = Device(ip="192.168.1.30", mac="aa:bb:cc:dd:ee:03",
                   hostname="camera.local", vendor="Hikvision",
                   device_type="camera", ports=[
                       type("Port", (), {"port": 554, "protocol": "tcp"})(),
                       type("Port", (), {"port": 80, "protocol": "tcp"})(),
                   ])

    # Previous scan: A + B + C
    prev = ScanResult(
        scan_time="2026-05-28T17:00:00",
        network="192.168.1.0/24",
        devices=[dev_a, dev_b, dev_c],
        edges=[],
    )

    # Current scan:
    #   - A: MAC changed (ARP spoof!), ports changed
    #   - B: gone
    #   - C: same
    #   - D: new device
    dev_a2 = replace(dev_a, mac="ff:ff:ff:ff:ff:ff", ports=[
        type("Port", (), {"port": 22, "protocol": "tcp"})(),
        type("Port", (), {"port": 443, "protocol": "tcp"})(),
    ])
    dev_d = Device(ip="192.168.1.40", mac="aa:bb:cc:dd:ee:04",
                   hostname="phone.local", vendor="Samsung",
                   device_type="phone", ports=[])

    curr = ScanResult(
        scan_time="2026-05-28T17:30:00",
        network="192.168.1.0/24",
        devices=[dev_a2, dev_c, dev_d],
        edges=[],
    )

    mgr = AlertManager({
        "alert_cooldown_seconds": 0,   # no cooldown for demo
        "min_importance": "info",
    })

    alerts = mgr.check_and_alert(prev, curr)
    print(f"\nGenerated {len(alerts)} alert(s):")
    for a in alerts:
        print(f"  {a.emoji} {a.label} — {a.device_ip} [{a.importance.value}]")

    print("\n✅ Smoke test passed.\n")


if __name__ == "__main__":
    _demo()
