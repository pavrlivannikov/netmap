"""
NetMap Tree — группировка устройств по подсетям в древовидную структуру.

Использование:
    from netmap_tree import NetNode, build_tree, get_stats, tree_to_dict

    devices = [...]          # список Device или dict'ов с полем ip
    root = build_tree(devices, "192.168.0.0/16")
    print(tree_to_dict(root))
"""

import re
import ipaddress
from typing import List, Optional, Dict, Any


class NetNode:
    """Узел дерева сети."""

    def __init__(
        self,
        name: str,
        node_type: str = "network",  # "network" | "subnet" | "device"
        children: Optional[List["NetNode"]] = None,
        data: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.node_type = node_type
        self.children = children or []
        self.data = data or {}

    def add_child(self, child: "NetNode") -> None:
        self.children.append(child)

    def to_dict(self) -> dict:
        """Рекурсивная сериализация в dict."""
        return {
            "name": self.name,
            "type": self.node_type,
            "children": [c.to_dict() for c in self.children],
            "data": self.data,
        }

    def __repr__(self) -> str:
        return f"NetNode({self.name!r}, type={self.node_type}, children={len(self.children)})"


# ── Device type → emoji icon ─────────────────────────────────────

_DEVICE_TYPE_ICONS: Dict[str, str] = {
    "router": "📡",
    "switch": "🔀",
    "access-point": "📶",
    "firewall": "🛡️",
    "printer": "🖨️",
    "camera": "📷",
    "phone": "📱",
    "laptop": "💻",
    "desktop": "🖥️",
    "server": "🗄️",
    "network-device": "🔌",
    "iot": "🔧",
    "virtual": "☁️",
    "unknown": "❓",
}

_STATUS_ICONS: Dict[str, str] = {
    "online": "🟢",
    "offline": "🔴",
}


def _get_device_icon(device_type: str) -> str:
    t = (device_type or "unknown").lower()
    return _DEVICE_TYPE_ICONS.get(t, "❓")


def _get_status_icon(status: str) -> str:
    s = (status or "online").lower()
    return _STATUS_ICONS.get(s, "⚪")


# ── IP helpers ───────────────────────────────────────────────────

def _extract_ip(device) -> Optional[str]:
    """Извлечь IP из Device, dict или строки."""
    if isinstance(device, dict):
        return device.get("ip")
    if hasattr(device, "ip"):
        return device.ip
    if isinstance(device, str):
        return device
    return None


def _extract_field(device, field: str, default: Any = "") -> Any:
    """Извлечь поле из Device или dict."""
    if isinstance(device, dict):
        return device.get(field, default)
    if hasattr(device, field):
        return getattr(device, field, default)
    return default


def _subnet_key(ip_str: str, prefix_len: int = 24) -> str:
    """Вернуть строку подсети для IP (напр. '192.168.1.0/24')."""
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        # Если IP невалидный — вернуть как есть
        return ip_str


def _guess_subnet_prefix(scan_subnet: str) -> int:
    """
    Определить, по какому префиксу группировать устройства внутри scan_subnet.

    Для /24 и меньше — группируем по /24.
    Для /16 — группируем по /24 (третий октет).
    Для /8  — группируем по /16.
    Иначе — группируем на один уровень глубже.
    """
    try:
        net = ipaddress.ip_network(scan_subnet, strict=False)
        plen = net.prefixlen
        if plen >= 24:
            return 24  # устройства прямо в группе
        if plen >= 16:
            return 24  # группируем по /24
        if plen >= 8:
            return 16  # группируем по /16
        return min(plen + 8, 24)
    except ValueError:
        return 24


def _short_subnet_label(cidr: str) -> str:
    """Краткая метка подсети: '192.168.1.x' вместо '192.168.1.0/24'."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # Для /24: 192.168.1.x
        # Для /16: 192.168.x.x
        parts = str(net.network_address).split(".")
        if net.prefixlen == 24:
            parts[-1] = "x"
            return ".".join(parts)
        if net.prefixlen == 16:
            parts[-2] = "x"
            parts[-1] = "x"
            return ".".join(parts)
        if net.prefixlen == 8:
            parts[-3] = "x"
            parts[-2] = "x"
            parts[-1] = "x"
            return ".".join(parts)
        return cidr
    except ValueError:
        return cidr


# ── Build tree ───────────────────────────────────────────────────

def build_tree(devices, subnet: str = "0.0.0.0/0") -> NetNode:
    """
    Построить дерево: Сеть → Подсеть → Устройства.

    Параметры:
        devices: список Device, dict (с полем 'ip') или строк IP.
        subnet: сканируемая подсеть (корень дерева).

    Возвращает:
        NetNode — корень дерева.
    """
    # Определяем уровень группировки
    group_prefix = _guess_subnet_prefix(subnet)

    # Группируем устройства по подсетям
    groups: Dict[str, List[Any]] = {}
    ungrouped: List[Any] = []

    for dev in devices:
        ip = _extract_ip(dev)
        if not ip:
            ungrouped.append(dev)
            continue

        key = _subnet_key(ip, group_prefix)
        groups.setdefault(key, []).append(dev)

    # Корень дерева
    root = NetNode(
        name=subnet,
        node_type="network",
        data={
            "cidr": subnet,
            "total_devices": len(devices),
            "subnet_count": len(groups),
        },
    )

    # Добавляем подсети
    for cidr in sorted(groups.keys()):
        devs = groups[cidr]

        online = sum(1 for d in devs if _extract_field(d, "status", "online") == "online")

        subnet_node = NetNode(
            name=cidr,
            node_type="subnet",
            data={
                "cidr": cidr,
                "label": _short_subnet_label(cidr),
                "total_devices": len(devs),
                "online": online,
                "offline": len(devs) - online,
            },
        )

        for dev in devs:
            ip = _extract_ip(dev) or ""
            hostname = _extract_field(dev, "hostname", "")
            vendor = _extract_field(dev, "vendor", "")
            device_type = _extract_field(dev, "device_type", "unknown")
            status = _extract_field(dev, "status", "online")
            mac = _extract_field(dev, "mac", "")

            label = hostname or ip
            if hostname and ip:
                label = f"{hostname} ({ip})"

            icon = _get_device_icon(device_type)
            status_icon = _get_status_icon(status)

            device_node = NetNode(
                name=label,
                node_type="device",
                data={
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": device_type,
                    "status": status,
                    "icon": icon,
                    "status_icon": status_icon,
                    "os": _extract_field(dev, "os", ""),
                    "ports": _extract_field(dev, "ports", []),
                },
            )
            subnet_node.add_child(device_node)

        root.add_child(subnet_node)

    # Несгруппированные устройства
    if ungrouped:
        other_node = NetNode(
            name="Other",
            node_type="subnet",
            data={
                "cidr": "",
                "label": "Other",
                "total_devices": len(ungrouped),
                "online": 0,
                "offline": len(ungrouped),
            },
        )
        for dev in ungrouped:
            other_node.add_child(NetNode(
                name=_extract_ip(dev) or str(dev),
                node_type="device",
                data={"ip": _extract_ip(dev) or "", "status": "unknown", "icon": "❓", "status_icon": "⚪"},
            ))
        root.add_child(other_node)

    return root


def tree_to_dict(node: NetNode) -> dict:
    """Сериализовать всё дерево в dict (для JSON)."""
    return node.to_dict()


def get_stats(node: NetNode) -> Dict[str, Any]:
    """
    Собрать статистику по узлу (рекурсивно):
        - total_devices: всего устройств в поддереве
        - online: сколько online
        - offline: сколько offline
        - by_type: { 'router': 2, 'switch': 1, ... }
    """

    def _walk(n: NetNode):
        if n.node_type == "device":
            status = n.data.get("status", "online")
            dtype = n.data.get("device_type", "unknown")
            return {
                "total_devices": 1,
                "online": 1 if status == "online" else 0,
                "offline": 1 if status != "online" else 0,
                "by_type": {dtype: 1},
            }

        result = {
            "total_devices": 0,
            "online": 0,
            "offline": 0,
            "by_type": {},
        }
        for child in n.children:
            child_stats = _walk(child)
            result["total_devices"] += child_stats["total_devices"]
            result["online"] += child_stats["online"]
            result["offline"] += child_stats["offline"]
            for dtype, count in child_stats["by_type"].items():
                result["by_type"][dtype] = result["by_type"].get(dtype, 0) + count

        return result

    stats = _walk(node)
    # Сортируем by_type по убыванию
    stats["by_type"] = dict(
        sorted(stats["by_type"].items(), key=lambda x: (-x[1], x[0]))
    )
    return stats


# ── CLI / Test ──────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    # Пример данных
    sample_devices = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "hostname": "gw-home", "vendor": "MikroTik", "device_type": "router", "status": "online"},
        {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:02", "hostname": "desktop-pavel", "vendor": "Dell", "device_type": "desktop", "status": "online"},
        {"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:03", "hostname": "printer", "vendor": "HP", "device_type": "printer", "status": "offline"},
        {"ip": "192.168.2.5", "mac": "aa:bb:cc:dd:ee:04", "hostname": "camera-front", "vendor": "Hikvision", "device_type": "camera", "status": "online"},
        {"ip": "192.168.2.10", "mac": "aa:bb:cc:dd:ee:05", "hostname": "switch-garage", "vendor": "TP-Link", "device_type": "switch", "status": "online"},
        {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:06", "hostname": "server-vpn", "vendor": "Supermicro", "device_type": "server", "status": "online"},
    ]

    root = build_tree(sample_devices, "192.168.0.0/16")
    print("=== Tree ===")
    print(json.dumps(tree_to_dict(root), indent=2, ensure_ascii=False))

    print("\n=== Stats ===")
    stats = get_stats(root)
    print(json.dumps(stats, indent=2, ensure_ascii=False))
