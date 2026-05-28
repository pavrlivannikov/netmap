#!/usr/bin/env python3
"""
NetMap Multicast — анализ multicast-групп в ARP-таблицах.

Multicast-записи — не шум, а характеристика сети:
  • 224.0.0.251 → mDNS / Bonjour (Apple TV, принтеры, Chromecast)
  • 239.255.255.250 → SSDP / UPnP (IoT, умные колонки, камеры)
  • 224.0.0.22 → IGMPv3 (свитч слушает группы)
  • 224.0.0.252 → LLMNR (Windows-устройства)
  • 224.0.0.2 → All Routers
  • 01:00:5e:xx:xx:xx → общий multicast MAC
"""
from dataclasses import dataclass, field
from typing import Optional, List


# ═══════════════════════════════════════════════════════════════
# MULTICAST_MAP — IP → (протокол, описание)
# ═══════════════════════════════════════════════════════════════

MULTICAST_MAP = {
    # ── Link-Local (224.0.0.0/24) ──────────────────────────
    "224.0.0.1":   ("IGMP", "All Hosts"),
    "224.0.0.2":   ("IGMP", "All Routers"),
    "224.0.0.4":   ("DVMRP", "DVMRP Routers"),
    "224.0.0.5":   ("OSPF", "OSPF All Routers"),
    "224.0.0.6":   ("OSPF", "OSPF Designated Routers"),
    "224.0.0.9":   ("RIP", "RIPv2 Routers"),
    "224.0.0.10":  ("EIGRP", "EIGRP Routers"),
    "224.0.0.12":  ("DHCP", "DHCP Server / Relay Agent"),
    "224.0.0.13":  ("PIM", "PIM Routers"),
    "224.0.0.18":  ("VRRP", "VRRP (High Availability)"),
    "224.0.0.19":  ("IS-IS", "IS-IS over IP"),
    "224.0.0.22":  ("IGMPv3", "IGMPv3 — свитч слушает группы"),
    "224.0.0.102": ("HSRP", "HSRPv1 (Cisco HA)"),
    "224.0.0.107": ("PTP", "PTPv2 Precision Time Protocol"),
    "224.0.0.113": ("Cisco", "Cisco Auto-RP"),
    "224.0.0.114": ("Cisco", "Cisco Auto-RP"),
    "224.0.0.251": ("mDNS", "mDNS / Bonjour (Apple TV, принтеры, Chromecast)"),
    "224.0.0.252": ("LLMNR", "LLMNR — Windows-устройства"),
    "224.0.0.253": ("LLMNR", "LLMNR — Windows-устройства"),

    # ── Organization-Local (239.x.x.x) ─────────────────────
    "239.255.255.250": ("SSDP", "SSDP / UPnP (IoT, умные колонки, камеры)"),
    "239.255.255.251": ("WS-Discovery", "WS-Discovery (Windows-устройства)"),

    # ── IPv6 Multicast ─────────────────────────────────────
    "ff02::1":     ("IPv6", "All Nodes (link-local)"),
    "ff02::2":     ("IPv6", "All Routers (link-local)"),
    "ff02::c":     ("SSDPv6", "SSDP IPv6"),
    "ff02::16":    ("MLDv2", "MLDv2 — IPv6 multicast listener"),
    "ff02::1:2":   ("DHCPv6", "DHCPv6 Servers / Relays"),
    "ff02::fb":    ("mDNSv6", "mDNS IPv6"),
    "ff02::1:3":   ("LLMNRv6", "LLMNR IPv6"),
}

# ── MAC prefix → (протокол, описание) ─────────────────────
MULTICAST_MAC_PREFIXES = [
    ("01:00:5e", "IPv4-Multicast", "Общий IPv4 multicast MAC (01:00:5e:xx:xx:xx)"),
    ("33:33",    "IPv6-Multicast", "IPv6 multicast MAC (33:33:xx:xx:xx:xx)"),
    ("01:80:c2", "IEEE-802.1",    "STP / LLDP / 802.1X"),
    ("09:00:07", "AppleTalk",     "AppleTalk multicast"),
    ("03:00:00", "NETBIOS",       "Microsoft NetBIOS / NetBEUI"),
    ("01:00:0c", "Cisco",         "CDP / VTP / PVST+"),
]

# ── Service → fingerprint tags ────────────────────────────
SERVICE_TAGS = {
    "mDNS":        ["Apple ecosystem", "IoT"],
    "mDNSv6":      ["Apple ecosystem"],
    "SSDP":        ["IoT", "Media"],
    "SSDPv6":      ["IoT"],
    "LLMNR":       ["Windows shop"],
    "LLMNRv6":     ["Windows shop"],
    "WS-Discovery": ["Windows shop"],
    "IGMPv3":      ["Managed switches"],
    "IGMP":        ["Multicast-enabled"],
    "PIM":         ["Multicast routing"],
    "OSPF":        ["Enterprise routing"],
    "EIGRP":       ["Cisco routing"],
    "VRRP":        ["High availability"],
    "HSRP":        ["Cisco HA"],
    "DHCP":        ["Infrastructure"],
    "DHCPv6":      ["Infrastructure"],
    "PTP":         ["Precision timing"],
    "RIP":         ["Legacy routing"],
    "DVMRP":       ["Legacy multicast"],
}


# ═══════════════════════════════════════════════════════════════
# IP / MAC helpers
# ═══════════════════════════════════════════════════════════════

def is_multicast_ip(ip: str) -> bool:
    """Проверяет, является ли IPv4 адрес multicast (224.0.0.0/4)."""
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        return 224 <= first <= 239
    except (ValueError, IndexError):
        return False


def is_multicast_mac(mac: str) -> bool:
    """
    Проверяет, является ли MAC-адрес multicast.
    LSB первого октета = 1 означает групповой адрес.
    """
    if not mac:
        return False
    try:
        clean = mac.lower().replace("-", ":").replace(".", "")
        parts = clean.split(":")
        if len(parts) < 2:
            return False
        first_byte = int(parts[0], 16)
        return (first_byte & 0x01) == 1
    except (ValueError, IndexError):
        return False


# ═══════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class MulticastEntry:
    """Одна multicast-запись."""
    ip: str
    protocol: str = "unknown"
    description: str = ""
    mac: str = ""


@dataclass
class MulticastAnalysis:
    """Полный анализ multicast-активности."""
    total_multicast: int = 0
    unique_ips: int = 0
    detected_services: List[str] = field(default_factory=list)
    entries: List[MulticastEntry] = field(default_factory=list)
    fingerprint: str = ""
    fingerprint_tags: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# Classification
# ═══════════════════════════════════════════════════════════════

def classify_multicast(ip_or_mac: str) -> tuple:
    """
    Классифицирует одну запись (IP или MAC).

    Возвращает (protocol: str, description: str).

    Примеры:
        classify_multicast("224.0.0.251") → ("mDNS", "mDNS / Bonjour (Apple TV, ...)")
        classify_multicast("01:00:5e:00:00:fb") → ("IPv4-Multicast", "Общий IPv4 multicast MAC ...")
    """
    if not ip_or_mac:
        return ("unknown", "Unknown")

    entry = ip_or_mac.strip()

    # ── Exact IP match ─────────────────────────────────────
    if entry in MULTICAST_MAP:
        return MULTICAST_MAP[entry]

    # ── IPv6 short-form lookup ─────────────────────────────
    entry_lower = entry.lower()
    if entry_lower in MULTICAST_MAP:
        return MULTICAST_MAP[entry_lower]

    # ── Multicast IP range classification ──────────────────
    if is_multicast_ip(entry):
        try:
            first = int(entry.split(".")[0])
            if first == 224:
                return ("Link-Local", f"Link-Local Multicast ({entry})")
            elif 232 <= first <= 232:
                return ("SSM", f"Source-Specific Multicast ({entry})")
            elif 239 <= first <= 239:
                return ("Admin-Scoped", f"Organization-Local Scope ({entry})")
            else:
                return ("Multicast", f"Multicast IP ({entry})")
        except (ValueError, IndexError):
            return ("Multicast", f"Multicast IP ({entry})")

    # ── MAC prefix classification ──────────────────────────
    entry_normalised = entry.lower().replace("-", ":")
    for prefix, proto, desc in MULTICAST_MAC_PREFIXES:
        if entry_normalised.startswith(prefix.lower()):
            return (proto, desc)

    if is_multicast_mac(entry):
        return ("Multicast-MAC", "Multicast MAC address")

    return ("unknown", "Unknown")


# ═══════════════════════════════════════════════════════════════
# Analysis
# ═══════════════════════════════════════════════════════════════

def analyze_multicast(devices) -> MulticastAnalysis:
    """
    Анализ multicast-групп в списке Device.

    Возвращает MulticastAnalysis:
      - total_multicast — всего multicast-записей
      - unique_ips — уникальных multicast IP
      - detected_services — найденные сервисы (mDNS, SSDP, IGMP, ...)
      - fingerprint — текстовая сводка типа сети
    """
    # Lazy import to avoid circular dependency
    try:
        from netmap_device import Device
        _Device = Device
    except ImportError:
        _Device = None

    seen_ips: set = set()
    services: set = set()
    tags: set = set()
    entries: List[MulticastEntry] = []

    for d in devices:
        ip = getattr(d, "ip", "")
        mac = getattr(d, "mac", "")

        # Check IP
        if is_multicast_ip(ip):
            proto, desc = classify_multicast(ip)
            seen_ips.add(ip)
            services.add(proto)
            entries.append(MulticastEntry(
                ip=ip, protocol=proto, description=desc, mac=mac,
            ))
            tags.update(SERVICE_TAGS.get(proto, []))

        # Check MAC (only if IP not already caught)
        elif mac and is_multicast_mac(mac):
            if ip not in seen_ips:
                proto, desc = classify_multicast(mac)
                seen_ips.add(ip)
                services.add(proto)
                entries.append(MulticastEntry(
                    ip=ip, protocol=proto, description=desc, mac=mac,
                ))
                tags.update(SERVICE_TAGS.get(proto, []))

    fingerprint, fp_tags = _build_fingerprint(services, tags, len(seen_ips))

    return MulticastAnalysis(
        total_multicast=len(entries),
        unique_ips=len(seen_ips),
        detected_services=sorted(services),
        entries=entries,
        fingerprint=fingerprint,
        fingerprint_tags=sorted(fp_tags),
    )


def _build_fingerprint(services: set, tags: set, unique_count: int) -> tuple:
    """Строит fingerprint-строку и список тэгов."""
    combined = list(services | tags)
    fp_parts: list = []

    # Service-based
    if "mDNS" in combined or "mDNSv6" in combined:
        fp_parts.append("Apple ecosystem")
    if "LLMNR" in combined or "LLMNRv6" in combined or "WS-Discovery" in combined:
        fp_parts.append("Windows shop")
    if "SSDP" in combined or "SSDPv6" in combined:
        fp_parts.append("IoT-heavy")
    if "IGMPv3" in combined:
        fp_parts.append("Managed switches")
    if "PIM" in combined:
        fp_parts.append("Multicast routing")
    if "OSPF" in combined or "EIGRP" in combined:
        fp_parts.append("Enterprise routing")
    if "VRRP" in combined or "HSRP" in combined:
        fp_parts.append("High availability")
    if "PTP" in combined:
        fp_parts.append("Precision timing")
    if "RIP" in combined or "DVMRP" in combined:
        fp_parts.append("Legacy protocols")

    # Count hints
    if unique_count >= 20:
        fp_parts.append("Dense multicast")
    elif unique_count >= 5:
        fp_parts.append("Active multicast")

    if not fp_parts:
        fp_parts = ["Sparse multicast"]

    fingerprint = ", ".join(fp_parts)
    return fingerprint, sorted(set(fp_parts))


def get_network_fingerprint(devices) -> str:
    """
    Быстрая сводка типа сети по multicast-сигнатурам.

    Возвращает строку вроде:
      - «Apple ecosystem, IoT-heavy, Active multicast»
      - «Windows shop, Managed switches»
      - «No multicast activity»

    Параметры:
        devices: список Device (или dict, если нет Device-датакласса)
    """
    analysis = analyze_multicast(devices)
    return analysis.fingerprint


def classify_device(ip: str, mac: str = "") -> dict:
    """
    Классифицирует одно устройство: является ли multicast, и если да — какой протокол.

    Возвращает dict:
        {"is_multicast": bool, "protocol": str, "description": str}
    """
    proto, desc = "unknown", ""
    is_mc = False

    if is_multicast_ip(ip):
        is_mc = True
        proto, desc = classify_multicast(ip)
    elif mac and is_multicast_mac(mac):
        is_mc = True
        proto, desc = classify_multicast(mac)

    return {
        "is_multicast": is_mc,
        "protocol": proto,
        "description": desc,
    }
