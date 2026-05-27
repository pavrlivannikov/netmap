"""
NetMap Scanner — системные утилиты (arp, ping, netsh/ip, socket)
Работает без админ-прав и без внешних зависимостей.
Windows / Linux.
"""
import subprocess
import socket
import json
import threading
import concurrent.futures
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Data classes ──────────────────────────────────────────────────

@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    state: str = "open"

@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    device_type: str = "unknown"
    status: str = "online"
    ports: list = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @property
    def id(self):
        return self.mac or self.ip

@dataclass
class Edge:
    source: str
    target: str
    edge_type: str = "direct"
    latency_ms: Optional[float] = None

@dataclass
class NetworkInfo:
    interface: str
    ip: str
    prefix: int
    gateway: str
    cidr: str
    description: str

@dataclass
class ScanResult:
    scan_time: str
    network: str
    devices: list
    edges: list

# ── Callbacks ────────────────────────────────────────────────────

class ScanCallbacks:
    def on_device_found(self, device: Device): pass
    def on_progress(self, msg: str, pct: int): pass
    def on_complete(self, result: ScanResult): pass
    def on_error(self, msg: str): pass

# ── Service map ──────────────────────────────────────────────────

COMMON_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 993, 995,
                1080, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                8443, 8888, 9090, 9100, 9200, 27017]

SERVICE_MAP = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt", 9100: "Printer",
    9200: "Elastic", 27017: "MongoDB",
}

# ── Helpers ──────────────────────────────────────────────────────

def _is_windows():
    import os
    return os.name == 'nt'

# Cache CREATE_NO_WINDOW flag
import sys as _sys
_NO_WINDOW = 0x08000000 if _sys.platform == 'win32' else 0

def _run(cmd, **kwargs):
    """subprocess.run без чёрных окон на Windows."""
    if _is_windows():
        kwargs.setdefault('creationflags', _NO_WINDOW)
    return subprocess.run(cmd, **kwargs)

def _check_output(cmd, **kwargs):
    """subprocess.check_output без чёрных окон."""
    if _is_windows():
        kwargs.setdefault('creationflags', _NO_WINDOW)
    return subprocess.check_output(cmd, **kwargs)

def _is_valid_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except (socket.error, OSError):
        return False

def _is_valid_mac(s: str) -> bool:
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)

def _count_dots(s: str) -> int:
    return s.count(".")

def expand_subnet(subnet: str) -> list:
    net = ipaddress.IPv4Network(subnet, strict=False)
    return [str(h) for h in net.hosts()]

def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return False

def _mask_to_prefix(mask: str) -> int:
    parts = mask.strip().split(".")
    if len(parts) != 4:
        return 24
    bits = sum(bin(int(p)).count("1") for p in parts)
    return bits or 24

# ── Win32 API helpers (ctypes, locale-independent) ─────────────────

_WIN32_CACHE = {}  # cache for API calls


def _win32_get_adapters() -> list:
    """Возвращает список (имя, ip, prefix, gateway) через Win32 API."""
    if not _is_windows():
        return []
    try:
        import ctypes
        from ctypes import wintypes, POINTER, Structure, c_ulong, c_ushort, c_char, c_ubyte, c_void_p

        # Structures
        class SOCKADDR_IN(Structure):
            _fields_ = [("sin_family", c_ushort),
                        ("sin_port", c_ushort),
                        ("sin_addr", c_ubyte * 4),
                        ("sin_zero", c_ubyte * 8)]

        class SOCKET_ADDRESS(Structure):
            _fields_ = [("lpSockaddr", c_void_p),
                        ("iSockaddrLength", ctypes.c_int)]

        class IP_ADAPTER_UNICAST_ADDRESS(Structure):
            pass
        IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
            ("Length", c_ulong),
            ("Flags", c_ulong),
            ("Next", c_void_p),
            ("Address", SOCKET_ADDRESS),
            ("PrefixOrigin", ctypes.c_int),
            ("SuffixOrigin", ctypes.c_int),
            ("DadState", ctypes.c_int),
            ("ValidLifetime", c_ulong),
            ("PreferredLifetime", c_ulong),
            ("LeaseLifetime", c_ulong),
            ("OnLinkPrefixLength", c_ubyte),
        ]

        class IP_ADAPTER_GATEWAY_ADDRESS(Structure):
            pass
        IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
            ("Length", c_ulong),
            ("Flags", c_ulong),
            ("Next", c_void_p),
            ("Address", SOCKET_ADDRESS),
        ]

        class IP_ADAPTER_ADDRESSES(Structure):
            pass
        IP_ADAPTER_ADDRESSES._fields_ = [
            ("Length", c_ulong),
            ("IfIndex", c_ulong),
            ("Next", c_void_p),
            ("AdapterName", c_char_p),
            ("FirstUnicastAddress", c_void_p),
            ("FirstAnycastAddress", c_void_p),
            ("FirstMulticastAddress", c_void_p),
            ("FirstDnsServerAddress", c_void_p),
            ("DnsSuffix", ctypes.c_wchar_p),
            ("Description", ctypes.c_wchar_p),
            ("FriendlyName", ctypes.c_wchar_p),
            ("PhysicalAddress", c_ubyte * 8),
            ("PhysicalAddressLength", c_ulong),
            ("Flags", c_ulong),
            ("Mtu", c_ulong),
            ("IfType", c_ulong),
            ("OperStatus", c_ulong),
            ("Ipv6IfIndex", c_ulong),
            ("ZoneIndices", c_ulong * 16),
            ("FirstPrefix", c_void_p),
            ("TransmitLinkSpeed", ctypes.c_ulonglong),
            ("ReceiveLinkSpeed", ctypes.c_ulonglong),
            ("FirstGatewayAddress", c_void_p),
        ]

        iphlpapi = ctypes.windll.iphlpapi

        buf_len = wintypes.ULONG(0)
        ret = iphlpapi.GetAdaptersAddresses(
            2, 0x0040, None, None, ctypes.byref(buf_len))
        if ret != 111:
            return []

        buf = ctypes.create_string_buffer(buf_len.value)
        ret = iphlpapi.GetAdaptersAddresses(
            2, 0x0040, None, ctypes.cast(buf, ctypes.c_void_p),
            ctypes.byref(buf_len))
        if ret != 0:
            return []

        result = []
        ptr = ctypes.cast(buf, POINTER(IP_ADAPTER_ADDRESSES))
        while ptr:
            adapter = ptr.contents
            name = adapter.FriendlyName or adapter.Description or "Unknown"

            ip = None
            prefix = 24
            uni = adapter.FirstUnicastAddress
            while uni:
                ua = ctypes.cast(uni, POINTER(IP_ADAPTER_UNICAST_ADDRESS)).contents
                sa = ua.Address
                if sa.lpSockaddr:
                    sin = ctypes.cast(sa.lpSockaddr, POINTER(SOCKADDR_IN)).contents
                    if sin.sin_family == 2:
                        ip = ".".join(str(b) for b in sin.sin_addr)
                        prefix = ua.OnLinkPrefixLength
                        break
                uni = ua.Next

            gw = ""
            gw_uni = adapter.FirstGatewayAddress
            while gw_uni:
                gwa = ctypes.cast(gw_uni, POINTER(IP_ADAPTER_GATEWAY_ADDRESS)).contents
                gsa = gwa.Address
                if gsa.lpSockaddr:
                    gsin = ctypes.cast(gsa.lpSockaddr, POINTER(SOCKADDR_IN)).contents
                    if gsin.sin_family == 2:
                        gw = ".".join(str(b) for b in gsin.sin_addr)
                        break
                gw_uni = gwa.Next

            if ip and "127." not in ip and "169.254." not in ip:
                result.append((name, ip, prefix, gw))

            ptr = ptr.contents.Next
            if ptr:
                ptr = ctypes.cast(ptr, POINTER(IP_ADAPTER_ADDRESSES))

        return result
    except Exception:
        return []


def _win32_get_arp_table() -> list:
    """Возвращает список (ip, mac) из ARP-таблицы через Win32 API."""
    if not _is_windows():
        return []
    try:
        import ctypes
        from ctypes import wintypes

        iphlpapi = ctypes.windll.iphlpapi
        buf_len = wintypes.ULONG(0)

        ret = iphlpapi.GetIpNetTable(None, ctypes.byref(buf_len), 0)
        if ret != 122:
            return []

        buf = ctypes.create_string_buffer(buf_len.value)
        ret = iphlpapi.GetIpNetTable(ctypes.cast(buf, ctypes.c_void_p),
                                     ctypes.byref(buf_len), 0)
        if ret != 0:
            return []

        count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value

        result = []
        # MIB_IPNETROW: dwIndex(4) + dwPhysAddrLen(4) + bPhysAddr(8 incl padding) + dwAddr(4) + dwType(4) = 24
        for i in range(count):
            off = 4 + i * 24
            # MIB_IPNETROW: dwIndex(4) dwPhysAddrLen(4) bPhysAddr(8) dwAddr(4) dwType(4)
            mac_len = buf[off + 4]
            if mac_len > 0 and mac_len <= 8:
                mac_raw = bytes(buf[off + 8:off + 8 + min(mac_len, 6)])
                if len(mac_raw) < 6:
                    mac_raw = mac_raw + b'\x00' * (6 - len(mac_raw))
                mac = ":".join(f"{b:02x}" for b in mac_raw)
                # dwAddr is at offset 16 (after 8 bytes physaddr + 4 bytes padding for alignment)
                ip_int = int.from_bytes(bytes(buf[off + 16:off + 20]), 'little')
                ip = f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"
                if ip != "0.0.0.0" and mac != "00:00:00:00:00:00" and _is_valid_ip(ip):
                    result.append((ip, mac))

        return result
    except Exception:
        return []


# ── Network discovery ────────────────────────────────────────────

def discover_networks() -> list:
    """Найти активные IPv4-сети (Win32 API на Windows, ip route на Linux)."""
    if _is_windows():
        return _discover_windows()
    return _discover_linux()


def _discover_windows() -> list:
    """Определение сетей: Win32 API → netifaces → netsh → ipconfig."""
    # Способ 1: Win32 API (локаль-независимо, без subprocess)
    adapters = _win32_get_adapters()
    if adapters:
        networks = []
        for name, ip, prefix, gw in adapters:
            networks.append(NetworkInfo(
                interface=name, ip=ip, prefix=prefix,
                gateway=gw or _guess_gw(ip, prefix),
                cidr=f"{ip}/{prefix}", description=name
            ))
        if networks:
            return _sort_networks(networks)

    # Способ 2: netifaces
    try:
        import netifaces
        networks = []
        gw = _find_gateway_win()
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr', '')
                mask = addr.get('netmask', '')
                if not ip or ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                prefix = _mask_to_prefix(mask)
                networks.append(NetworkInfo(
                    interface=iface, ip=ip, prefix=prefix,
                    gateway=gw or _guess_gw(ip, prefix),
                    cidr=f"{ip}/{prefix}", description=iface
                ))
        if networks:
            return _sort_networks(networks)
    except ImportError:
        pass

    # Способ 3: netsh
    networks = _discover_windows_netsh()
    if networks:
        return networks

    # Способ 4: ipconfig
    return _discover_windows_ipconfig()


def _find_gateway_for_iface_win(iface: str, ip: str) -> str:
    """Попытка найти шлюз для конкретного интерфейса."""
    try:
        import netifaces
        gws = netifaces.gateways()
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            default_gw = gws['default'][netifaces.AF_INET]
            if default_gw:
                return default_gw[0]
    except Exception:
        pass
    return ""


def _discover_windows_netsh() -> list:
    """Parse 'netsh interface ip show addresses' (locale-independent)."""
    networks = []
    try:
        out = _check_output(
            ["netsh", "interface", "ip", "show", "addresses"],
            text=True, timeout=10
        )
        cur_iface = ""
        cur_ip = ""
        cur_prefix = 24
        cur_gw = ""

        for raw in out.splitlines():
            line = raw.strip()

            if "Настройка интерфейса" in line or "Configuration for interface" in line:
                if cur_iface and cur_ip and not cur_ip.startswith("127.") and "169.254." not in cur_ip:
                    networks.append(NetworkInfo(
                        interface=cur_iface, ip=cur_ip, prefix=cur_prefix,
                        gateway=cur_gw or _guess_gw(cur_ip, cur_prefix),
                        cidr=f"{cur_ip}/{cur_prefix}", description=cur_iface
                    ))
                if '"' in line:
                    cur_iface = line.split('"')[1]
                cur_ip = ""
                cur_prefix = 24
                cur_gw = ""
                continue

            if ("IP-" in line or "IP " in line or "IP Address" in line) and _count_dots(line) >= 3:
                parts = line.split()
                for p in reversed(parts):
                    if _count_dots(p) == 3 and _is_valid_ip(p):
                        cur_ip = p
                        break
                continue

            if "Префикс подсети" in line or "Subnet Prefix" in line:
                for token in line.split():
                    token = token.rstrip(",()")
                    if "/" in token:
                        try:
                            cur_prefix = int(token.split("/")[1])
                        except ValueError:
                            pass
                continue

            if "Основной шлюз" in line or "Default Gateway" in line:
                parts = line.split()
                for p in reversed(parts):
                    if _count_dots(p) == 3 and _is_valid_ip(p):
                        cur_gw = p
                        break
                continue

        if cur_iface and cur_ip and not cur_ip.startswith("127.") and "169.254." not in cur_ip:
            networks.append(NetworkInfo(
                interface=cur_iface, ip=cur_ip, prefix=cur_prefix,
                gateway=cur_gw or _guess_gw(cur_ip, cur_prefix),
                cidr=f"{cur_ip}/{cur_prefix}", description=cur_iface
            ))
    except Exception:
        pass
    return networks


def _discover_windows_ipconfig() -> list:
    """Fallback: ipconfig (русская локаль)."""
    networks = []
    try:
        out = _check_output(["ipconfig"], text=True, timeout=10)
        cur_adapter = ""
        cur_ip = ""
        cur_mask = ""
        adapters = []

        for line in out.splitlines():
            line = line.strip()
            if line.endswith(":") and _count_dots(line) == 0:
                if cur_ip and cur_mask and "127." not in cur_ip and "169.254." not in cur_ip:
                    adapters.append((cur_adapter, cur_ip, _mask_to_prefix(cur_mask)))
                cur_adapter = line.rstrip(":").strip()
                cur_ip = ""
                cur_mask = ""
                continue

            if _count_dots(line) >= 3:
                parts_in_line = line.replace("(", " ").replace(")", " ").replace(":", " ").split()
                for part in reversed(parts_in_line):
                    if _count_dots(part) == 3 and all(p.isdigit() for p in part.split(".")):
                        lower = line.lower()
                        if any(kw in lower for kw in ("ip", "адрес", "address", "ipv4")):
                            cur_ip = part
                            break
                        elif any(kw in lower for kw in ("mask", "маска", "subnet")):
                            cur_mask = part
                            break

        if cur_ip and cur_mask and "127." not in cur_ip and "169.254." not in cur_ip:
            adapters.append((cur_adapter, cur_ip, _mask_to_prefix(cur_mask)))

        gw = _find_gateway_win()
        for adapter, ip, prefix in adapters:
            networks.append(NetworkInfo(
                interface=adapter, ip=ip, prefix=prefix,
                gateway=gw or _guess_gw(ip, prefix),
                cidr=f"{ip}/{prefix}", description=adapter
            ))
    except Exception:
        pass
    return networks


def _sort_networks(networks: list) -> list:
    def prio(n):
        d = (n.description + n.interface).lower()
        if any(x in d for x in ("eth", "ens", "enp", "ethernet")):
            return 0
        if any(x in d for x in ("wi", "wlan", "wireless")):
            return 1
        return 2
    networks.sort(key=prio)
    return networks


def _discover_linux() -> list:
    networks = []
    try:
        out = _check_output(["ip", "-4", "-o", "addr", "show"], text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[1] == "lo":
                continue
            try:
                inet_idx = parts.index("inet")
                cidr_raw = parts[inet_idx + 1]
                ip, prefix = cidr_raw.split("/")
                iface = parts[1]
                if ip.startswith("127."):
                    continue
                gw = _find_gateway_linux(iface)
                networks.append(NetworkInfo(
                    interface=iface, ip=ip, prefix=int(prefix),
                    gateway=gw or _guess_gw(ip, int(prefix)),
                    cidr=cidr_raw, description=iface
                ))
            except (ValueError, IndexError):
                continue
    except Exception:
        pass

    def prio(n):
        d = n.description.lower()
        if any(x in d for x in ("eth", "ens", "enp", "ethernet")): return 0
        if any(x in d for x in ("wi", "wlan")): return 1
        return 2
    networks.sort(key=prio)
    return networks


def _find_gateway_linux(iface: str) -> str:
    try:
        out = _check_output(["ip", "-4", "route", "show", "dev", iface], text=True, timeout=5)
        for line in out.splitlines():
            if line.startswith("default"):
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "via" and i + 1 < len(parts):
                        return parts[i + 1]
    except Exception:
        pass
    return ""


def _find_gateway_win() -> str:
    try:
        out = _check_output(["route", "print", "-4"], text=True, timeout=5)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "0.0.0.0":
                    return parts[2]
    except Exception:
        pass
    return ""


def _guess_gw(ip: str, prefix: int) -> str:
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(net.network_address + 1)
    except ValueError:
        return ""

# ── ARP scan ─────────────────────────────────────────────────────

def arp_scan(callbacks=None) -> list:
    """ARP scan: Win32 API -> PowerShell JSON -> arp -a regex."""
    devices = []
    try:
        if _is_windows():
            # 1. Win32 GetIpNetTable
            if callbacks:
                callbacks.on_progress("ARP: trying Win32 API...", 2)
            entries = _win32_get_arp_table()
            if entries:
                if callbacks:
                    callbacks.on_progress(f"ARP Win32: {len(entries)} entries", 5)
                for ip, mac in entries:
                    vendor = oui_lookup(mac)
                    dev = Device(ip=ip, mac=mac, vendor=vendor,
                        device_type=guess_device_type("", []), status="online")
                    devices.append(dev)
                    if callbacks:
                        callbacks.on_device_found(dev)
                return devices

            # 2. PowerShell Get-NetNeighbor (locale-independent JSON)
            if callbacks:
                callbacks.on_progress("ARP: trying PowerShell...", 4)
            ps_out = _run_ps_arp()
            if ps_out:
                import json
                try:
                    data = json.loads(ps_out)
                    if isinstance(data, dict):
                        data = [data]
                    for entry in data:
                        ip = entry.get('IPAddress', '')
                        mac = (entry.get('LinkLayerAddress', '') or '').replace('-', ':').lower()
                        if ip and mac and mac != '00:00:00:00:00:00' and _is_valid_ip(ip):
                            vendor = oui_lookup(mac)
                            dev = Device(ip=ip, mac=mac, vendor=vendor,
                                device_type=guess_device_type("", []), status="online")
                            devices.append(dev)
                            if callbacks:
                                callbacks.on_device_found(dev)
                    if devices:
                        if callbacks:
                            callbacks.on_progress(f"ARP PowerShell: {len(devices)} devices", 10)
                        return devices
                except (json.JSONDecodeError, Exception) as e:
                    if callbacks:
                        callbacks.on_progress(f"ARP PowerShell failed: {e}", 5)

            # 3. arp -a with regex (locale-independent)
            if callbacks:
                callbacks.on_progress("ARP: fallback arp -a...", 5)
            out = _check_output(["arp", "-a"], text=True, timeout=10)
            if callbacks:
                callbacks.on_progress(f"arp -a: {len(out.splitlines())} lines", 7)
            devices = _parse_arp_win(out)
            if callbacks:
                callbacks.on_progress(f"arp -a parsed: {len(devices)} devices", 10)
            for d in devices:
                if callbacks:
                    callbacks.on_device_found(d)
        else:
            try:
                out = _check_output(["ip", "-4", "neigh"], text=True, timeout=5)
                devices = _parse_ip_neigh(out)
            except Exception:
                out = _check_output(["arp", "-a"], text=True, timeout=5)
                devices = _parse_arp_linux(out)
            for d in devices:
                if callbacks:
                    callbacks.on_device_found(d)
    except Exception as e:
        if callbacks:
            callbacks.on_error(f"ARP error: {e}")
    return devices


def _run_ps_arp() -> str:
    """Run PowerShell Get-NetNeighbor, return JSON string or empty."""
    try:
        return _check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Stale,Delay,Probe,Permanent | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress"],
            text=True, timeout=15)
    except Exception:
        return ""


# removed: _parse_ps_neighbor(output: str) -> list:
    """Parse PowerShell Get-NetNeighbor JSON output."""
    import json
    devices = []
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            ip = entry.get('IPAddress', '')
            mac = (entry.get('LinkLayerAddress', '') or '').replace('-', ':').lower()
            if ip and mac and mac != '00:00:00:00:00:00':
                vendor = oui_lookup(mac)
                dev = Device(ip=ip, mac=mac, vendor=vendor,
                    device_type=guess_device_type("", []), status="online")
                devices.append(dev)
                if callbacks:
                    callbacks.on_device_found(dev)
    except (json.JSONDecodeError, Exception):
        pass
    return devices


def arp_scan_subnet(subnet: str, callbacks=None) -> list:
    """ARP scan for specific subnet (filtered from global ARP table)."""
    all_devices = arp_scan(callbacks)
    filtered = [d for d in all_devices if is_ip_in_subnet(d.ip, subnet)]
    return filtered


def _resolve_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Reverse DNS lookup with timeout."""
    try:
        import socket
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(None)
        return result
    except Exception:
        return None


def _parse_arp_win(output: str) -> list:
    """Parse arp -a output: locale-independent, regex-based."""
    import re
    devices = []
    seen_ips = set()
    # Pattern: IP (X.X.X.X) followed by MAC (xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
    # Handles Russian, English, any locale
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    mac_pattern = r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})'

    for line in output.splitlines():
        ips = re.findall(ip_pattern, line)
        macs = re.findall(mac_pattern, line)
        if len(ips) >= 1 and len(macs) >= 1:
            ip = ips[0]
            mac = macs[0].replace("-", ":").lower()
            # Validate
            if not _is_valid_ip(ip) or not _is_valid_mac(mac):
                continue
            # Skip invalid
            if ip in seen_ips or ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
                continue
            seen_ips.add(ip)
            vendor = oui_lookup(mac)
            devices.append(Device(ip=ip, mac=mac, vendor=vendor,
                                  device_type=guess_device_type("", []), status="online"))
    return devices


def _parse_arp_linux(output: str) -> list:
    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "(incomplete)" in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        hostname = parts[0] if not parts[0].startswith("(") and parts[0] != "?" else None
        ip = next((p.strip("()") for p in parts if p.startswith("(") and p.endswith(")")), "")
        mac = next((p for p in parts if ":" in p), "")
        if ip and mac:
            vendor = oui_lookup(mac)
            devices.append(Device(ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                                  device_type=guess_device_type(hostname or "", []), status="online"))
    return devices


def _parse_ip_neigh(output: str) -> list:
    devices = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[0]
        mac = parts[4] if len(parts) > 4 else ""
        state = parts[-1] if len(parts) >= 5 else ""
        if mac in ("FAILED", "") or state in ("FAILED", "INCOMPLETE"):
            continue
        if _is_valid_ip(ip) and _is_valid_mac(mac):
            vendor = oui_lookup(mac)
            devices.append(Device(ip=ip, mac=mac, vendor=vendor,
                                  device_type=guess_device_type("", []), status="online"))
    return devices

# ── ICMP Ping ────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> tuple:
    """Системный ping. Возвращает (alive, latency_ms)."""
    try:
        if _is_windows():
            out = _run(["ping", "-n", "1", "-w", str(int(timeout*1000)), ip],
                                 capture_output=True, text=True, timeout=timeout + 1)
        else:
            out = _run(["ping", "-c", "1", "-W", str(int(timeout)), ip],
                                 capture_output=True, text=True, timeout=timeout + 1)
        alive = out.returncode == 0
        latency = None
        for line in out.stdout.splitlines():
            if "time=" in line:
                try:
                    latency = float(line.split("time=")[1].split("ms")[0].strip())
                except (ValueError, IndexError):
                    pass
            elif "time<" in line:
                try:
                    latency = float(line.split("time<")[1].split("ms")[0].strip())
                except (ValueError, IndexError):
                    pass
        return (alive, latency)
    except Exception:
        return (False, None)


def ping_sweep(ips: list, callbacks=None, workers: int = 5) -> list:
    devices = []
    lock = threading.Lock()

    def worker(ip):
        alive, _ = ping_host(ip, timeout=0.5)
        if alive:
            dev = Device(ip=ip, device_type="unknown", status="online")
            with lock:
                devices.append(dev)
                if callbacks:
                    callbacks.on_device_found(dev)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(worker, ips))
    return devices

# ── TCP Port scan ────────────────────────────────────────────────

def check_port(ip: str, port: int, timeout: float = 0.4) -> Optional[Port]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return Port(port=port, protocol="tcp",
                        service=SERVICE_MAP.get(port, f"port-{port}"))
    except Exception:
        pass
    return None


def scan_ports(ip: str, ports: list = None, timeout: float = 0.4, callbacks=None) -> list:
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)
    open_ports.sort(key=lambda p: p.port)
    return open_ports

# ── OS detection (by ping TTL) ──────────────────────────────────

def guess_os_by_ttl(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Определение OS по TTL ответного ping'а."""
    try:
        if _is_windows():
            out = _run(["ping", "-n", "1", "-w", str(int(timeout*1000)), ip],
                                 capture_output=True, text=True, timeout=timeout + 1)
        else:
            out = _run(["ping", "-c", "1", "-W", str(int(timeout)), ip],
                                 capture_output=True, text=True, timeout=timeout + 1)

        for line in out.stdout.splitlines():
            if "TTL=" in line or "ttl=" in line:
                try:
                    ttl_str = line.split("TTL=")[-1].split("ttl=")[-1].split()[0].strip()
                    ttl = int(ttl_str)
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    elif ttl <= 255:
                        return "Network Device / Solaris"
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return None

# ── OUI Lookup ───────────────────────────────────────────────────

def oui_lookup(mac: str) -> Optional[str]:
    oui = "".join(c for c in mac if c.isalnum()).upper()[:6]
    # Try external OUI database first
    try:
        from oui_data import OUI_DB
        if oui in OUI_DB:
            return OUI_DB[oui]
        if oui[:3] in OUI_DB:
            return OUI_DB[oui[:3]]
    except ImportError:
        pass
    # Fallback to built-in db
    db = {
        "001372": "Cisco", "0016B6": "Cisco-Linksys", "0017F2": "Apple",
        "0019E3": "Apple", "001CB3": "Apple", "0022B0": "D-Link",
        "0023DF": "TP-Link", "00249B": "Actiontec", "0026F2": "Netgear",
        "003A7D": "Ubiquiti", "0050F1": "Intel", "0050FC": "TP-Link",
        "0050BA": "D-Link", "0080C8": "D-Link", "00A040": "Apple",
        "04F021": "Xerox", "08D833": "Xiaomi", "105172": "HP",
        "1866DA": "Dell", "1C872C": "Apple", "28107B": "D-Link",
        "2CF432": "Netgear", "3810D5": "Samsung", "3C5AB4": "Google",
        "3C8994": "Xiaomi", "40B034": "HP", "487604": "Huawei",
        "4C3275": "Apple", "50465D": "ASUS", "5061BF": "TP-Link",
        "54A050": "ASUS", "5C85FB": "Sony", "60A4B0": "Dell",
        "683E34": "Xiaomi", "6C3B6B": "Dell", "708BCD": "ASUS",
        "70B3D5": "Intel", "74D21D": "Intel", "78A051": "Intel",
        "7C2A31": "Intel", "8038BC": "Xiaomi", "841B5E": "Netgear",
        "8C8CD2": "Dell", "907B2B": "Huawei", "9803D8": "Apple",
        "A0369F": "Intel", "A41875": "Cisco", "A454D0": "Dell",
        "A85EE4": "Intel", "AC3743": "Apple", "B0C95B": "Intel",
        "BC1780": "Intel", "C05E79": "Samsung", "C4E92F": "Dell",
        "CC20A8": "TP-Link", "D017C2": "ASUS", "D496AA": "Intel",
        "DC722E": "Intel", "E02A82": "Samsung", "E83231": "Huawei",
        "ECA932": "Microsoft", "F09FC5": "Dell", "F82A67": "Intel",
        "FCA183": "Samsung", "FCF528": "Dell",
    }
    if oui in db:
        return db[oui]
    prefix_map = {
        "00": "IEEE", "04": "Samsung/Synology", "08": "Samsung/Huawei",
        "0C": "Cisco", "10": "Intel", "14": "Intel", "18": "Intel",
        "1C": "Intel", "20": "Cisco/Dell", "24": "Apple", "28": "Apple",
        "2C": "Apple", "30": "TP-Link", "34": "Intel", "38": "Intel",
        "3C": "Intel", "40": "Dell", "44": "Ubiquiti", "48": "Sony",
        "4C": "Apple", "50": "Netgear", "54": "ASUS", "58": "Google",
        "5C": "Intel", "60": "Apple", "64": "Dell", "68": "Intel",
        "6C": "Dell", "70": "Microsoft", "74": "Ubiquiti", "78": "Ubiquiti",
        "7C": "Intel", "80": "TP-Link", "84": "TP-Link", "88": "Intel",
        "8C": "Intel", "90": "Intel", "94": "Intel", "98": "Intel",
        "9C": "Intel", "A0": "Intel", "A4": "Intel", "A8": "Apple",
        "AC": "Apple", "B0": "Apple", "B4": "Apple", "B8": "Apple",
        "BC": "Apple", "C0": "D-Link", "C4": "D-Link", "C8": "Apple",
        "CC": "Apple", "D0": "Intel", "D4": "Intel", "D8": "Intel",
        "DC": "Intel", "E0": "Intel", "E4": "Intel", "E8": "Intel",
        "EC": "Intel", "F0": "Dell", "F4": "Apple", "F8": "Intel",
        "FC": "Ubiquiti",
    }
    return prefix_map.get(oui[:2])

# ── Device type guess ────────────────────────────────────────────

def guess_device_type(hostname: str, ports: list) -> str:
    hn = hostname.lower()
    port_nums = {p.port if hasattr(p, 'port') else p for p in ports}

    keywords = {
        ("router", "gateway", "шлюз"): "router",
        ("switch", "свитч", "коммутатор"): "switch",
        ("printer", "принтер", "mfp"): "printer",
        ("cam", "камера", "nvr", "dvr"): "camera",
        ("server", "сервер", "srv"): "server",
        ("ap", "access point", "точка", "wi-fi"): "access-point",
    }
    for keys, dtype in keywords.items():
        if any(k in hn for k in keys):
            return dtype

    if port_nums & {22, 3389, 5900, 3306, 5432, 6379, 27017}:
        return "server"
    if port_nums & {80, 443, 8080, 8443}:
        return "server"
    if port_nums & {9100, 515}:
        return "printer"
    if port_nums & {554}:
        return "camera"
    if port_nums & {23, 22}:
        return "network-device"
    return "workstation"

# ── Scan modes ───────────────────────────────────────────────────

def _get_gateway(subnet: str) -> str:
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        return str(net.network_address + 1)
    except ValueError:
        return ""


def scan_quick(subnet: str, callbacks=None) -> ScanResult:
    """Быстрый: только ARP."""
    if callbacks:
        callbacks.on_progress("ARP scan...", 10)
    devices = arp_scan_subnet(subnet, callbacks)
    if callbacks:
        callbacks.on_progress(f"Found {len(devices)} devices", 100)

    gw = _get_gateway(subnet)
    edges = [Edge(source=d.id, target=gw, edge_type="direct") for d in devices if gw and d.ip != gw]

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
    last_pct = [50]  # mutable for closure
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
    edges = [Edge(source=d.id, target=gw, edge_type="direct") for d in devices if gw and d.ip != gw]

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
            callbacks.on_progress(f"Deep: {d.ip}", 60 + (i+1)*35//max(len(result.devices),1))

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
                    callbacks.on_progress(f"LLDP: {d.ip}...", 25 + i * 60 // max(len(devices), 1))
                lldp = snmp_client.get_lldp_neighbors(d.ip)
                for local_port, rem_name, rem_port in lldp:
                    # Try to find target device by name/IP
                    target_id = _find_device_by_name(devices, rem_name)
                    if not target_id:
                        target_id = _get_gateway(subnet)  # fallback to gateway
                    edges.append(Edge(
                        source=d.id, target=target_id,
                        edge_type=f"LLDP port {local_port}"
                    ))

                # FDB → MAC-to-port mapping
                fdb = snmp_client.get_fdb(d.ip)
                if callbacks:
                    callbacks.on_progress(f"FDB: {d.ip} ({len(fdb)} entries)...",
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
            callbacks.on_progress(f"Topo {d.ip}: SNMP={d.device_type=='network-device'}", pct)

    # Fallback: connect all non-linked devices to gateway
    linked_ids = {e.source for e in edges} | {e.target for e in edges}
    gw = _get_gateway(subnet)
    for d in devices:
        if d.id not in linked_ids and d.ip != gw:
            edges.append(Edge(source=d.id, target=gw, edge_type="direct"))

    if callbacks:
        callbacks.on_progress(f"Topology: {len(devices)} devices, {len(edges)} edges", 100)

    return ScanResult(scan_time=datetime.now().isoformat(), network=subnet,
                      devices=devices, edges=edges)


def _find_device_by_name(devices: list, name: str) -> Optional[str]:
    """Найти ID устройства по имени (hostname или IP)."""
    if not name:
        return None
    name_l = name.lower().split(".")[0]  # short hostname
    for d in devices:
        if d.hostname and d.hostname.lower().split(".")[0] == name_l:
            return d.id
    # Try IP match
    for d in devices:
        if name in d.ip:
            return d.id
    return None


def _nmap_scan(ip: str) -> tuple:
    try:
        out = _run(["nmap", "-O", "-sV", "--top-ports", "20", "-T4", ip],
                             capture_output=True, text=True, timeout=120)
        stdout = out.stdout
        os_info = None
        ports = []
        for line in stdout.splitlines():
            line = line.strip()
            if "OS details:" in line or "Aggressive OS guesses:" in line:
                os_info = line.split(":", 1)[1].strip()
            if ("/tcp" in line or "/udp" in line) and "open" in line.split():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    ps = parts[0].split("/")
                    try:
                        pnum = int(ps[0])
                        proto = "udp" if "/udp" in parts[0] else "tcp"
                        svc = " ".join(parts[3:]) if len(parts) >= 4 else None
                        ports.append(Port(port=pnum, protocol=proto, service=svc))
                    except ValueError:
                        pass
        return (os_info, ports)
    except (FileNotFoundError, Exception):
        return (None, [])

# ── Monitor / Diff ────────────────────────────────────────────────

def monitor_diff(previous: ScanResult, current: ScanResult) -> dict:
    prev_ips = {d.ip: d for d in previous.devices}
    curr_ips = {d.ip: d for d in current.devices}

    appeared = [d for ip, d in curr_ips.items() if ip not in prev_ips]
    disappeared = [d for ip, d in prev_ips.items() if ip not in curr_ips]
    changed = []
    for ip in prev_ips.keys() & curr_ips.keys():
        prev_ports = {p.port for p in prev_ips[ip].ports}
        curr_set = {p.port for p in curr_ips[ip].ports}
        if prev_ports != curr_set:
            changed.append({"ip": ip, "prev": sorted(prev_ports), "curr": sorted(curr_set)})

    return {
        "appeared": [asdict(d) for d in appeared],
        "disappeared": [asdict(d) for d in disappeared],
        "changed": changed,
        "previous_count": len(previous.devices),
        "current_count": len(current.devices),
    }

# ── Serialisation ─────────────────────────────────────────────────

def save_result(result: ScanResult, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, indent=2, ensure_ascii=False)


def load_result(path: str) -> ScanResult:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    devices = []
    for d in data.get("devices", []):
        dev = Device(
            ip=d.get("ip", ""), mac=d.get("mac", ""),
            hostname=d.get("hostname"), vendor=d.get("vendor"),
            os=d.get("os"), device_type=d.get("device_type", "unknown"),
            status=d.get("status", "online"),
            first_seen=d.get("first_seen"), last_seen=d.get("last_seen"),
        )
        dev.ports = [Port(**p) for p in d.get("ports", [])]
        devices.append(dev)
    edges = [Edge(**e) for e in data.get("edges", [])]
    return ScanResult(scan_time=data.get("scan_time", ""),
                      network=data.get("network", ""),
                      devices=devices, edges=edges)
