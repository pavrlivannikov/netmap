"""
NetMap Utils — helpers, port scanning, OS detection, parsing, service maps.
"""
import subprocess
import socket
import re
import json
import ipaddress
import sys as _sys
from typing import Optional

try:
    from .netmap_device import Port, Device
except ImportError:
    from netmap_device import Port, Device


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


# ── Platform helpers ─────────────────────────────────────────────

_NO_WINDOW = 0x08000000 if _sys.platform == 'win32' else 0


def _is_windows():
    import os
    return os.name == 'nt'


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


# ── Validation ───────────────────────────────────────────────────

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


def _mask_to_prefix(mask: str) -> int:
    parts = mask.strip().split(".")
    if len(parts) != 4:
        return 24
    bits = sum(bin(int(p)).count("1") for p in parts)
    return bits or 24


# ── Subnet helpers ───────────────────────────────────────────────

def expand_subnet(subnet: str) -> list:
    net = ipaddress.IPv4Network(subnet, strict=False)
    return [str(h) for h in net.hosts()]


def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return False


def _guess_gw(ip: str, prefix: int) -> str:
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(net.network_address + 1)
    except ValueError:
        return ""


def _get_gateway(subnet: str) -> str:
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        return str(net.network_address + 1)
    except ValueError:
        return ""


# ── Gateway discovery ────────────────────────────────────────────

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


# ── DNS ──────────────────────────────────────────────────────────

def _resolve_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Reverse DNS lookup with timeout."""
    try:
        import socket as _sock
        _sock.setdefaulttimeout(timeout)
        result = _sock.gethostbyaddr(ip)[0]
        _sock.setdefaulttimeout(None)
        return result
    except Exception:
        return None


# ── ARP parsing ──────────────────────────────────────────────────

def _run_ps_arp() -> str:
    """Run PowerShell Get-NetNeighbor, return JSON string or empty."""
    try:
        return _check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Stale,Delay,Probe,Permanent | Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress"],
            text=True, timeout=15)
    except Exception:
        return ""


def _parse_arp_win(output: str) -> list:
    """Parse arp -a output: locale-independent, regex-based."""
    devices = []
    seen_ips = set()
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    mac_pattern = r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})'

    for line in output.splitlines():
        ips = re.findall(ip_pattern, line)
        macs = re.findall(mac_pattern, line)
        if len(ips) >= 1 and len(macs) >= 1:
            ip = ips[0]
            mac = macs[0].replace("-", ":").lower()
            if not _is_valid_ip(ip) or not _is_valid_mac(mac):
                continue
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
    import concurrent.futures as _cf
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    with _cf.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in _cf.as_completed(futures):
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


# ── Nmap ─────────────────────────────────────────────────────────

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


# ── Device name lookup ───────────────────────────────────────────

def _find_device_by_name(devices: list, name: str) -> Optional[str]:
    """Найти ID устройства по имени (hostname или IP)."""
    if not name:
        return None
    name_l = name.lower().split(".")[0]
    for d in devices:
        if d.hostname and d.hostname.lower().split(".")[0] == name_l:
            return d.id
    for d in devices:
        if name in d.ip:
            return d.id
    return None
