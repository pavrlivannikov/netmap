"""
NetMap Discovery — network interface discovery, ARP scan, ping sweep, Win32 API helpers.
"""
import subprocess
import json
import threading
import concurrent.futures

try:
    from .netmap_device import Device, NetworkInfo
except ImportError:
    from netmap_device import Device, NetworkInfo

try:
    from .netmap_utils import (
        _is_windows, _run, _check_output,
        _is_valid_ip, _is_valid_mac, _count_dots, _mask_to_prefix,
        expand_subnet, is_ip_in_subnet, _guess_gw, _get_gateway,
        _find_gateway_linux, _find_gateway_win, _find_gateway_for_iface_win,
        _sort_networks, _resolve_hostname, _run_ps_arp,
        oui_lookup, guess_device_type,
        _parse_arp_win, _parse_arp_linux, _parse_ip_neigh,
    )
except ImportError:
    from netmap_utils import (
        _is_windows, _run, _check_output,
        _is_valid_ip, _is_valid_mac, _count_dots, _mask_to_prefix,
        expand_subnet, is_ip_in_subnet, _guess_gw, _get_gateway,
        _find_gateway_linux, _find_gateway_win, _find_gateway_for_iface_win,
        _sort_networks, _resolve_hostname, _run_ps_arp,
        oui_lookup, guess_device_type,
        _parse_arp_win, _parse_arp_linux, _parse_ip_neigh,
    )


# ── Win32 API helpers (ctypes, locale-independent) ─────────────────

def _win32_get_adapters() -> list:
    """Возвращает список (имя, ip, prefix, gateway) через Win32 API."""
    if not _is_windows():
        return []
    try:
        import ctypes
        from ctypes import wintypes, POINTER, Structure, c_ulong, c_ushort, c_char, c_ubyte, c_void_p

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
        for i in range(count):
            off = 4 + i * 24
            mac_len = buf[off + 4]
            if mac_len > 0 and mac_len <= 8:
                mac_raw = bytes(buf[off + 8:off + 8 + min(mac_len, 6)])
                if len(mac_raw) < 6:
                    mac_raw = mac_raw + b'\x00' * (6 - len(mac_raw))
                mac = ":".join(f"{b:02x}" for b in mac_raw)
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


def arp_scan_subnet(subnet: str, callbacks=None) -> list:
    """ARP scan for specific subnet (filtered from global ARP table)."""
    all_devices = arp_scan(callbacks)
    filtered = [d for d in all_devices if is_ip_in_subnet(d.ip, subnet)]
    return filtered


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
    """ICMP ping sweep. After ping, enriches with MACs from ARP table."""
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

    # Enrich with MACs from ARP table so device.id returns MAC, not IP
    if devices:
        try:
            arp_devices = arp_scan(callbacks=None)
            arp_map = {d.ip: d for d in arp_devices if d.mac}
            for dev in devices:
                if not dev.mac and dev.ip in arp_map:
                    dev.mac = arp_map[dev.ip].mac
                    dev.vendor = dev.vendor or arp_map[dev.ip].vendor
                    dev.hostname = dev.hostname or arp_map[dev.ip].hostname
        except Exception:
            pass  # ARP enrichment is best-effort; ping results still valid

    return devices
