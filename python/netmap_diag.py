"""NetMap Diagnostic — консольная диагностика сети."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netmap_scanner import _win32_get_adapters, _win32_get_arp_table, arp_scan, discover_networks, _is_windows

print("=== NetMap Diagnostic ===")
print(f"Windows: {_is_windows()}")
print(f"Python: {sys.version}")

print("\n--- Win32 GetAdaptersAddresses ---")
adapters = _win32_get_adapters()
if adapters:
    for name, ip, prefix, gw in adapters:
        print(f"  {name}: {ip}/{prefix} gw={gw}")
else:
    print("  EMPTY — fallback to discover_networks()")
    nets = discover_networks()
    for n in nets:
        print(f"  {n.interface}: {n.cidr} gw={n.gateway}")

print("\n--- Win32 GetIpNetTable ---")
arp = _win32_get_arp_table()
if arp:
    for ip, mac in arp:
        print(f"  {ip} -> {mac}")
else:
    print("  EMPTY — fallback to arp_scan()")

print("\n--- arp_scan() ---")
devices = arp_scan()
print(f"  Found: {len(devices)} devices")
for d in devices[:10]:
    print(f"  {d.ip} | {d.mac} | {d.vendor}")

print("\n--- discover_networks() ---")
nets = discover_networks()
print(f"  Found: {len(nets)} networks")
for n in nets:
    print(f"  {n.cidr} on {n.interface}")

print("\nDone. Press Enter...")
input()
