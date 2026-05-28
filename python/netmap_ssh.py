"""
NetMap SSH — SSH fallback for FDB (MAC table) retrieval.

Supports switches that don't expose BRIDGE-MIB via SNMP:
  - Cisco IOS / IOS-like:  show mac address-table
  - TP-Link JetStream:     show mac-address
  - MikroTik RouterOS:     /interface bridge host print

Pure Python — only paramiko dependency.
"""
import re
import socket
from dataclasses import dataclass
from typing import Optional

import paramiko


# ── Dataclass ────────────────────────────────────────────────────

@dataclass
class MacEntry:
    """A single FDB entry retrieved via SSH."""
    mac: str
    port: str          # interface name (e.g. Gi1/0/1, ether2, 1/0/1)
    vlan: Optional[int] = None

    def to_dict(self):
        return {"mac": self.mac, "port": self.port, "vlan": self.vlan}


# ── MAC normalisation ────────────────────────────────────────────

def _normalise_mac(raw: str) -> str:
    """Normalise any MAC format to xx:xx:xx:xx:xx:xx (lowercase)."""
    hex_digits = re.findall(r"[0-9a-fA-F]{2}", raw.replace(".", "").replace("-", "").replace(":", ""))
    if len(hex_digits) == 6:
        return ":".join(h.lower() for h in hex_digits)
    return raw.strip()


# ── Output parsers ───────────────────────────────────────────────

def _parse_cisco_style(text: str) -> list[MacEntry]:
    """
    Parse ``show mac address-table`` (Cisco IOS / IOS-XE / TP-Link JetStream).

    Handles both dotted MAC (0011.2233.4455) and colon / dash MAC.
    """
    entries: list[MacEntry] = []
    # Regex matches lines like:
    #   *   1    0011.2233.4455    dynamic    Gi1/0/1
    #        1    00:11:22:33:44:55  Dynamic  1/0/1
    #  1        0011.2233.4455  dynamic     ip,ipx       GigabitEthernet1/0/1
    # The key is: VLAN (digits), MAC (hex hex hex), then port at end.
    pattern = re.compile(
        r"^\s*(?:\*)?\s*"                           # optional leading star
        r"(?P<vlan>\d{1,4})\s+"                     # vlan
        r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|"  # Cisco dotted
        r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})"  # colon/dash
        r"\s+.*?"                                    # type / protocol (greedy-lazy)
        r"(?P<port>\S+)\s*$",                        # port (last column)
        re.IGNORECASE,
    )
    for line in text.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        mac = _normalise_mac(m.group("mac"))
        vlan = int(m.group("vlan"))
        port = m.group("port").rstrip(",")
        # Filter out non-port endings that sneak in
        if port.lower() in ("dynamic", "static", "secure", "yes", "no", "learned", "management"):
            continue
        entries.append(MacEntry(mac=mac, port=port, vlan=vlan))
    return entries


def _parse_mikrotik(text: str) -> list[MacEntry]:
    """
    Parse ``/interface bridge host print`` (MikroTik RouterOS).

    Handles two column layouts:
      * BRIDGE + ON-INTERFACE + MAC-ADDRESS
      * ON-INTERFACE + BRIDGE + MAC-ADDRESS
    """
    entries: list[MacEntry] = []

    for line in text.splitlines():
        line = line.strip()
        # Skip header / separator / empty
        if not line or line.startswith("#") or line.startswith("Flags"):
            continue
        # Skip column-name rows
        if re.match(r"^\s*\d+\s+(MAC-ADDRESS|MAC)", line, re.IGNORECASE):
            continue

        # Try to extract: index MAC [VID] INTERFACE [BRIDGE] ... STATUS
        # Typical print:  0  00:11:22:33:44:55  bridge1  ether2  dynamic
        # Or with VLAN:   0  00:11:22:33:44:55  100  ether2  bridge1
        # Or simple:      0 D 00:11:22:33:44:55  ether2  bridge1
        parts = line.split()
        if len(parts) < 3:
            continue

        mac_idx = None
        for i, p in enumerate(parts):
            if re.match(r"^[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}$", p):
                mac_idx = i
                break

        if mac_idx is None:
            continue

        mac = _normalise_mac(parts[mac_idx])
        vlan: Optional[int] = None
        port = ""

        # Try to find port: either the column after MAC or after an optional VLAN
        after_mac = parts[mac_idx + 1:]
        if after_mac:
            # Check if next column is a VLAN number
            maybe_vlan = after_mac[0]
            if maybe_vlan.isdigit() and 1 <= int(maybe_vlan) <= 4095:
                vlan = int(maybe_vlan)
                port_candidates = after_mac[1:]
            else:
                vlan = None
                port_candidates = after_mac

            # Port is usually one of the first two non-keyword tokens
            for candidate in port_candidates:
                if candidate.lower() in ("dynamic", "static", "local", "external", "invalid"):
                    continue
                port = candidate
                break

        if port:
            entries.append(MacEntry(mac=mac, port=port, vlan=vlan))
    return entries


def _parse_tplink(text: str) -> list[MacEntry]:
    """
    Parse TP-Link JetStream ``show mac-address`` output.

    Typical format:
        VlanId  Mac Address        Type    Port
        ------  ---------------    ------  ---------
        1       00:11:22:33:44:55  Dynamic 1/0/1
    """
    entries: list[MacEntry] = []
    pattern = re.compile(
        r"^\s*(?P<vlan>\d{1,4})\s+"
        r"(?P<mac>[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+"
        r"\S+\s+"                                    # Type (Dynamic/Static)
        r"(?P<port>\S+)",                            # Port
        re.IGNORECASE,
    )
    for line in text.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        mac = _normalise_mac(m.group("mac"))
        vlan = int(m.group("vlan"))
        port = m.group("port")
        entries.append(MacEntry(mac=mac, port=port, vlan=vlan))
    return entries


# ── SSH Client ───────────────────────────────────────────────────

class SshClient:
    """Thin wrapper around paramiko for executing commands on network gear."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self, host: str, username: str, password: str, port: int = 22):
        """Establish SSH connection. Raises on failure."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
        )

    def exec_command(self, command: str) -> tuple[str, str, int]:
        """Run a command. Returns (stdout, stderr, exit_code)."""
        if self._client is None:
            raise RuntimeError("Not connected. Call connect() first.")
        stdin, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return out, err, exit_code

    def close(self):
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ── Probe ────────────────────────────────────────────────────────

def probe_ssh(host: str, port: int = 22, timeout: float = 2.0) -> bool:
    """Check whether an SSH port is open on *host*."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        # Read the banner to confirm it's SSH
        sock.settimeout(timeout)
        banner = sock.recv(256)
        sock.close()
        return banner.startswith(b"SSH-")
    except (OSError, socket.timeout):
        return False


# ── FDB retrieval ────────────────────────────────────────────────

# Commands to try, in order.  Each tuple is (command, parser_fn, is_mikrotik).
# MikroTik is special because it's not a regular shell command.
_CMD_CHAIN = [
    # Cisco IOS / IOS-XE / NX-OS
    ("show mac address-table", _parse_cisco_style),
    ("show mac-address-table", _parse_cisco_style),
    # TP-Link JetStream (some use "show mac-address" vs "show mac address-table")
    ("show mac-address", _parse_tplink),
    # Older Cisco / shorter form
    ("show mac", _parse_cisco_style),
]

# MikroTik is handled separately — it needs an explicit command via API-style
# but we can still do it via SSH with a non-interactive command.
_MIKROTIK_CMD = "/interface bridge host print"


def get_fdb_ssh(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: float = 10.0,
    vendor: Optional[str] = None,
) -> list[MacEntry]:
    """
    Retrieve the MAC address table (FDB) from a switch via SSH.

    Parameters
    ----------
    host : str
        Switch IP or hostname.
    username : str
        SSH username.
    password : str
        SSH password.
    port : int
        SSH port (default 22).
    timeout : float
        Connection and command timeout in seconds.
    vendor : Optional[str]
        Hint: ``"cisco"``, ``"tplink"``, or ``"mikrotik"`` to try only
        that vendor's command.  When *None*, tries common commands in order.

    Returns
    -------
    list[MacEntry]
        Parsed FDB entries.  Empty list on failure or no entries.
    """
    client = SshClient(timeout=timeout)
    entries: list[MacEntry] = []
    try:
        client.connect(host, username, password, port)

        if vendor and vendor.lower() == "mikrotik":
            cmd = _MIKROTIK_CMD
            out, err, _ = client.exec_command(cmd)
            if out.strip():
                return _parse_mikrotik(out)
            return []

        # Vendor hint — reorder chain
        chain = list(_CMD_CHAIN)
        if vendor:
            vendor_lower = vendor.lower()
            chain.sort(key=lambda x: 0 if vendor_lower in x[0].lower() else 1)

        for cmd, parser in chain:
            try:
                out, err, exit_code = client.exec_command(cmd)
            except Exception:
                continue

            text = out.strip()
            if not text:
                continue

            # If the output looks like a "command not found" or error
            first_line_lower = text.split("\n")[0].lower()
            if any(token in first_line_lower for token in
                   ("invalid", "unrecognized", "unknown", "error", "incomplete", "misspelled")):
                continue

            parsed = parser(text)
            if parsed:
                entries = parsed
                break

            # If command ran but returned no parsable rows, try the next
            # (e.g. TP-Link returned Cisco-format header but no data — try TP-Link parser)

    except paramiko.AuthenticationException:
        pass  # bad password — return empty
    except (paramiko.SSHException, socket.timeout, OSError):
        pass  # connection failed — return empty
    except RuntimeError:
        pass  # not connected
    finally:
        client.close()

    return entries
