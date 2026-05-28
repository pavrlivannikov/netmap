"""
NetMap DB — SQLite database for scan history.

Replaces JSON-based save_result/load_result with a queryable SQLite backend.
JSON serialization (netmap_monitor.py) continues to work — this module is
an additional persistence layer, not a replacement.

Usage:
    from netmap_db import ScanDB

    db = ScanDB("netmap.db")
    scan_id = db.save_scan(result)
    history = db.list_scans(limit=20)
    diff = db.diff_scans(id1, id2)
    stats = db.get_stats()
"""

import sqlite3
import json
import os
import glob
from dataclasses import asdict, fields
from typing import Optional

try:
    from .netmap_device import Device, Port, Edge, ScanResult
except ImportError:
    from netmap_device import Device, Port, Edge, ScanResult


class ScanDB:
    """SQLite-backed scan history with device-level query support."""

    def __init__(self, db_path: str = "netmap.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.create_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def create_tables(self):
        """Create tables and indexes if they do not exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time   TEXT    NOT NULL,
                network     TEXT    NOT NULL,
                scan_type   TEXT    DEFAULT 'full',
                device_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ip          TEXT    NOT NULL,
                mac         TEXT    DEFAULT '',
                hostname    TEXT,
                vendor      TEXT,
                device_type TEXT    DEFAULT 'unknown',
                status      TEXT    DEFAULT 'online',
                os          TEXT,
                first_seen  TEXT,
                last_seen   TEXT
            );

            CREATE TABLE IF NOT EXISTS ports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                port        INTEGER NOT NULL,
                protocol    TEXT    DEFAULT 'tcp',
                service     TEXT,
                state       TEXT    DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS edges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                source      TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                edge_type   TEXT    DEFAULT 'direct',
                latency_ms  REAL
            );

            -- Lookup indexes
            CREATE INDEX IF NOT EXISTS idx_devices_ip      ON devices(ip);
            CREATE INDEX IF NOT EXISTS idx_devices_mac     ON devices(mac);
            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_ports_device_id ON ports(device_id);
            CREATE INDEX IF NOT EXISTS idx_edges_scan_id   ON edges(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_time      ON scans(scan_time);
        """)
        self.conn.commit()

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save_scan(self, result: ScanResult, scan_type: str = "full") -> int:
        """Persist a ScanResult and return its database id."""
        cur = self.conn.execute(
            "INSERT INTO scans (scan_time, network, scan_type, device_count) VALUES (?, ?, ?, ?)",
            (result.scan_time, result.network, scan_type, len(result.devices)),
        )
        scan_id = cur.lastrowid

        for device in result.devices:
            cur = self.conn.execute(
                """INSERT INTO devices
                   (scan_id, ip, mac, hostname, vendor, device_type, status, os, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, device.ip, device.mac, device.hostname,
                    device.vendor, device.device_type, device.status,
                    device.os, device.first_seen, device.last_seen,
                ),
            )
            device_id = cur.lastrowid
            for port in device.ports:
                self.conn.execute(
                    "INSERT INTO ports (device_id, port, protocol, service, state) VALUES (?, ?, ?, ?, ?)",
                    (device_id, port.port, port.protocol, port.service, port.state),
                )

        for edge in result.edges:
            self.conn.execute(
                "INSERT INTO edges (scan_id, source, target, edge_type, latency_ms) VALUES (?, ?, ?, ?, ?)",
                (scan_id, edge.source, edge.target, edge.edge_type, edge.latency_ms),
            )

        self.conn.commit()
        return scan_id

    # ------------------------------------------------------------------
    # Load single scan
    # ------------------------------------------------------------------

    def get_scan(self, scan_id: int) -> Optional[ScanResult]:
        """Reconstruct a ScanResult from the database."""
        scan_row = self.conn.execute(
            "SELECT id, scan_time, network, device_count FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not scan_row:
            return None

        devices = []
        device_rows = self.conn.execute(
            "SELECT id, ip, mac, hostname, vendor, device_type, status, os, first_seen, last_seen "
            "FROM devices WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()

        for drow in device_rows:
            port_rows = self.conn.execute(
                "SELECT port, protocol, service, state FROM ports WHERE device_id = ? ORDER BY port",
                (drow["id"],),
            ).fetchall()
            device = Device(
                ip=drow["ip"], mac=drow["mac"] or "",
                hostname=drow["hostname"], vendor=drow["vendor"],
                device_type=drow["device_type"], status=drow["status"],
                os=drow["os"], first_seen=drow["first_seen"], last_seen=drow["last_seen"],
            )
            device.ports = [Port(port=r["port"], protocol=r["protocol"],
                                 service=r["service"], state=r["state"]) for r in port_rows]
            devices.append(device)

        edge_rows = self.conn.execute(
            "SELECT source, target, edge_type, latency_ms FROM edges WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        edges = [Edge(source=r["source"], target=r["target"],
                      edge_type=r["edge_type"], latency_ms=r["latency_ms"]) for r in edge_rows]

        return ScanResult(
            scan_time=scan_row["scan_time"],
            network=scan_row["network"],
            devices=devices,
            edges=edges,
        )

    # ------------------------------------------------------------------
    # List scans
    # ------------------------------------------------------------------

    def list_scans(self, limit: int = 50) -> list[dict]:
        """Return recent scans as lightweight dicts (no device/port detail)."""
        rows = self.conn.execute(
            "SELECT id, scan_time, network, scan_type, device_count "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Device history
    # ------------------------------------------------------------------

    def get_device_history(self, ip_or_mac: str) -> list[dict]:
        """All scan records for a device identified by IP or MAC."""
        rows = self.conn.execute(
            """SELECT DISTINCT s.scan_time, s.network, s.id AS scan_id,
                      d.ip, d.mac, d.hostname, d.vendor, d.device_type,
                      d.status, d.os, d.first_seen, d.last_seen
               FROM devices d
               JOIN scans s ON s.id = d.scan_id
               WHERE d.ip = ? OR (d.mac != '' AND d.mac = ?)
               ORDER BY s.scan_time DESC""",
            (ip_or_mac, ip_or_mac),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff_scans(self, scan_id_1: int, scan_id_2: int) -> dict:
        """Compare two scans: appeared / disappeared / changed devices and ports."""
        def _ip_map(scan_id):
            rows = self.conn.execute(
                "SELECT id, ip, mac, hostname, vendor, device_type, status, os "
                "FROM devices WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
            return {r["ip"]: r for r in rows}

        def _ports_for(device_id):
            return {
                r["port"] for r in self.conn.execute(
                    "SELECT port FROM ports WHERE device_id = ?", (device_id,)
                ).fetchall()
            }

        prev = _ip_map(scan_id_1)
        curr = _ip_map(scan_id_2)

        appeared = [
            dict(curr[ip]) for ip in curr if ip not in prev
        ]
        disappeared = [
            dict(prev[ip]) for ip in prev if ip not in curr
        ]

        changed = []
        for ip in prev.keys() & curr.keys():
            prev_ports = _ports_for(prev[ip]["id"])
            curr_ports = _ports_for(curr[ip]["id"])
            if prev_ports != curr_ports:
                changed.append({
                    "ip": ip,
                    "prev_ports": sorted(prev_ports),
                    "curr_ports": sorted(curr_ports),
                })
            # Check status/hostname changes
            for field in ("status", "hostname", "os", "vendor"):
                if prev[ip][field] != curr[ip][field]:
                    # Avoid duplicate entries in 'changed'
                    existing = next((c for c in changed if c["ip"] == ip), None)
                    if existing:
                        existing.setdefault("field_changes", {})[field] = {
                            "prev": prev[ip][field], "curr": curr[ip][field],
                        }
                    else:
                        changed.append({
                            "ip": ip,
                            "field_changes": {field: {"prev": prev[ip][field], "curr": curr[ip][field]}},
                        })
                    break  # one entry per ip is enough; field_changes collects all

        return {
            "appeared": appeared,
            "disappeared": disappeared,
            "changed": changed,
            "previous_count": sum(1 for _ in prev),
            "current_count": sum(1 for _ in curr),
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Aggregate stats: total scans, devices, OUI distribution."""
        total_scans = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        total_devices = self.conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM devices WHERE mac != ''"
        ).fetchone()[0]

        oui_rows = self.conn.execute(
            """SELECT vendor, COUNT(*) AS cnt
               FROM devices
               WHERE vendor IS NOT NULL AND vendor != ''
               GROUP BY vendor
               ORDER BY cnt DESC
               LIMIT 50"""
        ).fetchall()
        oui_distribution = {r["vendor"]: r["cnt"] for r in oui_rows}

        last_scan = self.conn.execute(
            "SELECT scan_time FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

        return {
            "total_scans": total_scans,
            "total_unique_devices": total_devices,
            "oui_distribution": oui_distribution,
            "last_scan_time": last_scan["scan_time"] if last_scan else None,
        }

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def vacuum(self):
        """Reclaim disk space after deletions."""
        self.conn.execute("VACUUM")

    def delete_scan(self, scan_id: int):
        """Remove a scan and all its children (CASCADE)."""
        self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.conn.commit()


# ------------------------------------------------------------------
# JSON → SQLite migration
# ------------------------------------------------------------------

def _json_to_scanresult(data: dict) -> ScanResult:
    """Reconstruct ScanResult from a JSON dict (same logic as load_result)."""
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
    return ScanResult(
        scan_time=data.get("scan_time", ""),
        network=data.get("network", ""),
        devices=devices, edges=edges,
    )


def migrate_json_to_sqlite(
    json_dir: str,
    db_path: str = "netmap.db",
    pattern: str = "*.json",
) -> int:
    """Import all JSON scan files from *json_dir* into the SQLite database.

    Returns the number of scans migrated.
    """
    json_files = sorted(glob.glob(os.path.join(json_dir, pattern)))
    if not json_files:
        return 0

    with ScanDB(db_path) as db:
        count = 0
        for fpath in json_files:
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                result = _json_to_scanresult(data)
                db.save_scan(result)
                count += 1
            except Exception as exc:
                print(f"[migrate] Skipping {fpath}: {exc}")
    return count
