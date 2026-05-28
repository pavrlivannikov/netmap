#!/usr/bin/env python3
"""
NetMap Web — FastAPI-интерфейс для сканирования сети.
Запуск: python netmap_web.py --port 8080
"""
import sys
import os
import json
import asyncio
import argparse
from datetime import datetime
from typing import Optional

# Switch to the script's directory so imports work regardless of cwd
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Query, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn

from netmap_scanner import (
    scan_quick, scan_discover, scan_deep, scan_topology,
    ScanResult, Device, Edge, ScanCallbacks,
    discover_networks,
)
from netmap_snmp import SnmpClient
from netmap_config import config
from netmap_alerts import TelegramChannel

app = FastAPI(title="NetMap Web", version="1.0.0")

# Load config on startup
_config = config.load()

# ── CORS middleware ──────────────────────────────────────────────
from starlette.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global scan state ────────────────────────────────────────────
_scan_state = {
    "running": False,
    "progress_msg": "",
    "progress_pct": 0,
    "last_result": None,  # ScanResult or None
    "last_scan_type": "",
    "last_scan_subnet": "",
}


# ── Helpers ──────────────────────────────────────────────────────

def _serialize_scan_result(result: ScanResult) -> dict:
    """Convert ScanResult to JSON-serializable dict."""
    devices = []
    for d in result.devices:
        devices.append({
            "ip": d.ip,
            "mac": d.mac,
            "hostname": d.hostname,
            "vendor": d.vendor,
            "os": d.os,
            "device_type": d.device_type,
            "status": d.status,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "state": p.state,
                }
                for p in (d.ports or [])
            ],
        })

    edges = []
    for e in result.edges:
        edges.append({
            "source": e.source,
            "target": e.target,
            "edge_type": e.edge_type,
            "latency_ms": e.latency_ms,
        })

    return {
        "scan_time": result.scan_time,
        "network": result.network,
        "devices": devices,
        "edges": edges,
    }


class _WebCallbacks(ScanCallbacks):
    """Callbacks that update global scan state."""
    def on_progress(self, msg: str, pct: int):
        _scan_state["progress_msg"] = msg
        _scan_state["progress_pct"] = pct

    def on_device_found(self, device: Device):
        pass  # devices accumulate in result

    def on_complete(self, result: ScanResult):
        pass

    def on_error(self, msg: str):
        _scan_state["progress_msg"] = f"Error: {msg}"


# ── API: Scan ────────────────────────────────────────────────────

@app.post("/api/scan")
async def api_scan(
    subnet: str = Query("192.168.1.0/24"),
    scan_type: str = Query("quick"),
    community: str = Query("public"),
    background_tasks: BackgroundTasks = None,
):
    """Запустить сканирование подсети."""
    global _scan_state

    if _scan_state["running"]:
        return {"ok": False, "error": "Scan already in progress"}

    valid_types = {"quick", "discover", "deep", "topology"}
    if scan_type not in valid_types:
        raise HTTPException(400, f"Invalid scan_type: {scan_type}. Use: {', '.join(sorted(valid_types))}")

    _scan_state["running"] = True
    _scan_state["progress_msg"] = "Starting..."
    _scan_state["progress_pct"] = 0
    _scan_state["last_scan_type"] = scan_type
    _scan_state["last_scan_subnet"] = subnet

    callbacks = _WebCallbacks()

    async def _run_scan():
        global _scan_state
        try:
            loop = asyncio.get_running_loop()

            if scan_type == "quick":
                result = await loop.run_in_executor(None, scan_quick, subnet, callbacks)
            elif scan_type == "discover":
                result = await loop.run_in_executor(None, scan_discover, subnet, callbacks)
            elif scan_type == "deep":
                result = await loop.run_in_executor(None, scan_deep, subnet, callbacks)
            elif scan_type == "topology":
                result = await loop.run_in_executor(None, scan_topology, subnet, callbacks, community)
            else:
                result = None

            _scan_state["last_result"] = result
            _scan_state["progress_msg"] = "Done"
            _scan_state["progress_pct"] = 100
        except Exception as e:
            _scan_state["progress_msg"] = f"Error: {e}"
            _scan_state["progress_pct"] = 0
        finally:
            _scan_state["running"] = False

    background_tasks.add_task(_run_scan)

    return {"ok": True, "scan_type": scan_type, "subnet": subnet}


@app.get("/api/scan/status")
async def api_scan_status():
    """Текущее состояние сканирования."""
    return {
        "running": _scan_state["running"],
        "progress_msg": _scan_state["progress_msg"],
        "progress_pct": _scan_state["progress_pct"],
        "last_scan_type": _scan_state["last_scan_type"],
        "last_scan_subnet": _scan_state["last_scan_subnet"],
    }


# ── API: Devices ─────────────────────────────────────────────────

@app.get("/api/devices")
async def api_devices():
    """Список устройств из последнего скана."""
    if _scan_state["last_result"] is None:
        return {"scan_time": "", "network": "", "devices": []}
    data = _serialize_scan_result(_scan_state["last_result"])
    return {
        "scan_time": data["scan_time"],
        "network": data["network"],
        "devices": data["devices"],
    }


# ── API: Topology ────────────────────────────────────────────────

@app.get("/api/topology")
async def api_topology():
    """Граф (устройства + связи)."""
    if _scan_state["last_result"] is None:
        return {"devices": [], "edges": []}
    data = _serialize_scan_result(_scan_state["last_result"])
    return {
        "devices": data["devices"],
        "edges": data["edges"],
        "scan_time": data["scan_time"],
        "network": data["network"],
    }


# ── API: Networks ────────────────────────────────────────────────

@app.get("/api/networks")
async def api_networks():
    """Список обнаруженных сетей."""
    try:
        loop = asyncio.get_running_loop()
        networks = await loop.run_in_executor(None, discover_networks)
        result = []
        for n in networks:
            result.append({
                "interface": n.interface,
                "ip": n.ip,
                "prefix": n.prefix,
                "gateway": n.gateway,
                "cidr": n.cidr,
                "description": n.description,
            })
        return {"networks": result}
    except Exception as e:
        return {"networks": [], "error": str(e)}


# ── API: FDB ─────────────────────────────────────────────────────

@app.get("/api/fdb")
async def api_fdb(
    device_ip: str = Query(""),
    community: str = Query("public"),
):
    """MAC-таблица (FDB) с конкретного устройства по SNMP."""
    if not device_ip:
        return {"device_ip": "", "entries": [], "error": "device_ip required"}

    try:
        loop = asyncio.get_running_loop()

        def _get_fdb():
            client = SnmpClient(community=community, timeout=2.0)
            if not client.probe(device_ip):
                return None, "SNMP not reachable"
            entries = client.get_fdb(device_ip)
            return entries, None

        entries, error = await loop.run_in_executor(None, _get_fdb)

        if error:
            return {"device_ip": device_ip, "entries": [], "error": error}

        return {
            "device_ip": device_ip,
            "entries": [
                {"vlan": vlan, "mac": mac, "port": port}
                for vlan, mac, port in entries
            ],
            "total": len(entries),
        }
    except Exception as e:
        return {"device_ip": device_ip, "entries": [], "error": str(e)}


# ── Token masking helper ────────────────────────────────────────

def _mask_token(token: str) -> str:
    """Mask token for display: show first 8 and last 4 chars."""
    if not token:
        return ""
    if len(token) <= 14:
        return token[:6] + "••••••"
    return token[:8] + "••••••" + token[-4:]


# ── API: Config ──────────────────────────────────────────────────

@app.get("/api/config")
async def api_config_get():
    """Return current config (token masked)."""
    cfg = config.to_dict()
    token = cfg.get("telegram_token", "")
    cfg["telegram_token"] = _mask_token(token)
    return {"config": cfg}


@app.post("/api/config")
async def api_config_save(payload: dict):
    """Save configuration. Accepts partial dict."""
    incoming = payload.get("config", payload)
    if not isinstance(incoming, dict):
        raise HTTPException(400, "Expected JSON object with 'config' key or flat dict")

    # Preserve existing token if placeholder sent
    token = incoming.get("telegram_token", "")
    if token and "••••" in token:
        incoming["telegram_token"] = config.get("telegram_token", "")

    config.update(incoming)
    config.save()
    return {"ok": True, "message": "Settings saved"}


@app.post("/api/config/test-telegram")
async def api_config_test_telegram():
    """Send a test message via configured Telegram bot."""
    token = config.get("telegram_token", "")
    chat_id = config.get("telegram_chat_id", "")

    if not token or not chat_id:
        return {"ok": False, "error": "Telegram token or chat_id not configured"}

    channel = TelegramChannel(token, str(chat_id), timeout=10.0)
    from netmap_alerts import Alert, AlertType
    test_alert = Alert(
        AlertType.NEW_DEVICE,
        "127.0.0.1",
        {
            "hostname": "netmap-test",
            "vendor": "NetMap Config Test",
            "mac": "00:00:00:00:00:00",
        },
    )
    ok = channel.send(test_alert)
    if ok:
        return {"ok": True, "message": "Test message sent to Telegram"}
    return {"ok": False, "error": "Failed to send Telegram message (check token & chat_id)"}


# ── Static files ─────────────────────────────────────────────────

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    """Redirect to index.html."""
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(static_dir, "index.html"))


# ── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="NetMap Web Server")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    args = parser.parse_args()

    print(f"NetMap Web → http://{args.host}:{args.port}")
    print(f"Config: {config._path}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
