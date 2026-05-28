#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# NetMap Monitor — periodic network change detection
# Invoked by systemd timer every 5 minutes.
#
# Flow:
#   1. Quick ARP scan via netmap_scanner.scan_quick()
#   2. Save result → data/scan_YYYYMMDD_HHMMSS.json
#   3. Compare with previous scan via netmap_monitor.monitor_diff()
#   4. If changes detected → alert via netmap_alerts.AlertManager()
#   5. Rotate old JSONs (keep last 10)
#
# Env overrides:
#   NETMAP_DATA_DIR  — where to store scan JSONs
#   NETMAP_CONFIG    — path to config JSON
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${NETMAP_DATA_DIR:-$PROJECT_DIR/data}"
LOG_FILE="${NETMAP_LOG_FILE:-$DATA_DIR/monitor.log}"

mkdir -p "$DATA_DIR"

# ── Run monitor via Python (heredoc passed to python3 stdin) ─────
python3 - "$PROJECT_DIR" "$DATA_DIR" << 'PYEOF'
import sys, os, json, glob
from datetime import datetime

project_dir = sys.argv[1]
data_dir    = sys.argv[2]
log_file    = os.environ.get("NETMAP_LOG_FILE",
                os.path.join(data_dir, "monitor.log"))

sys.path.insert(0, os.path.join(project_dir, "python"))

from netmap_scanner import scan_quick
from netmap_monitor import save_result, load_result, monitor_diff
from netmap_alerts import AlertManager
from netmap_config import config

TS = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg: str) -> None:
    line = f"[{TS()}] {msg}"
    print(line, flush=True)
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass

# ── Load config ───────────────────────────────────────────────────
cfg = config.load()
subnet = cfg.get("default_subnet", "192.168.1.0/24")

log(f"Monitor start — subnet={subnet}")

# ── 1. Quick scan ─────────────────────────────────────────────────
try:
    result = scan_quick(subnet)
    log(f"Scan complete: {len(result.devices)} device(s) on {subnet}")
except Exception as exc:
    log(f"Scan FAILED: {exc}")
    sys.exit(1)

# ── 2. Save current result ────────────────────────────────────────
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
curr_file = os.path.join(data_dir, f"scan_{ts}.json")
try:
    save_result(result, curr_file)
    log(f"Saved → {os.path.basename(curr_file)}")
except OSError as exc:
    log(f"Save FAILED: {exc}")
    sys.exit(1)

# ── 3. Compare with previous ──────────────────────────────────────
json_files = sorted(glob.glob(os.path.join(data_dir, "scan_*.json")))

if len(json_files) >= 2:
    prev_file = json_files[-2]  # second-to-last (just before current)
    try:
        prev_result = load_result(prev_file)
    except Exception as exc:
        log(f"Load previous FAILED ({os.path.basename(prev_file)}): {exc}")
        prev_result = None

    if prev_result is not None:
        diff = monitor_diff(prev_result, result)
        appeared    = diff["appeared"]
        disappeared = diff["disappeared"]
        changed     = diff["changed"]

        has_changes = bool(appeared or disappeared or changed)

        if has_changes:
            log(f"CHANGES: +{len(appeared)} appeared, "
                f"-{len(disappeared)} disappeared, "
                f"~{len(changed)} port-changed")

            # Build alert manager from config
            mgr = AlertManager({
                "telegram_token":     cfg.get("telegram_token", ""),
                "telegram_chat_id":   cfg.get("telegram_chat_id", ""),
                "alert_cooldown_seconds": cfg.get("alert_cooldown", 300),
                "min_importance":     "info",
            })
            try:
                alerts = mgr.check_and_alert(prev_result, result)
                log(f"Alerts sent: {len(alerts)}")
            except Exception as exc:
                log(f"Alert FAILED: {exc}")
        else:
            log("No changes detected")
else:
    log("First scan — no baseline to compare")

# ── 4. Rotate old JSONs (keep last 10) ────────────────────────────
json_files = sorted(glob.glob(os.path.join(data_dir, "scan_*.json")))
removed = 0
while len(json_files) > 10:
    old = json_files.pop(0)
    try:
        os.remove(old)
        removed += 1
    except OSError:
        pass
if removed:
    log(f"Rotated: removed {removed} old scan(s)")

log("Monitor done")
PYEOF
