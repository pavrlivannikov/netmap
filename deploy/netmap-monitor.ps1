<#──────────────────────────────────────────────────────────────────
 NetMap Monitor — Windows PowerShell wrapper
 Invoked by Task Scheduler every 5 minutes.

 Requires: Python 3.10+ with netmap dependencies installed.
           (Or use the compiled netmap.exe from python/dist/)

 Flow:
   1. Quick ARP scan via netmap_scanner.scan_quick()
   2. Save result → data\scan_YYYYMMDD_HHMMSS.json
   3. Compare with previous scan via netmap_monitor.monitor_diff()
   4. If changes detected → alert via netmap_alerts.AlertManager()
   5. Rotate old JSONs (keep last 10)

 ──────────────────────────────────────────────────────────────────#>

param(
    [string]$Subnet = "",
    [string]$DataDir = "",
    [string]$ConfigFile = ""
)

$ErrorActionPreference = "Stop"

# ── Resolve paths ────────────────────────────────────────────────
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$PythonDir  = Join-Path $ProjectDir "python"

if (-not $DataDir) {
    $DataDir = Join-Path $ProjectDir "data"
}
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
}

$LogFile = Join-Path $DataDir "monitor.log"

# ── Helper: timestamped log ──────────────────────────────────────
function Write-Log {
    param([string]$Message)
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $Message
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch {}
}

# ── Find Python ──────────────────────────────────────────────────
$PythonExe = $null
foreach ($candidate in @("python3", "python")) {
    $found = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($found) { $PythonExe = $found.Source; break }
}

if (-not $PythonExe) {
    Write-Log "ERROR: Python not found in PATH"
    exit 1
}

Write-Log "Monitor start (Python: $PythonExe)"

# ── Build inline Python script ───────────────────────────────────
$PyScript = @"
import sys, os, json, glob
from datetime import datetime

project_dir = r'$ProjectDir'
data_dir    = r'$DataDir'
log_file    = r'$LogFile'

sys.path.insert(0, os.path.join(project_dir, 'python'))

from netmap_scanner import scan_quick
from netmap_monitor import save_result, load_result, monitor_diff
from netmap_alerts import AlertManager
from netmap_config import config

def log(msg):
    line = f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] {msg}'
    print(line, flush=True)
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError:
        pass

cfg = config.load()
subnet = cfg.get('default_subnet', '192.168.1.0/24')
log(f'Monitor start — subnet={subnet}')

# 1. Scan
try:
    result = scan_quick(subnet)
    log(f'Scan complete: {len(result.devices)} device(s) on {subnet}')
except Exception as exc:
    log(f'Scan FAILED: {exc}')
    sys.exit(1)

# 2. Save
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
curr_file = os.path.join(data_dir, f'scan_{ts}.json')
try:
    save_result(result, curr_file)
    log(f'Saved -> {os.path.basename(curr_file)}')
except OSError as exc:
    log(f'Save FAILED: {exc}')
    sys.exit(1)

# 3. Compare
json_files = sorted(glob.glob(os.path.join(data_dir, 'scan_*.json')))
if len(json_files) >= 2:
    prev_file = json_files[-2]
    try:
        prev_result = load_result(prev_file)
    except Exception as exc:
        log(f'Load previous FAILED: {exc}')
        prev_result = None

    if prev_result is not None:
        diff = monitor_diff(prev_result, result)
        appeared    = diff['appeared']
        disappeared = diff['disappeared']
        changed     = diff['changed']
        has_changes = bool(appeared or disappeared or changed)

        if has_changes:
            log(f'CHANGES: +{len(appeared)} appeared, -{len(disappeared)} disappeared, ~{len(changed)} port-changed')
            mgr = AlertManager({
                'telegram_token': cfg.get('telegram_token', ''),
                'telegram_chat_id': cfg.get('telegram_chat_id', ''),
                'alert_cooldown_seconds': cfg.get('alert_cooldown', 300),
                'min_importance': 'info',
            })
            try:
                alerts = mgr.check_and_alert(prev_result, result)
                log(f'Alerts sent: {len(alerts)}')
            except Exception as exc:
                log(f'Alert FAILED: {exc}')
        else:
            log('No changes detected')
else:
    log('First scan — no baseline to compare')

# 4. Rotate
json_files = sorted(glob.glob(os.path.join(data_dir, 'scan_*.json')))
removed = 0
while len(json_files) > 10:
    old = json_files.pop(0)
    try:
        os.remove(old)
        removed += 1
    except OSError:
        pass
if removed:
    log(f'Rotated: removed {removed} old scan(s)')

log('Monitor done')
"@

# ── Execute ──────────────────────────────────────────────────────
try {
    $PyScript | & $PythonExe - 2>&1 | ForEach-Object {
        $line = $_.ToString().TrimEnd()
        if ($line) { Write-Host $line }
    }
    Write-Log "Monitor completed successfully"
} catch {
    Write-Log "Monitor FAILED: $_"
    exit 1
}
