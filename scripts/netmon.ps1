$ErrorActionPreference = "SilentlyContinue"
$stateFile = "$env:USERPROFILE\Desktop\netmon-state.json"
$logFile = "$env:USERPROFILE\Desktop\netmon-log.txt"
$start = Get-Date

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $msg" | Out-File $logFile -Append
    Write-Output "$ts $msg"
}

Write-Output "NetMap Monitor v1.0"
Write-Output "===================="
Write-Log "=== Scan started ==="

$current = @{}
arp -a 2>$null | ForEach-Object {
    if ($_ -match '(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-f]{2}-){5}[0-9a-f]{2})') {
        $ip = $matches[1]; $mac = ($matches[2]).ToUpper()
        if ($ip -notmatch '^(224|239|255)\.' -and $mac -ne 'FF-FF-FF-FF-FF-FF') {
            $current[$ip] = $mac
        }
    }
}
$cnt = $current.Count
Write-Log "Current: $cnt devices in ARP"

$previous = @{}
if (Test-Path $stateFile) {
    $raw = Get-Content $stateFile -Raw
    $prev = $raw | ConvertFrom-Json
    foreach ($p in $prev.PSObject.Properties) { $previous[$p.Name] = $p.Value }
    Write-Log "Previous: $($previous.Count) devices"
} else {
    Write-Log "No previous state - first run"
}

$newDevices = @{}; $lostDevices = @{}; $changedDevices = @{}
$sameCount = 0

foreach ($ip in $current.Keys) {
    if (-not $previous.ContainsKey($ip)) {
        $newDevices[$ip] = $current[$ip]
    } elseif ($previous[$ip] -ne $current[$ip]) {
        $changedDevices[$ip] = @{ old=$previous[$ip]; new=$current[$ip] }
    } else { $sameCount++ }
}
foreach ($ip in $previous.Keys) {
    if (-not $current.ContainsKey($ip)) {
        $lostDevices[$ip] = $previous[$ip]
    }
}

Write-Output ""
$ts = Get-Date -Format "HH:mm:ss"
Write-Output "=== SCAN: $ts ==="
Write-Output "Devices: $($current.Count) (was: $($previous.Count))"
Write-Output "  Same:    $sameCount"
Write-Output "  NEW:     $($newDevices.Count)"
Write-Output "  LOST:    $($lostDevices.Count)"
Write-Output "  CHANGED: $($changedDevices.Count)"

if ($newDevices.Count -gt 0) {
    Write-Output ""
    Write-Output "=== NEW ==="
    foreach ($ip in ($newDevices.Keys | Sort-Object)) {
        Write-Output "  + $ip  $($newDevices[$ip])"
        Write-Log "NEW: $ip $($newDevices[$ip])"
    }
}
if ($lostDevices.Count -gt 0) {
    Write-Output ""
    Write-Output "=== LOST ==="
    foreach ($ip in ($lostDevices.Keys | Sort-Object)) {
        Write-Output "  - $ip  $($lostDevices[$ip])"
        Write-Log "LOST: $ip $($lostDevices[$ip])"
    }
}

# Save state
$state = @{}
foreach ($ip in $current.Keys) { $state[$ip] = $current[$ip] }
$state | ConvertTo-Json | Out-File $stateFile -Encoding UTF8

$elapsed = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Output ""
Write-Output "State saved. Scan time: ${elapsed}s"
Write-Log "=== Done (${elapsed}s): $($current.Count) devices ==="

@{
    total = $current.Count
    new = $newDevices.Count
    lost = $lostDevices.Count
} | ConvertTo-Json
