# NetMap Full Network Scan v1.0
# Сканирует всю подсеть /21: ping + порты + SNMP
# Сохраняет результат в JSON

param($Subnet = "192.168.96.0/21")

$parts = $Subnet -split '/'
$base = $parts[0]
$prefix = [int]$parts[1]
$total = [Math]::Pow(2, 32 - $prefix) - 2  # minus network & broadcast

Write-Host "NetMap Full Scan" -ForegroundColor Cyan
Write-Host "Subnet: $Subnet ($total hosts)" -ForegroundColor Yellow
Write-Host ""

# Gen IPs
$baseBytes = ([Net.IPAddress]$base).GetAddressBytes()
[Array]::Reverse($baseBytes)
$baseNum = [BitConverter]::ToUInt32($baseBytes, 0)
$mask = if ($prefix -eq 0) { 0 } else { [UInt32]::MaxValue -shl (32 - $prefix) }
$network = $baseNum -band $mask

Write-Host "[1/3] ICMP sweep ($total hosts)..." -ForegroundColor Yellow
$alive = @()
$start = Get-Date

# Scan in batches of 64 parallel pings
$batchSize = 64
for ($n = 1; $n -le $total; $n += $batchSize) {
    $batchEnd = [Math]::Min($n + $batchSize - 1, $total)
    $jobs = @()
    
    for ($i = $n; $i -le $batchEnd; $i++) {
        $ipNum = $network + $i
        $ipBytes = [BitConverter]::GetBytes($ipNum)
        [Array]::Reverse($ipBytes)
        $ip = [Net.IPAddress]::new($ipBytes).ToString()
        
        $jobs += Test-Connection $ip -Count 1 -Quiet -AsJob -ErrorAction SilentlyContinue
    }
    
    # Wait for batch
    $jobs | Wait-Job | Out-Null
    $results = $jobs | Receive-Job
    $jobs | Remove-Job -Force
    
    for ($i = $n; $i -le $batchEnd; $i++) {
        if ($results[$i - $n] -eq $true) {
            $ipNum = $network + $i
            $ipBytes = [BitConverter]::GetBytes($ipNum)
            [Array]::Reverse($ipBytes)
            $alive += [Net.IPAddress]::new($ipBytes).ToString()
        }
    }
    
    $pct = [Math]::Round($n * 100 / $total, 1)
    $elapsed = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
    Write-Progress -Activity "ICMP Sweep" -Status "$($alive.Count) alive / $n scanned" -PercentComplete $pct
}
Write-Progress -Activity "ICMP Sweep" -Completed

$icmpTime = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Host "  Found $($alive.Count) alive hosts in ${icmpTime}s" -ForegroundColor Green

# [2/3] Port scan on alive hosts
Write-Host ""
Write-Host "[2/3] Port scan ($($alive.Count) hosts)..." -ForegroundColor Yellow
$commonPorts = @(22, 80, 443, 8080, 3389, 5900, 9100, 554, 161, 53, 25, 110)
$devices = @()
$n = 0

foreach ($ip in $alive) {
    $n++
    $ports = @()
    foreach ($p in $commonPorts) {
        $r = Test-NetConnection $ip -Port $p -WarningAction 0 -InformationLevel Quiet
        if ($r) { $ports += $p }
    }
    
    # SNMP probe
    $hasSnmp = $false
    if ($ports -contains 161) {
        $snmpUdp = New-Object Net.Sockets.UdpClient
        $snmpUdp.Client.ReceiveTimeout = 500
        try {
            $snmpPkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00)
            $snmpUdp.Connect($ip, 161)
            $snmpUdp.Send($snmpPkt, $snmpPkt.Length) | Out-Null
            $epr = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $snmpUdp.Receive([ref]$epr) | Out-Null
            $hasSnmp = $true
        } catch { }
        $snmpUdp.Close()
    }
    
    $type = "workstation"
    if ($ports -contains 22 -or $ports -contains 3389) { $type = "server" }
    if ($ports -contains 80 -or $ports -contains 443 -or $ports -contains 8080) { $type = "server" }
    if ($hasSnmp) { $type = "switch/router" }
    
    $devices += @{ ip=$ip; ports=$ports; type=$type; snmp=$hasSnmp }
    
    $pct = [Math]::Round($n * 100 / $alive.Count, 1)
    Write-Progress -Activity "Port scan" -Status "$ip : $($ports.Count) ports" -PercentComplete $pct
}
Write-Progress -Activity "Port scan" -Completed

# [3/3] Summary
Write-Host ""
Write-Host "[3/3] Result:" -ForegroundColor Cyan
$types = ($devices | Group-Object type | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
Write-Host "  Total alive:  $($alive.Count)" -ForegroundColor Green
Write-Host "  Types: $types" -ForegroundColor Green

$snmpCount = ($devices | Where-Object snmp).Count
Write-Host "  SNMP devices: $snmpCount" -ForegroundColor $(if($snmpCount -gt 0){'Green'}else{'Yellow'})
Write-Host ""

# Show interesting devices
Write-Host "=== INTERESTING ===" -ForegroundColor Yellow
$devices | Where-Object { $_.ports.Count -gt 0 -or $_.snmp } | ForEach-Object {
    $portsStr = $_.ports -join ","
    $snmpMark = if ($_.snmp) { " [SNMP]" } else { "" }
    Write-Host ("  {0,-18} {1,-10} ports:[ {2} ]{3}" -f $_.ip, $_.type, $portsStr, $snmpMark)
}

# Save JSON
$json = @{
    subnet = $Subnet
    scanned = $total
    alive = $alive.Count
    scan_time = (Get-Date).ToString("o")
    devices = $devices
} | ConvertTo-Json -Depth 4

$jsonFile = "$env:USERPROFILE\Desktop\netmap-scan.json"
$json | Out-File $jsonFile -Encoding UTF8
Write-Host "`nSaved: $jsonFile" -ForegroundColor Green
Write-Host "Done!" -ForegroundColor Green
