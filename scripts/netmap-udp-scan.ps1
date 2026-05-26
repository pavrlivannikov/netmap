# NetMap UDP Scanner — параллельный опрос портов 161(SNMP),53(DNS),137(NetBIOS)
# Слать по N запросов, мгновенно добавлять ответивших
param($MaxParallel = 3, $Ports = @(161,53,137), $TimeoutMs = 500)

$ErrorActionPreference = "SilentlyContinue"
$start = Get-Date

# Auto-detect network
$ip = ""; $mask = ""
ipconfig 2>$null | ForEach-Object {
    if ($_ -match 'IPv4|IP-' -and $_ -match '(\d+\.\d+\.\d+\.\d+)\s*$') { $ip = $matches[1] }
    if ($_ -match 'Subnet|Mask|Маска' -and $_ -match '(\d+\.\d+\.\d+\.\d+)\s*$') { $mask = $matches[1] }
}
$maskParts = $mask -split '\.' | % { [int]$_ }
$bits = 0; foreach ($p in $maskParts) { $bits += [Convert]::ToString($p, 2).Replace('0','').Length }
$ipParts = $ip -split '\.' | % { [int]$_ }
$netBytes = @(); for ($i=0;$i -lt 4;$i++) { $netBytes += $ipParts[$i] -band $maskParts[$i] }
$baseNum = $netBytes[0]*16777216 + $netBytes[1]*65536 + $netBytes[2]*256 + $netBytes[3]
$total = [Math]::Pow(2, 32 - $bits) - 2

Write-Output "NetMap UDP Scanner"
Write-Output "Network: $($netBytes -join '.')/$bits ($total IPs)"
Write-Output "Ports: $($Ports -join ',') | Parallel: $MaxParallel | Timeout: ${TimeoutMs}ms"
Write-Output "Started: $(Get-Date -Format 'HH:mm:ss')"
Write-Output ""

# UDP probe function
function Test-UDP($ip, $port, $timeout) {
    try {
        $u = New-Object Net.Sockets.UdpClient
        $u.Client.ReceiveTimeout = $timeout
        $u.Connect($ip, $port)
        $pkt = if ($port -eq 161) { [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00) }
              elseif ($port -eq 53) { [byte[]](0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x76,0x65,0x72,0x73,0x69,0x6f,0x6e,0x04,0x62,0x69,0x6e,0x64,0x00,0x00,0x10,0x00,0x03) }
              else { [byte[]](0x00) }
        $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep)
        $u.Close()
        return $true
    } catch { try { $u.Close() } catch {} }
    return $false
}

# Generate IP list
$ipList = @()
for ($i = 1; $i -le $total; $i++) {
    $val = $baseNum + $i
    $ipList += "$([Math]::Floor($val/16777216)%256).$([Math]::Floor($val/65536)%256).$([Math]::Floor($val/256)%256).$($val%256)"
}

Write-Output "[1/2] UDP sweep ($($ipList.Count) IPs)..."
$found = @{}
$scanned = 0

# Parallel processing using .NET ThreadPool
$runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallel)
$runspacePool.Open()
$jobs = @()

$scriptBlock = {
    param($ip, $ports, $timeout)
    $result = @{ ip=$ip; ports=@() }
    foreach ($p in $ports) {
        try {
            $u = New-Object Net.Sockets.UdpClient
            $u.Client.ReceiveTimeout = $timeout
            $u.Connect($ip, $p)
            $pkt = if ($p -eq 161) { [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00) }
                  elseif ($p -eq 53) { [byte[]](0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x76,0x65,0x72,0x73,0x69,0x6f,0x6e,0x04,0x62,0x69,0x6e,0x64,0x00,0x00,0x10,0x00,0x03) }
                  else { [byte[]](0x00) }
            $u.Send($pkt, $pkt.Length) | Out-Null
            $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $r = $u.Receive([ref]$ep)
            $result.ports += $p
        } catch {}
        try { $u.Close() } catch {}
    }
    return $result
}

$batchNum = 0
for ($i = 0; $i -lt $ipList.Count; $i += $MaxParallel) {
    $batchNum++
    $batchEnd = [Math]::Min($i + $MaxParallel - 1, $ipList.Count - 1)
    
    # Submit batch
    $psJobs = @()
    for ($j = $i; $j -le $batchEnd; $j++) {
        $ps = [PowerShell]::Create().AddScript($scriptBlock)
        $ps.AddArgument($ipList[$j]) | Out-Null
        $ps.AddArgument($Ports) | Out-Null
        $ps.AddArgument($TimeoutMs) | Out-Null
        $ps.RunspacePool = $runspacePool
        $psJobs += @{ ps=$ps; handle=$ps.BeginInvoke() }
    }
    
    # Collect results as they complete
    foreach ($job in $psJobs) {
        $result = $job.ps.EndInvoke($job.handle)
        $job.ps.Dispose()
        if ($result.ports.Count -gt 0) {
            $found[$result.ip] = $result.ports
        }
        $scanned++
    }
    
    if ($batchNum % 100 -eq 0) {
        $elapsed = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
        Write-Output "  $scanned/$total scanned, $($found.Count) found (${elapsed}s)"
    }
}

$runspacePool.Close()
$runspacePool.Dispose()

$scanTime = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Output "  Done: $($found.Count) hosts with open UDP ports (${scanTime}s)"

# [2] SNMP names for SNMP hosts
$snmpHosts = $found.Keys | Where-Object { $found[$_] -contains 161 }
Write-Output ""
Write-Output "[2/2] SNMP names ($($snmpHosts.Count) hosts)..."

foreach ($sip in $snmpHosts) {
    # GET sysName
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00,0x05,0x00)
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
    $name = ""
    try {
        $u.Connect($sip, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep)
        for ($j = $r.Length-1; $j -ge 2; $j--) {
            if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 80) {
                $len = $r[$j+1]
                $name = [Text.Encoding]::ASCII.GetString($r, $j+2, $len).Trim()
                break
            }
        }
    } catch {}
    $u.Close()
    if ($name) { Write-Output "  $sip = $name" }
    
    # Also GET sysDescr
    $pkt2 = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00)
    $u2 = New-Object Net.Sockets.UdpClient; $u2.Client.ReceiveTimeout = 2000
    try {
        $u2.Connect($sip, 161); $u2.Send($pkt2, $pkt2.Length) | Out-Null
        $ep2 = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r2 = $u2.Receive([ref]$ep2)
        for ($j = $r2.Length-1; $j -ge 2; $j--) {
            if ($r2[$j] -eq 0x04 -and $r2[$j+1] -lt 100) {
                $len = $r2[$j+1]
                $descr = [Text.Encoding]::ASCII.GetString($r2, $j+2, $len).Trim()
                if ($descr.Length -gt 2) { Write-Output "         $descr" }
                break
            }
        }
    } catch {}
    $u2.Close()
}

# Summary
$t = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Output ""
Write-Output "=== RESULTS (${t}s) ==="
Write-Output "Scanned: $total IPs"
Write-Output "UDP alive: $($found.Count)"
Write-Output "SNMP: $($snmpHosts.Count)"
Write-Output "DNS: $(($found.Keys | Where-Object { $found[$_] -contains 53 }).Count)"

# JSON output
@{
    network="$($netBytes -join '.')/$bits"; total=$total; udp_alive=$found.Count
    snmp=$snmpHosts.Count; time=$t
    hosts=@($found.Keys | ForEach-Object { @{ip=$_; ports=$found[$_]} })
} | ConvertTo-Json -Depth 3 | Out-File "$env:USERPROFILE\Desktop\netmap-udp.json" -Encoding UTF8

Write-Output "`nSaved: netmap-udp.json"
Write-Output "Done."
