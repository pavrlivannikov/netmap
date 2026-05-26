# NetMap Auto-Scan — сам определяет маску и сеть, сканирует все IP
$ErrorActionPreference = "SilentlyContinue"
$start = Get-Date

# Автоопределение сети
$net = Get-NetIPConfiguration -Detailed | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
if (-not $net) { Write-Output "ERROR: No active network"; exit 1 }
$myIp = $net.IPv4Address.IPAddress
$prefix = $net.IPv4Address.PrefixLength
$gw = $net.IPv4DefaultGateway.NextHop
$Subnet = "$myIp/$prefix"

Write-Output "NetMap Auto-Scan"
Write-Output "================"
Write-Output "Network: $Subnet"
Write-Output "Gateway: $gw"
Write-Output "Started: $(Get-Date -Format 'HH:mm:ss')"
Write-Output ""

# [1] ARP
Write-Output "[1] ARP table..."
$devices = [ordered]@{}
arp -a 2>$null | ForEach-Object {
    if ($_ -match '(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-f]{2}-){5}[0-9a-f]{2})') {
        $ip = $matches[1]; $mac = ($matches[2]).ToUpper()
        if ($ip -notmatch '^(224|239|255)\.' -and $mac -ne 'FF-FF-FF-FF-FF-FF') {
            $devices[$ip] = @{ mac=$mac; ports=@(); type='workstation'; snmp=$false; name='' }
        }
    }
}
Write-Output "  $($devices.Count) devices in ARP"

# [2] Port + SNMP scan
$ports = @(22,80,443,8080,3389,5900,161,53)
Write-Output "[2] Port scan..."
$n = 0; $withPorts = 0

foreach ($ip in $devices.Keys) {
    $n++
    $open = @()
    foreach ($p in $ports) {
        $r = Test-NetConnection $ip -Port $p -InformationLevel Quiet -WarningAction 0 2>$null
        if ($r) { $open += $p; if ($p -eq 161) { $devices[$ip].snmp = $true } }
    }
    $devices[$ip].ports = $open
    if ($open.Count -gt 0) {
        $withPorts++
        if ($devices[$ip].snmp) { $devices[$ip].type = 'network' }
        elseif ($open -contains 22 -or $open -contains 3389) { $devices[$ip].type = 'server' }
        elseif ($open -contains 80 -or $open -contains 443) { $devices[$ip].type = 'server' }
    }
    if ($n % 20 -eq 0) {
        Write-Output "  $n/$($devices.Count) scanned, $withPorts open ports, $(($devices.Values|? snmp).Count) SNMP"
    }
}

# [3] SNMP names
$snmpList = @($devices.Keys | Where-Object { $devices[$_].snmp })
if ($snmpList.Count -gt 0) {
    Write-Output "[3] SNMP names ($($snmpList.Count) devices)..."
    foreach ($ip in $snmpList) {
        $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00,0x05,0x00)
        $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
        try {
            $u.Connect($ip, 161); $u.Send($pkt, $pkt.Length) | Out-Null
            $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
            $r = $u.Receive([ref]$ep)
            for ($j = $r.Length-1; $j -ge 2; $j--) {
                if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 80) {
                    $len = $r[$j+1]
                    $devices[$ip].name = [Text.Encoding]::ASCII.GetString($r, $j+2, $len).Trim()
                    break
                }
            }
        } catch { }
        $u.Close()
        if ($devices[$ip].name) { Write-Output "  $ip = $($devices[$ip].name)" }
    }
}

# Summary
$t = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Output ""
Write-Output "=== RESULTS (${t}s) ==="
Write-Output "Network:  $Subnet (GW: $gw)"
Write-Output "Devices:  $($devices.Count)"
Write-Output "Ports:    $withPorts"
Write-Output "SNMP:     $($snmpList.Count)"
Write-Output ""

Write-Output "=== ALL DEVICES WITH PORTS ==="
foreach ($ip in $devices.Keys) {
    $d = $devices[$ip]
    if ($d.ports.Count -gt 0) {
        $icon = switch ($d.type) { 'network' { 'SW' } 'server' { 'SRV' } default { 'PC' } }
        $sn = if ($d.name) { " [$($d.name)]" } else { "" }
        Write-Output ("  $icon $ip  $($d.mac)  $($d.ports -join ",")$sn")
    }
}

# JSON
@{
    network=$Subnet; gateway=$gw; devices=$devices.Count; with_ports=$withPorts; snmp=$snmpList.Count;
    list=@($devices.Keys | ForEach-Object { @{ip=$_; mac=$devices[$_].mac; type=$devices[$_].type; ports=$devices[$_].ports; snmp=$devices[$_].snmp; name=$devices[$_].name} })
} | ConvertTo-Json -Depth 3 | Out-File "$env:USERPROFILE\Desktop\netmap.json" -Encoding UTF8

Write-Output ""
Write-Output "Saved: netmap.json"
Write-Output "Done."
