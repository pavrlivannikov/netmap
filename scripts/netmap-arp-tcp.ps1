$ErrorActionPreference = "SilentlyContinue"
$start = Get-Date

Write-Output "NetMap: ARP + TCP + SNMP"
Write-Output "========================"
Write-Output "Started: $(Get-Date -Format 'HH:mm:ss')"

# 1. ARP — мгновенно
Write-Output "[1] ARP..."
$devices = [ordered]@{}
arp -a 2>$null | ForEach-Object {
    if ($_ -match '(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-f]{2}-){5}[0-9a-f]{2})') {
        $ip = $matches[1]; $mac = ($matches[2]).ToUpper()
        if ($ip -notmatch '^(224|239|255)\.' -and $mac -ne 'FF-FF-FF-FF-FF-FF') {
            $devices[$ip] = @{ mac=$mac; tcp=$false; snmp=$false; name=''; type='workstation' }
        }
    }
}
Write-Output "  $($devices.Count) devices in ARP"

# 2. TCP-ping (port 80) + SNMP — параллельно
Write-Output "[2] TCP-ping + SNMP ($($devices.Count) hosts)..."
$n = 0; $tcpAlive = 0; $snmpFound = 0

foreach ($ip in $devices.Keys) {
    $n++
    
    # TCP-ping port 80
    $tcp = Test-NetConnection $ip -Port 80 -InformationLevel Quiet -WarningAction 0 2>$null
    if ($tcp) { $devices[$ip].tcp = $true; $tcpAlive++ }
    
    # SNMP
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x05,0x00,0x05,0x00)
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 1500
    $name = ""
    try {
        $u.Connect($ip, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep)
        for ($j = $r.Length-1; $j -ge 2; $j--) {
            if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 80) {
                $len = $r[$j+1]
                $name = [Text.Encoding]::ASCII.GetString($r, $j+2, $len).Trim()
                break
            }
        }
    } catch { }
    $u.Close()
    if ($name) { 
        $devices[$ip].snmp = $true; $devices[$ip].name = $name; $snmpFound++
        Write-Output "  SNMP $ip = $name"
    }
    
    if ($n % 15 -eq 0) {
        $elapsed = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
        Write-Output "  $n/$($devices.Count) done (${elapsed}s): TCP=$tcpAlive SNMP=$snmpFound"
    }
}

# Results
$t = [Math]::Round(((Get-Date) - $start).TotalSeconds, 0)
Write-Output ""
Write-Output "=== RESULTS (${t}s) ==="
Write-Output "ARP devices: $($devices.Count)"
Write-Output "TCP alive:  $tcpAlive"
Write-Output "SNMP found: $snmpFound"
Write-Output ""

if ($snmpFound -gt 0) {
    Write-Output "=== SNMP DEVICES ==="
    foreach ($ip in $devices.Keys) { if ($devices[$ip].snmp) { Write-Output "  $ip = $($devices[$ip].name)" } }
    Write-Output ""
}

Write-Output "=== ALL ARP DEVICES ==="
$devices.Keys | ForEach-Object {
    $d = $devices[$_]
    $flags = ""
    if ($d.tcp) { $flags += "TCP " }
    if ($d.snmp) { $flags += "SNMP" }
    Write-Output ("  {0,-16}  {1,-17}  {2}" -f $_, $d.mac, $flags)
}

# JSON
@{
    arp=$devices.Count; tcp_alive=$tcpAlive; snmp=$snmpFound; time=$t
    list=@($devices.Keys | ForEach-Object { @{ip=$_; mac=$devices[$_].mac; tcp=$devices[$_].tcp; snmp=$devices[$_].snmp; name=$devices[$_].name} })
} | ConvertTo-Json -Depth 3 | Out-File "$env:USERPROFILE\Desktop\netmap.json" -Encoding UTF8

Write-Output ""
Write-Output "JSON: netmap.json"
Write-Output "Done."
