$target = "192.168.97.151"

function snmp-get($oid_hex) {
    # Pre-built SNMP v1 GET with public community, with variable OID
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C) + $oid_hex + [byte[]](0x05,0x00)
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
    try {
        $u.Connect($target, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep); $u.Close()
        # Extract last OCTET STRING
        for ($j = $r.Length - 1; $j -ge 2; $j--) {
            if ($r[$j] -eq 0x04) { $len = $r[$j+1]; if ($len -gt 0 -and $len -lt 100) { 
                $str = [Text.Encoding]::ASCII.GetString($r, $j+2, $len).TrimEnd([char]0).Trim()
                if ($str.Length -gt 0) { return $str }
            }}
        }
    } catch { $u.Close() }
    return $null
}

function oid2hex($oid) {
    $parts = $oid -split '\.' | % { [int]$_ }
    $enc = @()
    $enc += 40 * $parts[0] + $parts[1]
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $v = $parts[$i]
        if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    return [byte[]](0x06, $enc.Length) + [byte[]]$enc
}

Write-Host "=== $target ===" -ForegroundColor Cyan

$sysName = snmp-get (oid2hex "1.3.6.1.2.1.1.5.0")
$sysDescr = snmp-get (oid2hex "1.3.6.1.2.1.1.1.0")
$sysLoc = snmp-get (oid2hex "1.3.6.1.2.1.1.6.0")

Write-Host "Name:     $sysName" -ForegroundColor Green
Write-Host "Descr:    $sysDescr" -ForegroundColor Green
Write-Host "Location: $sysLoc" -ForegroundColor Green
Write-Host ""

# Ports (first 12)
Write-Host "=== PORTS ===" -ForegroundColor Yellow
for ($i = 1; $i -le 12; $i++) {
    $name = snmp-get (oid2hex "1.3.6.1.2.1.31.1.1.1.1.$i")
    $oper = snmp-get (oid2hex "1.3.6.1.2.1.2.2.1.8.$i")
    if ($name) {
        $st = if ($oper -eq '1') { "[UP]" } else { "[DOWN]" }
        Write-Host "  Port $i $st : $name"
    }
}

Write-Host "`nDone." -ForegroundColor Green
