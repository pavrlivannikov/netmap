$target = "192.168.97.151"

function snmp-oid($oid_parts) {
    # Build SNMP v1 GET packet for given OID
    $enc = @()
    $enc += 40 * $oid_parts[0] + $oid_parts[1]
    for ($i = 2; $i -lt $oid_parts.Length; $i++) {
        $v = $oid_parts[$i]
        if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    $oid_hex = [byte[]](0x06, $enc.Length) + [byte[]]$enc
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C) + $oid_hex + [byte[]](0x05,0x00)
    
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
    try {
        $u.Connect($target, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep); $u.Close()
        
        # Extract last OCTET STRING for simple values, or INTEGER
        # First try integer (0x02)
        for ($j = $r.Length - 1; $j -ge 2; $j--) {
            if ($r[$j] -eq 0x02 -and $r[$j+1] -le 4) {
                $len = $r[$j+1]
                $val = 0
                for ($k = 0; $k -lt $len; $k++) { $val = ($val -shl 8) -bor $r[$j+2+$k] }
                $u.Close()
                return $val
            }
            if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 80) {
                $len = $r[$j+1]
                $str = [Text.Encoding]::ASCII.GetString($r, $j+2, $len).Trim()
                if ($str.Length -gt 0) { return $str }
            }
        }
    } catch { $u.Close() }
    return $null
}

# Quick approach: use the known OID structure to get MAC table
Write-Host "T2600G-52TS — MAC Table Discovery" -ForegroundColor Cyan
Write-Host "===================================="
Write-Host ""

# Get interface list first
Write-Host "PORTS:" -ForegroundColor Yellow
$ports = @()
for ($i = 1; $i -le 28; $i++) {
    $name = snmp-oid @(1,3,6,1,2,1,31,1,1,1,1,$i)
    $oper = snmp-oid @(1,3,6,1,2,1,2,2,1,8,$i)
    if ($name) {
        $ports += $i
        $st = if ($oper -eq 1) { "UP" } else { "DOWN" }
        Write-Host "  Port $i $st : $name"
    }
}

# MAC table via dot1dTpFdbTable (1.3.6.1.2.1.17.4.3.1)
# Format: dot1dTpFdbAddress.{mac} = OID with MAC encoded as decimal
# dot1dTpFdbPort.{mac} = port number 
Write-Host ""
Write-Host "MAC TABLE (dot1dTpFdbPort):" -ForegroundColor Yellow

# Quick scan of MAC table using SNMP GETNEXT
# Start at 1.3.6.1.2.1.17.4.3.1.2
# Actually dot1dTpFdbPort is: 1.3.6.1.2.1.17.4.3.1.2.{vlan}.{mac}
# For simple L2: vlan=0 or vlan=1

# Simpler: use dot1dTpFdbAddress (1.3.6.1.2.1.17.4.3.1.1) to walk
# But walking requires GETNEXT, let's do a quick scan

$macCount = 0
# Scan first 200 entries in dot1dTpFdbPort
for ($e = 1; $e -le 200; $e++) {
    # dot1dTpFdbPort entry
    $port = snmp-oid @(1,3,6,1,2,1,17,4,3,1,2,$e)
    if ($port -and [int]$port -gt 0) {
        # Get the MAC for this entry
        $mac_oid = @(1,3,6,1,2,1,17,4,3,1,1,$e)
        $macHex = snmp-oid $mac_oid
        if ($macHex -and $macHex.Length -ge 6) {
            $mac = ""
            for ($k = 0; $k -lt 6; $k++) { $mac += ([int][char]$macHex[$k]).ToString("X2") + ":" }
            $mac = $mac.TrimEnd(':')
            Write-Host "  MAC $mac -> Port $port"
            $macCount++
        }
    }
}
if ($macCount -eq 0) { 
    Write-Host "  SNMP walking not working. Need GETNEXT." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done: $macCount MAC entries" -ForegroundColor Green
