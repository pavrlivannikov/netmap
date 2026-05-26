$target = "192.168.97.151"

function sget($oid) {
    $p = $oid -split '\.' | % { [int]$_ }
    $enc = @(); $enc += 40 * $p[0] + $p[1]
    for ($i = 2; $i -lt $p.Length; $i++) {
        $v = $p[$i]
        if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    $olen = $enc.Length
    $oh = [byte[]](0x06, $olen) + [byte[]]$enc
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C) + $oh + [byte[]](0x05,0x00)
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 1500
    try {
        $u.Connect($target, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $r = $u.Receive([ref]$ep); $u.Close()
        
        # Find OID (0x06) position first, then find value after it
        $oidPos = -1
        for ($i = 0; $i -lt $r.Length - $olen - 2; $i++) {
            if ($r[$i] -eq 0x06 -and $r[$i+1] -eq $olen) {
                $match = $true
                for ($k = 0; $k -lt $olen; $k++) {
                    if ($r[$i+2+$k] -ne $enc[$k]) { $match = $false; break }
                }
                if ($match) { $oidPos = $i + 2 + $olen; break }
            }
        }
        
        if ($oidPos -gt 0 -and $oidPos + 1 -lt $r.Length) {
            $tag = $r[$oidPos]
            $len = $r[$oidPos + 1]
            if ($tag -eq 0x04 -and $len -lt 80) {
                return [Text.Encoding]::ASCII.GetString($r, $oidPos + 2, $len).Trim()
            }
            if ($tag -eq 0x02 -and $len -le 4) {
                $val = 0
                for ($k = 0; $k -lt $len; $k++) { $val = ($val -shl 8) -bor $r[$oidPos + 2 + $k] }
                return $val
            }
        }
    } catch { $u.Close() }
    return $null
}

Write-Host "=== T2600G-52TS @ DESNA3 ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "PORTS:" -ForegroundColor Yellow
$up = 0; $down = 0
for ($i = 1; $i -le 10; $i++) {
    $name = sget "1.3.6.1.2.1.2.2.1.2.$i"
    $oper = sget "1.3.6.1.2.1.2.2.1.8.$i"
    if ($name) {
        $st = if ($oper -eq 1) { $up++; "UP" } else { $down++; "DOWN" }
        Write-Host "  Port $i [$st] : $name"
    }
}
Write-Host ""
Write-Host "UP: $up  DOWN: $down  Total: $($up+$down)" -ForegroundColor Green
