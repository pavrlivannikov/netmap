$target = "192.168.97.151"

function snmpget($oid) {
    $parts = $oid -split '\.' | % { [int]$_ }
    # Encode OID
    $enc = @(); $enc += 40 * $parts[0] + $parts[1]
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $v = $parts[$i]
        if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    # Build OID field: 0x06 + length + value
    $oidField = @(0x06, $enc.Length) + $enc
    
    # Varbind: SEQUENCE containing OID + NULL
    $vb = @(0x30)
    $vbContent = $oidField + @(0x05, 0x00)
    $vb += $vbContent.Length
    $vb += $vbContent
    
    # VarbindList: SEQUENCE OF varbind
    $vbl = @(0x30)
    $vbl += $vb.Length
    $vbl += $vb
    
    # PDU: GET request (0xA0)
    $pdu = @(0xA0)
    $pduContent = @(0x02,0x01,0x01, 0x02,0x01,0x00, 0x02,0x01,0x00) + $vbl
    $pdu += $pduContent.Length
    $pdu += $pduContent
    
    # Community bytes
    $com = [Text.Encoding]::ASCII.GetBytes("public")
    
    # Whole message body
    $body = @(0x02,0x01,0x00)  # version v1
    $body += 0x04, $com.Length; $body += $com  # community
    $body += $pdu
    
    # SEQUENCE
    $pkt = @(0x30)
    $pkt += $body.Length
    $pkt += $body
    
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 1500
    try {
        $u.Connect($target, 161)
        $u.Send([byte[]]$pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep); $u.Close()
        
        # Find our OID in response and read value after it
        for ($i = 0; $i -lt $r.Length - $enc.Length - 4; $i++) {
            if ($r[$i] -eq 0x06 -and $r[$i+1] -eq $enc.Length) {
                $match = $true
                for ($k = 0; $k -lt $enc.Length; $k++) {
                    if ($r[$i+2+$k] -ne $enc[$k]) { $match = $false; break }
                }
                if ($match) {
                    $pos = $i + 2 + $enc.Length
                    $tag = $r[$pos]; $len = $r[$pos+1]
                    if ($tag -eq 0x04 -and $len -lt 80) {
                        return [Text.Encoding]::ASCII.GetString($r, $pos+2, $len).Trim()
                    }
                    if ($tag -eq 0x02 -and $len -le 4) {
                        $val = 0
                        for ($k = 0; $k -lt $len; $k++) { $val = ($val -shl 8) -bor $r[$pos+2+$k] }
                        return $val
                    }
                    break
                }
            }
        }
    } catch { $u.Close() }
    return $null
}

Write-Host "=== T2600G-52TS @ DESNA3 ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "PORTS:" -ForegroundColor Yellow
$up = 0; $down = 0
for ($i = 1; $i -le 8; $i++) {
    $name = snmpget "1.3.6.1.2.1.2.2.1.2.$i"
    $oper = snmpget "1.3.6.1.2.1.2.2.1.8.$i"
    if ($name) {
        $st = if ($oper -eq 1) { $up++; "UP" } else { $down++; "DOWN" }
        Write-Host "  $i [$st] $name"
    }
}
Write-Host ""
Write-Host "UP: $up DOWN: $down Total: $($up+$down)" -ForegroundColor Green
