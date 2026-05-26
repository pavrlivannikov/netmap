$target = "192.168.97.151"

function sget($oid) {
    $p = $oid -split '\.' | % { [int]$_ }
    $enc = @(); $enc += 40 * $p[0] + $p[1]
    for ($i = 2; $i -lt $p.Length; $i++) {
        $v = $p[$i]
        if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    $oh = [byte[]](0x06, $enc.Length) + [byte[]]$enc
    $pkt = [byte[]](0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C) + $oh + [byte[]](0x05,0x00)
    $u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
    try {
        $u.Connect($target, 161); $u.Send($pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0); $r = $u.Receive([ref]$ep); $u.Close()
        for ($j = $r.Length - 1; $j -ge 2; $j--) {
            if ($r[$j] -eq 0x02 -and $r[$j+1] -le 4) { $len=$r[$j+1];$v=0;for($k=0;$k -lt $len;$k++){$v=($v -shl 8) -bor $r[$j+2+$k]};return $v }
            if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 80) { $len=$r[$j+1];return [Text.Encoding]::ASCII.GetString($r,$j+2,$len).Trim() }
        }
    } catch { $u.Close() }
    return $null
}

Write-Host "=== T2600G-52TS ===" -ForegroundColor Cyan
Write-Host "Name: $(sget '1.3.6.1.2.1.1.5.0')" -ForegroundColor Green
Write-Host "Location: $(sget '1.3.6.1.2.1.1.6.0')" -ForegroundColor Green
Write-Host ""

# First 12 ports only - faster
Write-Host "PORTS (first 12):" -ForegroundColor Yellow
for ($i = 1; $i -le 12; $i++) {
    $n = sget "1.3.6.1.2.1.31.1.1.1.1.$i"
    if ($n) { Write-Host "  $i : $n" }
}
Write-Host ""
Write-Host "Done." -ForegroundColor Green
