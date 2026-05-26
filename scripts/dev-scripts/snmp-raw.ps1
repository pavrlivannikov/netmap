$target = "192.168.97.151"
$oid = "1.3.6.1.2.1.1.5.0"  # sysName
$com = [Text.Encoding]::ASCII.GetBytes("public")
$parts = $oid -split '\.' | % { [int]$_ }
$enc = @()
$enc += 40 * $parts[0] + $parts[1]
for ($i = 2; $i -lt $parts.Length; $i++) {
    $v = $parts[$i]
    if ($v -lt 128) { $enc += $v } else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
}
$body = @(0x02,0x01,0x00); $body += 0x04, $com.Length; $body += $com; $body += 0xA0
$pdu = @(0x02,0x01,0x01, 0x02,0x01,0x00, 0x02,0x01,0x00)
$vbl = @(0x30); $vb = @(0x30); $vb += 0x06, $enc.Length; $vb += $enc; $vb += 0x05, 0x00
$vbl += $vb.Length; $vbl += $vb; $pdu += $vbl; $body += $pdu.Length; $body += $pdu
$pkt = @(0x30); $pkt += $body.Length; $pkt += $body

$u = New-Object Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 2000
$u.Connect($target, 161); $u.Send([byte[]]$pkt, $pkt.Length) | Out-Null
$ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
$r = $u.Receive([ref]$ep); $u.Close()

Write-Host "Response: $($r.Length) bytes"
$hex = ($r | % { $_.ToString("X2") }) -join " "
Write-Host $hex

# Show ASCII parts
Write-Host "`nASCII strings:"
$s = ""
for ($i = 0; $i -lt $r.Length; $i++) {
    if ($r[$i] -ge 32 -and $r[$i] -le 126) { $s += [char]$r[$i] } else { if ($s.Length -gt 1) { Write-Host "  $s" }; $s = "" }
}
if ($s.Length -gt 1) { Write-Host "  $s" }
