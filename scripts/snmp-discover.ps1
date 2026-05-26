$target = "192.168.97.151"
$community = "public"
$timeout = 2000

function snmpget($oid) {
    $com = [Text.Encoding]::ASCII.GetBytes($community)
    
    # Encode OID
    $parts = $oid -split '\.' | % { [int]$_ }
    $enc = @()
    $enc += 40 * $parts[0] + $parts[1]
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $v = $parts[$i]
        if ($v -lt 128) { $enc += $v }
        else { $enc += (($v -shr 7) -bor 0x80); $enc += ($v -band 0x7F) }
    }
    
    # Build packet
    $body = @(0x02,0x01,0x00)  # v1
    $body += 0x04, $com.Length; $body += $com
    $body += 0xA0  # GET
    $pdu = @(0x02,0x01,0x01, 0x02,0x01,0x00, 0x02,0x01,0x00)  # id, err, idx
    $vbl = @(0x30)
    $vb = @(0x30)
    $vb += 0x06, $enc.Length; $vb += $enc
    $vb += 0x05, 0x00
    $vbl += $vb.Length; $vbl += $vb
    $pdu += $vbl
    $body += $pdu.Length; $body += $pdu
    $pkt = @(0x30)
    $pkt += $body.Length; $pkt += $body
    
    $u = New-Object Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = $timeout
    try {
        $u.Connect($target, 161)
        $u.Send([byte[]]$pkt, $pkt.Length) | Out-Null
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$ep)
        $u.Close()
        
        # Extract string
        for ($j = 0; $j -lt $r.Length - 2; $j++) {
            if ($r[$j] -eq 0x04 -and $r[$j+1] -lt 100) {
                $len = $r[$j+1]
                return [Text.Encoding]::ASCII.GetString($r, $j+2, $len).Trim()
            }
        }
    } catch { $u.Close() }
    return $null
}

Write-Host "SNMP DISCOVERY: $target" -ForegroundColor Cyan
Write-Host "=" * 50

$sysName = snmpget "1.3.6.1.2.1.1.5.0"
$sysDescr = snmpget "1.3.6.1.2.1.1.1.0"
$sysLocation = snmpget "1.3.6.1.2.1.1.6.0"

Write-Host "System Name    : $sysName" -ForegroundColor Green
Write-Host "Description    : $sysDescr" -ForegroundColor Green
Write-Host "Location       : $sysLocation" -ForegroundColor Green
Write-Host ""

# Interfaces
Write-Host "INTERFACES:" -ForegroundColor Yellow
for ($i = 1; $i -le 24; $i++) {
    $ifName = snmpget "1.3.6.1.2.1.31.1.1.1.1.$i"
    if ($ifName) {
        $ifAdmin = snmpget "1.3.6.1.2.1.2.2.1.7.$i"
        $ifOper = snmpget "1.3.6.1.2.1.2.2.1.8.$i"
        $status = if ($ifOper -eq '1') { "UP" } else { "DOWN" }
        Write-Host "  $i : $ifName ($status)"
    }
}
Write-Host ""
Write-Host "Done." -ForegroundColor Green
