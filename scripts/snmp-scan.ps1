$ips = @("192.168.99.254", "192.168.99.250", "192.168.103.202", "192.168.99.4", 
  "192.168.101.214", "192.168.100.43", "192.168.96.18", "192.168.97.93",
  "192.168.98.110", "192.168.103.150", "192.168.101.160", "192.168.100.20")

$snmpGet = [byte[]]@(0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x05,0x00,0x05,0x00)

foreach ($ip in $ips) {
  $udp = New-Object Net.Sockets.UdpClient
  $udp.Client.ReceiveTimeout = 500
  try {
    $udp.Connect($ip, 161)
    $udp.Send($snmpGet, $snmpGet.Length) | Out-Null
    $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
    $recv = $udp.Receive([ref]$ep)
    $udp.Close()
    Write-Host "SNMP $ip : RESPONDS" -ForegroundColor Green
  } catch {
    $udp.Close()
    Write-Host "$ip : no SNMP"
  }
}
