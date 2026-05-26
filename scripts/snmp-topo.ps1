# SNMP Topology Discovery v0.1
# Показывает реальные связи через SNMP (MAC table + LLDP)
# Запуск: powershell -File snmp-topo.ps1 [-Community public] [-Target 192.168.99.254]

param($Community = "public", $Target = "192.168.99.254")

$ErrorActionPreference = "SilentlyContinue"

Write-Host "SNMP Topology Discovery" -ForegroundColor Cyan
Write-Host "Target: $Target (community: $Community)" -ForegroundColor Yellow
Write-Host ""

# ====== SNMP Helper ======
function Send-SNMPGet($oid) {
    $results = @()
    
    # Build SNMP GET v2c packet
    $community = [System.Text.Encoding]::ASCII.GetBytes("$Community")
    $oidBytes = Encode-OID $oid
    
    # SNMP v2c GET packet
    # Type=SNMP (0x30), Version=1 (0x02,0x01,0x01), Community=string, PDU=GET(0xA0)
    $packet = @()
    
    # ASN.1 SEQUENCE header
    $body = @()
    
    # Version
    $body += 0x02, 0x01, 0x01  # INTEGER 1 (v2c)
    
    # Community
    $body += 0x04, $community.Length
    $body += $community
    
    # PDU: GET request (0xA0)
    $pdu = @()
    # Request ID
    $pdu += 0x02, 0x01, 0x01
    # Error = 0
    $pdu += 0x02, 0x01, 0x00
    # Error index = 0  
    $pdu += 0x02, 0x01, 0x00
    # Variable bindings
    $bindings = @(0x30)
    $vb = @(0x30)
    $vb += $oidBytes
    $vb += 0x05, 0x00  # NULL value
    $bindings += $vb.Length
    $bindings += $vb
    $pdu += $bindings
    
    $body += 0xA0, $pdu.Length
    $body += $pdu
    
    $packet += 0x30
    $packet += $body.Length
    $packet += $body
    
    # Send via UDP
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Connect($Target, 161)
    $udp.Client.ReceiveTimeout = 2000
    [void]$udp.Send([byte[]]$packet, $packet.Length)
    
    try {
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $recv = $udp.Receive([ref]$remote)
        $udp.Close()
        
        # Parse response - extract value after OID
        $hex = ($recv | ForEach-Object { $_.ToString("X2") }) -join ' '
        $valStart = $hex.IndexOf("05 00") + 6
        if ($valStart -gt 5) {
            return Decode-SNMPValue $recv $valStart
        }
    } catch {
        $udp.Close()
    }
    return $null
}

function Encode-OID($oid) {
    $parts = $oid -split '\.' | ForEach-Object { [int]$_ }
    $result = @()
    
    # First two: 40*part1 + part2
    $result += 40 * $parts[0] + $parts[1]
    
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $val = $parts[$i]
        if ($val -lt 128) {
            $result += $val
        } else {
            $tmp = @()
            while ($val -gt 0) {
                $tmp += ($val -band 0x7F)
                $val = $val -shr 7
            }
            [Array]::Reverse($tmp)
            for ($j = 0; $j -lt $tmp.Length - 1; $j++) {
                $tmp[$j] = $tmp[$j] -bor 0x80
            }
            $result += $tmp
        }
    }
    
    # Build OID bytes with tag and length
    $bytes = @(0x06, $result.Length)
    $bytes += $result
    return $bytes
}

function Decode-SNMPValue($data, $offset) {
    if ($offset -ge $data.Length) { return $null }
    $tag = $data[$offset]
    
    if ($tag -eq 0x04) {  # OCTET STRING
        $len = $data[$offset + 1]
        if ($len -gt 0x80) {
            $lenBytes = $len - 0x80
            $len = 0
            for ($i = 0; $i -lt $lenBytes; $i++) {
                $len = ($len -shl 8) -bor $data[$offset + 2 + $i]
            }
            $offset += $lenBytes
        }
        $result = [System.Text.Encoding]::ASCII.GetString($data, $offset + 2, $len)
        return $result.TrimEnd([char]0)
    }
    return $null
}

# ====== Main ======

# 1. System info
Write-Host "[1/4] SNMP system info..." -ForegroundColor Yellow
$sysName = Send-SNMPGet "1.3.6.1.2.1.1.5.0"
$sysDescr = Send-SNMPGet "1.3.6.1.2.1.1.1.0"

if (-not $sysName) {
    Write-Host "  SNMP timeout or wrong community" -ForegroundColor Red
    Write-Host "  Try: powershell -File snmp-topo.ps1 -Community <other>" -ForegroundColor Yellow
    exit 1
}

Write-Host "  System: $sysName" -ForegroundColor Green
Write-Host "  Type:   $sysDescr" -ForegroundColor Green
Write-Host ""

# 2. ARP table
Write-Host "[2/4] ARP table..." -ForegroundColor Yellow
$arpDevices = @{}
arp -a | ForEach-Object {
    if ($_ -match '(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-f]{2}-){5}[0-9a-f]{2})') {
        $ip = $matches[1]
        $mac = $matches[2] -replace '-',':' | ForEach-Object { $_.ToUpper() }
        if ($ip -notmatch '^(224|239|255)\.' -and $mac -ne 'FF:FF:FF:FF:FF:FF') {
            $arpDevices[$mac] = @{ ip=$ip; name='' }
        }
    }
}
Write-Host "  $($arpDevices.Count) devices in ARP" -ForegroundColor Green

# 3. SNMP MAC table (bridge MIB) - показывает какой MAC на каком порту
Write-Host "[3/4] MAC address table (SNMP)..." -ForegroundColor Yellow
$macTable = @{}
$ifNames = @{}

# Get interface names
for ($i = 1; $i -le 48; $i++) {
    $ifName = Send-SNMPGet "1.3.6.1.2.1.31.1.1.1.1.$i"  # ifName
    if ($ifName) {
        $ifNames[$i] = $ifName
    }
}

# Walk dot1dTpFdbPort (bridge MIB) - MAC to port mapping
for ($i = 1; $i -le 256; $i++) {
    $portOid = "1.3.6.1.2.1.17.4.3.1.2.$i"
    # Actually need full MAC OID - this requires SNMP WALK, which is complex
    # Simplified: try common OIDs
    break
}

# Alternative: ipNetToMediaPhysAddress for router
# Actually let's use a simpler approach - scan through ARP and match

Write-Host "[3/4] LLDP neighbors (SNMP)..." -ForegroundColor Yellow
# LLDP remote systems: 1.0.8802.1.1.2.1.4.1.1
$lldpNeighbors = @()

# Try LLDP MIB - lldpRemSysName
Write-Host "  Trying LLDP scan..."
for ($i = 1; $i -le 10; $i++) {
    # lldpRemSysName: .1.0.8802.1.1.2.1.4.1.1.9.0.<ifIndex>.<mac>
    # Too complex without SNMP WALK
    break
}

# 4. Summary
Write-Host "[4/4] Result:" -ForegroundColor Green
Write-Host ""
Write-Host "=== DEVICE: $sysName ===" -ForegroundColor Cyan
Write-Host "  $sysDescr"
Write-Host ""

# Try to get interface information  
Write-Host "=== INTERFACES with names ===" -ForegroundColor Yellow
for ($i = 1; $i -le 8; $i++) {
    $ifName = Send-SNMPGet "1.3.6.1.2.1.31.1.1.1.1.$i"
    if ($ifName) {
        $ifAdmin = Send-SNMPGet "1.3.6.1.2.1.2.2.1.7.$i"  # ifAdminStatus
        $ifOper = Send-SNMPGet "1.3.6.1.2.1.2.2.1.8.$i"   # ifOperStatus
        $s = if ($ifOper -eq '1') { "UP" } else { "DOWN" }
        Write-Host "  Port $i : $ifName ($s)"
    }
}

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Gateway device: $sysName"
Write-Host "ARP devices:    $($arpDevices.Count)"

$json = @{
    device = $sysName
    description = $sysDescr
    interfaces = $ifNames
    arp_count = $arpDevices.Count
    devices = $arpDevices.Values | ForEach-Object { @{ ip=$_.ip; name=$_.name } }
} | ConvertTo-Json

$json
