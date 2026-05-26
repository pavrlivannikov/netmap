use serde::{Deserialize, Serialize};
use std::process::Command;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interface: String,
    pub ip: String,
    pub prefix: u8,
    pub gateway: String,
    pub cidr: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetMapData {
    pub scan_time: String,
    pub network: String,
    pub devices: Vec<Device>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    #[serde(rename = "type")]
    pub device_type: String,
    pub status: String,
    pub ports: Vec<Port>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub source: String,
    pub target: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResult {
    pub ip: String,
    pub alive: bool,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hop {
    pub hop: u8,
    pub ip: String,
    pub latency_ms: Option<f64>,
}

/// Parse subnet string like "192.168.1.0/24" into list of IPs
pub fn expand_subnet(subnet: &str) -> Result<Vec<String>, String> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid subnet format. Use 192.168.1.0/24".into());
    }

    let base_ip = Ipv4Addr::from_str(parts[0]).map_err(|e| e.to_string())?;
    let prefix: u8 = parts[1].parse().map_err(|_| "Invalid prefix")?;
    if prefix > 32 {
        return Err("Prefix must be 0-32".into());
    }

    let base_u32 = u32::from(base_ip);
    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network = base_u32 & mask;
    let count = 1u32 << (32 - prefix);

    let mut ips = Vec::new();
    for i in 1..count.saturating_sub(1) {
        let ip_u32 = network | i;
        let ip = Ipv4Addr::from(ip_u32);
        ips.push(ip.to_string());
    }
    Ok(ips)
}

/// ARP scan using system arp command
pub fn arp_scan() -> Result<Vec<Device>, String> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .map_err(|e| format!("Failed to run arp: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("(incomplete)") {
            continue;
        }

        // Parse "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let hostname = if !parts[0].starts_with('(') && !parts[0].starts_with('?') {
            Some(parts[0].to_string())
        } else {
            None
        };

        let ip = parts.iter()
            .find(|p| p.starts_with('(') && p.ends_with(')'))
            .map(|p| p[1..p.len()-1].to_string())
            .unwrap_or_default();

        let mac = parts.iter()
            .find(|p| p.contains(':'))
            .map(|p| p.to_string())
            .unwrap_or_default();

        if !ip.is_empty() && !mac.is_empty() {
            let vendor = oui_lookup(&mac);
            devices.push(Device {
                id: mac.clone(),
                ip,
                mac,
                hostname,
                vendor,
                os: None,
                device_type: guess_device_type("", &[]),
                status: "online".into(),
                ports: vec![],
                first_seen: None,
                last_seen: None,
            });
        }
    }

    Ok(devices)
}

/// Quick ICMP ping
pub fn ping_host(ip: &str) -> PingResult {
    let output = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(ip)
        .output();

    match output {
        Ok(out) => {
            let alive = out.status.success();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let latency = parse_ping_latency(&stdout);
            PingResult {
                ip: ip.to_string(),
                alive,
                latency_ms: latency,
            }
        }
        Err(_) => PingResult {
            ip: ip.to_string(),
            alive: false,
            latency_ms: None,
        },
    }
}

fn parse_ping_latency(output: &str) -> Option<f64> {
    for line in output.lines() {
        if line.contains("time=") {
            if let Some(t) = line.split("time=").nth(1) {
                let val: &str = t.split_whitespace().next().unwrap_or("0");
                return val.parse::<f64>().ok();
            }
        }
    }
    None
}

/// OUI vendor lookup from MAC address
pub fn oui_lookup(mac: &str) -> Option<String> {
    let oui = mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_uppercase();

    // Embedded OUI database (common vendors)
    match oui.as_str() {
        "001372" => Some("Cisco".into()),
        "0016B6" => Some("Cisco-Linksys".into()),
        "0017F2" => Some("Apple".into()),
        "0019E3" => Some("Apple".into()),
        "001CB3" => Some("Apple".into()),
        "0022B0" => Some("D-Link".into()),
        "0023DF" => Some("TP-Link".into()),
        "00249B" => Some("Actiontec".into()),
        "0026F2" => Some("Netgear".into()),
        "003A7D" => Some("Ubiquiti".into()),
        "0050F1" => Some("Intel".into()),
        "0050FC" => Some("TP-Link".into()),
        "0050BA" => Some("D-Link".into()),
        "0080C8" => Some("D-Link".into()),
        "00A040" => Some("Apple".into()),
        s if s.starts_with("00") => Some("IEEE Registration".into()),
        s if s.starts_with("08") => Some("Samsung".into()),
        s if s.starts_with("18") => Some("Intel".into()),
        s if s.starts_with("20") => Some("Cisco".into()),
        s if s.starts_with("24") => Some("Apple".into()),
        s if s.starts_with("28") => Some("Apple".into()),
        s if s.starts_with("30") => Some("TP-Link".into()),
        s if s.starts_with("40") => Some("Dell".into()),
        s if s.starts_with("44") => Some("Ubiquiti".into()),
        s if s.starts_with("48") => Some("Sony".into()),
        s if s.starts_with("50") => Some("Netgear".into()),
        s if s.starts_with("54") => Some("ASUS".into()),
        s if s.starts_with("58") => Some("Google".into()),
        s if s.starts_with("60") => Some("Apple".into()),
        s if s.starts_with("64") => Some("Dell".into()),
        s if s.starts_with("68") => Some("Intel".into()),
        s if s.starts_with("70") => Some("Microsoft".into()),
        s if s.starts_with("74") => Some("Ubiquiti".into()),
        s if s.starts_with("78") => Some("Ubiquiti".into()),
        s if s.starts_with("7C") => Some("Intel".into()),
        s if s.starts_with("80") => Some("TP-Link".into()),
        s if s.starts_with("84") => Some("TP-Link".into()),
        s if s.starts_with("88") => Some("Intel".into()),
        s if s.starts_with("8C") => Some("Intel".into()),
        s if s.starts_with("90") => Some("Intel".into()),
        s if s.starts_with("94") => Some("Intel".into()),
        s if s.starts_with("98") => Some("Intel".into()),
        s if s.starts_with("9C") => Some("Intel".into()),
        s if s.starts_with("A0") => Some("Intel".into()),
        s if s.starts_with("A4") => Some("Intel".into()),
        s if s.starts_with("A8") => Some("Apple".into()),
        s if s.starts_with("AC") => Some("Apple".into()),
        s if s.starts_with("B0") => Some("Apple".into()),
        s if s.starts_with("B4") => Some("Apple".into()),
        s if s.starts_with("B8") => Some("Apple".into()),
        s if s.starts_with("BC") => Some("Apple".into()),
        s if s.starts_with("C0") => Some("D-Link".into()),
        s if s.starts_with("C4") => Some("D-Link".into()),
        s if s.starts_with("C8") => Some("Apple".into()),
        s if s.starts_with("CC") => Some("Apple".into()),
        s if s.starts_with("D0") => Some("Intel".into()),
        s if s.starts_with("D4") => Some("Intel".into()),
        s if s.starts_with("D8") => Some("Intel".into()),
        s if s.starts_with("DC") => Some("Intel".into()),
        s if s.starts_with("E0") => Some("Intel".into()),
        s if s.starts_with("E4") => Some("Intel".into()),
        s if s.starts_with("E8") => Some("Intel".into()),
        s if s.starts_with("EC") => Some("Intel".into()),
        s if s.starts_with("F0") => Some("Dell".into()),
        s if s.starts_with("F4") => Some("Apple".into()),
        s if s.starts_with("F8") => Some("Intel".into()),
        s if s.starts_with("FC") => Some("Ubiquiti".into()),
        _ => None,
    }
}

/// Guess device type by MAC vendor and open ports
pub fn guess_device_type(hostname: &str, ports: &[u16]) -> String {
    let hn = hostname.to_lowercase();
    if hn.contains("router") || hn.contains("gateway") || hn.contains("шлюз") {
        return "router".into();
    }
    if hn.contains("switch") || hn.contains("свитч") {
        return "switch".into();
    }
    if hn.contains("printer") || hn.contains("принтер") || hn.contains("mfp") {
        return "printer".into();
    }
    if hn.contains("cam") || hn.contains("камера") || hn.contains("nvr") {
        return "camera".into();
    }
    if hn.contains("server") || hn.contains("сервер") || hn.contains("srv") {
        return "server".into();
    }
    if ports.contains(&22) || ports.contains(&3389) || ports.contains(&5900) {
        return "server".into();
    }
    if ports.contains(&80) || ports.contains(&443) || ports.contains(&8080) {
        return "server".into();
    }
    "workstation".into()
}

/// Run nmap scan for OS detection and port scanning
pub async fn nmap_scan(ip: &str) -> Result<(Option<String>, Vec<Port>), String> {
    let output = Command::new("nmap")
        .args(["-O", "-sV", "--top-ports", "20", "-T4", ip])
        .output()
        .map_err(|e| format!("nmap error: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut os = None;
    let mut ports = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        // OS detection
        if line.starts_with("OS details:") || line.starts_with("Aggressive OS guesses:") {
            os = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
        }
        // Port: "22/tcp   open  ssh     OpenSSH 8.9p1"
        if line.contains("/tcp") || line.contains("/udp") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "open" {
                let port_str = parts[0].split('/').next().unwrap_or("0");
                if let Ok(port) = port_str.parse::<u16>() {
                    let proto = if parts[0].contains("/udp") { "udp" } else { "tcp" };
                    let service = if parts.len() >= 4 { Some(parts[3..].join(" ")) } else { None };
                    ports.push(Port {
                        port,
                        protocol: proto.into(),
                        service,
                        state: "open".into(),
                    });
                }
            }
        }
    }
    Ok((os, ports))
}

/// Quick scan: ARP only (fast, <5 sec)
pub async fn scan_network_quick(subnet: &str) -> Result<NetMapData, String> {
    let mut devices = Vec::new();
    let edges = Vec::new();

    if let Ok(arp_devices) = arp_scan() {
        for d in arp_devices {
            if is_ip_in_subnet(&d.ip, subnet) {
                devices.push(d);
            }
        }
    }

    Ok(NetMapData {
        scan_time: format!("{:?}", std::time::SystemTime::now()),
        network: subnet.to_string(),
        devices,
        edges,
    })
}

/// Parallel scan: ARP + ICMP sweep with concurrent pings (~30 sec for /24)
pub async fn scan_network_parallel(subnet: &str) -> Result<NetMapData, String> {
    let mut devices = Vec::new();
    let edges = Vec::new();

    // 1. ARP scan first (fast)
    if let Ok(arp_devices) = arp_scan() {
        for d in arp_devices {
            if is_ip_in_subnet(&d.ip, subnet) {
                devices.push(d);
            }
        }
    }

    // 2. Parallel ICMP sweep
    let ips = expand_subnet(subnet)?;
    let remaining: Vec<String> = ips.into_iter()
        .filter(|ip| !devices.iter().any(|d| d.ip == *ip))
        .collect();

    // Scan in chunks of 50 parallel pings
    for chunk in remaining.chunks(50) {
        let mut tasks = Vec::new();
        for ip in chunk {
            let ip = ip.clone();
            tasks.push(tokio::task::spawn_blocking(move || ping_host(&ip)));
        }
        for task in tasks {
            if let Ok(result) = task.await {
                if result.alive {
                    devices.push(Device {
                        id: result.ip.clone(),
                        ip: result.ip.clone(),
                        mac: String::new(),
                        hostname: None,
                        vendor: None,
                        os: None,
                        device_type: "unknown".into(),
                        status: "online".into(),
                        ports: vec![],
                        first_seen: None,
                        last_seen: None,
                    });
                }
            }
        }
    }

    Ok(NetMapData {
        scan_time: format!("{:?}", std::time::SystemTime::now()),
        network: subnet.to_string(),
        devices,
        edges,
    })
}

/// Full network scan (sequential, slow but thorough)
pub async fn scan_network(subnet: &str) -> Result<NetMapData, String> {
    let mut devices = Vec::new();
    let mut edges = Vec::new();

    // 1. ARP scan (fast, gives MAC+IP)
    if let Ok(arp_devices) = arp_scan() {
        for d in arp_devices {
            if is_ip_in_subnet(&d.ip, subnet) {
                devices.push(d);
            }
        }
    }

    // 2. ICMP sweep for remaining IPs
    let ips = expand_subnet(subnet)?;
    for ip in ips {
        if !devices.iter().any(|d| d.ip == ip) {
            let result = ping_host(&ip);
            if result.alive {
                devices.push(Device {
                    id: ip.clone(),
                    ip: ip.clone(),
                    mac: String::new(),
                    hostname: None,
                    vendor: None,
                    os: None,
                    device_type: "unknown".into(),
                    status: "online".into(),
                    ports: vec![],
                    first_seen: None,
                    last_seen: None,
                });
            }
        }
    }

    // 3. Quick port scan on discovered hosts (common ports)
    let common_ports = vec![22, 80, 443, 8080, 3389, 5900, 9100, 554];
    for device in &mut devices {
        let mut open_ports = Vec::new();
        for port in &common_ports {
            if let Ok(true) = check_port(&device.ip, *port).await {
                let service = guess_service(*port);
                open_ports.push(Port {
                    port: *port,
                    protocol: "tcp".into(),
                    service: Some(service),
                    state: "open".into(),
                });
            }
        }
        if device.device_type == "unknown" && !open_ports.is_empty() {
            let port_nums: Vec<u16> = open_ports.iter().map(|p| p.port).collect();
            device.device_type = guess_device_type(
                device.hostname.as_deref().unwrap_or(""),
                &port_nums,
            );
        }
        device.ports = open_ports;
    }

    // 4. Build edges (connect devices on same subnet to gateway)
    let gateway_ip = get_default_gateway(subnet);
    for device in &devices {
        if device.ip != gateway_ip {
            edges.push(Edge {
                source: device.id.clone(),
                target: gateway_ip.clone(),
                edge_type: "direct".into(),
                latency_ms: None,
            });
        }
    }

    Ok(NetMapData {
        scan_time: chrono_now(),
        network: subnet.to_string(),
        devices,
        edges,
    })
}

async fn check_port(ip: &str, port: u16) -> Result<bool, String> {
    use tokio::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => Ok(true),
        _ => Ok(false),
    }
}

fn is_ip_in_subnet(ip: &str, subnet: &str) -> bool {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let Ok(base_ip) = Ipv4Addr::from_str(parts[0]) else { return false };
    let Ok(prefix): Result<u8, _> = parts[1].parse() else { return false };
    let Ok(check_ip) = Ipv4Addr::from_str(ip) else { return false };

    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network = u32::from(base_ip) & mask;
    (u32::from(check_ip) & mask) == network
}

fn get_default_gateway(subnet: &str) -> String {
    let parts: Vec<&str> = subnet.split('/').collect();
    if let Ok(base) = Ipv4Addr::from_str(parts[0]) {
        let mut octets = base.octets();
        octets[3] = 1;
        return Ipv4Addr::from(octets).to_string();
    }
    "192.168.1.1".into()
}

fn guess_service(port: u16) -> String {
    match port {
        22 => "SSH".into(),
        80 => "HTTP".into(),
        443 => "HTTPS".into(),
        8080 => "HTTP-Alt".into(),
        3389 => "RDP".into(),
        5900 => "VNC".into(),
        9100 => "Printer".into(),
        554 => "RTSP".into(),
        _ => format!("port-{}", port),
    }
}

fn chrono_now() -> String {
    // Simple ISO timestamp without chrono dependency
    let output = Command::new("date")
        .arg("+%Y-%m-%dT%H:%M:%S%z")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    output
}

/// Discover all active IPv4 networks on the system
pub fn discover_networks() -> Vec<NetworkInfo> {
    let mut networks = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // ipconfig + route print (no PowerShell, works without admin)
        
        if let Ok(output) = Command::new("ipconfig").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut adapters: Vec<(String, String, u8)> = Vec::new();
            let mut current_adapter = String::new();
            let mut current_ip = String::new();
            let mut current_mask = String::new();
            
            for line in stdout.lines() {
                let line = line.trim();
                
                // New adapter section (ends with ":")
                if line.ends_with(':') && !line.contains('.') {
                    if !current_ip.is_empty() && !current_mask.is_empty() 
                        && !current_ip.starts_with("127.") && !current_ip.starts_with("169.254.") {
                        let prefix = mask_to_prefix_calc(&current_mask);
                        adapters.push((current_adapter.clone(), current_ip.clone(), prefix));
                    }
                    current_adapter = line.trim_end_matches(':').trim().to_string();
                    current_ip.clear();
                    current_mask.clear();
                    continue;
                }
                
                // IPv4 Address
                if (line.contains("IPv4") || line.contains("IP-")) && line.contains('.') {
                    for part in line.split_whitespace().rev() {
                        if part.chars().filter(|c| *c == '.').count() == 3 {
                            current_ip = part.to_string();
                            break;
                        }
                    }
                }
                
                // Subnet Mask
                if (line.to_lowercase().contains("subnet") || line.to_lowercase().contains("mask")) && line.contains('.') {
                    for part in line.split_whitespace().rev() {
                        if part.chars().filter(|c| *c == '.').count() == 3 {
                            current_mask = part.to_string();
                            break;
                        }
                    }
                }
            }
            // Last adapter
            if !current_ip.is_empty() && !current_mask.is_empty() 
                && !current_ip.starts_with("127.") && !current_ip.starts_with("169.254.") {
                let prefix = mask_to_prefix_calc(&current_mask);
                adapters.push((current_adapter.clone(), current_ip.clone(), prefix));
            }
            
            // Get gateways from route print
            let gateway = get_gateway_from_route();
            
            for (adapter, ip, prefix) in &adapters {
                let cidr = format!("{}/{}", ip, prefix);
                networks.push(NetworkInfo {
                    interface: adapter.clone(),
                    ip: ip.clone(),
                    prefix: *prefix,
                    gateway: gateway.clone(),
                    cidr,
                    description: adapter.clone(),
                });
            }
        }
    }

#[cfg(not(target_os = "windows"))]
    {
        // Linux: parse ip addr + ip route
        if let Ok(output) = Command::new("ip").args(["-4", "-o", "addr", "show"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let iface = parts[1].to_string();
                if iface == "lo" {
                    continue;
                }
                // Find inet line
                if let Some(inet_idx) = parts.iter().position(|x| *x == "inet") {
                    if let Some(cidr) = parts.get(inet_idx + 1) {
                        if let Some(slash) = cidr.find('/') {
                            let ip = &cidr[..slash];
                            let prefix: u8 = cidr[slash + 1..].parse().unwrap_or(24);
                            let gateway = find_gateway_linux(&iface);
                            networks.push(NetworkInfo {
                                interface: iface.clone(),
                                ip: ip.to_string(),
                                prefix,
                                gateway,
                                cidr: cidr.to_string(),
                                description: iface.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort: prefer Ethernet over WiFi, then by name
    networks.sort_by(|a, b| {
        let a_prio = if a.description.to_lowercase().contains("ethernet") || a.interface.to_lowercase().contains("eth") { 0 }
            else if a.description.to_lowercase().contains("wi") || a.interface.to_lowercase().contains("wlan") { 1 }
            else { 2 };
        let b_prio = if b.description.to_lowercase().contains("ethernet") || b.interface.to_lowercase().contains("eth") { 0 }
            else if b.description.to_lowercase().contains("wi") || b.interface.to_lowercase().contains("wlan") { 1 }
            else { 2 };
        a_prio.cmp(&b_prio).then(a.interface.cmp(&b.interface))
    });

    networks
}

#[cfg(not(target_os = "windows"))]
fn find_gateway_linux(iface: &str) -> String {
    if let Ok(output) = std::process::Command::new("ip").args(["-4", "route", "show", "dev", iface]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("default") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx) = parts.iter().position(|x| *x == "via") {
                    return parts.get(idx + 1).unwrap_or(&"").to_string();
                }
            }
        }
    }
    String::new()
}

#[allow(dead_code)]
fn mask_to_prefix(mask: u32) -> u8 {
    let mut prefix = 0u8;
    let mut m = mask;
    while m & 0x80000000 != 0 {
        prefix += 1;
        m <<= 1;
    }
    if prefix == 0 { 24 } else { prefix }
}

/// Convert dotted IPv4 mask string to prefix length

/// Extract default gateway from "route print -4"
fn get_gateway_from_route() -> String {
    if let Ok(output) = Command::new("route").args(["print", "-4"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("0.0.0.0") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let gw = parts[2].to_string();
                    if gw != "0.0.0.0" && !gw.is_empty() {
                        return gw;
                    }
                }
            }
        }
    }
    String::new()
}

fn mask_to_prefix_calc(mask_str: &str) -> u8 {
    let parts: Vec<&str> = mask_str.trim().split('.').collect();
    if parts.len() != 4 { return 24; }
    let mut bits = 0u8;
    for part in &parts {
        let byte: u8 = part.parse().unwrap_or(0);
        bits += byte.count_ones() as u8;
    }
    if bits == 0 { 24 } else { bits }
}
