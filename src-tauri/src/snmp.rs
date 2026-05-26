// SNMP v1/v2c client — manual UDP implementation
// Простой и надёжный, без внешних зависимостей
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct SnmpDevice {
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_location: Option<String>,
    pub interfaces: Vec<SnmpInterface>,
}

#[derive(Debug, Clone)]
pub struct SnmpInterface {
    pub index: u32,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct LldpNeighbor {
    pub local_port: u32,
    pub remote_name: String,
    pub remote_port: String,
}

#[derive(Debug, Clone)]
pub struct MacEntry {
    pub mac: String,
    pub port: u32,
    pub vlan: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct SnmpTopology {
    pub device: SnmpDevice,
    pub lldp_neighbors: Vec<LldpNeighbor>,
    pub mac_table: Vec<MacEntry>,
}

/// SNMP v2c client with manual packet building
pub struct SnmpClient {
    community: String,
    timeout: Duration,
}

impl SnmpClient {
    pub fn new(community: &str) -> Self {
        Self {
            community: community.to_string(),
            timeout: Duration::from_secs(2),
        }
    }

    /// Build and send SNMP GET, return raw response bytes
    fn send_get(&self, target: &str, oid: &str) -> Result<Vec<u8>, String> {
        let packet = build_snmp_get_v2c(&self.community, oid);
        let addr = format!("{}:161", target);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("bind: {}", e))?;
        socket.set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("timeout: {}", e))?;
        socket.send_to(&packet, &addr)
            .map_err(|e| format!("send: {}", e))?;
        let mut buf = [0u8; 2048];
        let (len, _) = socket.recv_from(&mut buf)
            .map_err(|e| format!("recv: {}", e))?;
        Ok(buf[..len].to_vec())
    }

    /// Extract OCTET STRING value from response that follows a matching OID
    fn extract_string(&self, response: &[u8], oid: &str) -> Option<String> {
        let encoded = encode_oid(oid);
        // Find OID in response
        for i in 0..response.len().saturating_sub(encoded.len() + 2) {
            if response[i] == 0x06 && response[i+1] == encoded.len() as u8 {
                let mut matched = true;
                for (j, &b) in encoded.iter().enumerate() {
                    if response[i+2+j] != b { matched = false; break; }
                }
                if matched {
                    let pos = i + 2 + encoded.len();
                    if pos + 1 < response.len() && response[pos] == 0x04 {
                        let len = response[pos+1] as usize;
                        if pos + 2 + len <= response.len() && len < 200 {
                            if let Ok(s) = String::from_utf8(response[pos+2..pos+2+len].to_vec()) {
                                let s = s.trim_end_matches('\0').trim();
                                if !s.is_empty() { return Some(s.to_string()); }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_integer(&self, response: &[u8], oid: &str) -> Option<u32> {
        let encoded = encode_oid(oid);
        for i in 0..response.len().saturating_sub(encoded.len() + 2) {
            if response[i] == 0x06 && response[i+1] == encoded.len() as u8 {
                let mut matched = true;
                for (j, &b) in encoded.iter().enumerate() {
                    if response[i+2+j] != b { matched = false; break; }
                }
                if matched {
                    let pos = i + 2 + encoded.len();
                    if pos + 1 < response.len() && response[pos] == 0x02 {
                        let len = response[pos+1] as usize;
                        if len <= 4 {
                            let mut val: u32 = 0;
                            for k in 0..len { val = (val << 8) | response[pos+2+k] as u32; }
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn probe(&self, target: &str) -> bool {
        self.send_get(target, "1.3.6.1.2.1.1.1.0")
            .map(|r| self.extract_string(&r, "1.3.6.1.2.1.1.1.0").is_some())
            .unwrap_or(false)
    }

    pub fn discover(&self, target: &str) -> SnmpDevice {
        let mut dev = SnmpDevice::default();
        
        if let Ok(r) = self.send_get(target, "1.3.6.1.2.1.1.5.0") {
            dev.sys_name = self.extract_string(&r, "1.3.6.1.2.1.1.5.0");
        }
        if let Ok(r) = self.send_get(target, "1.3.6.1.2.1.1.1.0") {
            dev.sys_descr = self.extract_string(&r, "1.3.6.1.2.1.1.1.0");
        }
        if let Ok(r) = self.send_get(target, "1.3.6.1.2.1.1.6.0") {
            dev.sys_location = self.extract_string(&r, "1.3.6.1.2.1.1.6.0");
        }
        
        // Interfaces
        for i in 1..=52 {
            let oid = format!("1.3.6.1.2.1.2.2.1.2.{}", i);
            if let Ok(r) = self.send_get(target, &oid) {
                if let Some(name) = self.extract_string(&r, &oid) {
                    let oper_oid = format!("1.3.6.1.2.1.2.2.1.8.{}", i);
                    let status = if let Ok(r2) = self.send_get(target, &oper_oid) {
                        match self.extract_integer(&r2, &oper_oid) {
                            Some(1) => "up", _ => "down"
                        }
                    } else { "down" };
                    
                    dev.interfaces.push(SnmpInterface { index: i, name, status: status.to_string() });
                }
            }
        }
        dev
    }

    pub fn discover_topology(&self, target: &str) -> SnmpTopology {
        SnmpTopology {
            device: self.discover(target),
            lldp_neighbors: Vec::new(),
            mac_table: Vec::new(),
        }
    }
}

fn build_snmp_get_v2c(community: &str, oid: &str) -> Vec<u8> {
    let oid_enc = encode_oid(oid);
    let com = community.as_bytes();
    
    // Varbind: OID + NULL
    let mut vb = vec![0x30]; // SEQUENCE
    vb.extend_from_slice(&oid_enc);
    vb.extend_from_slice(&[0x05, 0x00]);
    
    // Varbind list
    let mut vbl = vec![0x30];
    vbl.push(vb.len() as u8);
    vbl.extend_from_slice(&vb);
    
    // GET PDU (0xA0)
    let mut pdu = vec![0x02, 0x01, 0x01]; // req-id
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error-index
    pdu.extend_from_slice(&vbl);
    
    // Body
    let mut body = vec![0x02, 0x01, 0x01]; // version v2c
    body.push(0x04);
    body.push(com.len() as u8);
    body.extend_from_slice(com);
    body.push(0xA0); // GET PDU tag
    body.push(pdu.len() as u8);
    body.extend_from_slice(&pdu);
    
    // Message
    let mut msg = vec![0x30]; // SEQUENCE
    msg.push(body.len() as u8);
    msg.extend_from_slice(&body);
    msg
}

fn encode_oid(oid: &str) -> Vec<u8> {
    let parts: Vec<u32> = oid.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.is_empty() { return vec![0x06, 0x00]; }
    
    let mut result = vec![0x06]; // OID tag
    let mut encoded = Vec::new();
    encoded.push((40 * parts[0] + parts.get(1).copied().unwrap_or(0)) as u8);
    
    for &part in &parts[2..] {
        if part < 128 {
            encoded.push(part as u8);
        } else {
            let mut tmp = Vec::new();
            let mut val = part;
            tmp.push((val & 0x7F) as u8);
            val >>= 7;
            while val > 0 {
                tmp.push(((val & 0x7F) | 0x80) as u8);
                val >>= 7;
            }
            tmp.reverse();
            encoded.extend_from_slice(&tmp);
        }
    }
    
    result.push(encoded.len() as u8);
    result.extend_from_slice(&encoded);
    result
}
