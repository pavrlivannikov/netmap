pub mod scanner;
pub mod snmp;

use scanner::{NetMapData, NetworkInfo, PingResult, scan_network, ping_host, expand_subnet, discover_networks, nmap_scan};
use snmp::SnmpClient;

#[tauri::command]
async fn scan_network_cmd(subnet: String) -> Result<NetMapData, String> {
    scan_network(&subnet).await
}

#[tauri::command]
async fn ping_device(ip: String) -> Result<PingResult, String> {
    Ok(ping_host(&ip))
}

#[tauri::command]
fn get_subnet_hosts(subnet: String) -> Result<Vec<String>, String> {
    expand_subnet(&subnet)
}

#[tauri::command]
fn export_json(data: NetMapData) -> Result<String, String> {
    serde_json::to_string_pretty(&data).map_err(|e| e.to_string())
}

#[tauri::command]
fn discover_networks_cmd() -> Vec<NetworkInfo> {
    discover_networks()
}

#[tauri::command]
async fn nmap_scan_cmd(ip: String) -> Result<String, String> {
    let (os, ports) = nmap_scan(&ip).await?;
    let result = serde_json::json!({
        "os": os,
        "ports": ports
    });
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

#[tauri::command]
async fn snmp_probe(ip: String, community: String) -> Result<bool, String> {
    let client = SnmpClient::new(&community);
    Ok(client.probe(&ip))
}

#[tauri::command]
async fn snmp_discover(ip: String, community: String) -> Result<String, String> {
    let client = SnmpClient::new(&community);
    let device = client.discover(&ip);
    let result = serde_json::json!({
        "sys_name": device.sys_name,
        "sys_descr": device.sys_descr,
        "sys_location": device.sys_location,
        "interfaces": device.interfaces.iter().map(|i| serde_json::json!({
            "index": i.index,
            "name": i.name,
            "status": i.status
        })).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            scan_network_cmd,
            ping_device,
            get_subnet_hosts,
            export_json,
            discover_networks_cmd,
            nmap_scan_cmd,
            snmp_probe,
            snmp_discover,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetMap");
}
