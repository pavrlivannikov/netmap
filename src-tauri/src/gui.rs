// NetMap GUI — egui native interface
use eframe::egui;
use netmap_lib::scanner::{discover_networks, scan_network_quick, NetworkInfo};

#[derive(Default)]
pub struct NetMapApp {
    networks: Vec<NetworkInfo>,
    selected_network: String,
    devices: Vec<DeviceNode>,
    scanning: bool,
    status: String,
    discover_clicked: bool,
}

struct DeviceNode {
    ip: String,
    mac: String,
    vendor: String,
}

impl eframe::App for NetMapApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("NetMap");
                ui.separator();
                if ui.button("Discover").clicked() {
                    self.discover_clicked = true;
                }
                if ui.button("Scan").clicked() && !self.selected_network.is_empty() {
                    self.scanning = true;
                    self.status = format!("Scanning {}...", self.selected_network);
                    self.devices.clear();
                    
                    let subnet = self.selected_network.clone();
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    if let Ok(data) = rt.block_on(scan_network_quick(&subnet)) {
                        for d in &data.devices {
                            self.devices.push(DeviceNode {
                                ip: d.ip.clone(),
                                mac: d.mac.clone(),
                                vendor: d.vendor.clone().unwrap_or_default(),
                            });
                        }
                        self.status = format!("Found {} devices", data.devices.len());
                    }
                    self.scanning = false;
                }
                ui.separator();
                if self.scanning {
                    ui.spinner();
                }
                ui.label(&self.status.clone());
            });
        });
        
        egui::SidePanel::left("networks").resizable(false).default_width(200.0).show_inside(ui, |ui| {
            ui.heading("Networks");
            ui.separator();
            if self.discover_clicked {
                self.networks = discover_networks();
                if !self.networks.is_empty() {
                    self.selected_network = self.networks[0].cidr.clone();
                    self.status = format!("Found {} network(s)", self.networks.len());
                }
                self.discover_clicked = false;
            }
            for net in &self.networks {
                let label = format!("{} ({})", net.interface, net.cidr);
                if ui.selectable_label(self.selected_network == net.cidr, &label).clicked() {
                    self.selected_network = net.cidr.clone();
                }
            }
        });
        
        egui::CentralPanel::default().show_inside(ui, |ui| {
            if self.devices.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("Discover network, then Scan");
                });
            } else {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("devices").striped(true).show(ui, |ui| {
                        ui.heading("IP");
                        ui.heading("MAC");
                        ui.heading("Vendor");
                        ui.end_row();
                        for d in &self.devices {
                            ui.label(&d.ip);
                            ui.label(&d.mac);
                            ui.label(&d.vendor);
                            ui.end_row();
                        }
                    });
                });
                ui.separator();
                ui.label(format!("{} devices", self.devices.len()));
            }
        });
    }
}
