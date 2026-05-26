#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gui;

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    
    let app: Box<dyn eframe::App> = Box::new(gui::NetMapApp::default());
    eframe::run_native("NetMap - Карта сети", options, Box::new(|_cc| Ok(app))).unwrap();
}
