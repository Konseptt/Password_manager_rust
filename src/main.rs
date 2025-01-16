mod password_manager;
mod gui;

use gui::PasswordManagerApp;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(480.0, 640.0)),
        ..Default::default()
    };
    
    eframe::run_native(
        "Password Manager",
        native_options,
        Box::new(|_cc| Box::new(PasswordManagerApp::default())),
    )
}
