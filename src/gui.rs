use crate::password_manager::PasswordManager;
use eframe::egui::{self, RichText};
use std::sync::{Arc, Mutex};
use copypasta::{ClipboardContext, ClipboardProvider};

pub struct PasswordManagerApp {
    pm: Arc<Mutex<Option<PasswordManager>>>,
    master_password: String,
    website: String,
    username: String,
    password: String,
    message: String,
    password_length: String,
    initialized: bool,
    csv_path_input: String,
}

impl Default for PasswordManagerApp {
    fn default() -> Self {
        Self {
            pm: Arc::new(Mutex::new(Some(PasswordManager::new("passwords.enc")))),
            master_password: String::new(),
            csv_path_input: String::new(),
            website: String::new(),
            username: String::new(),
            password: String::new(),
            message: String::new(),
            password_length: "16".to_string(),
            initialized: false,
        }
    }
}

impl eframe::App for PasswordManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let visuals = egui::Visuals {
            dark_mode: true,
            panel_fill: egui::Color32::from_rgb(32, 33, 36),
            window_fill: egui::Color32::from_rgb(40, 41, 45),
            faint_bg_color: egui::Color32::from_rgb(45, 46, 50),
            extreme_bg_color: egui::Color32::from_rgb(25, 26, 30),
            code_bg_color: egui::Color32::from_rgb(35, 36, 40),
            hyperlink_color: egui::Color32::from_rgb(90, 170, 255),
            ..Default::default()
        };
        ctx.set_visuals(visuals);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                if !self.initialized {
                    ui.heading(RichText::new("Password Manager - Login").size(24.0));
                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Master Password: ").size(16.0));
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.master_password)
                                .password(true)
                                .desired_width(200.0)
                        );
                        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            self.try_login();
                        }
                    });

                    if ui.button(RichText::new("Login").size(16.0)).clicked() {
                        self.try_login();
                    }
                } else {
                    self.render_main_interface(ui);
                }

                // Status Message
                if !self.message.is_empty() {
                    ui.add_space(10.0);
                    let text_color = if self.message.starts_with("Error") {
                        egui::Color32::from_rgb(255, 100, 100)
                    } else {
                        egui::Color32::from_rgb(100, 255, 100)
                    };
                    ui.label(RichText::new(&self.message).color(text_color));
                }
            });
        });
    }
}

impl PasswordManagerApp {
    fn render_main_interface(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Password Manager").size(24.0));
        ui.add_space(20.0);

        self.draw_store_section(ui);
        ui.add_space(10.0);
        self.draw_retrieve_section(ui);
        ui.add_space(10.0);
        self.draw_generate_section(ui);
        ui.add_space(10.0);
        self.draw_import_section(ui);
    }

    fn try_login(&mut self) {
        if let Some(pm) = self.pm.lock().unwrap().as_mut() {
            if pm.initialize(&self.master_password).is_ok() {
                self.initialized = true;
                self.message = "Initialized successfully".to_string();
            } else {
                self.message = "Initialization failed".to_string();
            }
        }
    }

    fn draw_store_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading(RichText::new("Store Password").size(18.0));
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Website:").size(16.0));
                ui.text_edit_singleline(&mut self.website);
            });

            ui.horizontal(|ui| {
                ui.label(RichText::new("Username:").size(16.0));
                ui.text_edit_singleline(&mut self.username);
            });

            ui.horizontal(|ui| {
                ui.label(RichText::new("Password:").size(16.0));
                ui.add(egui::TextEdit::singleline(&mut self.password)
                    .password(true)
                    .desired_width(200.0));
            });

            if ui.button(RichText::new("Store Password").size(16.0)).clicked() {
                self.store_current_password();
            }
        });
    }

    fn draw_retrieve_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading(RichText::new("Retrieve Password").size(18.0));
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Website:").size(16.0));
                let response = ui.text_edit_singleline(&mut self.website);
                
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) 
                    || ui.button(RichText::new("Retrieve").size(16.0)).clicked() 
                {
                    if let Some(pm) = self.pm.lock().unwrap().as_ref() {
                        match pm.get_password(&self.website) {
                            Ok((username, password)) => {
                                self.username = username;
                                self.password = password.clone();
                                // Copy password to clipboard automatically
                                if let Ok(mut ctx) = ClipboardContext::new() {
                                    if let Ok(_) = ctx.set_contents(password) {
                                        self.message = "Password retrieved and copied to clipboard".to_string();
                                    } else {
                                        self.message = "Password retrieved but clipboard copy failed".to_string();
                                    }
                                }
                            }
                            Err(e) => self.message = format!("Error: {}", e),
                        }
                    }
                }
            });

            // Display retrieved credentials
            if !self.username.is_empty() {
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Username:").size(16.0).color(egui::Color32::LIGHT_BLUE));
                    ui.label(RichText::new(&self.username).size(16.0));
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Password:").size(16.0).color(egui::Color32::LIGHT_BLUE));
                    ui.label(RichText::new(&self.password).size(16.0));
                });
            }
        });
    }

    fn draw_generate_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading(RichText::new("Generate Password").size(18.0));
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Length:").size(16.0));
                ui.add(
                    egui::TextEdit::singleline(&mut self.password_length)
                        .desired_width(60.0)
                );

                if ui.button(RichText::new("Generate").size(16.0)).clicked() {
                    self.generate_and_copy_password();
                }
            });
        });
    }

    fn draw_import_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.heading(RichText::new("Import Passwords").size(18.0));
            ui.add_space(5.0);

            if ui.button(RichText::new("Import from CSV").size(16.0)).clicked() {
                self.start_import();
            }

            if self.message.starts_with("Please enter") {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("CSV Path:").size(16.0));
                    ui.text_edit_singleline(&mut self.csv_path_input);
                });
                
                if ui.button(RichText::new("Load").size(16.0)).clicked() {
                    self.import_from_csv();
                }
            }
        });
    }

    fn generate_and_copy_password(&mut self) {
        if let Some(pm) = self.pm.lock().unwrap().as_ref() {
            let length = self.password_length.parse().unwrap_or(16);
            self.password = pm.generate_password(length);

            // Copy to clipboard
            if let Ok(mut ctx) = ClipboardContext::new() {
                match ctx.set_contents(self.password.clone()) {
                    Ok(_) => self.message = "Password generated and copied to clipboard".to_string(),
                    Err(e) => self.message = format!("Generated but failed to copy: {}", e),
                }
            }
        }
    }

    fn retrieve_password(&mut self) {
        if let Some(pm) = self.pm.lock().unwrap().as_ref() {
            match pm.get_password(&self.website) {
                Ok((username, password)) => {
                    self.username = username;
                    self.password = password;
                    self.message = "Password retrieved successfully".to_string();
                }
                Err(e) => self.message = format!("Error: {}", e),
            }
        }
    }

    fn store_current_password(&mut self) {
        if let Some(pm) = self.pm.lock().unwrap().as_mut() {
            match pm.store_password(&self.website, &self.username, &self.password) {
                Ok(_) => self.message = "Password stored successfully".to_string(),
                Err(e) => self.message = format!("Error: {}", e),
            }
        }
    }

    fn start_import(&mut self) {
        self.message = "Please enter the path to Chrome Passwords.csv".to_string();
        self.csv_path_input.clear();
    }

    fn import_from_csv(&mut self) {
        let path = std::path::PathBuf::from(&self.csv_path_input);
        if path.exists() {
            if let Some(pm) = self.pm.lock().unwrap().as_mut() {
                match pm.import_from_csv(&self.csv_path_input) {
                    Ok(_) => {
                        self.message = "Passwords imported successfully. Use website URL to retrieve passwords.".to_string();
                    }
                    Err(e) => self.message = format!("Error importing CSV: {}", e),
                }
            }
        } else {
            self.message = "CSV file does not exist".to_string();
        }
        self.csv_path_input.clear();
    }
}
