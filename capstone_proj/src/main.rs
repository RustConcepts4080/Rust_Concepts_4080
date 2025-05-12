mod encryption;
mod file_shredder;
use std::fs;
use std::path::PathBuf;
use eframe::{egui, App as EframeApp, Frame, NativeOptions};
use egui::Context;
use file_shredder::shred_file;
use rfd::FileDialog;
use encryption::{generate_hmac, verify_hmac};

enum Tab {
    EncryptDecrypt,
    FileShredder
}

struct App {
    current_tab: Tab,
    encrypt_input: Option<PathBuf>,
    encrypt_output_dir: Option<PathBuf>,
    encrypt_key: String,
    encrypt_mode_parallel: bool,
    encrypt_threads: usize,
    decrypt_input: Option<PathBuf>,
    decrypt_output_dir: Option<PathBuf>,
    decrypt_key: String,
    decrypt_mode_parallel: bool,
    decrypt_threads: usize,
    status_message: String,
    show_encrypt: bool,
    show_decrypt: bool,
    hmac_info_message: Option<String>,
    file_shredder_input: Option<PathBuf>,
    confirm_shred: bool,
    success_shred: bool,
    failure_shred: bool
}

impl Default for App {
    fn default() -> Self {
        Self {
            current_tab: Tab::EncryptDecrypt,
            encrypt_input: None,
            encrypt_output_dir: None,
            encrypt_key: String::new(),
            encrypt_mode_parallel: false,
            encrypt_threads: 1,
            decrypt_input: None,
            decrypt_output_dir: None,
            decrypt_key: String::new(),
            decrypt_mode_parallel: false,
            decrypt_threads: 1,
            status_message: String::new(),
            show_encrypt: false,
            show_decrypt: false,
            hmac_info_message: None,
            file_shredder_input: None,
            confirm_shred: false,
            success_shred: false,
            failure_shred: false
        }
    }
}

impl EframeApp for App {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        let mut style = (*ctx.style()).clone();
        style.override_font_id = Some(egui::FontId::monospace(20.0));
        ctx.set_style(style);

        // The `ui` from CentralPanel will be passed to the ScrollArea
        egui::CentralPanel::default().show(ctx, |panel_ui| {
            panel_ui.add_space(30.0);
            panel_ui.vertical_centered(|ui| { // Using `ui` here for this specific centered label
                ui.label(
                    egui::RichText::new("Rust File Encryptor").strong().size(62.0)
                        .color(egui::Color32::from_rgb(255, 165, 0))
                );
            });

            panel_ui.add_space(40.0);
            panel_ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 20.0;

                let tab_text = |label: &str, active: bool| {
                    if active {
                        egui::RichText::new(label)
                            .strong()
                            .color(egui::Color32::from_rgb(255, 165, 0))
                    } else {
                        egui::RichText::new(label).color(egui::Color32::GRAY)
                    }
                };

                if ui.button(tab_text("Encrypt/Decrypt", matches!(self.current_tab, Tab::EncryptDecrypt))).clicked() {
                    self.current_tab = Tab::EncryptDecrypt;
                }
                if ui.button(tab_text("File Shredder", matches!(self.current_tab, Tab::FileShredder))).clicked() {
                    self.current_tab = Tab::FileShredder;
                }
            });

            panel_ui.add_space(20.0);
            panel_ui.allocate_ui(egui::vec2(panel_ui.available_width(), 3.0), |ui| { // Using `ui` here for this specific allocation
                let rect = ui.max_rect();
                ui.painter().rect_filled(
                    rect,
                    0.0,
                    egui::Color32::WHITE,
                );
            });
            panel_ui.add_space(40.0);

            match self.current_tab {
                Tab::EncryptDecrypt => {
                    // --- MINIMAL CHANGE: Wrap the main content area with a ScrollArea ---
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false]) // Ensures the ScrollArea tries to fill available space
                        .show(panel_ui, |scroll_ui| { // `scroll_ui` is the Ui object for the content within the ScrollArea
                        
                        // The rest of your UI logic now uses `scroll_ui` instead of the original `ui` from vertical_centered_justified
                        scroll_ui.vertical_centered_justified(|ui| { // The `ui` here is from vertical_centered_justified, using `scroll_ui` as its parent
                            if ui.add_sized(
                                egui::vec2(50.0, 60.0), // Consider relative sizing if fixed sizes cause issues in scrollview
                                egui::Button::new(egui::RichText::new("🔐 Encrypt").size(35.0).strong())
                            ).clicked() {
                                self.show_encrypt = !self.show_encrypt;
                            }

                            if self.show_encrypt {
                                if ui.button("Select Input File").clicked() {
                                    if let Some(p) = FileDialog::new().pick_file() {
                                        self.encrypt_input = Some(p);
                                    }
                                }
                                if let Some(path) = &self.encrypt_input {
                                    ui.label(egui::RichText::new(path.display().to_string()).size(20.0));
                                }

                                if ui.button("Select Output Folder").clicked() {
                                    if let Some(f) = FileDialog::new().pick_folder() {
                                        self.encrypt_output_dir = Some(f);
                                    }
                                }
                                if let Some(dir) = &self.encrypt_output_dir {
                                    ui.label(egui::RichText::new(dir.display().to_string()).size(20.0));
                                }

                                ui.label(egui::RichText::new("Key (16 chars):").size(20.0));
                                ui.text_edit_singleline(&mut self.encrypt_key);

                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut self.encrypt_mode_parallel, "Parallel");
                                    if self.encrypt_mode_parallel {
                                        ui.add(egui::DragValue::new(&mut self.encrypt_threads).range(1..=32).prefix("threads: "));
                                    }
                                });

                                if ui.button("Encrypt ▶").clicked() {
                                    self.hmac_info_message = None;
                                    if let (Some(in_path), Some(out_dir)) = (&self.encrypt_input, &self.encrypt_output_dir) {
                                        if self.encrypt_key.len() == 16 {
                                            let data = fs::read(in_path).expect("read failed");
                                            let ext = in_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                                            let iv = encryption::generate_base_iv();
                                            let encrypted = if self.encrypt_mode_parallel {
                                                encryption::parallel_encrypt(
                                                    &data,
                                                    self.encrypt_key.as_bytes().try_into().unwrap(),
                                                    &iv,
                                                    self.encrypt_threads,
                                                )
                                            } else {
                                                encryption::encrypt_series(
                                                    &data,
                                                    self.encrypt_key.as_bytes().try_into().unwrap(),
                                                    &iv,
                                                )
                                            };
                                            let mut blob = Vec::new();
                                            let ext_bytes = ext.as_bytes();
                                            blob.extend(&(ext_bytes.len() as u32).to_be_bytes());
                                            blob.extend(ext_bytes);
                                            blob.extend(&iv);
                                            blob.extend(&encrypted);
                                            let hmac = generate_hmac(&encrypted, self.encrypt_key.as_bytes());
                                            blob.extend(&hmac);
                                            let file_stem = in_path
                                                .file_stem()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or("output");
                                            let out_file = out_dir.join(format!("{file_stem}_enc.bin"));
                                            fs::write(&out_file, blob).expect("write failed");
                                            self.status_message = format!("Encrypted → {}", out_file.display());
                                        } else {
                                            self.status_message = "Key must be 16 characters".into();
                                        }
                                    } else {
                                        self.status_message = "Select input file and output folder first".into();
                                    }
                                }
                            } // end if self.show_encrypt

                            ui.add_space(20.0);

                            if ui.add_sized(
                                egui::vec2(50.0, 60.0), // Consider relative sizing
                                egui::Button::new(egui::RichText::new("🔓 Decrypt").size(35.0).strong())
                            ).clicked() {
                                self.show_decrypt = !self.show_decrypt;
                            }

                            if self.show_decrypt {
                                if ui.button("Select Encrypted File").clicked() {
                                    if let Some(p) = FileDialog::new().pick_file() {
                                        self.decrypt_input = Some(p);
                                    }
                                }
                                if let Some(path) = &self.decrypt_input {
                                    ui.label(egui::RichText::new(path.display().to_string()).size(20.0));
                                }

                                if ui.button("Select Output Folder").clicked() {
                                    if let Some(f) = FileDialog::new().pick_folder() {
                                        self.decrypt_output_dir = Some(f);
                                    }
                                }
                                if let Some(dir) = &self.decrypt_output_dir {
                                    ui.label(egui::RichText::new(dir.display().to_string()).size(20.0));
                                }

                                ui.label(egui::RichText::new("Key (16 chars):").size(20.0));
                                ui.text_edit_singleline(&mut self.decrypt_key);

                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut self.decrypt_mode_parallel, "Parallel");
                                    if self.decrypt_mode_parallel {
                                        ui.add(egui::DragValue::new(&mut self.decrypt_threads).range(1..=32).prefix("threads: "));
                                    }
                                });

                                if ui.button("Decrypt ▶").clicked() {
                                    self.hmac_info_message = None;
                                    if let (Some(in_path), Some(out_dir)) = (&self.decrypt_input, &self.decrypt_output_dir) {
                                        if self.decrypt_key.len() == 16 {
                                            let blob = fs::read(in_path).expect("read failed");
                                            if blob.len() < 4 {
                                                self.status_message = "Invalid file! File size too small".to_string();
                                                return; // This return is from the vertical_centered_justified closure
                                            }
                                            
                                            let ext_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
                                            let iv_start = 4 + ext_len;
                                            let iv_end = iv_start + 16;
                                            
                                            if blob.len() < iv_end + 32 {
                                                self.status_message = "Invalid file! Corrupted or tampered.".to_string();
                                                return;
                                            }
                                            
                                            let ext = if ext_len > 0 {
                                                String::from_utf8_lossy(&blob[4..4 + ext_len]).to_string()
                                            } else {
                                                String::new()
                                            };
                                            
                                            let mut iv_arr = [0u8; 16]; // Renamed to avoid conflict if `iv` name is used below
                                            iv_arr.copy_from_slice(&blob[iv_start..iv_end]);
                                            let total = blob.len();
                                            
                                            if total < iv_start + 16 + 32 {
                                                self.status_message = "File too small or corrupted.".to_string();
                                                return;
                                            }

                                            let encrypted_data_end = total - 32;
                                            let encrypted_data = &blob[iv_start + 16..encrypted_data_end];
                                            let hmac = &blob[encrypted_data_end..];

                                            if !verify_hmac(hmac, encrypted_data, self.decrypt_key.as_bytes()) {
                                                self.status_message = "HMAC verification failed! Your file may be corrupted OR the Key is incorrect.".to_string();
                                                return;
                                            } else {
                                                self.hmac_info_message = Some("Yoohoo! HMAC verified. File has not been tampered with.".to_string());
                                            }

                                            let decrypted = if self.decrypt_mode_parallel {
                                                encryption::parallel_decrypt(
                                                    encrypted_data,
                                                    self.decrypt_key.as_bytes().try_into().unwrap(),
                                                    &iv_arr, // Use renamed iv_arr
                                                    self.decrypt_threads,
                                                )
                                            } else {
                                                encryption::decrypt_series(
                                                    encrypted_data,
                                                    self.decrypt_key.as_bytes().try_into().unwrap(),
                                                    &iv_arr, // Use renamed iv_arr
                                                )
                                            };
                                            let file_stem = in_path.file_stem().and_then(|s| s.to_str()).unwrap_or("decrypted");
                                            let out_name = if ext.is_empty() {
                                                format!("{file_stem}_dec.bin")
                                            } else {
                                                format!("{file_stem}_dec.{ext}")
                                            };
                                            let out_file = out_dir.join(out_name);
                                            fs::write(&out_file, decrypted).expect("write failed");
                                            self.status_message = format!("Decrypted → {}", out_file.display());
                                        } else {
                                            self.status_message = "Key must be 16 characters".into();
                                        }
                                    } else {
                                        self.status_message = "Select encrypted file and output folder first".into();
                                    }
                                }
                            } // end if self.show_decrypt

                            ui.add_space(10.0);

                            if let Some(msg) = &self.hmac_info_message {
                                ui.colored_label(egui::Color32::BLUE, egui::RichText::new(msg).size(20.0));
                            }
                            
                            let color = if self.status_message.contains("Encrypted") || self.status_message.contains("Decrypted") {
                                egui::Color32::GREEN
                            } else {
                                egui::Color32::RED
                            };
                            ui.colored_label(color, egui::RichText::new(&self.status_message).size(20.0));
                        }); // End of vertical_centered_justified
                    }); // End of ScrollArea
                }
                Tab::FileShredder => {
                    panel_ui.vertical_centered_justified(|ui| {
                        ui.label(
                            egui::RichText::new("🚮 Secure File Shredder")
                                .size(35.0)
                                .strong()
                        );

                        ui.add_space(20.0);

                        if ui.button("Select File").clicked() {
                            self.success_shred = false;
                            self.failure_shred = false;
                            self.confirm_shred = false;

                            if let Some(p) = FileDialog::new().pick_file() {
                                self.file_shredder_input = Some(p);
                            }
                        }
                        if let Some(path) = &self.file_shredder_input {
                            ui.label(egui::RichText::new(path.display().to_string()).size(20.0));
                        }

                        ui.add_space(20.0);

                        if ui.add_enabled(self.file_shredder_input.is_some(),
                            egui::Button::new("Shred File")
                        ).clicked() {
                            self.confirm_shred = true;
                            self.success_shred = false;
                            self.failure_shred = false;
                        }

                        if self.confirm_shred {
                            ui.label("Are you sure you want to permanently delete this file?");

                            if ui.button("Yes").clicked() {
                                if let Some(path) = &self.file_shredder_input {
                                    match shred_file(path, 3) {
                                        Ok(()) => {
                                            self.success_shred = true;
                                            self.failure_shred = false;
                                            self.file_shredder_input = None;
                                        }
                                        Err(_e) => {
                                            self.success_shred = false;
                                            self.failure_shred = true;
                                        }
                                    }
                                    self.confirm_shred = false;
                                }
                            }

                            if ui.button("No").clicked() {
                                self.file_shredder_input = None;
                                self.confirm_shred = false;
                            }
                        }

                        if self.success_shred {
                            ui.label(egui::RichText::new("File deletion successful").color(egui::Color32::from_rgb(0, 255, 0)));
                        }

                        if self.failure_shred {
                            ui.label(egui::RichText::new("An error occured when trying to delete file").color(egui::Color32::from_rgb(255, 0, 0)));
                        }
                    });
                }
            }

        }); // End of CentralPanel
    }
}

fn main() -> Result<(), eframe::Error> {
    let native_options = NativeOptions::default();
    eframe::run_native(
        "RustCrypt",
        native_options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}