mod encryption;

use std::fs;
use std::path::PathBuf;
use eframe::{egui, App as EframeApp, Frame, NativeOptions};
use egui::Context;
use rfd::FileDialog;
use sha2::{Sha256, Digest};

struct App {
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
}

impl Default for App {
    fn default() -> Self {
        Self {
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
        }
    }
}

impl EframeApp for App {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        let mut style = (*ctx.style()).clone();
        style.override_font_id = Some(egui::FontId::monospace(20.0));
        ctx.set_style(style);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Rust File Encryptor").strong().size(62.0)
                        .color(egui::Color32::from_rgb(255, 165, 0))
                );
            });

            ui.add_space(20.0);
            ui.allocate_ui(egui::vec2(ui.available_width(), 3.0), |ui| {
                let rect = ui.max_rect();
                ui.painter().rect_filled(
                    rect,
                    0.0,
                    egui::Color32::WHITE,
                );
            });
            ui.add_space(40.0);

            ui.vertical_centered_justified(|ui| {
                if ui.add_sized(
                    egui::vec2(50.0, 60.0),
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

                                let mut hasher = Sha256::new();
                                hasher.update(&encrypted);
                                let hash = hasher.finalize();
                                blob.extend(&hash);

                                let file_stem = in_path.file_stem().and_then(|s| s.to_str()).unwrap_or("output");
                                let out_file = out_dir.join(format!("{file_stem}.crypt"));
                                fs::write(&out_file, blob).expect("write failed");
                                self.status_message = format!("Encrypted → {}", out_file.display());
                            } else {
                                self.status_message = "Key must be 16 characters".into();
                            }
                        } else {
                            self.status_message = "Select input file and output folder first".into();
                        }
                    }
                }

                ui.add_space(20.0);

                if ui.add_sized(
                    egui::vec2(50.0, 60.0),
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
                        if let (Some(in_path), Some(out_dir)) = (&self.decrypt_input, &self.decrypt_output_dir) {
                            if self.decrypt_key.len() == 16 {
                                let blob = fs::read(in_path).expect("read failed");
                                let ext_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
                                let ext = if ext_len > 0 {
                                    String::from_utf8_lossy(&blob[4..4 + ext_len]).to_string()
                                } else {
                                    String::new()
                                };
                                let iv_start = 4 + ext_len;
                                let mut iv = [0u8; 16];
                                iv.copy_from_slice(&blob[iv_start..iv_start + 16]);

                                let hash_start = blob.len() - 32;
                                let encrypted_data = &blob[iv_start + 16..hash_start];
                                let hash = &blob[hash_start..];

                                let mut hasher = Sha256::new();
                                hasher.update(encrypted_data);
                                let computed = hasher.finalize();

                                if hash != computed.as_slice() {
                                    self.status_message = "Integrity check failed!".into();
                                    return;
                                }

                                let decrypted = if self.decrypt_mode_parallel {
                                    encryption::parallel_decrypt(
                                        encrypted_data,
                                        self.decrypt_key.as_bytes().try_into().unwrap(),
                                        &iv,
                                        self.decrypt_threads,
                                    )
                                } else {
                                    encryption::decrypt_series(
                                        encrypted_data,
                                        self.decrypt_key.as_bytes().try_into().unwrap(),
                                        &iv,
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
                }

                ui.add_space(10.0);
                let color = if self.status_message.contains("Encrypted") || self.status_message.contains("Decrypted") {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                ui.colored_label(color, egui::RichText::new(&self.status_message).size(20.0));
                
                
                //ui.label(egui::RichText::new(&self.status_message).size(20.0));
            });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let native_options = NativeOptions::default();
    eframe::run_native(
        "Rust File Encryptor",
        native_options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
