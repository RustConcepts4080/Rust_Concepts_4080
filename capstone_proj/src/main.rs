mod encryption;

use std::fs;
use std::path::PathBuf;
use eframe::{egui, App as EframeApp, Frame, NativeOptions};
use egui::Context;
use rfd::FileDialog;
use encryption::{generate_hmac, verify_hmac};

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
        }
    }
}

impl EframeApp for App {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        // Top header
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.heading("Rust File Encryptor");
        });

        // Main area
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                // ── Encrypt section ─────────────────────────────────────
                ui.group(|ui| {
                    ui.heading("Encrypt");

                    if ui.button("Select Input File").clicked() {
                        if let Some(p) = FileDialog::new().pick_file() {
                            self.encrypt_input = Some(p);
                        }
                    }
                    if let Some(path) = &self.encrypt_input {
                        ui.label(path.display().to_string());
                    }

                    if ui.button("Select Output Folder").clicked() {
                        if let Some(f) = FileDialog::new().pick_folder() {
                            self.encrypt_output_dir = Some(f);
                        }
                    }
                    if let Some(dir) = &self.encrypt_output_dir {
                        ui.label(dir.display().to_string());
                    }

                    ui.label("Key (16 chars):");
                    ui.text_edit_singleline(&mut self.encrypt_key);

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.encrypt_mode_parallel, "Parallel");
                        if self.encrypt_mode_parallel {
                            ui.add(
                                egui::DragValue::new(&mut self.encrypt_threads)
                                    .range(1..=32)
                                    .prefix("threads: "),
                            );
                        }
                    });

                    if ui.button("Encrypt ▶").clicked() {
                        if let (Some(in_path), Some(out_dir)) =
                            (&self.encrypt_input, &self.encrypt_output_dir)
                        {
                            if self.encrypt_key.len() == 16 {
                                let data = fs::read(in_path).expect("read failed");
                                let ext = in_path
                                    .extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("");
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
                                println!("Encrypted → {}", out_file.display());
                            } else {
                                println!("Key must be 16 characters");
                            }
                        } else {
                            println!("Select input file and output folder first");
                        }
                    }
                }); 

                ui.add_space(20.0);

                // ── Decrypt section ─────────────────────────────────────
                ui.group(|ui| {
                    ui.heading("Decrypt");

                    if ui.button("Select Encrypted File").clicked() {
                        if let Some(p) = FileDialog::new().pick_file() {
                            self.decrypt_input = Some(p);
                        }
                    }
                    if let Some(path) = &self.decrypt_input {
                        ui.label(path.display().to_string());
                    }

                    if ui.button("Select Output Folder").clicked() {
                        if let Some(f) = FileDialog::new().pick_folder() {
                            self.decrypt_output_dir = Some(f);
                        }
                    }
                    if let Some(dir) = &self.decrypt_output_dir {
                        ui.label(dir.display().to_string());
                    }

                    ui.label("Key (16 chars):");
                    ui.text_edit_singleline(&mut self.decrypt_key);

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.decrypt_mode_parallel, "Parallel");
                        if self.decrypt_mode_parallel {
                            ui.add(
                                egui::DragValue::new(&mut self.decrypt_threads)
                                    .range(1..=32)
                                    .prefix("threads: "),
                            );
                        }
                    });

                    if ui.button("Decrypt ▶").clicked() {
                        if let (Some(in_path), Some(out_dir)) =
                            (&self.decrypt_input, &self.decrypt_output_dir)
                        {
                            if self.decrypt_key.len() == 16 {
                           
                                let blob = fs::read(in_path).expect("read failed");
                                if blob.len() < 4 {
                                    println!("Invalid file! File size too small");
                                    return;
                                }
                                
                                let ext_len = u32::from_be_bytes(blob[0..4].try_into().unwrap()) as usize;
                                let iv_start = 4 + ext_len;
                                let iv_end = iv_start + 16;
                                
                                if blob.len() < iv_end + 32 {
                                    println!("Invalid file! Corrupted or tampered.");
                                    return;
                                }
                                
                                let ext = if ext_len > 0 {
                                    String::from_utf8_lossy(&blob[4..4 + ext_len]).to_string()
                                } else {
                                    String::new()
                                };
                                
                                let mut iv = [0u8; 16];
                                iv.copy_from_slice(&blob[iv_start..iv_end]);
                                let total = blob.len();
                                if total < iv_start + 16 + 32 {
                                    println!("File too small or corrupted.");
                                    return;
                                }

                                let encrypted_data_end = total - 32;
                                let encrypted_data = &blob[iv_start + 16..encrypted_data_end];
                                let hmac = &blob[encrypted_data_end..];

                                if !verify_hmac(hmac, encrypted_data, self.decrypt_key.as_bytes()) {
                                    println!("HMAC verification failed! Your file may be corrupted OR the Key is incorrect.");
                                    return;
                                } else {
                                    println!("Yoohoo! HMAC verified. File has not been tampered with.");
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
                                let file_stem = in_path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("decrypted");
                                let out_name = if ext.is_empty() {
                                    format!("{file_stem}_dec.bin")
                                } else {
                                    format!("{file_stem}_dec.{ext}")
                                };
                                let out_file = out_dir.join(out_name);
                                fs::write(&out_file, decrypted).expect("write failed");
                                println!("Decrypted → {}", out_file.display());
                            } else {
                                println!("Key must be 16 characters");
                            }
                        } else {
                            println!("Select encrypted file and output folder first");
                        }
                    }
                }); 
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