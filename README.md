# RustCrypt

GUI intended to encrypt, decrypt, or shred individual files via AES-128 CTR. Ensuring file integrity by verifying if encrypted file was tampered with or not.

## How to run
1. Ensure rustc is installed
   - Verify if installed via running `rustc --version` on desired terminal
3. Pull Rust_Concepts_4080 repository
4. Open a terminal and go to Repository directory
5. `cd` into capstone_proj
6. run `cargo run`
Should now install dependencies and run the GUI!

## Implemented Features
- Concurrency: Allowing Encryption & Decryption to be done in parallel and able to select amount of desired threads.
- GUI: Simplified userface to allow users to navigate through the options.
- File Integrity: Implementing HMAC to ensure that encrypted files were not tampered with before decrypting files.
- File Shredder: Properly deleting encrypted or desired files.

## Codebase Structure
```
.
└── capstone_proj/
    ├── src/
    │   ├── encryption.rs
    │   ├── file_shredder.rs
    │   └── main.rs
    └── Cargo.toml
```
- encryption.rs: contains logic for AES-128 encryption, decryption, and file intregrity
- file_shredder.rs: contains logic for shredding files
- main.rs: contains logic of GUI & integrates `encryption.rs` & `file_shredder.rs` logic into the GUI.

## Dependencies Used
*Can refer to `capstone_proj/Cargo.toml` also*  

```toml
base64 = "0.21"  
aes = "0.8"  
ctr = "0.9"  
rand = "0.8"  
sha2 = "0.10"  
eframe = "0.31.1"  
egui = "0.31.1"  
rfd = "0.15.3"  
hmac = "0.12"
```
