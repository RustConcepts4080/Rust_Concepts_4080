mod encryption;

use std::fs;
use std::io::{self, Write};
use base64::{engine::general_purpose, Engine as _};

fn prompt_choice(prompt: &str, valid_options: &[&str]) -> String {
    loop {
        let input = prompt_input(prompt);
        if valid_options.contains(&input.as_str()) {
            return input;
        }
        println!("Invalid option. Please try again.");
    }
}

fn prompt_usize(prompt: &str) -> usize {
    loop {
        let input = prompt_input(prompt);
        if let Ok(n) = input.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
        println!("Please enter a valid integer greater than 0.");
    }
}

fn prompt_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}


fn main() -> io::Result<()> {
    // PROMPTING
    let action = prompt_choice("Choose operation:\n1) Encrypt\n2) Decrypt\n> ", &["1", "2"]);

    // ENCRYPTION
    if action == "1" {   
        let mode = prompt_choice("Choose input type:\n1) String\n2) File path\n> ", &["1", "2"]);
        let data = match mode.as_str() {
            "1" => prompt_input("Enter string to encrypt: ").into_bytes(),
            "2" => {
                let path = prompt_input("Enter file path: ");
                match fs::read(&path) {
                    Ok(data) => data,
                    Err(_) => {
                        println!("Failed to read file. Exiting.");
                        return Ok(());
                    }
                }
            },
            _ => unreachable!(),
        };
    
        let key: [u8; 16] = loop {
            let key_input = prompt_input("Enter 16-character encryption key: ");
            if key_input.len() == 16 {
                break key_input.as_bytes().try_into().unwrap();
            } else {
                println!("Key must be exactly 16 characters long. Please try again.");
            }
        };
    
        let enc_method = prompt_choice("Choose encryption mode:\n1) Parallel\n2) Series\n> ", &["1", "2"]);
        let num_threads = if enc_method == "1" {
            prompt_usize("Enter number of threads to use: ").min(4).max(32)
        } else {
            0
        };
    
        let base_iv = encryption::generate_base_iv();
        let encrypted_data = match enc_method.as_str() {
            "1" => encryption::parallel_encrypt(&data, &key, &base_iv, num_threads),
            "2" => encryption::encrypt_series(&data, &key, &base_iv),
            _ => unreachable!(),
        };
    
        let encoded_iv = general_purpose::STANDARD.encode(&base_iv);
        println!("\nBase IV (Base64): {}", encoded_iv);

        println!("Encrypted (Base64): {}", general_purpose::STANDARD.encode(&encrypted_data));
        
        // HMAC
        let hmac = encryption::generate_hmac(&data, &key);
        println!("HMAC (for integrity verification): {}", hmac);
    }
    // DECRYPTION
    else if action == "2" {
        let mode = prompt_choice("Choose input type:\n1) Base64 string\n2) File path\n> ", &["1", "2"]);
        let encrypted_data = match mode.as_str() {
            "1" => {
                let b64 = prompt_input("Paste Base64 encrypted text: ");
                match general_purpose::STANDARD.decode(b64) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        println!("Invalid Base64 input. Exiting.");
                        return Ok(());
                    }
                }
            },
            "2" => {
                let path = prompt_input("Enter file path to encrypted data: ");
                match fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        println!("Failed to read file. Exiting.");
                        return Ok(());
                    }
                }
            },
            _ => unreachable!(),
        };
    
        let key: [u8; 16] = loop {
            let key_input = prompt_input("Enter 16-character decryption key: ");
            if key_input.len() == 16 {
                break key_input.as_bytes().try_into().unwrap();
            } else {
                println!("Key must be exactly 16 characters long. Please try again.");
            }
        };
    
        let iv_b64 = prompt_input("Enter Base64-encoded Base IV: ");
        let decoded_iv = match general_purpose::STANDARD.decode(iv_b64) {
            Ok(bytes) if bytes.len() == 16 => {
                let mut base_iv = [0u8; 16];
                base_iv.copy_from_slice(&bytes);
                base_iv
            }
            _ => {
                println!("Invalid Base64 IV. Must decode to exactly 16 bytes.");
                return Ok(());
            }
        };

    
        let dec_method = prompt_choice("Choose decryption mode:\n1) Parallel\n2) Series\n> ", &["1", "2"]);
        let num_threads = if dec_method == "1" {
            prompt_usize("Enter number of threads to use: ").min(4).max(32)
        } else {
            0
        };
    
        let decrypted_data = match dec_method.as_str() {
            "1" => encryption::parallel_decrypt(&encrypted_data, &key, &decoded_iv, num_threads),
            "2" => encryption::decrypt_series(&encrypted_data, &key, &decoded_iv),
            _ => unreachable!(),
        };
    
        println!("Decrypted text:\n{}", String::from_utf8_lossy(&decrypted_data));
    

        //HMAC File integrity check
        let expected_hmac = prompt_input("Enter expected HMAC for integrity check: ");
        if encryption::verify_hmac(&expected_hmac, &decrypted_data, &key) {
        println!("Integrity verified!");
        } else {
        println!("Integrity check failed. The file may have been tampered with.");
        }
    }

    Ok(())
}