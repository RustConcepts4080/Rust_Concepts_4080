mod encryption;

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use base64::{engine::general_purpose, Engine as _};

fn prompt_choice(prompt: &str, valid: &[&str]) -> String {
    loop {
        let input = prompt_input(prompt);
        if valid.contains(&input.as_str()) {
            return input;
        }
        println!("Invalid option. Try again.");
    }
}

fn prompt_usize(prompt: &str) -> usize {
    loop {
        if let Ok(n) = prompt_input(prompt).parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
        println!("Enter a number > 0.");
    }
}

fn prompt_key() -> [u8; 16] {
    loop {
        let k = prompt_input("Enter 16-character key: ");
        if k.len() == 16 {
            return k.as_bytes().try_into().unwrap();
        }
        println!("Key must be exactly 16 characters.");
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
    match prompt_choice("Choose operation:\n1) Encrypt\n2) Decrypt\n> ", &["1", "2"]).as_str() {
        "1" => run_encryption()?,
        "2" => run_decryption()?,
        _ => unreachable!(),
    }
    Ok(())
}

fn run_encryption() -> io::Result<()> {
    let mode = prompt_choice("Input type:\n1) String\n2) File\n> ", &["1", "2"]);
    let (data, extension) = match mode.as_str() {
        "1" => (prompt_input("Enter string: ").into_bytes(), None),
        "2" => {
            let path = prompt_input("Enter file path: ");
            let ext = Path::new(&path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();
            (fs::read(&path)?, Some(ext))
        },
        _ => unreachable!(),
    };

    let output = prompt_input("Output path & file name: ");
    let key = prompt_key();
    let method = prompt_choice("Encrypt mode:\n1) Parallel\n2) Series\n> ", &["1", "2"]);
    let threads = if method == "1" {
        prompt_usize("Threads: ").min(32)
    } else {
        0
    };

    let iv = encryption::generate_base_iv();
    let encrypted = match method.as_str() {
        "1" => encryption::parallel_encrypt(&data, &key, &iv, threads),
        "2" => encryption::encrypt_series(&data, &key, &iv),
        _ => unreachable!(),
    };

    let mut result = Vec::new();

    // Embed file extension
    if let Some(ext) = extension {
        let ext_bytes = ext.as_bytes();
        let ext_len = ext_bytes.len() as u32;
        result.extend(&ext_len.to_be_bytes());
        result.extend(ext_bytes);
    } else {
        result.extend(&(0u32.to_be_bytes()));
    }

    result.extend(&iv);
    result.extend(encrypted);

    fs::write(output, result)?;
    println!("Encryption complete.");
    Ok(())
}

fn run_decryption() -> io::Result<()> {
    let mode = prompt_choice("Input type:\n1) Base64\n2) File\n> ", &["1", "2"]);
    let (data, base_iv, extension, output_path) = if mode == "1" {
        let b64 = general_purpose::STANDARD.decode(prompt_input("Paste Base64: ")).unwrap();
        let iv_b64 = general_purpose::STANDARD.decode(prompt_input("Enter IV (Base64): ")).unwrap();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_b64);
        (b64, iv, None, prompt_input("Output path: "))
    } else {
        let file = fs::read(prompt_input("Encrypted file path: "))?;
        if file.len() < 20 {
            println!("Invalid file.");
            return Ok(());
        }
        let ext_len = u32::from_be_bytes(file[..4].try_into().unwrap()) as usize;
        let ext = if ext_len > 0 {
            Some(String::from_utf8_lossy(&file[4..4 + ext_len]).to_string())
        } else {
            None
        };
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&file[4 + ext_len..4 + ext_len + 16]);
        let data = file[4 + ext_len + 16..].to_vec();

        let mut output_path = prompt_input("Enter output file path (or leave blank to restore extension): ");
        if output_path.is_empty() {
            output_path = if let Some(ext) = &ext {
                format!("decrypted_output.{}", ext)
            } else {
                "decrypted_output.bin".to_string()
            };
        } else if let Some(ext) = &ext {
            output_path = format!("{}.{ext}", output_path);
        }

        (data, iv, ext, output_path)
    };

    let key = prompt_key();
    let method = prompt_choice("Decrypt mode:\n1) Parallel\n2) Series\n> ", &["1", "2"]);
    let threads = if method == "1" {
        prompt_usize("Threads: ").min(32)
    } else {
        0
    };

    let decrypted = match method.as_str() {
        "1" => encryption::parallel_decrypt(&data, &key, &base_iv, threads),
        "2" => encryption::decrypt_series(&data, &key, &base_iv),
        _ => unreachable!(),
    };

    fs::write(output_path, decrypted)?;
    println!("Decryption complete.");
    Ok(())
}
