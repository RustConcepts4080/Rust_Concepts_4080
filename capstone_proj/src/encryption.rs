use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Sha256, Digest};
use rand::Rng;
use std::sync::{Arc, Mutex};
use std::thread;

pub type Aes128Ctr = ctr::Ctr128BE<Aes128>;

pub fn encrypt_series(data: &[u8], key: &[u8], base_iv: &[u8; 16]) -> Vec<u8> {
    let iv = derive_chunk_iv(base_iv, 0);
    encrypt_chunk(data, key, &iv)
}


pub fn parallel_encrypt(data: &[u8], key: &[u8], base_iv: &[u8; 16], num_threads: usize) -> Vec<u8> {
    let chunk_size = (data.len() + num_threads - 1) / num_threads;

    let encrypted_results = Arc::new(Mutex::new(vec![Vec::new(); num_threads]));
    let mut encrypt_handles = vec![];

    for i in 0..num_threads {
        let start = i * chunk_size;
        let end = ((i + 1) * chunk_size).min(data.len());

        if start >= end {
            continue;
        }

        let chunk = data[start..end].to_vec();
        let encrypted_results = Arc::clone(&encrypted_results);
        let iv = derive_chunk_iv(base_iv, i as u32);
        let key = key.to_vec();

        let handle = thread::spawn(move || {
            let encrypted = encrypt_chunk(&chunk, &key, &iv);
            encrypted_results.lock().unwrap()[i] = encrypted;
        });

        encrypt_handles.push(handle);
    }

    for handle in encrypt_handles {
        handle.join().unwrap();
    }

    encrypted_results.lock().unwrap().concat()
}


fn encrypt_chunk(chunk: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
    let mut buffer = chunk.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}


pub fn decrypt_series(data: &[u8], key: &[u8], base_iv: &[u8; 16]) -> Vec<u8> {
    let iv = derive_chunk_iv(base_iv, 0);
    decrypt_chunk(data, key, &iv)
}

pub fn parallel_decrypt(data: &[u8], key: &[u8], base_iv: &[u8; 16], num_threads: usize) -> Vec<u8> {
    let chunk_size = (data.len() + num_threads - 1) / num_threads;

    let decrypted_results = Arc::new(Mutex::new(vec![Vec::new(); num_threads]));
    let mut decrypt_handles = vec![];

    for i in 0..num_threads {
        let start = i * chunk_size;
        let end = ((i + 1) * chunk_size).min(data.len());

        if start >= end {
            continue;
        }
        
        let chunk = data[start..end].to_vec();
        let decrypted_results = Arc::clone(&decrypted_results);
        let iv = derive_chunk_iv(base_iv, i as u32);
        let key = key.to_vec(); // clone key for thread move

        let handle = thread::spawn(move || {
            let decrypted = decrypt_chunk(&chunk, &key, &iv);
            decrypted_results.lock().unwrap()[i] = decrypted;
        });

        decrypt_handles.push(handle);
    }

    for handle in decrypt_handles {
        handle.join().unwrap();
    }

    decrypted_results.lock().unwrap().concat()
}


fn decrypt_chunk(chunk: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    encrypt_chunk(chunk, key, iv)
}

fn derive_chunk_iv(base_iv: &[u8; 16], chunk_index: u32) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(base_iv);
    hasher.update(chunk_index.to_be_bytes());
    let result = hasher.finalize();

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&result[..16]);
    iv
}

/// Generates a secure random 128-bit (16-byte) IV.
pub fn generate_base_iv() -> [u8; 16] {
    rand::thread_rng().r#gen()
}
