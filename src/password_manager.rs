use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{distributions::Alphanumeric, Rng, RngCore};  // Added RngCore
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use csv::ReaderBuilder;  // Added CSV reader

const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;

#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PasswordFile {
    salt: Vec<u8>,
    passwords: HashMap<String, PasswordEntry>,
}

pub struct PasswordManager {
    file_path: String,
    cipher: Option<XChaCha20Poly1305>,
    password_file: PasswordFile,
}

impl PasswordManager {
    pub fn new(file_path: &str) -> Self {
        let password_file = if Path::new(file_path).exists() {
            let content = fs::read_to_string(file_path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or(PasswordFile {
                salt: vec![],
                passwords: HashMap::new(),
            })
        } else {
            PasswordFile {
                salt: rand::thread_rng().sample_iter(&Alphanumeric).take(SALT_LENGTH).collect(),
                passwords: HashMap::new(),
            }
        };

        Self {
            file_path: file_path.to_string(),
            cipher: None,
            password_file,
        }
    }

    pub fn initialize(&mut self, master_password: &str) -> Result<()> {
        let argon2 = argon2::Argon2::default();
        let mut key = [0u8; 32];
        
        argon2.hash_password_into(
            master_password.as_bytes(),
            &self.password_file.salt,
            &mut key,
        )?;
        
        self.cipher = Some(XChaCha20Poly1305::new(key.as_ref().into()));
        Ok(())
    }

    pub fn store_password(&mut self, website: &str, username: &str, password: &str) -> Result<()> {
        let cipher = self.cipher.as_ref().ok_or(anyhow!("Not initialized"))?;
        let mut nonce = [0u8; NONCE_LENGTH];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce = XNonce::from_slice(&nonce);
        
        let data = format!("{}:{}", username, password);
        let ciphertext = cipher
            .encrypt(nonce, data.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        self.password_file.passwords.insert(
            website.to_string(),
            PasswordEntry {
                nonce: nonce.to_vec(),
                ciphertext,
            },
        );

        self.save_to_file()?;
        Ok(())
    }

    pub fn get_password(&self, website: &str) -> Result<(String, String)> {
        let cipher = self.cipher.as_ref().ok_or(anyhow!("Not initialized"))?;
        let entry = self.password_file
            .passwords
            .get(website)
            .ok_or(anyhow!("Website not found"))?;

        let nonce = XNonce::from_slice(&entry.nonce);
        let plaintext = cipher
            .decrypt(nonce, entry.ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        let data = String::from_utf8(plaintext)?;
        let mut parts = data.split(':');
        let username = parts.next().ok_or(anyhow!("Invalid data format"))?.to_string();
        let password = parts.next().ok_or(anyhow!("Invalid data format"))?.to_string();

        Ok((username, password))
    }

    pub fn generate_password(&self, length: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub fn import_from_csv(&mut self, csv_path: &str) -> Result<()> {
        let mut rdr = ReaderBuilder::new()
            .has_headers(true)
            .from_path(csv_path)
            .map_err(|e| anyhow!("Failed to open CSV file: {}", e))?;
        
        for result in rdr.records() {
            let record = result.map_err(|e| anyhow!("Error reading CSV record: {}", e))?;
            let website = record.get(1).ok_or(anyhow!("Missing URL"))?;
            let username = record.get(2).ok_or(anyhow!("Missing Username"))?;
            let password = record.get(3).ok_or(anyhow!("Missing Password"))?;
            
            self.store_password(website, username, password)?;
        }
        
        Ok(())
    }

    fn save_to_file(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.password_file)?;
        fs::write(&self.file_path, content)?;
        Ok(())
    }
}
