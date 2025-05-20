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
            match fs::read_to_string(file_path) {
                Ok(content) => {
                    match serde_json::from_str(&content) {
                        Ok(pf) => pf,
                        Err(e) => {
                            eprintln!("Error parsing password file {}: {}", file_path, e);
                            PasswordFile {
                                salt: rand::thread_rng().sample_iter(&Alphanumeric).take(SALT_LENGTH).collect(),
                                passwords: HashMap::new(),
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading password file {}: {}", file_path, e);
                    PasswordFile {
                        salt: rand::thread_rng().sample_iter(&Alphanumeric).take(SALT_LENGTH).collect(),
                        passwords: HashMap::new(),
                    }
                }
            }
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
            let website = record.get(1).ok_or_else(|| {
                anyhow!(
                    "Missing URL (expected at index 1) in CSV record. Record data: {:?}",
                    record.iter().collect::<Vec<&str>>()
                )
            })?;
            let username = record.get(2).ok_or_else(|| {
                anyhow!(
                    "Missing Username (expected at index 2) in CSV record. Record data: {:?}",
                    record.iter().collect::<Vec<&str>>()
                )
            })?;
            let password = record.get(3).ok_or_else(|| {
                anyhow!(
                    "Missing Password (expected at index 3) in CSV record. Record data: {:?}",
                    record.iter().collect::<Vec<&str>>()
                )
            })?;
            
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    // Helper function to clean up files, ignoring errors if the file doesn't exist
    fn cleanup_file(path: &str) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_new_password_manager() {
        let test_file = "test_passwords_new.enc";
        cleanup_file(test_file); // Ensure clean state before test

        let pm = PasswordManager::new(test_file);
        assert!(!pm.password_file.salt.is_empty(), "Salt should be generated for a new password manager.");
        
        // The PasswordManager::new creates an empty file if it doesn't exist, or reads it.
        // If it was newly created, it won't save the salt until a password is stored.
        // For this test, the salt is in memory. If the file was created, it would be empty.
        // If we want to test file creation, we should store a password.
        // However, the requirement is to check `password_file.salt` in memory.

        cleanup_file(test_file);
    }

    #[test]
    fn test_store_and_get_password() {
        let test_file = "test_passwords_store_get.enc";
        cleanup_file(test_file);

        let mut pm = PasswordManager::new(test_file);
        pm.initialize("test_master_password").expect("Initialization failed");

        let website = "https://example.com";
        let username = "testuser";
        let password = "testpassword123";

        pm.store_password(website, username, password).expect("Storing password failed");
        
        let (retrieved_username, retrieved_password) = pm.get_password(website).expect("Getting password failed");

        assert_eq!(retrieved_username, username);
        assert_eq!(retrieved_password, password);

        cleanup_file(test_file);
    }

    #[test]
    fn test_get_non_existent_password() {
        let test_file = "test_passwords_non_existent.enc";
        cleanup_file(test_file);

        let mut pm = PasswordManager::new(test_file);
        pm.initialize("test_master_password").expect("Initialization failed");

        let result = pm.get_password("https://nonexistent.com");
        assert!(result.is_err(), "Expected an error when getting a non-existent password.");

        cleanup_file(test_file);
    }

    #[test]
    fn test_generate_password() {
        let test_file = "test_passwords_generate.enc"; // Not strictly used, but for consistency
        cleanup_file(test_file);

        let pm = PasswordManager::new(test_file);
        let length = 12;
        let password = pm.generate_password(length);
        assert_eq!(password.len(), length, "Generated password has incorrect length.");

        // Optional: Check if password contains characters from the defined CHARSET
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        for char_code in password.as_bytes() {
            assert!(CHARSET.contains(char_code), "Generated password contains invalid character.");
        }
        
        cleanup_file(test_file); // File might not be created, but cleanup is harmless
    }

    #[test]
    fn test_import_from_csv_basic() {
        let csv_file_path = "test_import_data.csv";
        let pm_file_path = "test_passwords_import.enc";
        cleanup_file(csv_file_path);
        cleanup_file(pm_file_path);

        // Create a temporary CSV file
        let mut file = fs::File::create(csv_file_path).expect("Failed to create test CSV file");
        writeln!(file, "name,url,username,password").expect("Write header failed");
        writeln!(file, "ExampleSite,https://example.com,user1,pass1").expect("Write row 1 failed");
        writeln!(file, "AnotherSite,https://another.org,user2,pass2").expect("Write row 2 failed");
        drop(file); // Ensure file is closed

        let mut pm = PasswordManager::new(pm_file_path);
        pm.initialize("test_master_password").expect("Initialization failed");

        let import_result = pm.import_from_csv(csv_file_path);
        assert!(import_result.is_ok(), "Import from CSV failed: {:?}", import_result.err());

        // Verify imported passwords
        let (user1_username, user1_password) = pm.get_password("https://example.com").expect("Failed to get password for example.com");
        assert_eq!(user1_username, "user1");
        assert_eq!(user1_password, "pass1");

        let (user2_username, user2_password) = pm.get_password("https://another.org").expect("Failed to get password for another.org");
        assert_eq!(user2_username, "user2");
        assert_eq!(user2_password, "pass2");
        
        cleanup_file(csv_file_path);
        cleanup_file(pm_file_path);
    }
}
