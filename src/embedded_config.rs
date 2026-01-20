use hbb_common::{log, sodiumoxide::crypto::secretbox};
use std::fs;
use std::path::PathBuf;

/// Encrypted configuration file system
/// Creates encrypted rustdesk.cfg next to exe if it doesn't exist
/// Always reads and decrypts configuration from this file
/// Users cannot read the settings in plain text

// Encryption key (32 bytes) - Random characters
const ENCRYPTION_KEY: &[u8; 32] = b"7Kq9Xp2Wm5Nv8Rz3Yc6Hb1Jf4Gt0Ls!";

// Nonce for secretbox (24 bytes) - Random characters  
const NONCE_BYTES: &[u8; 24] = b"9Az4Qx7Wd2Sc5Vf8Gb1Nk3M";

// Default configuration values
const DEFAULT_SERVER: &str = "85.113.41.100";
const DEFAULT_API: &str = "https://85.113.41.100";
const DEFAULT_KEY: &str = "sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=";
const DEFAULT_PASSWORD: &str = "Pw59881141";

#[derive(Debug, Clone)]
pub struct EncryptedConfig {
    pub server: String,
    pub api: String,
    pub key: String,
    pub password: String,
}

impl EncryptedConfig {
    /// Get the path to rustdesk.cfg next to the executable
    fn get_config_path() -> Option<PathBuf> {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return Some(exe_dir.join("rustdesk.cfg"));
            }
        }
        None
    }
    
    /// Create default configuration with default values
    fn default() -> Self {
        EncryptedConfig {
            server: DEFAULT_SERVER.to_string(),
            api: DEFAULT_API.to_string(),
            key: DEFAULT_KEY.to_string(),
            password: DEFAULT_PASSWORD.to_string(),
        }
    }
    
    /// Serialize config to string format: server|api|key|password
    fn to_string(&self) -> String {
        format!("{}|{}|{}|{}", self.server, self.api, self.key, self.password)
    }
    
    /// Deserialize config from string format
    fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() != 4 {
            return None;
        }
        
        Some(EncryptedConfig {
            server: parts[0].to_string(),
            api: parts[1].to_string(),
            key: parts[2].to_string(),
            password: parts[3].to_string(),
        })
    }
    
    /// Encrypt configuration data
    fn encrypt(&self) -> Vec<u8> {
        let key = secretbox::Key(*ENCRYPTION_KEY);
        let nonce = secretbox::Nonce(*NONCE_BYTES);
        let plaintext = self.to_string().into_bytes();
        
        secretbox::seal(&plaintext, &nonce, &key)
    }
    
    /// Decrypt configuration data
    fn decrypt(encrypted: &[u8]) -> Option<Self> {
        let key = secretbox::Key(*ENCRYPTION_KEY);
        let nonce = secretbox::Nonce(*NONCE_BYTES);
        
        match secretbox::open(encrypted, &nonce, &key) {
            Ok(decrypted) => {
                if let Ok(text) = String::from_utf8(decrypted) {
                    Self::from_string(&text)
                } else {
                    None
                }
            }
            Err(_) => {
                log::error!("Failed to decrypt configuration - file may be corrupted");
                None
            }
        }
    }
    
    /// Save encrypted configuration to file
    fn save_to_file(&self, path: &PathBuf) -> bool {
        let encrypted = self.encrypt();
        match fs::write(path, encrypted) {
            Ok(_) => {
                log::info!("Encrypted configuration saved to: {}", path.display());
                true
            }
            Err(e) => {
                log::error!("Failed to save encrypted configuration: {}", e);
                false
            }
        }
    }
    
    /// Load encrypted configuration from file
    fn load_from_file(path: &PathBuf) -> Option<Self> {
        match fs::read(path) {
            Ok(encrypted) => {
                log::info!("Reading encrypted configuration from: {}", path.display());
                Self::decrypt(&encrypted)
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {}", e);
                None
            }
        }
    }
    
    /// Load configuration: read from file or create default
    pub fn load() -> Option<Self> {
        let config_path = Self::get_config_path()?;
        
        // Check if config file exists
        if config_path.exists() {
            // Try to load from file
            if let Some(config) = Self::load_from_file(&config_path) {
                log::info!("Encrypted configuration loaded from file");
                return Some(config);
            } else {
                log::warn!("Failed to load configuration from file, creating new one");
            }
        } else {
            log::info!("Configuration file not found, creating default");
        }
        
        // Create default configuration and save it
        let config = Self::default();
        if config.save_to_file(&config_path) {
            log::info!("Default encrypted configuration created successfully");
            Some(config)
        } else {
            log::error!("Failed to create default configuration file");
            // Still return the config even if save failed
            Some(config)
        }
    }
    
    /// Apply the configuration to RustDesk settings
    pub fn apply(&self) {
        log::info!("Applying encrypted configuration");
        
        // Set custom rendezvous server (ID Server)
        if !self.server.is_empty() {
            hbb_common::config::Config::set_option(
                "custom-rendezvous-server".to_owned(),
                self.server.clone(),
            );
            log::info!("Applied rendezvous server: {}", self.server);
        }
        
        // Set API server
        if !self.api.is_empty() {
            hbb_common::config::Config::set_option("api-server".to_owned(), self.api.clone());
            log::info!("Applied API server: {}", self.api);
        }
        
        // Set encryption key
        if !self.key.is_empty() {
            hbb_common::config::Config::set_option("key".to_owned(), self.key.clone());
            log::info!("Applied encryption key");
        }
        
        // Set permanent password
        if !self.password.is_empty() {
            hbb_common::config::Config::set_permanent_password(&self.password);
            log::info!("Applied permanent password");
        }
    }
}

/// Main entry point: Load and apply encrypted configuration
/// This function is called during RustDesk startup
/// - Checks if rustdesk.cfg exists next to exe
/// - If not, creates it with default encrypted settings
/// - Reads and decrypts configuration from file
/// - Applies settings to RustDesk
pub fn load_and_apply_embedded_config() {
    log::info!("Initializing encrypted configuration system");
    
    if let Some(config) = EncryptedConfig::load() {
        config.apply();
        log::info!("Encrypted configuration successfully applied");
    } else {
        log::error!("Failed to load encrypted configuration");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = EncryptedConfig::default();
        let serialized = config.to_string();
        let deserialized = EncryptedConfig::from_string(&serialized);
        
        assert!(deserialized.is_some());
        let config2 = deserialized.unwrap();
        assert_eq!(config.server, config2.server);
        assert_eq!(config.api, config2.api);
        assert_eq!(config.key, config2.key);
        assert_eq!(config.password, config2.password);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let config = EncryptedConfig::default();
        let encrypted = config.encrypt();
        let decrypted = EncryptedConfig::decrypt(&encrypted);
        
        assert!(decrypted.is_some());
        let config2 = decrypted.unwrap();
        assert_eq!(config.server, config2.server);
        assert_eq!(config.api, config2.api);
        assert_eq!(config.key, config2.key);
        assert_eq!(config.password, config2.password);
    }
}
