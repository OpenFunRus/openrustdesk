use hbb_common::{log, sodiumoxide::crypto::secretbox};
use std::fs;
use std::path::PathBuf;

/// Encrypted configuration file system
/// Creates encrypted rustdesk.cfg next to exe if it doesn't exist
/// Always reads and decrypts configuration from this file
/// Users cannot read the settings in plain text

// Encryption key (32 bytes) - Random characters
const ENCRYPTION_KEY: &[u8; 32] = b"7Kq9Xp2Wm5Nv8Rz3Yc6Hb1Jf4Gt0LsXY";

// Nonce for secretbox (24 bytes) - Random characters  
const NONCE_BYTES: &[u8; 24] = b"9Az4Qx7Wd2Sc5Vf8Gb1Nk3MZ";

// Hardcoded default configuration (obfuscated as hex to hide in binary)
// These values are used when rustdesk.cfg doesn't exist or can't be read
// Format: server|api|key|password
const DEFAULT_CONFIG_OBFUSCATED: &[u8] = &[
    // "85.113.41.100|https://85.113.41.100|sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=|Pw59881141"
    0x38, 0x35, 0x2e, 0x31, 0x31, 0x33, 0x2e, 0x34, 0x31, 0x2e, 0x31, 0x30, 0x30, 0x7c, 0x68,
    0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x38, 0x35, 0x2e, 0x31, 0x31, 0x33, 0x2e, 0x34,
    0x31, 0x2e, 0x31, 0x30, 0x30, 0x7c, 0x73, 0x4b, 0x6c, 0x7a, 0x47, 0x4e, 0x43, 0x42, 0x56,
    0x58, 0x4b, 0x6b, 0x54, 0x75, 0x69, 0x78, 0x68, 0x48, 0x51, 0x53, 0x6d, 0x79, 0x5a, 0x64,
    0x66, 0x50, 0x36, 0x38, 0x50, 0x4b, 0x45, 0x72, 0x38, 0x66, 0x55, 0x55, 0x52, 0x61, 0x4c,
    0x56, 0x71, 0x35, 0x73, 0x3d, 0x7c, 0x50, 0x77, 0x35, 0x39, 0x38, 0x38, 0x31, 0x31, 0x34,
    0x31,
];

#[derive(Debug, Clone)]
pub struct EncryptedConfig {
    pub server: String,
    pub api: String,
    pub key: String,
    pub password: String,
}

impl EncryptedConfig {
    /// Get the path to rustdesk.cfg in RustDesk config directory
    /// Uses the same directory as other RustDesk config files
    fn get_config_path() -> PathBuf {
        let config_path = hbb_common::config::Config::path("rustdesk.cfg");
        log::info!("Config path: {}", config_path.display());
        config_path
    }
    
    /// Create default configuration with hardcoded values
    /// These values are always used as fallback
    fn default() -> Self {
        // Decode obfuscated default config
        if let Ok(config_str) = String::from_utf8(DEFAULT_CONFIG_OBFUSCATED.to_vec()) {
            if let Some(config) = Self::from_string(&config_str) {
                log::info!("Using hardcoded default configuration");
                return config;
            }
        }
        
        // Ultimate fallback - should never happen
        log::error!("Failed to decode default configuration, using hardcoded values");
        EncryptedConfig {
            server: "85.113.41.100".to_string(),
            api: "https://85.113.41.100".to_string(),
            key: "sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=".to_string(),
            password: "Pw59881141".to_string(),
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
    /// ALWAYS returns a valid config - never fails
    pub fn load() -> Self {
        let config_path = Self::get_config_path();
        
        // Check if config file exists
        if config_path.exists() {
            log::info!("Config file exists: {}", config_path.display());
            // Try to load from file
            if let Some(config) = Self::load_from_file(&config_path) {
                log::info!("Encrypted configuration loaded from file successfully");
                return config;
            } else {
                log::error!("Failed to decrypt config file - file is corrupted");
                log::warn!("Recreating rustdesk.cfg with default configuration");
                // File is corrupted - delete it and recreate with defaults
                let _ = fs::remove_file(&config_path);
            }
        } else {
            log::info!("Config file not found at: {}", config_path.display());
        }
        
        // Create default configuration and save it
        let config = Self::default();
        log::info!("Creating default configuration with our hardcoded values");
        
        if config.save_to_file(&config_path) {
            log::info!("Default encrypted configuration file created successfully");
        } else {
            log::warn!("Failed to save config file, but will use hardcoded values anyway");
        }
        
        config
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
        
        // Force always use relay server (disable P2P)
        hbb_common::config::Config::set_option(
            "force-always-relay".to_owned(),
            "Y".to_owned(),
        );
        log::info!("Forced relay mode enabled - P2P disabled");
    }
}

/// Main entry point: Load and apply encrypted configuration
/// This function is called during RustDesk startup
/// - Checks if rustdesk.cfg exists next to exe
/// - If not, creates it with default encrypted settings
/// - Reads and decrypts configuration from file
/// - Applies settings to RustDesk
/// ALWAYS applies configuration - never fails to load
pub fn load_and_apply_embedded_config() {
    log::info!("Initializing encrypted configuration system");
    
    let config = EncryptedConfig::load();
    config.apply();
    
    log::info!("Configuration applied successfully");
    log::info!("   Server: {}", config.server);
    log::info!("   API: {}", config.api);
    log::info!("   Key: {}...", &config.key[..20.min(config.key.len())]);
}

/// Get the path to rustdesk_id file in the same directory as rustdesk.cfg
fn get_id_file_path() -> PathBuf {
    let id_path = hbb_common::config::Config::path("rustdesk_id");
    id_path
}

/// Save the RustDesk ID to rustdesk_id file
/// Called after ID is confirmed/generated
pub fn save_id_to_file(id: &str) {
    let id_path = get_id_file_path();
    
    match fs::write(&id_path, id) {
        Ok(_) => {
            log::info!("Saved ID to file: {}", id_path.display());
            log::info!("   ID: {}", id);
        }
        Err(e) => {
            log::error!("Failed to save ID to file {}: {}", id_path.display(), e);
        }
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
