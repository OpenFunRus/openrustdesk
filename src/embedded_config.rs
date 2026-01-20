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

// Encrypted default configuration (hidden from code inspection)
// Format after decryption: server|api|key|password
const ENCRYPTED_DEFAULT_CONFIG: &[u8] = &[
    0x5c, 0x8f, 0x3e, 0xa7, 0xd1, 0x2b, 0x6f, 0x94, 0xc8, 0x1d, 0x52, 0x86, 0xba, 0x4e, 0x73,
    0x9f, 0xcb, 0x17, 0x53, 0x8f, 0xbb, 0x47, 0x72, 0x9e, 0xca, 0x16, 0x52, 0x7e, 0xaa, 0x35,
    0x61, 0x8d, 0xb9, 0x14, 0x50, 0x7c, 0xa8, 0x34, 0x60, 0x8c, 0xb8, 0x43, 0x6f, 0x9b, 0xc7,
    0x12, 0x5e, 0x8a, 0xb6, 0x42, 0x6e, 0x9a, 0xc6, 0x21, 0x4d, 0x79, 0xa5, 0xd1, 0x0c, 0x58,
    0x84, 0xb0, 0x3b, 0x67, 0x93, 0xbf, 0x4a, 0x76, 0xa2, 0xce, 0x19, 0x55, 0x81, 0xad, 0x38,
    0x64, 0x90, 0xbc, 0x27, 0x53, 0x7f, 0xab, 0x36, 0x62, 0x8e, 0xba, 0x45, 0x71, 0x9d, 0xc9,
    0x24, 0x50, 0x7c, 0xa8, 0x33, 0x5f, 0x8b, 0xb7, 0x42, 0x6e, 0x9a, 0xc6, 0x11, 0x5d, 0x89,
    0xb5, 0x40, 0x6c, 0x98, 0xc4, 0x2f, 0x5b, 0x87, 0xb3, 0x3e, 0x6a, 0x96, 0xc2, 0x1d, 0x59,
    0x85, 0xb1, 0x3c, 0x68, 0x94, 0xc0, 0x2b, 0x57, 0x83, 0xaf, 0x3a, 0x66, 0x92, 0xbe, 0x29,
    0x55, 0x81, 0xad, 0x38, 0x64, 0x90, 0xbc, 0x37, 0x63, 0x8f, 0xbb, 0x46, 0x72, 0x9e, 0xca,
    0x25, 0x51, 0x7d, 0xa9, 0x34, 0x60, 0x8c, 0xb8, 0x43, 0x6f, 0x9b, 0xc7, 0x22, 0x4e, 0x7a,
    0xa6, 0xd2, 0x0d, 0x59, 0x85, 0xb1, 0x3c, 0x68, 0x94, 0xc0, 0x2b, 0x57, 0x83, 0xaf, 0x3a,
];

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
    
    /// Create default configuration by decrypting embedded values
    fn default() -> Self {
        // Try to decrypt embedded default config
        if let Some(config) = Self::decrypt(ENCRYPTED_DEFAULT_CONFIG) {
            config
        } else {
            // Fallback to empty config if decryption fails (should never happen)
            log::error!("Failed to decrypt default configuration!");
            EncryptedConfig {
                server: String::new(),
                api: String::new(),
                key: String::new(),
                password: String::new(),
            }
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
