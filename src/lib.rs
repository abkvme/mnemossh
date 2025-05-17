/*!
 * Mnemossh - A library for generating and managing Ed25519 SSH keys using BIP-39 mnemonic phrases
 *
 * This library provides functionality to:
 * - Generate SSH keys from mnemonic phrases
 * - Create new mnemonic phrases and corresponding SSH keys
 * - Save and load keys in OpenSSH format
 * - Verify key integrity against mnemonic phrases
 * - Handle keys securely in memory
 */

use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

pub mod crypto;
pub mod utils;
pub mod cli;

// Re-export main functionality at the top level
pub use crypto::keys::{KeyPair, generate_keypair_from_mnemonic, generate_new_keypair_with_mnemonic};
pub use crypto::mnemonic::{Mnemonic, MnemonicLength};

/// Main result type for the mnemossh library
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for the mnemossh library
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error("SSH key error: {0}")]
    SshKeyError(String),
    
    #[error("Dialog error: {0}")]
    DialogError(#[from] dialoguer::Error),
}

/// Constructs a default path for storing SSH keys
pub fn default_ssh_key_path() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| Error::IoError(
        std::io::Error::new(std::io::ErrorKind::NotFound, "Home directory not found")))?;
    
    let ssh_dir = home_dir.join(".ssh");
    
    // Create the .ssh directory if it doesn't exist
    if !ssh_dir.exists() {
        std::fs::create_dir_all(&ssh_dir)?;
    }
    
    Ok(ssh_dir.join("id_ed25519"))
}

/// Core configuration for key generation
#[derive(Debug, Clone)]
pub struct KeyGenConfig {
    /// Output file path for the private key
    pub output_path: PathBuf,
    
    /// Comment to add to the public key (usually an email address)
    pub comment: Option<String>,
    
    /// Passphrase for private key encryption
    pub passphrase: Option<String>,
    
    /// Length of mnemonic phrase for generation
    pub mnemonic_length: MnemonicLength,
    
    /// Path to save the mnemonic phrase to (if applicable)
    pub mnemonic_file: Option<PathBuf>,
}

impl Default for KeyGenConfig {
    fn default() -> Self {
        Self {
            output_path: default_ssh_key_path().unwrap_or_else(|_| PathBuf::from("id_ed25519")),
            comment: None,
            passphrase: None,
            mnemonic_length: MnemonicLength::Words24,
            mnemonic_file: None,
        }
    }
}

impl fmt::Display for KeyGenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyGenConfig {{ output_path: {:?}, comment: {:?}, passphrase: [redacted], mnemonic_length: {:?}, mnemonic_file: {:?} }}",
            self.output_path, self.comment, self.mnemonic_length, self.mnemonic_file)
    }
}
