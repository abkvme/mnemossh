/*!
 * SSH key generation and handling
 */

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::ZeroizeOnDrop;

use crate::crypto::mnemonic::{Mnemonic, MnemonicLength};
use crate::{Error, Result};

/// Represents an Ed25519 SSH key pair with secure memory handling
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    /// Ed25519 signing key (private key)
    signing_key: SigningKey,

    /// Ed25519 verifying key (public key)
    #[zeroize(skip)]
    verifying_key: VerifyingKey,

    /// OpenSSH formatted private key
    #[zeroize(skip)]
    private_key_openssh: String,

    /// OpenSSH formatted public key
    #[zeroize(skip)]
    public_key_openssh: String,
}

impl KeyPair {
    /// Create a new key pair from an Ed25519 signing key
    fn new(
        signing_key: SigningKey,
        comment: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let verifying_key = signing_key.verifying_key();

        // Format the public key in OpenSSH format
        let public_key_openssh = format_openssh_public_key(&verifying_key, comment)?;

        // Format the private key in OpenSSH format
        let private_key_openssh = format_openssh_private_key(&signing_key, passphrase)?;

        Ok(Self {
            signing_key,
            verifying_key,
            private_key_openssh,
            public_key_openssh,
        })
    }

    /// Create a key pair from raw seed bytes
    pub fn from_seed(seed: &[u8], comment: Option<&str>, passphrase: Option<&str>) -> Result<Self> {
        // Use the first 32 bytes of the seed for the key (Ed25519 needs exactly 32 bytes)
        if seed.len() < 32 {
            return Err(Error::KeyGenerationFailed("Seed is too short".to_string()));
        }

        // Convert the first 32 bytes of the seed to the secret key bytes
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed[..32]);

        let signing_key = SigningKey::from(key_bytes);
        KeyPair::new(signing_key, comment, passphrase)
    }

    /// Generate a signature for the given message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    /// Verify a signature against a message
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }

        // Convert the signature bytes to the expected format
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // Create a signature from the bytes
        let signature = Signature::from_bytes(&sig_bytes);

        // Use the Verifier trait to verify the signature
        self.verifying_key.verify(message, &signature).is_ok()
    }

    /// Save the key pair to files
    pub fn save_to_files(&self, path: impl AsRef<Path>) -> Result<(PathBuf, PathBuf)> {
        let path = path.as_ref();
        let private_key_path = path.to_path_buf();
        let public_key_path = path.with_extension("pub");

        // Ensure the directory exists
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        // Write the private and public keys
        fs::write(&private_key_path, &self.private_key_openssh)?;
        fs::write(&public_key_path, &self.public_key_openssh)?;

        // Set appropriate permissions for the private key (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&private_key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&private_key_path, perms)?;
        }

        Ok((private_key_path, public_key_path))
    }

    /// Get the OpenSSH formatted private key
    pub fn private_key_openssh(&self) -> &str {
        &self.private_key_openssh
    }

    /// Get the OpenSSH formatted public key
    pub fn public_key_openssh(&self) -> &str {
        &self.public_key_openssh
    }

    /// Get the verifying key (public key)
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Calculate MD5 fingerprint of the public key
    /// Returns fingerprint in OpenSSH format: MD5:xx:xx:xx:...
    pub fn md5_fingerprint(&self) -> String {
        // Parse the public key to get the raw key bytes
        // Format: "ssh-ed25519 <base64> [comment]"
        let parts: Vec<&str> = self.public_key_openssh.split_whitespace().collect();
        if parts.len() < 2 {
            return "Invalid key format".to_string();
        }

        // Decode the base64 portion
        let key_data = match BASE64.decode(parts[1]) {
            Ok(data) => data,
            Err(_) => return "Failed to decode key".to_string(),
        };

        // Calculate MD5 hash
        let result = md5::compute(&key_data);

        // Format as colon-separated hex
        let hex_pairs: Vec<String> = result.iter().map(|byte| format!("{:02x}", byte)).collect();
        format!("MD5:{}", hex_pairs.join(":"))
    }

    /// Calculate SHA256 fingerprint of the public key
    /// Returns fingerprint in OpenSSH format: SHA256:<base64>
    pub fn sha256_fingerprint(&self) -> String {
        // Parse the public key to get the raw key bytes
        // Format: "ssh-ed25519 <base64> [comment]"
        let parts: Vec<&str> = self.public_key_openssh.split_whitespace().collect();
        if parts.len() < 2 {
            return "Invalid key format".to_string();
        }

        // Decode the base64 portion
        let key_data = match BASE64.decode(parts[1]) {
            Ok(data) => data,
            Err(_) => return "Failed to decode key".to_string(),
        };

        // Calculate SHA256 hash
        let mut hasher = Sha256::new();
        hasher.update(&key_data);
        let result = hasher.finalize();

        // Encode as base64 without padding (OpenSSH style)
        let b64 = BASE64.encode(result);
        // Remove trailing '=' padding to match OpenSSH format
        let b64_no_padding = b64.trim_end_matches('=');
        format!("SHA256:{}", b64_no_padding)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ verifying_key: {:?}, private_key: [REDACTED], public_key: {:?} }}",
            self.verifying_key, self.public_key_openssh
        )
    }
}

/// Generate a key pair from a mnemonic phrase
pub fn generate_keypair_from_mnemonic(
    mnemonic: &Mnemonic,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<KeyPair> {
    let seed = mnemonic.to_seed();
    KeyPair::from_seed(&seed, comment, passphrase)
}

/// Generate a new mnemonic phrase and corresponding key pair
pub fn generate_new_keypair_with_mnemonic(
    length: MnemonicLength,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<(Mnemonic, KeyPair)> {
    let mnemonic = Mnemonic::new(length)?;
    let keypair = generate_keypair_from_mnemonic(&mnemonic, comment, passphrase)?;
    Ok((mnemonic, keypair))
}

/// Format an Ed25519 verifying key in OpenSSH public key format
fn format_openssh_public_key(
    verifying_key: &VerifyingKey,
    comment: Option<&str>,
) -> Result<String> {
    let key_bytes = verifying_key.to_bytes();
    let mut buffer = Vec::new();

    // OpenSSH format: "ssh-ed25519 <base64 data> [comment]"
    // The <base64 data> part contains:
    // - length of "ssh-ed25519" as u32 big-endian
    // - "ssh-ed25519" as UTF-8
    // - length of key data as u32 big-endian
    // - key data

    // Add the key type string "ssh-ed25519"
    let key_type = "ssh-ed25519";
    buffer.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    buffer.extend_from_slice(key_type.as_bytes());

    // Add the actual key data
    buffer.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&key_bytes);

    // Base64 encode the whole buffer
    let encoded = BASE64.encode(&buffer);

    // Construct the final OpenSSH public key string
    let mut result = format!("{} {}", key_type, encoded);
    if let Some(comment_text) = comment {
        result.push_str(&format!(" {}", comment_text));
    }

    Ok(result)
}

/// Format an Ed25519 signing key in OpenSSH private key format
fn format_openssh_private_key(
    signing_key: &SigningKey,
    passphrase: Option<&str>,
) -> Result<String> {
    // This is a simplified implementation; a real one would need to handle
    // the complex OpenSSH private key format with proper encryption if passphrase is provided

    let key_bytes = signing_key.to_bytes();
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    // OpenSSH private key format is complex; this is a minimal implementation
    // that doesn't include encryption, but it's recognizable by OpenSSH

    let mut buffer = Vec::new();

    // Magic Header
    let openssh_header = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    let openssh_footer = "-----END OPENSSH PRIVATE KEY-----\n";

    // OpenSSH private key format
    let auth_magic = "openssh-key-v1";
    buffer.extend_from_slice(auth_magic.as_bytes());
    buffer.push(0); // null terminator

    // No encryption by default (simplified)
    let cipher_name = if passphrase.is_some() {
        "aes256-ctr"
    } else {
        "none"
    };
    buffer.extend_from_slice(&(cipher_name.len() as u32).to_be_bytes());
    buffer.extend_from_slice(cipher_name.as_bytes());

    // KDF (key derivation function)
    let kdf_name = if passphrase.is_some() {
        "bcrypt"
    } else {
        "none"
    };
    buffer.extend_from_slice(&(kdf_name.len() as u32).to_be_bytes());
    buffer.extend_from_slice(kdf_name.as_bytes());

    // KDF options (empty for "none")
    let kdf_options = if passphrase.is_some() {
        // Real implementation would include salt and rounds
        // This is a simplified placeholder
        vec![0, 0, 0, 0]
    } else {
        vec![0, 0, 0, 0]
    };
    buffer.extend_from_slice(&kdf_options);

    // Number of keys (always 1 for us)
    buffer.extend_from_slice(&(1_u32).to_be_bytes());

    // Public key section
    let mut pub_key_section = Vec::new();
    let key_type = "ssh-ed25519";
    pub_key_section.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    pub_key_section.extend_from_slice(key_type.as_bytes());
    pub_key_section.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    pub_key_section.extend_from_slice(&public_key_bytes);

    buffer.extend_from_slice(&(pub_key_section.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&pub_key_section);

    // Private key section
    let mut priv_key_section = Vec::new();

    // Checkints for corruption detection
    let checkint: u32 = rand::random();
    priv_key_section.extend_from_slice(&checkint.to_be_bytes());
    priv_key_section.extend_from_slice(&checkint.to_be_bytes());

    // Key type
    priv_key_section.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    priv_key_section.extend_from_slice(key_type.as_bytes());

    // Public key
    priv_key_section.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
    priv_key_section.extend_from_slice(&public_key_bytes);

    // Private key (includes both private and public parts for Ed25519)
    let full_key_len = key_bytes.len() + public_key_bytes.len();
    priv_key_section.extend_from_slice(&(full_key_len as u32).to_be_bytes());
    priv_key_section.extend_from_slice(&key_bytes);
    priv_key_section.extend_from_slice(&public_key_bytes);

    // Comment
    let comment = passphrase.unwrap_or("");
    priv_key_section.extend_from_slice(&(comment.len() as u32).to_be_bytes());
    priv_key_section.extend_from_slice(comment.as_bytes());

    // Padding to a multiple of the cipher block size (8 bytes for aes256-ctr)
    let block_size = 8;
    let padding_len = block_size - (priv_key_section.len() % block_size);
    for i in 0..padding_len {
        priv_key_section.push((i + 1) as u8);
    }

    // If a passphrase is provided, encrypt the private key section
    // Note: In a real implementation, you would encrypt priv_key_section here

    buffer.extend_from_slice(&(priv_key_section.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&priv_key_section);

    // Base64 encode the entire buffer
    let encoded = BASE64.encode(&buffer);

    // Format with line breaks (64 chars per line)
    let mut formatted = String::new();
    formatted.push_str(openssh_header);
    for i in 0..(encoded.len().div_ceil(70)) {
        let start = i * 70;
        let end = std::cmp::min((i + 1) * 70, encoded.len());
        formatted.push_str(&encoded[start..end]);
        formatted.push('\n');
    }
    formatted.push_str(openssh_footer);

    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mnemonic::Mnemonic;
    use tempfile::tempdir;

    #[test]
    fn test_keypair_generation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("test@example.com"), None).unwrap();

        // Check that the public key is in the expected format
        let public_key = keypair.public_key_openssh();
        assert!(public_key.starts_with("ssh-ed25519 "));
        assert!(public_key.ends_with(" test@example.com"));

        // Check that the private key is in the expected format
        let private_key = keypair.private_key_openssh();
        assert!(private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(private_key.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_save_keypair() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test_key");

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("test@example.com"), None).unwrap();

        let (private_path, public_path) = keypair.save_to_files(&key_path).unwrap();

        // Check that both files exist
        assert!(private_path.exists());
        assert!(public_path.exists());

        // Check that the file contents match
        let saved_private_key = fs::read_to_string(private_path).unwrap();
        let saved_public_key = fs::read_to_string(public_path).unwrap();

        assert_eq!(saved_private_key, keypair.private_key_openssh());
        assert_eq!(saved_public_key, keypair.public_key_openssh());
    }

    #[test]
    fn test_signing_and_verification() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        let keypair = generate_keypair_from_mnemonic(&mnemonic, None, None).unwrap();

        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));
        assert!(!keypair.verify(b"wrong message", &signature));
    }
}
