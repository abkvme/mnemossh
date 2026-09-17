/*!
 * SSH key generation and handling
 */

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bcrypt_pbkdf::bcrypt_pbkdf;
use ctr::Ctr128BE;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-256 in counter mode, the cipher OpenSSH uses for encrypted private keys.
type Aes256Ctr = Ctr128BE<Aes256>;

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
        let private_key_openssh = format_openssh_private_key(&signing_key, comment, passphrase)?;

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

        // The private key is created 0600 rather than written and then
        // repaired: writing first and calling set_permissions afterwards leaves
        // the key on disk under the process umask, readable by every local user,
        // for as long as the two syscalls are apart.
        crate::utils::write_secret_file(&private_key_path, self.private_key_openssh.as_bytes())?;

        // The public key is not secret and keeps the usual umask-derived mode.
        fs::write(&public_key_path, &self.public_key_openssh)?;

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

/// Number of bcrypt-pbkdf rounds used when encrypting a private key.
///
/// Matches the default OpenSSH's `ssh-keygen` uses for new keys.
const BCRYPT_ROUNDS: u32 = 16;

/// Length of the random salt fed to bcrypt-pbkdf, in bytes.
const BCRYPT_SALT_LEN: usize = 16;

/// Cipher block size for `aes256-ctr`, in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Block size OpenSSH uses to pad unencrypted private keys, in bytes.
const NONE_BLOCK_SIZE: usize = 8;

/// Append a length-prefixed byte string, as defined by RFC 4251 section 5.
fn put_string(buffer: &mut Vec<u8>, data: &[u8]) {
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
}

/// Build the `kdfoptions` blob for the bcrypt KDF: a salt followed by a round count.
fn bcrypt_kdf_options(salt: &[u8], rounds: u32) -> Vec<u8> {
    let mut options = Vec::new();
    put_string(&mut options, salt);
    options.extend_from_slice(&rounds.to_be_bytes());
    options
}

/// Derive an AES-256-CTR key and IV from a passphrase using bcrypt-pbkdf.
///
/// OpenSSH derives both from a single KDF output: the first 32 bytes are the
/// key and the following 16 bytes are the initial counter block.
fn derive_key_and_iv(passphrase: &str, salt: &[u8], rounds: u32) -> Result<([u8; 32], [u8; 16])> {
    let mut derived = [0u8; 48];
    bcrypt_pbkdf(passphrase, salt, rounds, &mut derived)
        .map_err(|e| Error::CryptoError(format!("Key derivation failed: {}", e)))?;

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..]);
    derived.zeroize();

    Ok((key, iv))
}

/// Format an Ed25519 signing key in OpenSSH private key format
///
/// When a passphrase is supplied the private section is encrypted with
/// `aes256-ctr`, keyed by bcrypt-pbkdf, exactly as OpenSSH does. Without one the
/// private section is stored in the clear and the header says so.
fn format_openssh_private_key(
    signing_key: &SigningKey,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<String> {
    let key_bytes = signing_key.to_bytes();
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let key_type = "ssh-ed25519";

    // Pick the cipher and KDF up front; both the header and the padding depend on them.
    let (cipher_name, kdf_name, block_size) = if passphrase.is_some() {
        ("aes256-ctr", "bcrypt", AES_BLOCK_SIZE)
    } else {
        ("none", "none", NONE_BLOCK_SIZE)
    };

    // The salt has to be fresh for every key, so two keys encrypted with the
    // same passphrase never share a derived key.
    let salt = match passphrase {
        Some(_) => {
            let mut salt = [0u8; BCRYPT_SALT_LEN];
            rand::rng().fill(&mut salt[..]);
            Some(salt)
        }
        None => None,
    };

    // Public key section, repeated verbatim inside the private section below.
    let mut pub_key_section = Vec::new();
    put_string(&mut pub_key_section, key_type.as_bytes());
    put_string(&mut pub_key_section, &public_key_bytes);

    // Private key section: two matching checkints let a decrypting reader tell
    // a wrong passphrase from a corrupt file.
    let mut priv_key_section = Vec::new();
    let checkint: u32 = rand::random();
    priv_key_section.extend_from_slice(&checkint.to_be_bytes());
    priv_key_section.extend_from_slice(&checkint.to_be_bytes());
    put_string(&mut priv_key_section, key_type.as_bytes());
    put_string(&mut priv_key_section, &public_key_bytes);

    // Ed25519 private keys are stored as the seed followed by the public key.
    let mut full_key = Vec::with_capacity(key_bytes.len() + public_key_bytes.len());
    full_key.extend_from_slice(&key_bytes);
    full_key.extend_from_slice(&public_key_bytes);
    put_string(&mut priv_key_section, &full_key);
    full_key.zeroize();

    put_string(&mut priv_key_section, comment.unwrap_or("").as_bytes());

    // Pad with 1, 2, 3, ... up to the cipher block size.
    let mut pad_byte = 1u8;
    while priv_key_section.len() % block_size != 0 {
        priv_key_section.push(pad_byte);
        pad_byte += 1;
    }

    // Encrypt the padded private section in place.
    if let (Some(passphrase), Some(salt)) = (passphrase, salt.as_ref()) {
        let (mut key, mut iv) = derive_key_and_iv(passphrase, salt, BCRYPT_ROUNDS)?;
        let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
        cipher.apply_keystream(&mut priv_key_section);
        key.zeroize();
        iv.zeroize();
    }

    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"openssh-key-v1");
    buffer.push(0); // null terminator
    put_string(&mut buffer, cipher_name.as_bytes());
    put_string(&mut buffer, kdf_name.as_bytes());
    match salt.as_ref() {
        Some(salt) => put_string(&mut buffer, &bcrypt_kdf_options(salt, BCRYPT_ROUNDS)),
        None => put_string(&mut buffer, &[]),
    }
    buffer.extend_from_slice(&1u32.to_be_bytes()); // number of keys
    put_string(&mut buffer, &pub_key_section);
    put_string(&mut buffer, &priv_key_section);

    let encoded = BASE64.encode(&buffer);
    priv_key_section.zeroize();

    // Wrap the base64 payload between the PEM-style markers.
    let mut formatted = String::new();
    formatted.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        formatted.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        formatted.push('\n');
    }
    formatted.push_str("-----END OPENSSH PRIVATE KEY-----\n");

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

#[cfg(test)]
mod format_tests {
    use super::*;
    use crate::crypto::mnemonic::Mnemonic;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Decode the base64 body of an OpenSSH private key into its raw bytes.
    fn decode_private_key(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        BASE64
            .decode(body)
            .expect("private key body is valid base64")
    }

    /// Read one RFC 4251 length-prefixed string, advancing the cursor past it.
    fn read_string<'a>(buffer: &'a [u8], pos: &mut usize) -> &'a [u8] {
        let len_bytes: [u8; 4] = buffer[*pos..*pos + 4].try_into().expect("length prefix");
        let len = u32::from_be_bytes(len_bytes) as usize;
        *pos += 4;
        let value = &buffer[*pos..*pos + len];
        *pos += len;
        value
    }

    /// The fields of an OpenSSH private key that precede the private section.
    struct Header {
        cipher: String,
        kdf: String,
        kdf_options: Vec<u8>,
        public_section: Vec<u8>,
        private_section: Vec<u8>,
    }

    fn parse_header(buffer: &[u8]) -> Header {
        assert_eq!(&buffer[..15], b"openssh-key-v1\0", "auth magic");
        let mut pos = 15;

        let cipher = String::from_utf8(read_string(buffer, &mut pos).to_vec()).unwrap();
        let kdf = String::from_utf8(read_string(buffer, &mut pos).to_vec()).unwrap();
        let kdf_options = read_string(buffer, &mut pos).to_vec();

        let num_keys = u32::from_be_bytes(buffer[pos..pos + 4].try_into().unwrap());
        pos += 4;
        assert_eq!(num_keys, 1, "exactly one key per file");

        let public_section = read_string(buffer, &mut pos).to_vec();
        let private_section = read_string(buffer, &mut pos).to_vec();
        assert_eq!(pos, buffer.len(), "no trailing bytes");

        Header {
            cipher,
            kdf,
            kdf_options,
            public_section,
            private_section,
        }
    }

    /// Assert the private section carries the expected key and comment, and that
    /// it is padded with the 1, 2, 3, ... sequence OpenSSH expects.
    fn assert_private_section(section: &[u8], expected_seed: &[u8], expected_comment: &str) {
        let mut pos = 0;

        let checkint1 = u32::from_be_bytes(section[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let checkint2 = u32::from_be_bytes(section[pos..pos + 4].try_into().unwrap());
        pos += 4;
        assert_eq!(checkint1, checkint2, "checkints must match");

        assert_eq!(read_string(section, &mut pos), b"ssh-ed25519");
        let public_key = read_string(section, &mut pos).to_vec();
        assert_eq!(public_key.len(), 32);

        // Ed25519 private keys are stored as the 32-byte seed plus the public key.
        let private_key = read_string(section, &mut pos);
        assert_eq!(private_key.len(), 64);
        assert_eq!(&private_key[..32], expected_seed, "seed round-trips");
        assert_eq!(&private_key[32..], &public_key[..], "public half matches");

        let comment = read_string(section, &mut pos);
        assert_eq!(comment, expected_comment.as_bytes(), "comment round-trips");

        for (offset, byte) in section[pos..].iter().enumerate() {
            assert_eq!(*byte as usize, offset + 1, "padding is 1, 2, 3, ...");
        }
    }

    fn seed_bytes() -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        mnemonic.to_seed()[..32].to_vec()
    }

    #[test]
    fn test_unencrypted_key_structure() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), None).unwrap();

        let header = parse_header(&decode_private_key(keypair.private_key_openssh()));

        assert_eq!(header.cipher, "none");
        assert_eq!(header.kdf, "none");
        assert!(
            header.kdf_options.is_empty(),
            "no KDF options without a passphrase"
        );
        assert_eq!(
            header.private_section.len() % NONE_BLOCK_SIZE,
            0,
            "padded to the block size"
        );

        let mut pos = 0;
        assert_eq!(
            read_string(&header.public_section, &mut pos),
            b"ssh-ed25519"
        );
        assert_eq!(
            read_string(&header.public_section, &mut pos),
            keypair.verifying_key().to_bytes()
        );

        assert_private_section(&header.private_section, &seed_bytes(), "alice@example.com");
    }

    #[test]
    fn test_encrypted_key_structure() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), Some("hunter2"))
                .unwrap();

        let header = parse_header(&decode_private_key(keypair.private_key_openssh()));

        assert_eq!(header.cipher, "aes256-ctr");
        assert_eq!(header.kdf, "bcrypt");
        assert_eq!(
            header.private_section.len() % AES_BLOCK_SIZE,
            0,
            "ciphertext is a whole number of AES blocks"
        );

        // KDF options are a salt followed by the round count.
        let mut pos = 0;
        let salt = read_string(&header.kdf_options, &mut pos);
        assert_eq!(salt.len(), BCRYPT_SALT_LEN);
        assert_ne!(salt, [0u8; BCRYPT_SALT_LEN], "salt is not all zeroes");
        let rounds = u32::from_be_bytes(header.kdf_options[pos..pos + 4].try_into().unwrap());
        assert_eq!(rounds, BCRYPT_ROUNDS);
        assert_eq!(pos + 4, header.kdf_options.len(), "no trailing KDF options");
    }

    #[test]
    fn test_encrypted_key_decrypts_with_the_passphrase() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), Some("hunter2"))
                .unwrap();

        let header = parse_header(&decode_private_key(keypair.private_key_openssh()));

        let mut pos = 0;
        let salt = read_string(&header.kdf_options, &mut pos).to_vec();
        let rounds = u32::from_be_bytes(header.kdf_options[pos..pos + 4].try_into().unwrap());

        let (key, iv) = derive_key_and_iv("hunter2", &salt, rounds).unwrap();
        let mut decrypted = header.private_section.clone();
        Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut decrypted);

        assert_private_section(&decrypted, &seed_bytes(), "alice@example.com");
    }

    #[test]
    fn test_wrong_passphrase_does_not_yield_matching_checkints() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair = generate_keypair_from_mnemonic(&mnemonic, None, Some("hunter2")).unwrap();

        let header = parse_header(&decode_private_key(keypair.private_key_openssh()));

        let mut pos = 0;
        let salt = read_string(&header.kdf_options, &mut pos).to_vec();
        let rounds = u32::from_be_bytes(header.kdf_options[pos..pos + 4].try_into().unwrap());

        let (key, iv) = derive_key_and_iv("wrong passphrase", &salt, rounds).unwrap();
        let mut decrypted = header.private_section.clone();
        Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut decrypted);

        // This is the check OpenSSH uses to reject a wrong passphrase.
        assert_ne!(
            decrypted[..4],
            decrypted[4..8],
            "checkints must not match under the wrong key"
        );
    }

    #[test]
    fn test_encrypted_key_leaks_neither_passphrase_nor_seed() {
        let passphrase = "correct horse battery staple";
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), Some(passphrase))
                .unwrap();

        let raw = decode_private_key(keypair.private_key_openssh());
        let seed = seed_bytes();

        assert!(
            !raw.windows(passphrase.len())
                .any(|w| w == passphrase.as_bytes()),
            "the passphrase must never appear in the key file"
        );
        assert!(
            !raw.windows(seed.len()).any(|w| w == seed.as_slice()),
            "the private seed must never appear in an encrypted key file"
        );
        assert!(
            !keypair
                .private_key_openssh()
                .contains(&BASE64.encode(passphrase)),
            "the passphrase must not survive base64 encoding either"
        );
    }

    #[test]
    fn test_each_encryption_uses_a_fresh_salt() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let first =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), Some("hunter2"))
                .unwrap();
        let second =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), Some("hunter2"))
                .unwrap();

        // Same key, same passphrase, but the ciphertext must differ.
        assert_eq!(first.public_key_openssh(), second.public_key_openssh());
        assert_ne!(first.private_key_openssh(), second.private_key_openssh());

        let salt_of = |keypair: &KeyPair| {
            let header = parse_header(&decode_private_key(keypair.private_key_openssh()));
            let mut pos = 0;
            read_string(&header.kdf_options, &mut pos).to_vec()
        };
        assert_ne!(salt_of(&first), salt_of(&second), "salts must differ");
    }

    #[test]
    fn test_missing_comment_is_stored_as_empty() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair = generate_keypair_from_mnemonic(&mnemonic, None, None).unwrap();

        let header = parse_header(&decode_private_key(keypair.private_key_openssh()));
        assert_private_section(&header.private_section, &seed_bytes(), "");
    }

    #[test]
    fn test_passphrase_does_not_change_the_derived_key() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let plain = generate_keypair_from_mnemonic(&mnemonic, Some("alice"), None).unwrap();
        let encrypted =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice"), Some("hunter2")).unwrap();

        // The passphrase protects the file; it is not an input to key derivation.
        assert_eq!(plain.public_key_openssh(), encrypted.public_key_openssh());
        assert_eq!(
            plain.verifying_key().to_bytes(),
            encrypted.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_known_public_key_for_the_bip39_test_vector() {
        // Guards against any future change silently altering key derivation.
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair =
            generate_keypair_from_mnemonic(&mnemonic, Some("alice@example.com"), None).unwrap();

        assert_eq!(
            keypair.public_key_openssh(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMV4XhhltwiTiv+BYdVzAGSWZjsaoQg045bcVmhposZq alice@example.com"
        );
    }

    #[test]
    fn test_from_seed_rejects_a_short_seed() {
        let error = KeyPair::from_seed(&[0u8; 31], None, None).unwrap_err();
        assert!(matches!(error, Error::KeyGenerationFailed(_)));
    }

    #[test]
    fn test_verify_rejects_malformed_signatures() {
        let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
        let keypair = generate_keypair_from_mnemonic(&mnemonic, None, None).unwrap();

        let message = b"test message";
        let mut signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));
        assert!(!keypair.verify(message, &signature[..63]), "wrong length");
        assert!(!keypair.verify(message, &[]), "empty signature");

        signature[0] ^= 0xff;
        assert!(!keypair.verify(message, &signature), "tampered signature");
        assert!(
            !keypair.verify(b"different message", &keypair.sign(message)),
            "signature is bound to the message"
        );
    }
}
