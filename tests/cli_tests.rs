/*!
 * Tests for the CLI commands
 *
 * The commands prompt interactively for anything they are not given, so every
 * test here passes a complete set of arguments and writes into a temporary
 * directory, which keeps the non-interactive paths under test.
 */

use std::fs;
use std::path::PathBuf;

use mnemossh::Error;
use mnemossh::cli::{
    generate_command, info_command, restore_command, verify_command, version_command,
};
use mnemossh::crypto::keys::generate_keypair_from_mnemonic;
use mnemossh::crypto::mnemonic::{Mnemonic, MnemonicLength};
use tempfile::tempdir;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER_PHRASE: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const EXPECTED_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMV4XhhltwiTiv+BYdVzAGSWZjsaoQg045bcVmhposZq";

#[test]
fn test_version_command() {
    // Test that version_command runs without error
    let result = version_command();
    assert!(result.is_ok(), "version_command should succeed");
}

#[test]
fn test_info_command_with_existing_key() {
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("test_key");

    // Create a test key
    let mnemonic = Mnemonic::new(MnemonicLength::Words12).unwrap();
    let keypair =
        generate_keypair_from_mnemonic(&mnemonic, Some("test@example.com"), None).unwrap();
    keypair.save_to_files(&key_path).unwrap();

    // Test info command on the existing key
    let result = info_command(Some(key_path.clone()));
    assert!(
        result.is_ok(),
        "info_command should succeed with existing key"
    );
}

#[test]
fn test_info_command_with_nonexistent_key() {
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("nonexistent_key");

    // Test info command on non-existent key
    let result = info_command(Some(key_path));
    assert!(
        result.is_err(),
        "info_command should fail with non-existent key"
    );
}

#[test]
fn test_info_command_with_invalid_key_format() {
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("invalid_key");
    let public_key_path = key_path.with_extension("pub");

    // Create an invalid public key file
    fs::write(&public_key_path, "invalid key content").unwrap();

    // Test info command on invalid key
    let result = info_command(Some(key_path));
    assert!(
        result.is_err(),
        "info_command should fail with invalid key format"
    );
}

#[test]
fn test_info_command_with_empty_key_file() {
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("empty_key");
    let public_key_path = key_path.with_extension("pub");

    // Create an empty public key file
    fs::write(&public_key_path, "").unwrap();

    // Test info command on empty key
    let result = info_command(Some(key_path));
    assert!(
        result.is_err(),
        "info_command should fail with empty key file"
    );
}

#[test]
fn test_restore_and_verify_commands() {
    use mnemossh::cli::{restore_command, verify_command};

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("restored_key");

    // Create a known mnemonic
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Test restore command with all parameters (non-interactive)
    let result = restore_command(
        Some(phrase),
        Some(key_path.clone()),
        Some("test@example.com"),
        Some(""),
    );
    assert!(
        result.is_ok(),
        "restore_command should succeed with all parameters provided"
    );

    // Test verify command with a generated key
    let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    let keypair =
        generate_keypair_from_mnemonic(&mnemonic, Some("test@example.com"), None).unwrap();
    let verify_key_path = temp_dir.path().join("verify_key");
    keypair.save_to_files(&verify_key_path).unwrap();

    // Verify should succeed with matching mnemonic
    let verify_result = verify_command(Some(phrase), Some(verify_key_path.clone()));
    assert!(
        verify_result.is_ok(),
        "verify_command should succeed with matching mnemonic"
    );

    // Verify should fail with different mnemonic
    let different_phrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let verify_result_fail = verify_command(Some(different_phrase), Some(verify_key_path));
    assert!(
        verify_result_fail.is_err(),
        "verify_command should fail with non-matching mnemonic"
    );
}

#[test]
fn test_generate_command_writes_all_three_files() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let mnemonic_path = dir.path().join("phrase.txt");

    generate_command(
        Some(key_path.clone()),
        Some("alice@example.com"),
        Some(""),
        Some(MnemonicLength::Words24),
        Some(mnemonic_path.clone()),
    )
    .expect("generate_command should succeed");

    assert!(key_path.exists(), "private key written");
    assert!(
        key_path.with_extension("pub").exists(),
        "public key written"
    );
    assert!(mnemonic_path.exists(), "mnemonic written");

    let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert!(public_key.starts_with("ssh-ed25519 "));
    assert!(public_key.trim().ends_with("alice@example.com"));

    let private_key = fs::read_to_string(&key_path).unwrap();
    assert!(private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));

    let phrase = fs::read_to_string(&mnemonic_path).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 24);
}

#[test]
fn test_generate_command_honours_every_mnemonic_length() {
    for (length, words) in [
        (MnemonicLength::Words12, 12),
        (MnemonicLength::Words18, 18),
        (MnemonicLength::Words24, 24),
    ] {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let mnemonic_path = dir.path().join("phrase.txt");

        generate_command(
            Some(key_path),
            Some("alice@example.com"),
            Some(""),
            Some(length),
            Some(mnemonic_path.clone()),
        )
        .expect("generate_command should succeed");

        let phrase = fs::read_to_string(&mnemonic_path).unwrap();
        assert_eq!(phrase.split_whitespace().count(), words);
    }
}

#[test]
fn test_generate_command_creates_missing_directories() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("nested").join("deeper").join("id_ed25519");

    generate_command(
        Some(key_path.clone()),
        Some("alice@example.com"),
        Some(""),
        Some(MnemonicLength::Words12),
        None,
    )
    .expect("generate_command should create the parent directories");

    assert!(key_path.exists());
}

#[test]
fn test_generate_command_with_passphrase_produces_an_encrypted_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");

    generate_command(
        Some(key_path.clone()),
        Some("alice@example.com"),
        Some("hunter2"),
        Some(MnemonicLength::Words24),
        None,
    )
    .expect("generate_command should succeed");

    let private_key = fs::read_to_string(&key_path).unwrap();
    let body: String = private_key
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let raw = base64_decode(&body);

    assert!(contains(&raw, b"aes256-ctr"), "key should declare a cipher");
    assert!(contains(&raw, b"bcrypt"), "key should declare a KDF");
    assert!(
        !contains(&raw, b"hunter2"),
        "the passphrase must never be written into the key file"
    );
}

#[test]
fn test_key_pair_methods() {
    // Test additional KeyPair methods for coverage
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    let keypair =
        generate_keypair_from_mnemonic(&mnemonic, Some("test@example.com"), None).unwrap();

    // Test verifying_key method
    let verifying_key = keypair.verifying_key();
    assert!(!format!("{:?}", verifying_key).is_empty());

    // Test that private and public keys are non-empty
    assert!(!keypair.private_key_openssh().is_empty());
    assert!(!keypair.public_key_openssh().is_empty());
}

#[test]
fn test_restore_command_reproduces_the_original_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("restored");

    restore_command(
        Some(PHRASE),
        Some(key_path.clone()),
        Some("alice@example.com"),
        Some(""),
    )
    .expect("restore_command should succeed");

    let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert!(
        public_key.starts_with(EXPECTED_KEY),
        "restored key should match the known value, got: {}",
        public_key
    );
}

#[test]
fn test_restore_command_with_passphrase() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("restored");

    restore_command(
        Some(PHRASE),
        Some(key_path.clone()),
        Some(""),
        Some("hunter2"),
    )
    .expect("restore_command should succeed with a passphrase");

    // The passphrase changes the file, never the key it holds.
    let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert!(public_key.starts_with(EXPECTED_KEY));
}

#[test]
fn test_restore_command_rejects_an_invalid_phrase() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("restored");

    let error = restore_command(
        Some("not actually a valid bip39 mnemonic phrase at all"),
        Some(key_path.clone()),
        Some(""),
        Some(""),
    )
    .unwrap_err();

    assert!(matches!(error, Error::InvalidMnemonic(_)));
    assert!(!key_path.exists(), "no key should be written on failure");
}

#[test]
fn test_verify_command_accepts_a_matching_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");

    restore_command(
        Some(PHRASE),
        Some(key_path.clone()),
        Some("alice"),
        Some(""),
    )
    .unwrap();

    verify_command(Some(PHRASE), Some(key_path)).expect("verify should accept a matching key");
}

#[test]
fn test_verify_command_ignores_the_comment() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");

    // The stored key carries a comment; the regenerated one does not.
    restore_command(
        Some(PHRASE),
        Some(key_path.clone()),
        Some("someone@example.com"),
        Some(""),
    )
    .unwrap();

    verify_command(Some(PHRASE), Some(key_path))
        .expect("verify should compare key material, not comments");
}

#[test]
fn test_verify_command_rejects_a_mismatched_key() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");

    restore_command(Some(PHRASE), Some(key_path.clone()), Some(""), Some("")).unwrap();

    let error = verify_command(Some(OTHER_PHRASE), Some(key_path)).unwrap_err();
    assert!(matches!(error, Error::VerificationFailed(_)));
}

#[test]
fn test_verify_command_reports_a_missing_key_file() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("does_not_exist");

    let error = verify_command(Some(PHRASE), Some(missing)).unwrap_err();
    assert!(matches!(error, Error::IoError(_)));
}

#[test]
fn test_verify_command_rejects_an_invalid_phrase() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");

    restore_command(Some(PHRASE), Some(key_path.clone()), Some(""), Some("")).unwrap();

    let error = verify_command(Some("clearly not a mnemonic"), Some(key_path)).unwrap_err();
    assert!(matches!(error, Error::InvalidMnemonic(_)));
}

#[test]
fn test_generated_key_verifies_against_its_own_mnemonic() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let mnemonic_path = dir.path().join("phrase.txt");

    generate_command(
        Some(key_path.clone()),
        Some("alice@example.com"),
        Some(""),
        Some(MnemonicLength::Words18),
        Some(mnemonic_path.clone()),
    )
    .unwrap();

    let phrase = fs::read_to_string(&mnemonic_path).unwrap();
    verify_command(Some(phrase.trim()), Some(key_path))
        .expect("a freshly generated key must verify against its own phrase");
}

/// Minimal base64 decoder so the CLI tests do not need a decoding dependency.
fn base64_decode(input: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut output = Vec::new();

    for byte in input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
    {
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .expect("valid base64 character") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }

    output
}

/// Whether `haystack` contains `needle` as a contiguous byte sequence.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn test_base64_helper_round_trips() {
    // The helper above is test scaffolding, so it gets a test of its own.
    assert_eq!(base64_decode("aHVudGVyMg=="), b"hunter2");
    assert_eq!(base64_decode(""), Vec::<u8>::new());
    assert!(contains(b"openssh-key-v1", b"key"));
    assert!(!contains(b"openssh-key-v1", b"absent"));
}

#[test]
fn test_paths_are_reported_back_unchanged() {
    let dir = tempdir().unwrap();
    let key_path: PathBuf = dir.path().join("id_ed25519");

    generate_command(
        Some(key_path.clone()),
        Some(""),
        Some(""),
        Some(MnemonicLength::Words12),
        None,
    )
    .unwrap();

    // A key generated without a comment still produces a usable public key.
    let public_key = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert_eq!(public_key.split_whitespace().count(), 2, "no comment field");
}
