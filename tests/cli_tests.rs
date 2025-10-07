/*!
 * Tests for the CLI commands
 */

use mnemossh::cli::{info_command, version_command};
use mnemossh::crypto::keys::generate_keypair_from_mnemonic;
use mnemossh::crypto::mnemonic::{Mnemonic, MnemonicLength};
use std::fs;
use tempfile::tempdir;

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
