/*!
 * Integration tests for mnemossh
 */

use mnemossh::crypto::keys::{generate_keypair_from_mnemonic, generate_new_keypair_with_mnemonic};
use mnemossh::crypto::mnemonic::{Mnemonic, MnemonicLength};
use mnemossh::default_ssh_key_path;
use mnemossh::utils::ensure_dir_exists;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_full_workflow() {
    // Create a temporary directory for our test
    let temp_dir = tempdir().unwrap();
    let test_dir = temp_dir.path().join("ssh_keys");

    // Ensure the directory exists
    ensure_dir_exists(&test_dir).unwrap();
    assert!(test_dir.exists());

    // Generate a new mnemonic and keypair
    let (mnemonic, keypair) =
        generate_new_keypair_with_mnemonic(MnemonicLength::Words24, Some("test@example.com"), None)
            .unwrap();

    // Save the mnemonic to a file
    let mnemonic_path = test_dir.join("mnemonic.txt");
    fs::write(&mnemonic_path, mnemonic.phrase()).unwrap();
    assert!(mnemonic_path.exists());

    // Save the keypair to files
    let key_path = test_dir.join("id_ed25519");
    let public_key_path = key_path.with_extension("pub");
    fs::write(&key_path, keypair.private_key_openssh()).unwrap();
    fs::write(&public_key_path, keypair.public_key_openssh()).unwrap();
    assert!(key_path.exists());
    assert!(public_key_path.exists());

    // Read back the mnemonic
    let saved_mnemonic_content = fs::read_to_string(&mnemonic_path).unwrap();
    let recovered_mnemonic = Mnemonic::from_phrase(&saved_mnemonic_content).unwrap();

    // Generate a keypair from the recovered mnemonic
    let recovered_keypair =
        generate_keypair_from_mnemonic(&recovered_mnemonic, Some("test@example.com"), None)
            .unwrap();

    // Verify that the keys match
    assert_eq!(
        keypair.public_key_openssh(),
        recovered_keypair.public_key_openssh()
    );

    // Sign a message with the original keypair
    let message = b"Test message to verify key functionality";
    let signature = keypair.sign(message);

    // Verify the signature with the recovered keypair
    assert!(recovered_keypair.verify(message, &signature));

    // Try with an invalid message - should fail
    let invalid_message = b"Wrong message";
    assert!(!recovered_keypair.verify(invalid_message, &signature));
}

#[test]
fn test_default_ssh_key_path() {
    // Test that default_ssh_key_path returns a valid path
    let result = default_ssh_key_path();
    assert!(result.is_ok(), "default_ssh_key_path should succeed");

    let path = result.unwrap();

    // The path should end with .ssh/id_ed25519
    assert!(path.to_string_lossy().contains(".ssh"));
    assert!(path.to_string_lossy().ends_with("id_ed25519"));

    // The parent directory (.ssh) should exist after calling default_ssh_key_path
    if let Some(parent) = path.parent() {
        assert!(
            parent.exists(),
            ".ssh directory should exist after calling default_ssh_key_path"
        );
    }
}
