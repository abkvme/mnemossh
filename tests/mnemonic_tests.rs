/*!
 * Tests for the mnemonic functionality
 */

use std::fs;
use tempfile::tempdir;

use mnemossh::crypto::mnemonic::{Mnemonic, MnemonicLength, generate_seed_from_mnemonic};

/// Test creating mnemonics of different lengths
#[test]
fn test_mnemonic_length() {
    for length in [
        MnemonicLength::Words12,
        MnemonicLength::Words18,
        MnemonicLength::Words24,
    ] {
        let mnemonic = Mnemonic::new(length).unwrap();
        let word_count = mnemonic.phrase().split_whitespace().count();
        assert_eq!(word_count, length.word_count());
    }
}

/// Test parsing word counts from strings
#[test]
fn test_mnemonic_length_from_word_count() {
    assert_eq!(
        MnemonicLength::from_word_count("12").unwrap(),
        MnemonicLength::Words12
    );
    assert_eq!(
        MnemonicLength::from_word_count("18").unwrap(),
        MnemonicLength::Words18
    );
    assert_eq!(
        MnemonicLength::from_word_count("24").unwrap(),
        MnemonicLength::Words24
    );
    assert!(MnemonicLength::from_word_count("15").is_err());
    assert!(MnemonicLength::from_word_count("invalid").is_err());
}

/// Test default mnemonic length (24 words)
#[test]
fn test_mnemonic_length_default() {
    assert_eq!(MnemonicLength::default(), MnemonicLength::Words24);
}

/// Test creating a mnemonic from an existing phrase
#[test]
fn test_mnemonic_from_valid_phrase() {
    // Standard test vector from BIP-39 spec
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
    assert_eq!(mnemonic.phrase(), phrase);

    // Verify the entropy bytes are correct for this known phrase
    assert_eq!(
        hex::encode(mnemonic.entropy()),
        "00000000000000000000000000000000"
    );
}

/// Test that invalid phrases are rejected
#[test]
fn test_mnemonic_from_invalid_phrase() {
    // Too short
    assert!(Mnemonic::from_phrase("abandon abandon abandon").is_err());

    // Invalid checksum
    assert!(Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());

    // Not a mnemonic at all
    assert!(Mnemonic::from_phrase("not a valid mnemonic phrase at all").is_err());
}

/// Test saving and loading mnemonic to/from a file
#[test]
fn test_mnemonic_file_operations() {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("mnemonic.txt");

    // Create a mnemonic and save it
    let mnemonic = Mnemonic::new(MnemonicLength::Words12).unwrap();
    let phrase = mnemonic.phrase().to_string();
    mnemonic.save_to_file(&file_path).unwrap();

    // Read it back and verify
    let saved_content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(saved_content, phrase);

    // Create a new mnemonic from the saved phrase
    let loaded_mnemonic = Mnemonic::from_phrase(&saved_content).unwrap();
    assert_eq!(loaded_mnemonic.phrase(), phrase);

    // Ensure both generate the same seed
    assert_eq!(mnemonic.to_seed(), loaded_mnemonic.to_seed());
}

/// Test seed generation from mnemonics
#[test]
fn test_mnemonic_seed_generation() {
    // BIP-39 test vector
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

    // Test direct method
    let seed = mnemonic.to_seed();
    assert_eq!(seed.len(), 64); // 512 bits = 64 bytes
    assert_eq!(hex::encode(&seed[..8]), "5eb00bbddcf06908");

    // Test via the function
    let seed2 = generate_seed_from_mnemonic(&mnemonic);
    assert_eq!(seed, seed2);
}

/// Test that multiple new mnemonics are unique
#[test]
fn test_mnemonic_uniqueness() {
    let mnemonic1 = Mnemonic::new(MnemonicLength::Words24).unwrap();
    let mnemonic2 = Mnemonic::new(MnemonicLength::Words24).unwrap();
    let mnemonic3 = Mnemonic::new(MnemonicLength::Words24).unwrap();

    assert_ne!(mnemonic1.phrase(), mnemonic2.phrase());
    assert_ne!(mnemonic1.phrase(), mnemonic3.phrase());
    assert_ne!(mnemonic2.phrase(), mnemonic3.phrase());

    assert_ne!(mnemonic1.entropy(), mnemonic2.entropy());
    assert_ne!(mnemonic1.entropy(), mnemonic3.entropy());
    assert_ne!(mnemonic2.entropy(), mnemonic3.entropy());
}

/// Test Debug and Display implementations do not leak sensitive information
#[test]
fn test_mnemonic_formatting() {
    let mnemonic = Mnemonic::new(MnemonicLength::Words12).unwrap();

    let debug_str = format!("{:?}", mnemonic);
    let display_str = format!("{}", mnemonic);

    assert!(!debug_str.contains(mnemonic.phrase()));
    assert!(!display_str.contains(mnemonic.phrase()));

    assert_eq!(debug_str, "Mnemonic { [REDACTED] }");
    assert_eq!(display_str, "[REDACTED MNEMONIC]");
}
