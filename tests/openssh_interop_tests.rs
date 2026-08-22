/*!
 * Interoperability tests that run the generated keys through real OpenSSH.
 *
 * These are the tests that catch a key file which looks structurally plausible
 * but that `ssh` would refuse to load. They are skipped when `ssh-keygen` is
 * not installed so the suite still runs everywhere.
 */

use std::path::Path;
use std::process::{Command, Output};

use mnemossh::crypto::keys::generate_keypair_from_mnemonic;
use mnemossh::crypto::mnemonic::Mnemonic;
use tempfile::tempdir;

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Whether `ssh-keygen` is available to test against.
fn ssh_keygen_available() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .output()
        .map(|output| output.status.code() != Some(127))
        .unwrap_or(false)
}

/// Ask `ssh-keygen` to load a private key and print the public key it derives.
fn ssh_keygen_read_key(path: &Path, passphrase: &str) -> Output {
    Command::new("ssh-keygen")
        .arg("-y")
        .arg("-P")
        .arg(passphrase)
        .arg("-f")
        .arg(path)
        .output()
        .expect("failed to run ssh-keygen")
}

/// The `ssh-ed25519 AAAA...` part of a public key, without the comment.
fn key_material(public_key: &str) -> String {
    public_key
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Write a key pair to a temporary directory and hand back the private key path.
fn write_key(
    dir: &Path,
    name: &str,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> std::path::PathBuf {
    let mnemonic = Mnemonic::from_phrase(PHRASE).unwrap();
    let keypair = generate_keypair_from_mnemonic(&mnemonic, comment, passphrase).unwrap();
    let (private_path, _) = keypair.save_to_files(dir.join(name)).unwrap();
    private_path
}

#[test]
fn test_openssh_loads_an_unencrypted_key() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempdir().unwrap();
    let key_path = write_key(dir.path(), "plain", Some("alice@example.com"), None);

    let output = ssh_keygen_read_key(&key_path, "");
    assert!(
        output.status.success(),
        "ssh-keygen rejected the key: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let derived = String::from_utf8_lossy(&output.stdout);
    let expected = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert_eq!(key_material(&derived), key_material(&expected));
}

#[test]
fn test_openssh_loads_an_encrypted_key_with_the_right_passphrase() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempdir().unwrap();
    let key_path = write_key(
        dir.path(),
        "encrypted",
        Some("alice@example.com"),
        Some("hunter2"),
    );

    let output = ssh_keygen_read_key(&key_path, "hunter2");
    assert!(
        output.status.success(),
        "ssh-keygen rejected the encrypted key: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let derived = String::from_utf8_lossy(&output.stdout);
    let expected = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert_eq!(key_material(&derived), key_material(&expected));

    // OpenSSH prints the comment stored inside the private key blob.
    assert!(
        derived.contains("alice@example.com"),
        "comment should round-trip through the private key: {}",
        derived
    );
}

#[test]
fn test_openssh_rejects_an_encrypted_key_with_the_wrong_passphrase() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempdir().unwrap();
    let key_path = write_key(dir.path(), "encrypted", None, Some("hunter2"));

    let output = ssh_keygen_read_key(&key_path, "definitely-not-the-passphrase");
    assert!(
        !output.status.success(),
        "ssh-keygen must not load the key with a wrong passphrase"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("incorrect passphrase"),
        "expected a passphrase error, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_openssh_rejects_an_encrypted_key_with_an_empty_passphrase() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempdir().unwrap();
    let key_path = write_key(dir.path(), "encrypted", None, Some("hunter2"));

    // An encrypted key must not be readable without the passphrase. This is the
    // check that fails loudly if the private section is ever left in the clear.
    let output = ssh_keygen_read_key(&key_path, "");
    assert!(
        !output.status.success(),
        "an encrypted key must not load with an empty passphrase"
    );
}

#[test]
fn test_openssh_accepts_the_public_key() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    let dir = tempdir().unwrap();
    let key_path = write_key(dir.path(), "plain", Some("alice@example.com"), None);

    let output = Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(key_path.with_extension("pub"))
        .output()
        .expect("failed to run ssh-keygen");

    assert!(
        output.status.success(),
        "ssh-keygen could not fingerprint the public key"
    );
    let fingerprint = String::from_utf8_lossy(&output.stdout);
    assert!(
        fingerprint.contains("256"),
        "expected a 256-bit key: {}",
        fingerprint
    );
    assert!(
        fingerprint.contains("ED25519"),
        "expected an Ed25519 key: {}",
        fingerprint
    );
    assert!(
        fingerprint.contains("alice@example.com"),
        "expected the comment: {}",
        fingerprint
    );
}

#[test]
fn test_openssh_loads_keys_for_every_mnemonic_length() {
    if !ssh_keygen_available() {
        eprintln!("skipping: ssh-keygen not available");
        return;
    }

    use mnemossh::crypto::keys::generate_new_keypair_with_mnemonic;
    use mnemossh::crypto::mnemonic::MnemonicLength;

    let dir = tempdir().unwrap();
    for (index, length) in [
        MnemonicLength::Words12,
        MnemonicLength::Words18,
        MnemonicLength::Words24,
    ]
    .into_iter()
    .enumerate()
    {
        let (_, keypair) =
            generate_new_keypair_with_mnemonic(length, Some("alice@example.com"), Some("hunter2"))
                .unwrap();
        let (key_path, _) = keypair
            .save_to_files(dir.path().join(format!("key{}", index)))
            .unwrap();

        let output = ssh_keygen_read_key(&key_path, "hunter2");
        assert!(
            output.status.success(),
            "ssh-keygen rejected a {}-word key: {}",
            length.word_count(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
