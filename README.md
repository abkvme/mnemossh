# MnemoSSH

MnemoSSH is a Rust-based library and command-line utility designed to generate and manage Ed25519 SSH keys using BIP-39 mnemonic phrases. It provides secure and reproducible key generation from mnemonic phrases, allowing easy backup and recovery of SSH keys.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Generate SSH keys from mnemonic phrases**: Create Ed25519 SSH keys deterministically from BIP-39 mnemonic phrases
- **Create new mnemonics**: Generate cryptographically secure mnemonic phrases (12, 18, or 24 words)
- **Restore keys**: Easily recover your SSH keys from your saved mnemonic phrase
- **Secure memory handling**: Sensitive information is zeroed from memory when no longer needed
- **Compatible with OpenSSH**: Generated keys work with standard SSH tools and servers
- **Passphrase protection**: Optionally encrypt your private keys with a passphrase

## Installation

### From Source

```bash
git clone https://github.com/abkvme/mnemossh.git
cd mnemossh
cargo build --release
```

The binary will be available at `target/release/mnemossh`.

## Usage

### Generate a new SSH key with mnemonic

```bash
mnemossh generate
```

or with options:

```bash
mnemossh gen -o ~/.ssh/id_ed25519 -c user@example.com -l 18 -m ~/.ssh/mnemonic.txt -p mysecretpass
```

### Restore an SSH key from mnemonic

```bash
mnemossh restore "abandon ability able about ..." -o ~/.ssh/id_ed25519
```

### Verify key integrity

```bash
mnemossh verify "abandon ability able about ..."
```

### Display help

```bash
mnemossh --help
```

## Command Line Options

### Generate Command

- `-o, --output <FILE>`: Specify output file for the private key
- `-c, --comment <COMMENT>`: Add a comment to the public key (typically an email)
- `-p, --passphrase <PASSPHRASE>`: Provide a passphrase for encrypting the private key
- `-l, --length <LENGTH>`: Specify mnemonic length (12, 18, or 24 words)
- `-m, --mnemonic-file <FILE>`: Save mnemonic to a file instead of displaying it

### Restore Command

- `-o, --output <FILE>`: Specify output file for the private key
- `-c, --comment <COMMENT>`: Add a comment to the public key
- `-p, --passphrase <PASSPHRASE>`: Provide a passphrase for encrypting the private key

### Verify Command

- `-k, --key <FILE>`: Specify the SSH key file to verify against

## Library Usage

MnemoSSH can be used as a library in other Rust projects:

```rust
use mnemossh::{Mnemonic, MnemonicLength, generate_keypair_from_mnemonic};

// Generate a new mnemonic
let mnemonic = Mnemonic::new(MnemonicLength::Words24)?;

// Or restore from an existing phrase
let mnemonic = Mnemonic::from_phrase("abandon ability able about ...")?;

// Generate a key pair
let keypair = generate_keypair_from_mnemonic(&mnemonic, Some("user@example.com"), None)?;

// Save the key pair
let (private_path, public_path) = keypair.save_to_files("~/.ssh/id_ed25519")?;
```

## Security Considerations

- **Keep your mnemonic phrase secure**: Anyone with access to your mnemonic phrase can generate your SSH key
- **Consider using a passphrase**: For additional security, encrypt your private key with a passphrase
- **Offline generation**: For highest security, generate keys on an air-gapped machine

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details