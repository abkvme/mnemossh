# MnemoSSH

MnemoSSH is a Rust-based library and command-line utility designed to generate and manage Ed25519 SSH keys using BIP-39 mnemonic phrases. It provides secure and reproducible key generation from mnemonic phrases, allowing easy backup and recovery of SSH keys.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/abkvme/mnemossh/ci.yml?label=ci&branch=main)](https://github.com/abkvme/mnemossh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/abkvme/mnemossh/release.yml?label=release)](https://github.com/abkvme/mnemossh/actions/workflows/release.yml)
[![Clippy](https://img.shields.io/badge/Clippy-Checked-brightgreen)](https://github.com/abkvme/mnemossh/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/abkvme/mnemossh/branch/main/graph/badge.svg)](https://codecov.io/gh/abkvme/mnemossh)
[![Crates.io](https://img.shields.io/crates/v/mnemossh.svg)](https://crates.io/crates/mnemossh)


## Features

- **Generate SSH keys from mnemonic phrases**: Create Ed25519 SSH keys deterministically from BIP-39 mnemonic phrases
- **Create new mnemonics**: Generate cryptographically secure mnemonic phrases (12, 18, or 24 words)
- **Restore keys**: Easily recover your SSH keys from your saved mnemonic phrase
- **Key fingerprints**: Display MD5 and SHA256 fingerprints in OpenSSH format for all key operations
- **Key inspection**: View detailed information about existing SSH keys, including fingerprints
- **Compatible with OpenSSH**: Generated keys work with standard SSH tools and servers
- **Passphrase protection**: Optionally encrypt your private keys with a passphrase
- **Fully interactive**: Guided, interactive workflows when command-line parameters aren't provided
- **File safety**: Prompts before overwriting existing key files

## Installation

### From Source

```bash
git clone https://github.com/abkvme/mnemossh.git
cd mnemossh
cargo build --release
```

The binary will be available at `target/release/mnemossh`.

## Usage

MnemoSSH provides five main commands: `generate`, `restore`, `verify`, `info`, and `version`. All commands support both their full name and their aliases (`gen`, `res`, `ver`, `i`, and `v` respectively).

### Generate a new SSH key with mnemonic

The `generate` command creates a new mnemonic phrase and uses it to derive an Ed25519 SSH key pair. When run without parameters, it guides you through an interactive process.

**Basic usage:**
```bash
mnemossh generate
```

**With all options:**
```bash
mnemossh gen -o ~/.ssh/id_ed25519 -c user@example.com -l 24 -m ~/.ssh/mnemonic.txt -p mysecretpass
```

**Without a terminal (scripts, CI):** supply every option, using an empty value
for anything you want to skip, so nothing prompts:
```bash
mnemossh gen -o ./id_ed25519 -c user@example.com -l 24 -m ./mnemonic.txt -p ""
```

**Output includes fingerprints:**
```
✓ SSH keys saved successfully:
  Private key: /Users/user/.ssh/id_ed25519
  Public key:  /Users/user/.ssh/id_ed25519.pub

🔑 Key fingerprints:
  MD5:12:f8:7e:78:61:b4:bf:e2:de:24:15:96:4e:d4:72:53
  SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8

✓ Mnemonic saved to file: /Users/user/.ssh/mnemonic.txt
```

### Restore an SSH key from mnemonic

The `restore` command recreates an SSH key pair from an existing mnemonic phrase. The mnemonic can be provided as a parameter or entered interactively.

**Basic usage:**
```bash
mnemossh restore
# You'll be prompted to enter the mnemonic phrase
```

**With mnemonic as parameter:**
```bash
mnemossh restore "abandon ability able about ..."
```

**With all options:**
```bash
mnemossh res "abandon ability able about ..." -o ~/.ssh/id_ed25519 -c user@example.com -p mysecretpass
```

**Output includes fingerprints:**
```
✓ SSH keys restored successfully:
  Private key: /Users/user/.ssh/id_ed25519
  Public key:  /Users/user/.ssh/id_ed25519.pub

🔑 Key fingerprints:
  MD5:12:f8:7e:78:61:b4:bf:e2:de:24:15:96:4e:d4:72:53
  SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
```

### Verify key integrity

The `verify` command checks that an existing SSH key matches a given mnemonic phrase. The mnemonic can be provided as a parameter or entered interactively.

**Basic usage:**
```bash
mnemossh verify
# You'll be prompted to enter the mnemonic phrase
```

**With mnemonic as parameter:**
```bash
mnemossh verify "abandon ability able about ..."
```

**With key path specified:**
```bash
mnemossh ver "abandon ability able about ..." -k ~/.ssh/id_ed25519
```

**Output includes fingerprints:**
```
✓ Key verification successful!

🔑 Key fingerprints:
  MD5:12:f8:7e:78:61:b4:bf:e2:de:24:15:96:4e:d4:72:53
  SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
```

### Display key information

The `info` command displays detailed information about an existing SSH key, including its fingerprints.

**Basic usage:**
```bash
mnemossh info
# Uses default SSH location (~/.ssh/id_ed25519)
```

**With key path specified:**
```bash
mnemossh info -k ~/.ssh/id_ed25519
# or using alias
mnemossh i -k ~/.ssh/id_ed25519
```

**Example output:**
```
🔑 SSH Key Information

Key Type:    ssh-ed25519
Comment:     user@example.com

Fingerprints:
  MD5:     12:f8:7e:78:61:b4:bf:e2:de:24:15:96:4e:d4:72:53
  SHA256:  nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8

Key File:    /Users/user/.ssh/id_ed25519.pub
```

### Display version information

```bash
mnemossh version
# or simply
mnemossh v
```

### Display help

```bash
# General help
mnemossh --help

# Command-specific help
mnemossh generate --help
mnemossh restore --help
mnemossh verify --help
```

## Interactive Features and Safety

### Guided Workflow

MnemoSSH uses an interactive workflow when parameters aren't specified:

1. **Output Path Selection**: Choose between default SSH location, current directory, or a custom path
2. **Mnemonic Input**: Type your mnemonic phrase when restoring or verifying if not provided as an argument
3. **Mnemonic Length**: Select from 12, 18, or 24 words when generating a new mnemonic
4. **Passphrase Entry**: Securely enter and confirm passphrases with masked input

### Overwrite Protection

The utility includes protection against accidentally overwriting existing SSH keys. When generating or restoring SSH keys to a location where keys already exist:

1. The tool will detect any existing files
2. Show a clear warning message
3. Ask for confirmation before proceeding
4. Default to NOT overwriting for safety

## Command Line Reference

MnemoSSH provides comprehensive command line options for all operations. Below is a detailed reference of all available commands and their parameters.

### Global Options

- `--help`: Display help information for any command
- `--version`: Display version information

### `generate` Command (alias: `gen`)

Generate a new mnemonic phrase and SSH key pair.

**Parameters:**

- `-o, --output <FILE>`: Output file for the private key (public key will be saved as `<file>.pub`)
  - If not specified, you'll be prompted interactively to choose:
    - Default SSH location (`~/.ssh/id_ed25519`)
    - Current directory (`./id_ed25519`)
    - Custom location (enter path)
  - Checks for existing files and prompts before overwriting

- `-c, --comment <COMMENT>`: Comment to add to the public key (typically an email address)
  - This is added to the end of the public key and is useful for identifying the key owner
  - It is stored in the private key as well, so `ssh-add -l` shows it
  - Pass an empty value (`-c ""`) for no comment without being prompted

- `-p, --passphrase <PASSPHRASE>`: Passphrase for encrypting the private key
  - If not provided via command line, you'll be prompted interactively
  - Pass an empty value (`-p ""`) to skip encryption without being prompted, which
    is what you want when scripting
  - The key is encrypted with AES-256-CTR, keyed by bcrypt-pbkdf, the same way
    OpenSSH's own `ssh-keygen` does it
  - Use a strong passphrase for additional security

- `-l, --length <LENGTH>`: Length of the mnemonic phrase (12, 18, or 24 words)
  - If not specified, you'll be prompted to choose interactively
  - Options are: 24 words (highest security, 256 bits), 18 words (high security, 192 bits), or 12 words (standard security, 128 bits)

- `-m, --mnemonic-file <FILE>`: Save the mnemonic phrase to a file instead of displaying it
  - Useful for storing the phrase securely
  - IMPORTANT: Anyone with access to this file can recreate your SSH key

### `restore` Command (alias: `res`)

Restore an SSH key from a mnemonic phrase.

**Parameters:**

- `<MNEMONIC>`: The BIP-39 mnemonic phrase to restore from (optional)
  - Should be 12, 18, or 24 words matching the original phrase
  - If not provided via command line, you'll be prompted to enter it interactively

- `-o, --output <FILE>`: Output file for the private key (public key will be saved as `<file>.pub`)
  - If not specified, you'll be prompted interactively to choose:
    - Default SSH location (`~/.ssh/id_ed25519`)
    - Current directory (`./id_ed25519`)
    - Custom location (enter path)
  - Checks for existing files and prompts before overwriting

- `-c, --comment <COMMENT>`: Comment to add to the public key (typically an email address)
  - This is added to the end of the public key and is useful for identifying the key owner

- `-p, --passphrase <PASSPHRASE>`: Passphrase for encrypting the private key
  - If not provided via command line, you'll be prompted interactively
  - Pass an empty value (`-p ""`) to skip encryption without being prompted
  - This creates a new encryption for the private key and does not need to match original passphrase
  - The passphrase protects the key file only; it is not part of key derivation,
    so the same mnemonic always restores the same key

### `verify` Command (alias: `ver`)

Verify that a key matches a mnemonic phrase.

**Parameters:**

- `<MNEMONIC>`: The BIP-39 mnemonic phrase to verify (optional)
  - Should be 12, 18, or 24 words to verify against the key
  - If not provided via command line, you'll be prompted to enter it interactively

- `-k, --key <FILE>`: The SSH key file to verify against
  - If not specified, you'll be prompted interactively to choose:
    - Default SSH location (`~/.ssh/id_ed25519`)
    - Current directory (`./id_ed25519`)
    - Custom location (enter path)
  - The utility will check if this key was generated from the provided mnemonic phrase

### `info` Command (alias: `i`)

Display information about an existing SSH key.

**Parameters:**

- `-k, --key <FILE>`: The SSH key file to inspect
  - If not specified, uses the default SSH location (`~/.ssh/id_ed25519`)
  - Displays key type, comment, and fingerprints (MD5 and SHA256)

### `version` Command (alias: `v`)

Display version information about the MnemoSSH utility.

**Parameters:** None

## Library Usage

MnemoSSH can be used as a library in other Rust projects. For complete examples, see the [examples](examples/) directory.

```rust
use mnemossh::{Mnemonic, MnemonicLength, generate_keypair_from_mnemonic};

// Generate a new mnemonic
let mnemonic = Mnemonic::new(MnemonicLength::Words24)?;

// Or restore from an existing phrase
let mnemonic = Mnemonic::from_phrase("abandon ability able about ...")?;

// Generate a key pair
let keypair = generate_keypair_from_mnemonic(&mnemonic, Some("user@example.com"), None)?;

// Get fingerprints
println!("MD5:     {}", keypair.md5_fingerprint());
println!("SHA256:  {}", keypair.sha256_fingerprint());

// Save the key pair
let (private_path, public_path) = keypair.save_to_files("~/.ssh/id_ed25519")?;
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to get started, and our [Code of Conduct](CODE_OF_CONDUCT.md) for community guidelines.

## Contact

For questions, feedback, or discussions, you can reach out to the author on X: [@abkvme](https://x.com/abkvme)

## Security

For information about security best practices and how to report security vulnerabilities, please see our [Security Policy](SECURITY.md).

> **Keys generated with a passphrase by version 0.1.10 or earlier are not
> protected.** Those versions labelled the key `aes256-ctr`/`bcrypt` but stored it
> unencrypted, with the passphrase in cleartext. Regenerate any such key from a
> new mnemonic — see [SECURITY.md](SECURITY.md) for details. Keys generated
> without a passphrase are unaffected.

## Security Considerations

- **Keep your mnemonic phrase secure**: Anyone with access to your mnemonic phrase can generate your SSH key
- **Consider using a passphrase**: For additional security, encrypt your private key with a passphrase. Keys are encrypted with AES-256-CTR using a key derived by bcrypt-pbkdf, the same construction OpenSSH uses
- **Offline generation**: For highest security, generate keys on an air-gapped machine

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details