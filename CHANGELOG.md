# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.12] - 2026-08-23

### Security
- **Private key encryption is now actually performed.** Previous versions wrote
  `aes256-ctr` and `bcrypt` into the key header but stored the private key
  unencrypted, and wrote the passphrase itself in cleartext into the key's
  comment field. Keys are now encrypted with AES-256-CTR using a key derived by
  bcrypt-pbkdf (16 rounds, fresh 16-byte salt per key), matching OpenSSH.
  - **Any key generated with a passphrase by version 0.1.10 or earlier must be
    treated as compromised.** Both the private key and the passphrase are
    recoverable from such a file. Because the key is derived from the mnemonic,
    re-encrypting the same mnemonic is not sufficient: generate a *new* mnemonic,
    install the new public key wherever the old one was authorised, and stop
    using that passphrase elsewhere.
  - Keys generated without a passphrase are unaffected and remain valid.

### Fixed
- The `--comment` value is now stored in the private key as well as the public
  key. It was previously overwritten by the passphrase (or left empty), so
  `ssh-add -l` showed no comment.
- Passphrase-protected keys are now loadable by OpenSSH. Previously `ssh`,
  `ssh-add`, and `ssh-keygen` all rejected them with "incomplete message".
- Private key padding now uses the cipher's block size (16 bytes for
  `aes256-ctr`, 8 for unencrypted keys) instead of a fixed 8 bytes.
- `expand_tilde` no longer rewrites `~user/path` into the current user's home
  directory, and no longer panics on a multi-byte character after the tilde.
- An empty `--passphrase` or `--comment` is now treated as an explicit "none"
  instead of prompting, so `generate` and `restore` can be run without a
  terminal. An empty passphrase no longer produces an "encrypted" key.

### Added
- OpenSSH interoperability tests that load generated keys with the real
  `ssh-keygen`, covering both the encrypted and unencrypted paths and confirming
  that a wrong passphrase is rejected (`tests/openssh_interop_tests.rs`).
- Unit tests that parse the generated private key format field by field, verify
  the encrypted section decrypts to the expected key, and assert that neither the
  passphrase nor the private seed appears anywhere in an encrypted key file.
- Tests for the non-interactive `generate`, `restore`, and `verify` command
  paths, `KeyGenConfig`, and the `utils` permission helpers.
- Argument parsing tests covering every flag, the positional mnemonic, the
  subcommand aliases, and the inputs that must be rejected
  (`tests/cli_parsing_tests.rs`).
- The test suite grew from 33 to 86 tests, raising line coverage from 40.25% to
  56.12%. What remains uncovered is the interactive prompt handling, which needs
  a terminal, and the `main` entry point.

### Changed
- Updated dependencies to latest versions:
  - ed25519-dalek: 2.2.0 → 3.0.0 (the `zeroize` feature is now explicit, so
    private keys are still wiped on drop)
  - base64: 0.22.1 → 0.23.1
  - rand: 0.9.2 → 0.10.2
  - clap: 4.5.48 → 4.6.6
  - time: 0.3.44 → 0.3.55
  - zeroize: 1.8.2 → 1.9.0
  - thiserror: 2.0.17 → 2.0.20
  - anyhow: 1.0.100 → 1.0.104
  - console: 0.16.1 → 0.16.4
  - tempfile: 3.23.0 → 3.27.0, assert_fs: 1.1.3 → 1.1.4
- Added `aes` 0.9.2, `ctr` 0.10.1, and `bcrypt-pbkdf` 0.11.0 for private key
  encryption, and `clap` as a dev-dependency for the argument parsing tests.
- Removed `hmac` and `secrecy`, which were declared but never used, and moved
  `hex` to dev-dependencies. `sha2` is retained (0.10.9 → 0.11.0) and `md5`
  upgraded (0.7.0 → 0.8.1); both are used by the key fingerprints.
- Key derivation is unchanged: the same mnemonic still produces the same public
  key as in earlier versions, verified against a pinned test vector.
- Expanded `.gitignore`: OS cruft (`.DS_Store`, `Thumbs.db`), editor and local
  tool directories, coverage output, and patterns for generated private keys and
  mnemonic files so a phrase or key cannot be committed by accident.

### CI/CD
- Split the single `rust.yml` workflow into `ci.yml` (tests, lint, coverage on
  every push and pull request) and `release.yml`, which is triggered *only* by a
  `v*.*.*` tag, so nothing can be released by an ordinary push.
- A release now fails before building unless the pushed tag matches the version
  in `Cargo.toml`, `Cargo.lock` agrees with the manifest (`--locked`), and it
  warns when `CHANGELOG.md` has no section for the version.
- `release.yml` reuses `ci.yml`, so a tag cannot ship untested code.
- Release notes are taken from the matching `CHANGELOG.md` section, falling back
  to the commit list since the previous tag.
- Replaced the archived `actions-rs/*` actions with `dtolnay/rust-toolchain` and
  `Swatinem/rust-cache`, and updated `actions/checkout`, `upload-artifact`,
  `download-artifact`, and `action-gh-release` to current major versions.
- Clippy now lints `--all-targets`, so test code is checked too, and the
  `needless_range_loop` this surfaced in `tests/keys_tests.rs` is fixed.
- The release job uses the built-in `GITHUB_TOKEN` instead of a personal access
  token, which had expired and failed the release step with "Bad credentials".
- README build badges now point at the new workflows.
- Fixed the Windows build of the test suite: the permission tests are now gated
  behind `#[cfg(unix)]`, the OpenSSH interoperability tests run on Unix only,
  and the Unix-only `std::process::Command` import in `utils` no longer warns on
  Windows. Verified by type-checking every target against
  `x86_64-pc-windows-gnu`.

### Documentation
- `SECURITY.md` now carries an advisory for the unencrypted-key issue in 0.1.10
  and earlier, and lists 0.1.12 as the only supported version.
- `README.md` documents that `-p ""` skips encryption without prompting, and
  names the cipher and KDF used for encrypted keys.

## [0.1.10] - 2025-11-19

### Added
- SSH key fingerprints (MD5 and SHA256) and an `info` command for inspecting an
  existing key.

## [0.1.9] - 2025-10-07

### Added
- Comprehensive test coverage for previously uncovered code paths
  - Test for `version_command` in CLI (src/cli/commands.rs:255)
  - Test for `default_ssh_key_path` function (src/lib.rs:62-66)
  - Tests for `is_file_writable` and `is_dir_writable` functions (src/utils/mod.rs)
- New test file: `tests/cli_tests.rs`

### Changed
- Updated dependencies to latest versions:
  - console: 0.15.11 → 0.16.1
  - dialoguer: 0.11.0 → 0.12.0
  - ed25519-dalek: 2.1.1 → 2.2.0
  - clap: 4.5.38 → 4.5.48
  - anyhow: 1.0.98 → 1.0.100
  - time: 0.3.41 → 0.3.44
  - thiserror: 2.0.12 → 2.0.17
  - rand: 0.9.1 → 0.9.2
  - zeroize: 1.8.1 → 1.8.2
  - tempfile: 3.20.0 → 3.23.0

### Fixed
- Code formatting issues to comply with rustfmt
  - Fixed import ordering (std imports before third-party)
  - Fixed long line formatting for assert statements
- Clippy warnings for CI compliance
  - Collapsed nested if statements using let-chain syntax (&&)
  - Fixed needless borrows in dialoguer `.items()` calls (dialoguer 0.12.0 compatibility)
- Code coverage increased from 9.09% to 70.58%

## [0.1.7] - 2005-05-18

### Added
- Initial release
- BIP-39 mnemonic phrase generation for SSH keys
- Ed25519 SSH key pair generation from mnemonic phrases
- Key restoration from mnemonic phrases
- Key verification against mnemonic phrases
- Support for encrypted private keys with passphrases
- Interactive CLI with user-friendly prompts
- Cross-platform support (Linux, macOS, Windows)
- Support for 12, 18, and 24-word mnemonic phrases

[0.1.12]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.12
[0.1.10]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.10
[0.1.9]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.9
[0.1.7]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.7
