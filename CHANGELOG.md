# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.9]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.9
[0.1.7]: https://github.com/abkvme/mnemossh/releases/tag/v0.1.7
