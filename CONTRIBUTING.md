# Contributing to MnemoSSH

Thank you for your interest in contributing to MnemoSSH! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub with:
- A clear description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (OS, Rust version, etc.)

### Suggesting Features

We welcome feature suggestions! Please open an issue with:
- A clear description of the feature
- Use cases and benefits
- Any relevant examples or mockups

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for any new functionality
4. **Ensure all tests pass**: `cargo test`
5. **Run formatting**: `cargo fmt`
6. **Run clippy**: `cargo clippy -- -D warnings`
7. **Update documentation** if needed
8. **Submit a pull request**

## Development Setup

### Prerequisites

- Rust 1.90.0 or later
- Cargo

### Building

```bash
git clone https://github.com/abkvme/mnemossh.git
cd mnemossh
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Quality

Before submitting a PR, ensure your code passes:

```bash
# Format code
cargo fmt

# Check for common mistakes
cargo clippy -- -D warnings

# Run tests
cargo test
```

## Coding Standards

- Follow Rust naming conventions
- Write clear, descriptive commit messages
- Keep functions focused and modular
- Add comments for complex logic
- Write tests for new functionality
- Update CHANGELOG.md for significant changes

## Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Keep first line under 72 characters
- Reference issues and pull requests when relevant

Examples:
```
Add support for RSA key generation

Fix clippy warnings in crypto module

Update dependencies to latest versions
```

## Code of Conduct

Please note that this project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Questions?

If you have questions, feel free to:
- Open an issue for discussion
- Check existing issues and pull requests
- Review the documentation in README.md

## License

By contributing to MnemoSSH, you agree that your contributions will be licensed under the MIT License.
