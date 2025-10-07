# MnemoSSH Example Project

This is a simple example project demonstrating how to use the `mnemossh` library in your Rust application.

## What it does

This example:
1. Generates a new 24-word BIP-39 mnemonic phrase
2. Creates an Ed25519 SSH keypair from that mnemonic
3. Saves the keypair to files

## Running the example

```bash
cd examples/simple_project
cargo run
```

## Using in your project

Add mnemossh to your `Cargo.toml`:

```toml
[dependencies]
mnemossh = "0.1.9"
```

Then use it in your code as shown in `src/main.rs`.
