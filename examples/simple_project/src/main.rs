use mnemossh::{Mnemonic, MnemonicLength, generate_keypair_from_mnemonic};

fn main() -> anyhow::Result<()> {
    println!("MnemoSSH Library Example\n");

    // Generate a new 24-word mnemonic
    let mnemonic = Mnemonic::new(MnemonicLength::Words24)?;
    println!("Generated mnemonic phrase:");
    println!("{}\n", mnemonic.phrase());

    // Generate SSH keypair from the mnemonic
    let keypair = generate_keypair_from_mnemonic(&mnemonic, Some("user@example.com"), None)?;

    // Save to files
    let (private_path, public_path) = keypair.save_to_files("./my_ssh_key")?;

    println!("SSH keys generated and saved:");
    println!("  Private key: {}", private_path.display());
    println!("  Public key: {}", public_path.display());
    println!("\nKeep your mnemonic phrase safe - you can use it to restore this key!");

    Ok(())
}
