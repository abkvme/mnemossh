/*!
 * Command implementations for the mnemossh CLI
 */

use std::path::PathBuf;
use console::{style, Term};
use dialoguer::Password;
use chrono::Datelike;

use crate::crypto::keys::generate_new_keypair_with_mnemonic;
use crate::crypto::mnemonic::MnemonicLength;
use crate::{default_ssh_key_path, Result, Error};
use crate::utils::ensure_dir_exists;

/// Generate a new mnemonic phrase and SSH key pair
pub fn generate_command(
    output: Option<PathBuf>,
    comment: Option<&str>,
    passphrase: Option<&str>,
    mnemonic_length: Option<MnemonicLength>,
    mnemonic_file: Option<PathBuf>,
) -> Result<()> {
    let term = Term::stdout();
    
    // Get the output path from command line or interactively
    let output_path = match output {
        Some(path) => path,
        None => {
            // User didn't specify path, use interactive mode
            term.write_line("\nNo output path specified. Please select where to save the SSH key:")?;
            
            let default_path = default_ssh_key_path().unwrap_or_else(|_| PathBuf::from("id_ed25519"));
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let current_path = current_dir.join("id_ed25519");
            
            term.write_line(&format!("  [0] Default SSH location: {}", style(&default_path.display()).cyan()))?;
            term.write_line(&format!("  [1] Current directory: {}", style(&current_path.display()).cyan()))?;
            term.write_line("  [2] Custom location")?;
            
            let selection = dialoguer::Select::new()
                .with_prompt("Select path option")
                .default(0)
                .items(&["Default SSH location", "Current directory", "Custom location"])
                .interact()?;
            
            match selection {
                0 => default_path,
                1 => current_path,
                2 => {
                    let input = dialoguer::Input::<String>::new()
                        .with_prompt("Enter custom path for SSH key")
                        .interact_text()?;
                    PathBuf::from(input)
                },
                _ => unreachable!()
            }
        }
    };
    
    // Check if the key files already exist and warn the user
    let private_exists = output_path.exists();
    let public_exists = output_path.with_extension("pub").exists();
    
    if private_exists || public_exists {
        let files_str = match (private_exists, public_exists) {
            (true, true) => "Private and public key files",
            (true, false) => "Private key file",
            (false, true) => "Public key file",
            _ => unreachable!()
        };
        
        term.write_line(&format!("\n{} {} already exist at the specified location.",
            style("Warning:").yellow().bold(),
            files_str
        ))?;
        
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Do you want to overwrite the existing files?")
            .default(false)
            .interact()?;
            
        if !confirm {
            return Err(Error::UserCancelled("Key generation was cancelled by the user".to_string()));
        }
    }
    
    // If output directory doesn't exist, create it
    if let Some(parent) = output_path.parent() {
        ensure_dir_exists(parent)?;
    }
    
    // Get passphrase interactively if not provided
    let passphrase = match passphrase {
        Some(pass) => Some(pass.to_string()),
        None => {
            term.write_line("Generating a new SSH key pair from a BIP-39 mnemonic phrase.")?;
            
            // Ask if the user wants to encrypt the private key
            let encrypt_input = dialoguer::Confirm::new()
                .with_prompt("Do you want to encrypt the private key with a passphrase?")
                .default(false)
                .interact()?;
            
            if encrypt_input {
                let pass = Password::new()
                    .with_prompt("Enter passphrase (empty for no passphrase)")
                    .with_confirmation("Confirm passphrase", "Passphrases do not match")
                    .allow_empty_password(true)
                    .interact()?;
                
                if pass.is_empty() {
                    None
                } else {
                    Some(pass)
                }
            } else {
                None
            }
        }
    };
    
    // Get mnemonic length interactively if not provided via command line
    let mnemonic_length = match mnemonic_length {
        Some(length) => length,
        None => {
            term.write_line("\nPlease select the mnemonic phrase length:")?;
            term.write_line("  [0] 24 words (highest security, 256 bits of entropy)")?;
            term.write_line("  [1] 18 words (high security, 192 bits of entropy)")?;
            term.write_line("  [2] 12 words (standard security, 128 bits of entropy)")?;
            
            let selection = dialoguer::Select::new()
                .with_prompt("Select mnemonic length")
                .default(0) // Default to 24 words
                .items(&["24 words", "18 words", "12 words"])
                .interact()?;
                
            match selection {
                0 => MnemonicLength::Words24,
                1 => MnemonicLength::Words18,
                2 => MnemonicLength::Words12,
                _ => unreachable!()
            }
        }
    };
    
    // Get comment interactively if not provided
    let comment = match comment {
        Some(c) => Some(c.to_string()),
        None => {
            term.write_line("\nEnter a comment for your SSH key (typically your email address):")?;
            term.write_line("This will be added to the end of your public key.")?;
            
            let input = dialoguer::Input::<String>::new()
                .with_prompt("Comment (email)")
                .allow_empty(true)
                .interact_text()?;
                
            if input.is_empty() {
                None
            } else {
                Some(input)
            }
        }
    };
    
    // Generate new mnemonic and key pair
    let (mnemonic, keypair) = generate_new_keypair_with_mnemonic(
        mnemonic_length,
        comment.as_deref(),
        passphrase.as_deref(),
    )?;
    
    // Save the key pair
    let (private_path, public_path) = keypair.save_to_files(&output_path)?;
    
    term.write_line(&format!(
        "\n{} Private key saved to: {}",
        style("✓").green().bold(),
        style(private_path.display()).cyan()
    ))?;
    
    term.write_line(&format!(
        "{} Public key saved to: {}\n",
        style("✓").green().bold(),
        style(public_path.display()).cyan()
    ))?;
    
    // Save or display the mnemonic phrase
    if let Some(mnemonic_path) = mnemonic_file {
        if let Some(parent) = mnemonic_path.parent() {
            ensure_dir_exists(parent)?;
        }
        
        mnemonic.save_to_file(&mnemonic_path)?;
        
        term.write_line(&format!(
            "{} Mnemonic phrase saved to: {}",
            style("✓").green().bold(),
            style(mnemonic_path.display()).cyan()
        ))?;
        
        // Warning about securing the mnemonic phrase
        term.write_line(&format!(
            "\n{} {}\n",
            style("⚠").yellow().bold(),
            style("IMPORTANT: Keep your mnemonic phrase in a safe place. Anyone with access to it can generate your SSH key.").yellow()
        ))?;
    } else {
        term.write_line(&format!(
            "{} Your mnemonic phrase ({} words):",
            style("✓").green().bold(),
            match mnemonic_length {
                MnemonicLength::Words12 => "12",
                MnemonicLength::Words18 => "18",
                MnemonicLength::Words24 => "24",
            }
        ))?;
        
        term.write_line(&format!("\n    {}\n", style(mnemonic.phrase()).yellow().bold()))?;
        
        term.write_line(&format!(
            "{} {}\n",
            style("⚠").yellow().bold(),
            style("IMPORTANT: Write down your mnemonic phrase and keep it in a safe place. It will not be shown again.").yellow()
        ))?;
    }
    
    Ok(())
}



/// Display version information
pub fn version_command() -> Result<()> {
    let term = Term::stdout();
    
    term.write_line(&format!(
        "{} version {}",
        style("mnemossh").cyan().bold(),
        style(env!("CARGO_PKG_VERSION")).yellow().bold()
    ))?;
    
    term.write_line(&format!(
        "Copyright (c) {} {}",
        env!("CARGO_PKG_AUTHORS"),
        chrono::Local::now().year()
    ))?;
    
    Ok(())
}
