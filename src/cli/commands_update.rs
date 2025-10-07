use base64::Engine;
use console::{Term, style};
use dialoguer::Password;
use std::fs;
use std::path::PathBuf;

use crate::crypto::keys::generate_keypair_from_mnemonic;
use crate::crypto::mnemonic::Mnemonic;
use crate::utils::ensure_dir_exists;
use crate::{Error, Result, default_ssh_key_path};

/// Restore an SSH key from a mnemonic phrase
pub fn restore_command(
    mnemonic_str: Option<&str>,
    output: Option<PathBuf>,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    let term = Term::stdout();

    // Get the output path from command line or interactively
    let output_path = match output {
        Some(path) => path,
        None => {
            // User didn't specify path, use interactive mode
            term.write_line(
                "\nNo output path specified. Please select where to restore the SSH key:",
            )?;

            let default_path =
                default_ssh_key_path().unwrap_or_else(|_| PathBuf::from("id_ed25519"));
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let current_path = current_dir.join("id_ed25519");

            term.write_line(&format!(
                "  [0] Default SSH location: {}",
                style(&default_path.display()).cyan()
            ))?;
            term.write_line(&format!(
                "  [1] Current directory: {}",
                style(&current_path.display()).cyan()
            ))?;
            term.write_line("  [2] Custom location")?;

            let selection = dialoguer::Select::new()
                .with_prompt("Select path option")
                .default(0)
                .items([
                    "Default SSH location",
                    "Current directory",
                    "Custom location",
                ])
                .interact()?;

            match selection {
                0 => default_path,
                1 => current_path,
                2 => {
                    let input = dialoguer::Input::<String>::new()
                        .with_prompt("Enter custom path for SSH key")
                        .interact_text()?;
                    PathBuf::from(input)
                }
                _ => unreachable!(),
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
            _ => unreachable!(),
        };

        term.write_line(&format!(
            "\n{} {} already exist at the specified location.",
            style("Warning:").yellow().bold(),
            files_str
        ))?;

        let confirm = dialoguer::Confirm::new()
            .with_prompt("Do you want to overwrite the existing files?")
            .default(false)
            .interact()?;

        if !confirm {
            return Err(Error::UserCancelled(
                "Key restoration was cancelled by the user".to_string(),
            ));
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

                if pass.is_empty() { None } else { Some(pass) }
            } else {
                None
            }
        }
    };

    // Get mnemonic phrase from command line or interactively
    let mnemonic_phrase = match mnemonic_str {
        Some(phrase) => phrase.to_string(),
        None => {
            term.write_line("\nPlease enter your mnemonic phrase to restore your SSH key:")?;
            term.write_line("(Enter all words separated by spaces)")?;

            dialoguer::Input::<String>::new()
                .with_prompt("Mnemonic phrase")
                .interact_text()?
        }
    };

    // Parse the mnemonic phrase
    let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase)?;

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

            if input.is_empty() { None } else { Some(input) }
        }
    };

    // Generate the key pair from the mnemonic
    let keypair =
        generate_keypair_from_mnemonic(&mnemonic, comment.as_deref(), passphrase.as_deref())?;

    // Save the key pair
    let (private_path, public_path) = keypair.save_to_files(&output_path)?;

    term.write_line(&format!(
        "\n{} Private key restored to: {}",
        style("✓").green().bold(),
        style(private_path.display()).cyan()
    ))?;

    term.write_line(&format!(
        "{} Public key restored to: {}",
        style("✓").green().bold(),
        style(public_path.display()).cyan()
    ))?;

    // Display key fingerprints
    term.write_line(&format!(
        "\n{} Key fingerprints:",
        style("🔑").cyan().bold()
    ))?;
    term.write_line(&format!("  {}", style(keypair.md5_fingerprint()).dim()))?;
    term.write_line(&format!(
        "  {}\n",
        style(keypair.sha256_fingerprint()).dim()
    ))?;

    Ok(())
}

/// Verify that a key matches a mnemonic phrase
pub fn verify_command(mnemonic_str: Option<&str>, key_path: Option<PathBuf>) -> Result<()> {
    let term = Term::stdout();
    let key_path = key_path
        .unwrap_or_else(|| default_ssh_key_path().unwrap_or_else(|_| PathBuf::from("id_ed25519")));

    // Get mnemonic phrase from command line or interactively
    let mnemonic_phrase = match mnemonic_str {
        Some(phrase) => phrase.to_string(),
        None => {
            term.write_line("\nPlease enter your mnemonic phrase to verify against the SSH key:")?;
            term.write_line("(Enter all words separated by spaces)")?;

            dialoguer::Input::<String>::new()
                .with_prompt("Mnemonic phrase")
                .interact_text()?
        }
    };

    // Parse the mnemonic phrase
    let mnemonic = Mnemonic::from_phrase(&mnemonic_phrase)?;

    // Generate the key pair from the mnemonic
    let expected_keypair = generate_keypair_from_mnemonic(&mnemonic, None, None)?;

    // Check if the key file exists
    if !key_path.exists() {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Key file not found: {}", key_path.display()),
        )));
    }

    // Read the public key from file
    let key_content = fs::read_to_string(key_path.with_extension("pub"))?;

    // Extract just the key portion (without comment) for comparison
    fn extract_key_without_comment(openssh_key: &str) -> &str {
        // Format is: "ssh-ed25519 BASE64_DATA [comment]"
        // We want just the "ssh-ed25519 BASE64_DATA" part
        let parts: Vec<&str> = openssh_key.trim().splitn(3, ' ').collect();
        if parts.len() >= 2 {
            // Return the key type and base64 data without the comment
            &openssh_key[0..parts[0].len() + 1 + parts[1].len()]
        } else {
            // If there are fewer than 2 parts, just return the trimmed string
            openssh_key.trim()
        }
    }

    // Extract key parts without comments
    let existing_key_part = extract_key_without_comment(&key_content);
    let expected_key_part = extract_key_without_comment(expected_keypair.public_key_openssh());

    // Compare only the key portions, ignoring any comments
    if existing_key_part == expected_key_part {
        term.write_line(&format!(
            "\n{} The key at {} matches the provided mnemonic phrase.",
            style("✓").green().bold(),
            style(key_path.display()).cyan()
        ))?;

        // Display key fingerprints
        term.write_line(&format!(
            "\n{} Key fingerprints:",
            style("🔑").cyan().bold()
        ))?;
        term.write_line(&format!(
            "  {}",
            style(expected_keypair.md5_fingerprint()).dim()
        ))?;
        term.write_line(&format!(
            "  {}\n",
            style(expected_keypair.sha256_fingerprint()).dim()
        ))?;
    } else {
        term.write_line(&format!(
            "\n{} The key at {} does NOT match the provided mnemonic phrase.",
            style("✗").red().bold(),
            style(key_path.display()).cyan()
        ))?;

        return Err(Error::VerificationFailed(
            "Key does not match mnemonic phrase".to_string(),
        ));
    }

    Ok(())
}

/// Display information about an existing SSH key
pub fn info_command(key_path: Option<PathBuf>) -> Result<()> {
    let term = Term::stdout();
    let key_path = key_path
        .unwrap_or_else(|| default_ssh_key_path().unwrap_or_else(|_| PathBuf::from("id_ed25519")));

    // Check if the public key file exists
    let public_key_path = key_path.with_extension("pub");
    if !public_key_path.exists() {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Public key file not found: {}", public_key_path.display()),
        )));
    }

    // Read the public key
    let key_content = fs::read_to_string(&public_key_path)?;
    let key_content = key_content.trim();

    // Parse the key components
    let parts: Vec<&str> = key_content.split_whitespace().collect();
    if parts.is_empty() {
        return Err(Error::InvalidKeyFormat("Empty key file".to_string()));
    }

    let key_type = parts.first().unwrap_or(&"unknown");
    let comment = if parts.len() >= 3 {
        parts[2..].join(" ")
    } else {
        String::from("(no comment)")
    };

    // Calculate fingerprints
    // Parse the base64 key data
    if parts.len() < 2 {
        return Err(Error::InvalidKeyFormat(
            "Invalid key format: missing key data".to_string(),
        ));
    }

    let key_data = match base64::engine::general_purpose::STANDARD.decode(parts[1]) {
        Ok(data) => data,
        Err(_) => {
            return Err(Error::InvalidKeyFormat(
                "Failed to decode key data".to_string(),
            ));
        }
    };

    // Calculate fingerprints directly from the key data
    let md5_fp = {
        let result = md5::compute(&key_data);
        let hex_pairs: Vec<String> = result.iter().map(|byte| format!("{:02x}", byte)).collect();
        format!("MD5:{}", hex_pairs.join(":"))
    };

    let sha256_fp = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&key_data);
        let result = hasher.finalize();
        let b64 = base64::engine::general_purpose::STANDARD.encode(result);
        let b64_no_padding = b64.trim_end_matches('=');
        format!("SHA256:{}", b64_no_padding)
    };

    // Display key information
    term.write_line(&format!(
        "\n{} SSH Key Information",
        style("🔑").cyan().bold()
    ))?;

    term.write_line(&format!(
        "\n{} {}",
        style("Key type:").bold(),
        style(key_type).cyan()
    ))?;

    term.write_line(&format!(
        "{} {}",
        style("Comment:").bold(),
        style(&comment).dim()
    ))?;

    term.write_line(&format!(
        "{} {}",
        style("Public key:").bold(),
        style(public_key_path.display()).cyan()
    ))?;

    if key_path.exists() {
        term.write_line(&format!(
            "{} {}",
            style("Private key:").bold(),
            style(key_path.display()).cyan()
        ))?;
    } else {
        term.write_line(&format!(
            "{} {}",
            style("Private key:").bold(),
            style("(not found)").yellow()
        ))?;
    }

    term.write_line(&format!("\n{} Fingerprints:", style("🔐").cyan().bold()))?;
    term.write_line(&format!("  {}", style(md5_fp).dim()))?;
    term.write_line(&format!("  {}\n", style(sha256_fp).dim()))?;

    Ok(())
}
