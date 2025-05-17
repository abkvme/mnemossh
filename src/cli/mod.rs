/*!
 * Command-line interface for the mnemossh utility
 */

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::crypto::mnemonic::MnemonicLength;
use crate::Result;

mod commands;
pub use commands::*;

/// CLI command structure
#[derive(Parser, Debug)]
#[clap(
    name = "mnemossh",
    about = "Generate and manage Ed25519 SSH keys using BIP-39 mnemonic phrases",
    version,
    author = "OxiSoft"
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a new mnemonic phrase and SSH key
    #[clap(name = "generate", alias = "gen")]
    Generate {
        /// Output file for the private key (public key will be saved as <file>.pub)
        #[clap(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        
        /// Comment to add to the public key (typically an email address)
        #[clap(short, long, value_name = "COMMENT")]
        comment: Option<String>,
        
        /// Passphrase for encrypting the private key
        #[clap(short, long, value_name = "PASSPHRASE")]
        passphrase: Option<String>,
        
        /// Length of the mnemonic phrase (12, 18, or 24 words)
        #[clap(short, long, value_name = "LENGTH", default_value = "24")]
        length: String,
        
        /// Save the mnemonic phrase to a file instead of displaying it
        #[clap(short, long, value_name = "FILE")]
        mnemonic_file: Option<PathBuf>,
    },
    
    /// Restore an SSH key from a mnemonic phrase
    #[clap(name = "restore", alias = "res")]
    Restore {
        /// The BIP-39 mnemonic phrase to restore from
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
        
        /// Output file for the private key (public key will be saved as <file>.pub)
        #[clap(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        
        /// Comment to add to the public key (typically an email address)
        #[clap(short, long, value_name = "COMMENT")]
        comment: Option<String>,
        
        /// Passphrase for encrypting the private key
        #[clap(short, long, value_name = "PASSPHRASE")]
        passphrase: Option<String>,
    },
    
    /// Verify that a key matches a mnemonic phrase
    #[clap(name = "verify", alias = "ver")]
    Verify {
        /// The BIP-39 mnemonic phrase to verify
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
        
        /// The SSH key file to verify against (defaults to ~/.ssh/id_ed25519)
        #[clap(short, long, value_name = "FILE")]
        key: Option<PathBuf>,
    },
    
    /// Display version information
    #[clap(name = "version", alias = "v")]
    Version,
}

/// Parse CLI arguments and run the appropriate command
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Generate { 
            output, 
            comment, 
            passphrase, 
            length, 
            mnemonic_file 
        } => {
            let mnemonic_length = MnemonicLength::from_word_count(length)?;
            commands::generate_command(
                output.clone(),
                comment.as_deref(),
                passphrase.as_deref(),
                mnemonic_length,
                mnemonic_file.clone(),
            )
        },
        
        Commands::Restore { 
            mnemonic, 
            output, 
            comment, 
            passphrase 
        } => {
            commands::restore_command(
                mnemonic,
                output.clone(),
                comment.as_deref(),
                passphrase.as_deref(),
            )
        },
        
        Commands::Verify { 
            mnemonic, 
            key 
        } => {
            commands::verify_command(mnemonic, key.clone())
        },
        
        Commands::Version => {
            commands::version_command()
        },
    }
}
