/*!
 * Command-line interface for the mnemossh utility
 */

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::crypto::mnemonic::MnemonicLength;
use crate::Result;

mod commands;
mod commands_update;

pub use commands::generate_command;
pub use commands::version_command;
pub use commands_update::restore_command;
pub use commands_update::verify_command;

/// CLI command structure
#[derive(Parser, Debug)]
#[clap(
    name = "mnemossh",
    about = "Generate and manage Ed25519 SSH keys using BIP-39 mnemonic phrases",
    long_about = "A utility for generating and managing Ed25519 SSH keys using BIP-39 mnemonic phrases. This allows you to backup and restore your SSH keys using a human-readable phrase, avoiding the need to securely store the private key file itself.",
    version,
    author = "Ales Bykau <abkvme>",
    after_help = "For more information, visit: https://github.com/abkvme/mnemossh"
)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a new mnemonic phrase and SSH key pair
    #[clap(
        name = "generate", 
        alias = "gen",
        about = "Generate a new mnemonic phrase and SSH key pair",
        long_about = "Generate a new cryptographically secure mnemonic phrase and use it to derive an Ed25519 SSH key pair. The mnemonic phrase can be used to recover the SSH key if lost."
    )]
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
        #[clap(
            short, 
            long, 
            value_name = "LENGTH", 
            help = "Length of the mnemonic phrase (12, 18, or 24 words)",
            long_help = "Specify the length of the generated mnemonic phrase in words. Longer phrases provide more security. Options are 12, 18, or 24 words. If not specified, you'll be prompted to choose interactively."
        )]
        length: Option<String>,
        
        /// Save the mnemonic phrase to a file instead of displaying it
        #[clap(
            short, 
            long, 
            value_name = "FILE",
            help = "Save the mnemonic phrase to a file instead of displaying it",
            long_help = "Save the generated mnemonic phrase to a file rather than printing it to the console. This is useful for storing the phrase securely, but take care to protect this file as anyone with access to it can recreate your SSH key."
        )]
        mnemonic_file: Option<PathBuf>,
    },
    
    /// Restore an SSH key from a mnemonic phrase
    #[clap(
        name = "restore", 
        alias = "res",
        about = "Restore an SSH key from a mnemonic phrase",
        long_about = "Recreate an Ed25519 SSH key pair from a previously generated BIP-39 mnemonic phrase. This allows you to recover your SSH key if you have the mnemonic phrase but lost the key file."
    )]
    Restore {
        /// The BIP-39 mnemonic phrase to restore from
        #[clap(
            value_name = "MNEMONIC",
            help = "The BIP-39 mnemonic phrase to restore from",
            long_help = "Provide the full BIP-39 mnemonic phrase (12, 18, or 24 words) that was previously generated. This is used to deterministically recreate the exact same SSH key pair. If not provided, you'll be prompted to enter it interactively.",
            required = false
        )]
        mnemonic: Option<String>,
        
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
    #[clap(
        name = "verify", 
        alias = "ver",
        about = "Verify that a key matches a mnemonic phrase",
        long_about = "Check that an existing SSH key was generated from the provided mnemonic phrase. This is useful to confirm that your backup mnemonic phrase will correctly restore your SSH key."
    )]
    Verify {
        /// The BIP-39 mnemonic phrase to verify
        #[clap(
            value_name = "MNEMONIC",
            help = "The BIP-39 mnemonic phrase to verify",
            long_help = "Provide the full BIP-39 mnemonic phrase (12, 18, or 24 words) that you want to verify. The utility will generate a key from this phrase and compare it to the specified key file. If not provided, you'll be prompted to enter it interactively.",
            required = false
        )]
        mnemonic: Option<String>,
        
        /// The SSH key file to verify against (defaults to ~/.ssh/id_ed25519)
        #[clap(
            short, 
            long, 
            value_name = "FILE",
            help = "The SSH key file to verify against (defaults to ~/.ssh/id_ed25519)",
            long_help = "Specify the path to the SSH key file to verify against the mnemonic phrase. If not specified, defaults to ~/.ssh/id_ed25519 or ./id_ed25519 if the default path can't be determined."
        )]
        key: Option<PathBuf>,
    },
    
    /// Display version information
    #[clap(
        name = "version", 
        alias = "v",
        about = "Display version information",
        long_about = "Show detailed version information about the MnemoSSH utility, including version number and copyright."
    )]
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
            // Convert length string to MnemonicLength if provided
            let mnemonic_length = if let Some(length_str) = length {
                Some(MnemonicLength::from_word_count(length_str)?)
            } else {
                None
            };
            
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
            commands_update::restore_command(
                mnemonic.as_deref(),
                output.clone(),
                comment.as_deref(),
                passphrase.as_deref(),
            )
        },
        
        Commands::Verify { 
            mnemonic, 
            key 
        } => {
            commands_update::verify_command(mnemonic.as_deref(), key.clone())
        },
        
        Commands::Version => {
            commands::version_command()
        },
    }
}
