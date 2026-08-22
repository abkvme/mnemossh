/*!
 * Tests for the command line argument parsing.
 *
 * `run()` itself reads the process arguments, so these tests drive the parser
 * directly to check that each flag lands in the field the command expects.
 */

use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use mnemossh::cli::{Cli, Commands};
use mnemossh::crypto::mnemonic::MnemonicLength;

#[test]
fn test_cli_definition_is_valid() {
    // Catches conflicting flags, duplicate short options, and similar mistakes.
    Cli::command().debug_assert();
}

#[test]
fn test_parse_generate_with_every_option() {
    let cli = Cli::try_parse_from([
        "mnemossh",
        "generate",
        "--output",
        "/tmp/key",
        "--comment",
        "alice@example.com",
        "--passphrase",
        "hunter2",
        "--length",
        "24",
        "--mnemonic-file",
        "/tmp/phrase.txt",
    ])
    .expect("generate should parse");

    match cli.command {
        Commands::Generate {
            output,
            comment,
            passphrase,
            length,
            mnemonic_file,
        } => {
            assert_eq!(output, Some(PathBuf::from("/tmp/key")));
            assert_eq!(comment.as_deref(), Some("alice@example.com"));
            assert_eq!(passphrase.as_deref(), Some("hunter2"));
            assert_eq!(length.as_deref(), Some("24"));
            assert_eq!(mnemonic_file, Some(PathBuf::from("/tmp/phrase.txt")));
        }
        other => panic!("expected Generate, got {:?}", other),
    }
}

#[test]
fn test_parse_generate_with_short_flags() {
    let cli = Cli::try_parse_from([
        "mnemossh", "generate", "-o", "/tmp/key", "-c", "alice", "-p", "pw", "-l", "12",
    ])
    .expect("short flags should parse");

    match cli.command {
        Commands::Generate {
            output,
            comment,
            passphrase,
            length,
            ..
        } => {
            assert_eq!(output, Some(PathBuf::from("/tmp/key")));
            assert_eq!(comment.as_deref(), Some("alice"));
            assert_eq!(passphrase.as_deref(), Some("pw"));
            assert_eq!(length.as_deref(), Some("12"));
        }
        other => panic!("expected Generate, got {:?}", other),
    }
}

#[test]
fn test_parse_generate_without_options() {
    let cli = Cli::try_parse_from(["mnemossh", "generate"]).expect("bare generate should parse");

    match cli.command {
        Commands::Generate {
            output,
            comment,
            passphrase,
            length,
            mnemonic_file,
        } => {
            assert!(output.is_none());
            assert!(comment.is_none());
            assert!(passphrase.is_none());
            assert!(length.is_none());
            assert!(mnemonic_file.is_none());
        }
        other => panic!("expected Generate, got {:?}", other),
    }
}

#[test]
fn test_parse_restore() {
    let cli = Cli::try_parse_from([
        "mnemossh",
        "restore",
        // the mnemonic is positional, not a flag
        "abandon abandon about",
        "--output",
        "/tmp/restored",
        "--comment",
        "alice",
    ])
    .expect("restore should parse");

    match cli.command {
        Commands::Restore {
            mnemonic,
            output,
            comment,
            passphrase,
        } => {
            assert_eq!(mnemonic.as_deref(), Some("abandon abandon about"));
            assert_eq!(output, Some(PathBuf::from("/tmp/restored")));
            assert_eq!(comment.as_deref(), Some("alice"));
            assert!(passphrase.is_none());
        }
        other => panic!("expected Restore, got {:?}", other),
    }
}

#[test]
fn test_parse_verify() {
    let cli = Cli::try_parse_from([
        "mnemossh",
        "verify",
        "abandon abandon about",
        "--key",
        "/tmp/id_ed25519",
    ])
    .expect("verify should parse");

    match cli.command {
        Commands::Verify { mnemonic, key } => {
            assert_eq!(mnemonic.as_deref(), Some("abandon abandon about"));
            assert_eq!(key, Some(PathBuf::from("/tmp/id_ed25519")));
        }
        other => panic!("expected Verify, got {:?}", other),
    }
}

#[test]
fn test_parse_restore_and_verify_without_a_mnemonic() {
    // Both accept the phrase interactively, so the positional is optional.
    let cli = Cli::try_parse_from(["mnemossh", "restore"]).expect("bare restore should parse");
    assert!(matches!(
        cli.command,
        Commands::Restore { mnemonic: None, .. }
    ));

    let cli = Cli::try_parse_from(["mnemossh", "verify"]).expect("bare verify should parse");
    assert!(matches!(
        cli.command,
        Commands::Verify { mnemonic: None, .. }
    ));
}

#[test]
fn test_subcommand_aliases() {
    // Each subcommand has a short alias; they must keep working.
    assert!(matches!(
        Cli::try_parse_from(["mnemossh", "v"]).unwrap().command,
        Commands::Version
    ));
    assert!(matches!(
        Cli::try_parse_from(["mnemossh", "ver", "phrase"])
            .unwrap()
            .command,
        Commands::Verify { .. }
    ));
}

#[test]
fn test_parse_version() {
    let cli = Cli::try_parse_from(["mnemossh", "version"]).expect("version should parse");
    assert!(matches!(cli.command, Commands::Version));
}

#[test]
fn test_parse_rejects_unknown_input() {
    assert!(
        Cli::try_parse_from(["mnemossh"]).is_err(),
        "a subcommand is required"
    );
    assert!(
        Cli::try_parse_from(["mnemossh", "frobnicate"]).is_err(),
        "unknown subcommand"
    );
    assert!(
        Cli::try_parse_from(["mnemossh", "generate", "--nonsense"]).is_err(),
        "unknown flag"
    );
    assert!(
        Cli::try_parse_from(["mnemossh", "generate", "--length"]).is_err(),
        "--length needs a value"
    );
}

#[test]
fn test_length_argument_maps_to_mnemonic_length() {
    // `run()` converts the raw --length string through this same call.
    assert_eq!(
        MnemonicLength::from_word_count("12").unwrap(),
        MnemonicLength::Words12
    );
    assert_eq!(
        MnemonicLength::from_word_count("18").unwrap(),
        MnemonicLength::Words18
    );
    assert_eq!(
        MnemonicLength::from_word_count("24").unwrap(),
        MnemonicLength::Words24
    );
    assert!(MnemonicLength::from_word_count("20").is_err());
    assert!(MnemonicLength::from_word_count("twelve").is_err());
    assert!(MnemonicLength::from_word_count("").is_err());
}
