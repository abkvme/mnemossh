/*!
 * Main entry point for the mnemossh command-line utility
 */

use std::process;

/// Main entry point
fn main() {
    if let Err(e) = mnemossh::cli::run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
