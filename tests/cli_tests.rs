/*!
 * Tests for the CLI commands
 */

use mnemossh::cli::version_command;

#[test]
fn test_version_command() {
    // Test that version_command runs without error
    let result = version_command();
    assert!(result.is_ok(), "version_command should succeed");
}
