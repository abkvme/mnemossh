/*!
 * Utility functions for file operations, path handling, and other helpers
 */

use std::fs;
use std::path::{Path, PathBuf};
// Only the Unix uid lookup shells out, so the import is Unix-only too.
#[cfg(unix)]
use std::process::Command;

use crate::Result;

/// Get the current user ID using a cross-platform approach
#[cfg(unix)]
fn get_current_uid() -> Option<u32> {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|id_str| id_str.trim().parse::<u32>().ok())
        })
}

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir_exists(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    Ok(())
}

/// Expand a tilde in a path string to the user's home directory
pub fn expand_tilde(path: &str) -> PathBuf {
    // Only a bare "~" or a "~/" prefix refers to the current user's home
    // directory. "~other/path" names a different user's home, which we cannot
    // resolve here, so it is left untouched rather than silently rewritten.
    if (path == "~" || path.starts_with("~/"))
        && let Some(base_dirs) = directories::BaseDirs::new()
    {
        let home_dir = base_dirs.home_dir();
        return match path.strip_prefix("~/") {
            Some(rest) => home_dir.join(rest),
            None => home_dir.to_owned(),
        };
    }

    PathBuf::from(path)
}

/// Check if a file exists and is writable
pub fn is_file_writable(path: &Path) -> bool {
    if path.exists() {
        // On Unix-like systems, this checks if the file is writable by the current user
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            // First try using file metadata
            if let (Ok(metadata), Some(current_uid)) = (fs::metadata(path), get_current_uid()) {
                let mode = metadata.mode();
                let uid = metadata.uid();

                // Check if current user is owner and owner has write permission
                if uid == current_uid && (mode & 0o200) != 0 {
                    return true;
                }
            }

            // If metadata check fails, try the actual write test
            if let Ok(permissions) = fs::metadata(path).map(|m| m.permissions())
                && permissions.readonly()
            {
                return false;
            }
        }

        // On non-Unix systems or as a fallback, try to open the file in write mode
        if let Ok(_file) = fs::OpenOptions::new().write(true).open(path) {
            return true;
        }
    }

    // If the file doesn't exist, check if the parent directory is writable
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        return is_dir_writable(parent);
    }

    false
}

/// Check if a directory exists and is writable
pub fn is_dir_writable(path: &Path) -> bool {
    if path.exists() && path.is_dir() {
        // On Unix-like systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            // First try using directory metadata
            if let (Ok(metadata), Some(current_uid)) = (fs::metadata(path), get_current_uid()) {
                let mode = metadata.mode();
                let uid = metadata.uid();

                // Check if current user is owner and owner has write permission
                if uid == current_uid && (mode & 0o200) != 0 {
                    return true;
                }
            }

            // If metadata check fails, try the actual write test
            if let Ok(permissions) = fs::metadata(path).map(|m| m.permissions())
                && permissions.readonly()
            {
                return false;
            }
        }

        // Try to create a temporary file in the directory (works on all platforms)
        let temp_file = path.join(".mnemossh_write_test");
        let result = fs::File::create(&temp_file).is_ok();
        if result {
            let _ = fs::remove_file(&temp_file);
        }
        return result;
    }

    false
}

/// Write secret material to a file that is never readable by anyone but the owner.
///
/// The obvious `fs::write` followed by `set_permissions` leaves a window in
/// which the file exists on disk with whatever the process umask allows —
/// commonly `0644`. Anything holding a secret has to be created `0600` in the
/// first place, so the permissions are part of the `open(2)` call rather than a
/// repair applied afterwards.
///
/// An existing file is also re-restricted before its new contents are written,
/// because `mode` only takes effect when the file is created. Truncation is
/// deliberately deferred until after that, so a file that is already on disk
/// with loose permissions is locked down before it holds the new secret.
///
/// On Windows the file inherits the ACLs of its parent directory; restricting
/// those needs platform APIs this crate does not otherwise depend on. The path
/// is unchanged from previous releases, and the caller is expected to keep such
/// files inside an already-protected directory.
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    // `mode` above only applies to a newly created file, so an existing one is
    // tightened here, before it is truncated and refilled.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.set_len(0)?;
    file.write_all(contents)?;
    file.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_dir_exists() {
        let dir = tempdir().unwrap();
        let test_dir = dir.path().join("test_dir");

        // Directory doesn't exist yet
        assert!(!test_dir.exists());

        // Create it
        ensure_dir_exists(&test_dir).unwrap();

        // Now it exists
        assert!(test_dir.exists());

        // Calling it again should be fine
        ensure_dir_exists(&test_dir).unwrap();
    }

    #[test]
    fn test_expand_tilde() {
        let home_dir = directories::BaseDirs::new()
            .expect("Failed to get base directories")
            .home_dir()
            .to_owned();

        let path = expand_tilde("~");
        assert_eq!(path, home_dir);

        let path = expand_tilde("~/test");
        assert_eq!(path, home_dir.join("test"));

        let path = expand_tilde("/absolute/path");
        assert_eq!(path, PathBuf::from("/absolute/path"));
    }
}
