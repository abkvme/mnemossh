/*!
 * Utility functions for file operations, path handling, and other helpers
 */

use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir_exists(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    
    Ok(())
}

/// Expand a tilde in a path string to the user's home directory
pub fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with('~') {
        if let Some(home_dir) = dirs::home_dir() {
            if path.len() > 1 {
                home_dir.join(&path[2..])
            } else {
                home_dir
            }
        } else {
            PathBuf::from(path)
        }
    } else {
        PathBuf::from(path)
    }
}

/// Check if a file exists and is writable
pub fn is_file_writable(path: &Path) -> bool {
    if path.exists() {
        // On Unix-like systems, this checks if the file is writable by the current user
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.mode();
                let uid = metadata.uid();
                
                // Check if current user is owner and owner has write permission
                return uid == unsafe { libc::getuid() } && (mode & 0o200) != 0;
            }
        }
        
        // On non-Unix systems, just try to open the file in write mode
        #[cfg(not(unix))]
        {
            if let Ok(_file) = fs::OpenOptions::new().write(true).open(path) {
                return true;
            }
        }
    }
    
    // If the file doesn't exist, check if the parent directory is writable
    if let Some(parent) = path.parent() {
        if parent.exists() {
            return is_dir_writable(parent);
        }
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
            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.mode();
                let uid = metadata.uid();
                
                // Check if current user is owner and owner has write permission
                return uid == unsafe { libc::getuid() } && (mode & 0o200) != 0;
            }
        }
        
        // On non-Unix systems, try to create a temporary file in the directory
        #[cfg(not(unix))]
        {
            let temp_file = path.join(".mnemossh_write_test");
            let result = fs::File::create(&temp_file).is_ok();
            if result {
                let _ = fs::remove_file(&temp_file);
            }
            return result;
        }
    }
    
    false
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
        let home_dir = dirs::home_dir().unwrap();
        
        let path = expand_tilde("~");
        assert_eq!(path, home_dir);
        
        let path = expand_tilde("~/test");
        assert_eq!(path, home_dir.join("test"));
        
        let path = expand_tilde("/absolute/path");
        assert_eq!(path, PathBuf::from("/absolute/path"));
    }
}
