//! The smoke driver's helpers with plain Unix calls (macOS and Linux): a private directory for the run's fixtures and
//! a file's permission bits.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// A fresh private directory (0700) under `base`: `<base>/<prefix>.<random>`, created exclusively (an existing path,
/// a symlink among them, is an error).
pub(super) fn private_temp_dir(prefix: &str, base: &Path) -> Result<PathBuf, String> {
    let dir = base.join(format!("{prefix}.{}", Uuid::new_v4().simple()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The umask may have taken bits away, never added any; set them exactly.
    if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(format!("{}: {e}", dir.display()));
    }
    Ok(dir)
}

/// The file's permission bits in octal (`600`).
pub(super) fn mode(path: &Path) -> String {
    format!("{:o}", std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0))
}
