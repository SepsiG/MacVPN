//! Private temporary directories and scripts (port of `SecureTempDirectory.swift` and the temp helpers of
//! `RootInstaller.swift`).

use crate::sys;
use macvpn_core::l10n::{self, Arg};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// An error with a ready (localized) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageError(pub String);

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MessageError {}

const RANDOM_LENGTH: usize = 8;

/// `URL.standardizedFileURL.path` for an absolute path: `.` and empty components dropped, `..` removed together
/// with the preceding component, no trailing slash. Relative paths are returned unchanged.
pub fn standardize(path: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }
    let mut out: Vec<&std::ffi::OsStr> = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    let mut p = PathBuf::from("/");
    for s in out {
        p.push(s);
    }
    p
}

/// Secure `mkdtemp(3)` and the matching removal.
pub struct SecureTempDirectory;

impl SecureTempDirectory {
    /// A fresh 0700 directory: `<parent>/<prefix>XXXXXXXX`.
    pub fn make(prefix: &str, parent: &Path) -> Result<PathBuf, MessageError> {
        let message = || l10n::tr("Cannot create a temporary directory", &[]);
        let parent_path = standardize(parent);
        if !parent_path.is_absolute() || prefix.is_empty() || prefix.contains('/') {
            return Err(MessageError(message()));
        }
        let template = parent_path.join(format!("{prefix}{}", "X".repeat(RANDOM_LENGTH)));
        let path = sys::mkdtemp(&template)
            .map_err(|e| MessageError(format!("{} ({}: {})", message(), template.display(), strerror(&e))))?;
        if !Self::is_owned_path(&path, prefix, Some(&parent_path)) {
            return Err(MessageError(format!("{} ({})", message(), template.display())));
        }
        Ok(path)
    }

    /// An absolute path, directly in the parent, named `<prefix>` + exactly 8 random characters.
    pub fn is_owned_path(path: &Path, prefix: &str, parent_path: Option<&Path>) -> bool {
        let s = path.to_string_lossy();
        if !s.starts_with('/') || s == "/" {
            return false;
        }
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else { return false };
        if !name.starts_with(prefix)
            || name.chars().count() != prefix.chars().count() + RANDOM_LENGTH
            || name.contains('/')
            || name == "."
            || name == ".."
        {
            return false;
        }
        if let Some(parent) = parent_path
            && path.parent() != Some(parent)
        {
            return false;
        }
        true
    }

    /// Removes only our own directory made by [`Self::make`]: absolute path, prefixed name, a real directory (not
    /// a symlink). Does nothing in every other case.
    pub fn remove_if_owned(dir: &Path, prefix: &str) {
        let path = standardize(dir);
        if !Self::is_owned_path(&path, prefix, None) {
            return;
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_dir() => {
                let _ = fs::remove_dir_all(&path);
            }
            _ => {}
        }
    }
}

/// `strerror(errno)` text of an I/O error (without Rust's " (os error N)" suffix).
pub fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// The user's private temporary directory, as Foundation's `FileManager.default.temporaryDirectory`:
/// `confstr(_CS_DARWIN_USER_TEMP_DIR)` (never `$TMPDIR`, never a shared `/tmp`). An error if unavailable.
pub fn temporary_directory() -> Result<PathBuf, MessageError> {
    crate::sys::darwin_user_temp_dir()
        .filter(|p| p.is_dir())
        .ok_or_else(|| MessageError(l10n::tr("Cannot create a temporary directory", &[])))
}

/// A fresh directory only the user can access (0700), with `mkdtemp(3)` (atomic, unpredictable name):
/// `<base>/<prefix>.XXXXXX`.
pub fn make_private_temp_directory(prefix: &str, base: &Path) -> Result<PathBuf, MessageError> {
    let template = base.join(format!("{prefix}.XXXXXX"));
    let path = sys::mkdtemp(&template).map_err(|e| {
        MessageError(format!(
            "{} ({}: {})",
            l10n::tr("Cannot create a temporary directory", &[]),
            template.display(),
            strerror(&e)
        ))
    })?;
    if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
        let _ = fs::remove_dir_all(&path);
        return Err(MessageError(format!(
            "{} ({}: {})",
            l10n::tr("Cannot set the permissions of the temporary directory", &[]),
            path.display(),
            strerror(&e)
        )));
    }
    Ok(path)
}

/// Writes `script` as `<dir>/<name>` with mode 0700, exclusively created (O_EXCL, a symlink is not followed).
pub fn write_script(script: &str, dir: &Path, name: &str) -> Result<PathBuf, MessageError> {
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| MessageError(l10n::tr("Cannot write the installer script", &[])))?;
    file.write_all(script.as_bytes()).map_err(|e| MessageError(e.to_string()))?;
    drop(file);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|_| MessageError(l10n::tr("Cannot set the permissions of the script", &[])))?;
    Ok(path)
}

/// The permission bits of a path (tests and checks).
pub fn mode(path: &Path) -> io::Result<u32> {
    Ok(fs::symlink_metadata(path)?.mode() & 0o7777)
}

/// Swift's `L10n.tr` with one string argument, a small convenience.
pub(crate) fn tr1(key: &str, arg: &str) -> String {
    l10n::tr(key, &[Arg::Str(arg)])
}
