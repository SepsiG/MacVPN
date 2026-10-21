//! Port of `ConnectionStore.swift`: `<base>/<UUID>/meta.json` and `config`.
//!
//! The root layer reads the same path: `<data dir>/connections/<UUID>/config`, where the data dir is the app's data
//! directory (`Product::data_dir`).
//! Directories are 0700, files 0600, written via an `O_EXCL` temp file + fsync + rename + directory fsync.

use crate::collation;
use crate::fsx::{self, Access, Follow, OpenFor};
use crate::l10n::{self, Arg};
use crate::models::{Connection, uuid_string};
use crate::swift_json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// An error with a user-facing (localized) message.
#[derive(Debug)]
pub struct RemovalError {
    pub message: String,
}

impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RemovalError {}

/// Deletes the user data (on uninstall): the app's data directory (`Product::data_dir`). Only a real (non-symlink)
/// directory named `expected_name` (the product's name); a missing one is fine.
pub fn remove_user_data(dir: &Path, expected_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let display = dir.to_string_lossy();
    if dir.file_name().and_then(|n| n.to_str()) != Some(expected_name) {
        return Err(Box::new(RemovalError { message: l10n::tr("Cannot delete: %@", &[Arg::Str(&display)]) }));
    }
    let meta = match fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if !meta.file_type().is_dir() {
        return Err(Box::new(RemovalError { message: l10n::tr("Not a directory: %@", &[Arg::Str(&display)]) }));
    }
    fs::remove_dir_all(dir)?;
    Ok(())
}

/// The old versions wrote the native profile here (with the password and the PSK in it); deleted at start.
pub const LEGACY_PROFILE_NAME: &str = "profile.mobileconfig";

#[derive(Debug, Clone)]
pub struct ConnectionStore {
    pub base_dir: PathBuf,
}

impl ConnectionStore {
    /// `<data dir>/connections`: `data_dir` is the app's data directory (`Product::data_dir`).
    pub fn default_base_dir(data_dir: &Path) -> PathBuf {
        data_dir.join("connections")
    }

    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        ConnectionStore { base_dir: base_dir.into() }
    }

    pub fn directory(&self, id: &Uuid) -> PathBuf {
        self.base_dir.join(uuid_string(id))
    }

    pub fn config_path(&self, id: &Uuid) -> PathBuf {
        self.directory(id).join("config")
    }

    pub fn meta_path(&self, id: &Uuid) -> PathBuf {
        self.directory(id).join("meta.json")
    }

    /// Every connection with a readable, valid `meta.json`, sorted by name (localized, case-insensitive; ties keep
    /// the directory listing order). Invalid ones are skipped.
    pub fn list(&self) -> io::Result<Vec<Connection>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let Ok(entry) = entry else { continue };
            let Ok(data) = fs::read(entry.path().join("meta.json")) else { continue };
            if let Ok(c) = swift_json::parse(&data)
                .map_err(|e| e.to_string())
                .and_then(|v| Connection::from_json(&v).map_err(|e| e.to_string()))
            {
                out.push(c);
            }
        }
        out.sort_by(|a, b| collation::localized_case_insensitive_compare(&a.name, &b.name));
        Ok(out)
    }

    /// `config == None`: the existing config file stays unchanged.
    pub fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()> {
        let dir = self.directory(&connection.id);
        fsx::create_private_dir_all(&dir)?;
        let json = swift_json::to_pretty_sorted(&connection.to_json()).map_err(io::Error::other)?;
        write_private(json.as_bytes(), &self.meta_path(&connection.id))?;
        if let Some(config) = config {
            write_private(config.as_bytes(), &self.config_path(&connection.id))?;
        }
        Ok(())
    }

    /// Migration: deletes the old `profile.mobileconfig` files left in the connection directories (a symlink
    /// itself, never its target). Returns how many were removed.
    pub fn remove_legacy_profiles(&self) -> usize {
        let Ok(entries) = fs::read_dir(&self.base_dir) else { return 0 };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path().join(LEGACY_PROFILE_NAME);
            if fs::symlink_metadata(&path).is_err() {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    pub fn load_config(&self, id: &Uuid) -> io::Result<String> {
        let bytes = fs::read(self.config_path(id))?;
        crate::swift_str::string_from_utf8_data(bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the config is not UTF-8"))
    }

    pub fn delete(&self, id: &Uuid) -> io::Result<()> {
        fs::remove_dir_all(self.directory(id))
    }
}

/// Temp file created 0600 (`O_EXCL`, `O_NOFOLLOW`), fsync, then rename and an fsync of the directory: never a
/// wider-permission state, and no empty / truncated file after a power loss.
pub fn write_private(data: &[u8], path: &Path) -> io::Result<()> {
    fsx::atomic_write(path, data, Access::Private)
}

/// Deletes a file after overwriting its contents in place with zeros of the same length and an `fsync` (the
/// 1.2 migration's "overwrite, then unlink" of the 1.1 files).
///
/// - A symlink is only unlinked (never followed; its target is not touched).
/// - The file is opened with `O_NOFOLLOW | O_NONBLOCK` and checked with `fstat` on the open descriptor: anything
///   that is not a regular file (a directory, a FIFO, a device) is refused and left in place.
/// - A file with more than one hard link is only unlinked: the other name is not ours to overwrite. Where the link
///   count is unknown (Windows in phase 1, see `fsx::hard_links`) every file is treated so.
/// - A missing file is fine (a resumed cleanup).
///
/// Best effort against later recovery: on APFS (copy-on-write) or an SSD the old blocks may survive the
/// overwrite, so this narrows the window rather than guaranteeing erasure. The unlink is by path (no `unlinkat`
/// without `unsafe` here); the caller checks that the parent directories are real directories.
pub fn shred_file(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_symlink() {
        let (mut file, opened) = fsx::open_regular(path, OpenFor::Write, Follow::No, false)?;
        if fsx::hard_links(&opened) <= 1 {
            let mut left = opened.len();
            let zeros = [0u8; 64 * 1024];
            while left > 0 {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(zeros.len());
                file.write_all(&zeros[..n])?;
                left -= n as u64;
            }
            file.sync_all()?;
        }
    }
    fs::remove_file(path)?;
    if let Some(dir) = path.parent() {
        fsx::sync_dir(dir);
    }
    Ok(())
}

/// Creates the parent directory 0700 if it does not exist yet (ranking / system OTP stores).
pub(crate) fn ensure_private_parent(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.exists()
    {
        fsx::create_missing_private_dirs(dir)?;
    }
    Ok(())
}
