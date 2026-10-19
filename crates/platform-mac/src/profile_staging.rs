//! The native (L2TP / Cisco) profile staging (port of `NativeProfileStaging.swift`).
//!
//! The generated profile is written to a fresh private temp directory (never into the connection store), opened
//! from there, and deleted once the service shows up in `scutil --nc list`, or at the latest on the next launch.
//! The password is never in the profile (it is passed in-process when connecting); the PSK is, because without it
//! the system service would not work from System Settings.

use crate::temp_dir::{MessageError, SecureTempDirectory};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Prefix of the staging directories (`mkdtemp`), also what the launch sweep looks for.
pub const PREFIX: &str = "macvpn-profile.";

/// `mkdtemp` 0700 directory in `parent`, with the profile created 0600 (O_EXCL, no symlink follow).
pub fn stage(data: &[u8], file_name: &str, parent: &Path) -> Result<PathBuf, MessageError> {
    if file_name.is_empty() || file_name.contains('/') || file_name == "." || file_name == ".." {
        return Err(MessageError(l10n::tr("Cannot write: %@", &[Arg::Str(file_name)])));
    }
    let dir = SecureTempDirectory::make(PREFIX, parent)?;
    let file = dir.join(file_name);
    let opened = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&file);
    let mut handle = match opened {
        Ok(handle) => handle,
        Err(_) => {
            SecureTempDirectory::remove_if_owned(&dir, PREFIX);
            return Err(MessageError(l10n::tr("Cannot write: %@", &[Arg::Str(&file.to_string_lossy())])));
        }
    };
    if let Err(e) = handle.write_all(data).and_then(|_| handle.sync_all()) {
        drop(handle);
        SecureTempDirectory::remove_if_owned(&dir, PREFIX);
        return Err(MessageError(e.to_string()));
    }
    Ok(file)
}

/// Deletes the staging directory of `profile`. Anything not inside a staging directory is left alone.
pub fn remove(profile: &Path) {
    let Some(dir) = profile.parent() else { return };
    let named = dir.file_name().is_some_and(|n| n.to_string_lossy().starts_with(PREFIX));
    if named && is_real_directory(dir) {
        SecureTempDirectory::remove_if_owned(dir, PREFIX);
    }
}

/// Launch sweep: deletes every leftover staging directory in `parent` (real directories only, not symlinks).
pub fn sweep(parent: &Path) -> usize {
    let Ok(entries) = fs::read_dir(parent) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(PREFIX) {
            continue;
        }
        let path = entry.path();
        if is_real_directory(&path) && fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn is_real_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// A re-saved profile whose service already existed: the service being listed says nothing about whether the new
/// profile was installed. macOS keeps an opened profile in System Settings for a few minutes, so the file is
/// deleted only after this much time (or on the next launch).
pub const REGENERATED_GRACE: f64 = 600.0;

struct Entry {
    profile: PathBuf,
    staged_at: Date,
    service_existed: bool,
}

/// The staged profiles waiting for their service to appear (the Swift `StagedProfiles`). Not synchronized: the
/// app keeps it behind a mutex.
pub struct StagedProfiles {
    entries: HashMap<Uuid, Entry>,
    clock: Box<dyn Fn() -> Date + Send + Sync>,
}

impl Default for StagedProfiles {
    fn default() -> Self {
        Self::new(Box::new(Date::now))
    }
}

impl StagedProfiles {
    pub fn new(clock: Box<dyn Fn() -> Date + Send + Sync>) -> Self {
        StagedProfiles { entries: HashMap::new(), clock }
    }

    pub fn pending_ids(&self) -> HashSet<Uuid> {
        self.entries.keys().copied().collect()
    }

    /// A previous staged profile of the same connection is deleted.
    pub fn track(&mut self, id: Uuid, profile: PathBuf, service_existed: bool) {
        if let Some(old) = self.entries.get(&id)
            && old.profile != profile
        {
            remove(&old.profile);
        }
        self.entries.insert(id, Entry { profile, staged_at: (self.clock)(), service_existed });
    }

    /// Called after each successful `scutil --nc list` with the connections whose service is listed.
    pub fn services_seen(&mut self, ids: &HashSet<Uuid>) {
        let now = (self.clock)();
        self.entries.retain(|id, entry| {
            if !ids.contains(id) {
                return true;
            }
            if entry.service_existed && now.time_interval_since(entry.staged_at) < REGENERATED_GRACE {
                return true;
            }
            remove(&entry.profile);
            false
        });
    }

    pub fn remove_all(&mut self) {
        for entry in self.entries.values() {
            remove(&entry.profile);
        }
        self.entries.clear();
    }
}
