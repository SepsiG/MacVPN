//! Where the `RasEngine` keeps its files, all in WinVPN's data directory (`%LOCALAPPDATA%\WinVPN`):
//! `ras\WinVPN.pbk` (the private phonebook), `ras\<UUID>.ras` (an L2TP connection's saved profile: its plan, no
//! secret) and `logs\ras\<UUID>.log` (the masked log of each connection). Every folder has the data directory's
//! private ACL (the user and SYSTEM: RasMan runs as SYSTEM and reads the phonebook) and is refused when it is not
//! a real folder of this user (a reparse point, a file, another owner): the 2a rules of the data directory.

use crate::pure::ras_connect as rc;
use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::uuid_string;
use macvpn_core::ras::names;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use uuid::Uuid;

/// A log rolls at this size: it becomes `<UUID>.log.1` (one generation kept) and a new `<UUID>.log` starts.
pub(crate) const LOG_MAX: u64 = 1024 * 1024;
/// A saved profile is a few short lines (`ras_connect::decode_profile` refuses more).
const PROFILE_READ_MAX: u64 = 16 * 1024;
/// The sweep looks at no more files than this per folder (a folder flooded by other software stays bounded).
const LISTED_MAX: usize = 10_000;

#[derive(Debug, Clone)]
pub(crate) struct RasPaths {
    /// `<data>\ras`
    dir: PathBuf,
    /// `<data>\logs\ras`
    logs: PathBuf,
}

impl RasPaths {
    /// The folders under WinVPN's data directory `data` (`%LOCALAPPDATA%\WinVPN`), created when missing.
    pub(crate) fn prepare(data: &Path) -> Result<RasPaths, String> {
        let paths = RasPaths { dir: data.join(names::PHONEBOOK_DIR), logs: data.join("logs").join("ras") };
        let me = FileOwner::current_user().map_err(|e| e.to_string())?;
        // The data directory itself is the app's (2a); its parents are created as Windows makes them.
        for dir in [paths.dir.clone(), data.join("logs"), paths.logs.clone()] {
            match fsx::ensure_private_dir(&dir) {
                Ok(owner) if owner == me => {}
                _ => {
                    let shown = dir.display().to_string();
                    return Err(l10n::tr(
                        "WinVPN's folder %@ is not a private folder of this user. Delete it, then start WinVPN again.",
                        &[Arg::Str(&shown)],
                    ));
                }
            }
        }
        Ok(paths)
    }

    /// `<data>\ras\WinVPN.pbk`
    pub(crate) fn phonebook(&self) -> PathBuf {
        self.dir.join(names::PHONEBOOK_FILE)
    }

    /// `<data>\ras\<UUID>.ras`: the saved profile of an L2TP connection.
    pub(crate) fn profile(&self, id: &Uuid) -> PathBuf {
        self.dir.join(format!("{}.ras", uuid_string(id)))
    }

    /// `<data>\logs\ras\<UUID>.log`
    pub(crate) fn log(&self, id: &Uuid) -> PathBuf {
        self.logs.join(format!("{}.log", uuid_string(id)))
    }

    /// The saved profile (a regular file, never through a link; bounded).
    pub(crate) fn read_profile(&self, id: &Uuid) -> Result<Vec<u8>, String> {
        let (file, _) =
            fsx::open_regular(&self.profile(id), OpenFor::Read, Follow::No, false).map_err(|_| rc::entry_damaged())?;
        let mut data = Vec::new();
        file.take(PROFILE_READ_MAX + 1).read_to_end(&mut data).map_err(|_| rc::entry_damaged())?;
        Ok(data)
    }

    pub(crate) fn write_profile(&self, id: &Uuid, data: &[u8]) -> std::io::Result<()> {
        fsx::atomic_write(&self.profile(id), data, Access::Private)
    }

    /// The names of the files in the profile folder and the log folder (the sweep picks WinVPN's own names from
    /// them; at most [`LISTED_MAX`] per folder). A folder that cannot be read gives none.
    pub(crate) fn file_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for dir in [&self.dir, &self.logs] {
            let Ok(read) = std::fs::read_dir(dir) else { continue };
            out.extend(read.flatten().take(LISTED_MAX).filter_map(|e| e.file_name().into_string().ok()));
        }
        out
    }

    /// "Clear Log…": `<UUID>.log` emptied in place with `note` first (through `live`, the log a dial holds, when
    /// there is one) and `<UUID>.log.1` emptied; only this user's regular files, never through a link.
    pub(crate) fn clear_log(&self, id: &Uuid, note: &str, live: Option<&RasLog>) -> Result<(), String> {
        let me = FileOwner::current_user().map_err(|e| cleared_error(&e))?;
        let log = self.log(id);
        macvpn_core::log::clear_file(&rotated(&log), &me, None).map_err(|e| cleared_error(&e))?;
        match live {
            Some(live) => live.clear(&me, note),
            None => macvpn_core::log::clear_file(&log, &me, Some(note)).map(|_| ()).map_err(|e| cleared_error(&e)),
        }
    }

    /// Deletes the connection's profile and logs (the connection was deleted).
    pub(crate) fn forget(&self, id: &Uuid) {
        let log = self.log(id);
        for path in [self.profile(id), rotated(&log), log] {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// `<UUID>.log.1`
fn rotated(path: &Path) -> PathBuf {
    path.with_extension("log.1")
}

fn cleared_error(e: &std::io::Error) -> String {
    l10n::tr("The log could not be cleared: %@", &[Arg::Str(&e.to_string())])
}

/// One connection's log file, written line by line (each line already masked by the caller).
pub(crate) struct RasLog {
    path: PathBuf,
    state: Mutex<LogState>,
}

struct LogState {
    file: Option<File>,
    written: u64,
}

impl RasLog {
    /// A new log for a connect: the previous one is replaced (a new file: the Log tab's tail starts over). A file
    /// that cannot be created leaves the log empty; the connect goes on.
    pub(crate) fn create(path: PathBuf) -> RasLog {
        let _ = std::fs::remove_file(&path);
        let file = fsx::create_new(&path, Access::Private).ok();
        RasLog { path, state: Mutex::new(LogState { file, written: 0 }) }
    }

    /// The log of a connection WinVPN found running (after a relaunch): appended to.
    pub(crate) fn append_to(path: PathBuf) -> RasLog {
        let file = fsx::open_append(&path, Access::Private).ok();
        let written = file.as_ref().and_then(|f| f.metadata().ok()).map_or(0, |m| m.len());
        RasLog { path, state: Mutex::new(LogState { file, written }) }
    }

    /// "Clear Log…" while a dial holds the log: under its lock the handle is closed, the same file emptied in place
    /// with `note` first, and opened again for appending (the next lines follow the note).
    pub(crate) fn clear(&self, owner: &FileOwner, note: &str) -> Result<(), String> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.file = None;
        let cleared = macvpn_core::log::clear_file(&self.path, owner, Some(note));
        s.file = fsx::open_append(&self.path, Access::Private).ok();
        s.written = s.file.as_ref().and_then(|f| f.metadata().ok()).map_or(0, |m| m.len());
        cleared.map(|_| ()).map_err(|e| cleared_error(&e))
    }

    pub(crate) fn lines(&self, lines: &[String]) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for line in lines {
            if s.written >= LOG_MAX {
                s.file = None;
                let _ = std::fs::rename(&self.path, rotated(&self.path));
                s.file = fsx::create_new(&self.path, Access::Private).ok();
                s.written = 0;
            }
            let Some(file) = s.file.as_mut() else { return };
            let mut bytes = line.replace(['\r', '\n'], " ").into_bytes();
            bytes.push(b'\n');
            if file.write_all(&bytes).is_ok() {
                s.written += bytes.len() as u64;
            }
        }
    }
}
