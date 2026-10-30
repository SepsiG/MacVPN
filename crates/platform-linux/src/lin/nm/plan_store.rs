//! The managed L2TP / Cisco plan records (`$XDG_DATA_HOME/LinVPN/nm/<UUID>.json`, resolved point 2; L-b Task 22).
//!
//! A record is what `NativeController::start` needs to build the volatile NM connection, and never a secret:
//! `{"v":1,"kind":"l2tp|cisco","name":…,"server":…,"account":…,"group":…,"sendAll":true}`. It is parsed strictly
//! (exactly these keys, these types, at most [`MAX_RECORD`] bytes, no control character). Fail closed (R9): the
//! folder must be a real directory of ours with mode 0700, each record a regular file of ours with mode 0600, never
//! reached through a symlink.

use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use serde_json::{Map, Value};
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The largest record read or written.
pub const MAX_RECORD: u64 = 16 * 1024;
/// The longest text field (a name, a server, an account, a group).
const MAX_FIELD: usize = 1024;

/// A managed native connection's settings (no secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRecord {
    /// `VPNKind::L2tp` or `VPNKind::Cisco`.
    pub kind: VPNKind,
    pub name: String,
    pub server: String,
    pub account: String,
    pub group: String,
    pub send_all: bool,
}

impl PlanRecord {
    /// The record of a native connection (`None` for any other kind, or without native settings).
    pub fn of(connection: &Connection) -> Option<PlanRecord> {
        if !connection.kind.is_native() {
            return None;
        }
        let native = connection.native.as_ref()?;
        Some(PlanRecord {
            kind: connection.kind,
            name: connection.name.trim().to_string(),
            server: native.server.trim().to_string(),
            account: native.account.trim().to_string(),
            group: native.group_name.trim().to_string(),
            send_all: native.send_all_traffic,
        })
    }

    /// The connection `nm_plan` plans from (the id is the LinVPN connection's, so the NM UUID derives from it).
    pub fn connection(&self, id: Uuid) -> Connection {
        let mut c = Connection::with_id(id, self.name.clone(), self.kind, macvpn_core::date::Date::now());
        c.native = Some(NativeSettings {
            server: self.server.clone(),
            account: self.account.clone(),
            group_name: self.group.clone(),
            send_all_traffic: self.send_all,
        });
        c
    }

    pub fn encode(&self) -> Vec<u8> {
        let kind = if self.kind == VPNKind::Cisco { "cisco" } else { "l2tp" };
        let value = serde_json::json!({
            "v": 1,
            "kind": kind,
            "name": self.name,
            "server": self.server,
            "account": self.account,
            "group": self.group,
            "sendAll": self.send_all,
        });
        serde_json::to_vec(&value).unwrap_or_default()
    }

    /// The strict parse (see the module).
    pub fn decode(bytes: &[u8]) -> Result<PlanRecord, String> {
        if bytes.len() as u64 > MAX_RECORD {
            return Err("the plan record is too large".into());
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "the plan record is not JSON".to_string())?;
        let Value::Object(map) = value else { return Err("the plan record is not an object".into()) };
        const KEYS: [&str; 7] = ["v", "kind", "name", "server", "account", "group", "sendAll"];
        if map.len() != KEYS.len() || !KEYS.iter().all(|k| map.contains_key(*k)) {
            return Err("the plan record has other keys".into());
        }
        if map.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("unknown plan record version".into());
        }
        let kind = match map.get("kind").and_then(Value::as_str) {
            Some("l2tp") => VPNKind::L2tp,
            Some("cisco") => VPNKind::Cisco,
            _ => return Err("unknown plan record kind".into()),
        };
        let send_all = map.get("sendAll").and_then(Value::as_bool).ok_or("sendAll is not a boolean")?;
        Ok(PlanRecord {
            kind,
            name: text(&map, "name")?,
            server: text(&map, "server")?,
            account: text(&map, "account")?,
            group: text(&map, "group")?,
            send_all,
        })
    }
}

fn text(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    let s = map.get(key).and_then(Value::as_str).ok_or_else(|| format!("{key} is not a string"))?;
    if s.len() > MAX_FIELD || s.chars().any(char::is_control) {
        return Err(format!("{key} is not a valid text"));
    }
    Ok(s.to_string())
}

/// `<data>/nm` (`data` = `$XDG_DATA_HOME/LinVPN`).
pub fn dir(data: &Path) -> PathBuf {
    data.join("nm")
}

/// `<dir>/<uuid>.json` (lower-case hyphenated).
pub fn path(dir: &Path, id: &Uuid) -> PathBuf {
    dir.join(format!("{}.json", id.hyphenated()))
}

fn current_owner() -> FileOwner {
    // SAFETY: getuid has no arguments and cannot fail.
    FileOwner::from_uid(unsafe { libc::getuid() })
}

fn not_ours(path: &Path) -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, format!("{} is not our own private file or directory", path.display()))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

/// The existing folder is a real directory of ours, 0700 (R9). `Ok(false)`: there is none.
fn checked_dir(dir: &Path) -> io::Result<bool> {
    let stat = match fsx::stat_path(dir, Follow::No) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !stat.file_type().is_dir() || fsx::owner(&stat)? != current_owner() || !fsx::has_access(&stat, Access::Private) {
        return Err(not_ours(dir));
    }
    Ok(true)
}

/// Writes the record atomically (0600) into `dir` (created 0700, or refused when it is not ours).
pub fn write(dir: &Path, id: &Uuid, record: &PlanRecord) -> io::Result<()> {
    if fsx::ensure_private_dir(dir)? != current_owner() {
        return Err(not_ours(dir));
    }
    let bytes = record.encode();
    PlanRecord::decode(&bytes).map_err(invalid)?;
    fsx::atomic_write(&path(dir, id), &bytes, Access::Private)
}

/// The record of `id` (`NotFound` when there is none).
pub fn read(dir: &Path, id: &Uuid) -> io::Result<PlanRecord> {
    if !checked_dir(dir)? {
        return Err(io::Error::new(ErrorKind::NotFound, "no plan records"));
    }
    let file_path = path(dir, id);
    let (file, stat) = fsx::open_regular(&file_path, OpenFor::Read, Follow::No, true)?;
    if fsx::owner(&stat)? != current_owner() || !fsx::has_access(&stat, Access::Private) {
        return Err(not_ours(&file_path));
    }
    if stat.len() > MAX_RECORD {
        return Err(invalid("the plan record is too large".into()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
    PlanRecord::decode(&bytes).map_err(invalid)
}

/// The raw bytes stored for `id`, if a valid record is there (an unchanged install is skipped).
pub fn read_bytes(dir: &Path, id: &Uuid) -> Option<Vec<u8>> {
    read(dir, id).ok().map(|r| r.encode())
}

/// Deletes the record of `id` (none: `Ok`).
pub fn remove(dir: &Path, id: &Uuid) -> io::Result<()> {
    if !checked_dir(dir)? {
        return Ok(());
    }
    match fs::remove_file(path(dir, id)) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The ids of every `<uuid>.json` in `dir`, sorted (none when the folder is missing or not ours).
pub fn ids(dir: &Path) -> Vec<Uuid> {
    if !checked_dir(dir).unwrap_or(false) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    let mut ids: Vec<Uuid> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            let stem = name.strip_suffix(".json")?;
            let id = Uuid::parse_str(stem).ok()?;
            (id.hyphenated().to_string() == stem).then_some(id)
        })
        .collect();
    ids.sort();
    ids
}

/// Every valid record with its id, sorted by id; an unreadable or invalid one is left out.
pub fn list(dir: &Path) -> Vec<(Uuid, PlanRecord)> {
    ids(dir).into_iter().filter_map(|id| read(dir, &id).ok().map(|r| (id, r))).collect()
}
