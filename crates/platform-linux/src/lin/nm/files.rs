//! The runtime directory of a connection's inline certificates and keys: `$XDG_RUNTIME_DIR/linvpn/nm/<nm uuid>`
//! (0700, files 0600), removed when the guard is dropped. It also holds the run record ([`RECORD`]): what the next
//! LinVPN process needs to adopt the connection when it is still up (NM's activation is not bound to LinVPN's
//! process, so "Quit, Keep Them Running" and a crash leave it running, as on macOS and Windows).
//!
//! Fail closed (R9): `linvpn`, `nm` and the connection's directory must be real directories (never a symlink) owned
//! by us, and are tightened to 0700; every file is created new (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600) under a name
//! that is one plain path component.
use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use macvpn_core::models::VPNKind;
use macvpn_core::nm_plan::RuntimeFile;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The run record's name in the connection's directory: a dot name, which no plan file can have
/// ([`is_plain_name`]).
pub const RECORD: &str = ".linvpn-run.json";
/// The largest run record read.
const MAX_RECORD: u64 = 4096;
/// The longest interface name the record keeps (Linux's `IFNAMSIZ` - 1).
const MAX_IFACE: usize = 15;

/// What adopting a still-active connection needs and NM does not say (never a secret):
/// `{"v":1,"id":…,"kind":…,"iface":…|null,"keepalive":…,"since":…}`, parsed strictly.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRecord {
    /// The LinVPN connection's id (its NM UUID derives from it: [`macvpn_core::nm_plan::names::nm_uuid`]).
    pub id: Uuid,
    pub kind: VPNKind,
    /// LinVPN's interface name (WireGuard, OpenVPN).
    pub iface: Option<String>,
    pub keepalive: u32,
    /// Unix seconds of the connect.
    pub since: f64,
}

impl RunRecord {
    pub fn encode(&self) -> Vec<u8> {
        let value = serde_json::json!({
            "v": 1,
            "id": self.id.hyphenated().to_string(),
            "kind": self.kind.raw_value(),
            "iface": self.iface,
            "keepalive": self.keepalive,
            "since": self.since,
        });
        serde_json::to_vec(&value).unwrap_or_default()
    }

    /// The strict parse: exactly these keys and types, a plain interface name, a finite time.
    pub fn decode(bytes: &[u8]) -> Option<RunRecord> {
        if bytes.len() as u64 > MAX_RECORD {
            return None;
        }
        let Value::Object(map) = serde_json::from_slice::<Value>(bytes).ok()? else { return None };
        const KEYS: [&str; 6] = ["v", "id", "kind", "iface", "keepalive", "since"];
        if map.len() != KEYS.len() || !KEYS.iter().all(|k| map.contains_key(*k)) {
            return None;
        }
        if map.get("v").and_then(Value::as_u64) != Some(1) {
            return None;
        }
        let id = Uuid::parse_str(str_of(&map, "id")?).ok()?;
        let kind = VPNKind::from_raw_value(str_of(&map, "kind")?)?;
        let iface = match map.get("iface")? {
            Value::Null => None,
            Value::String(s)
                if !s.is_empty()
                    && s.len() <= MAX_IFACE
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.') =>
            {
                Some(s.clone())
            }
            _ => return None,
        };
        let keepalive = u32::try_from(map.get("keepalive")?.as_u64()?).ok()?;
        let since = map.get("since")?.as_f64().filter(|s| s.is_finite() && *s >= 0.0)?;
        Some(RunRecord { id, kind, iface, keepalive, since })
    }
}

fn str_of<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)?.as_str()
}

#[derive(Debug)]
pub struct RuntimeFiles {
    pub dir: PathBuf,
}

impl Drop for RuntimeFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl RuntimeFiles {
    /// Writes the run record (0600, created new) into the directory.
    pub fn write_record(&self, record: &RunRecord) -> io::Result<()> {
        let mut out = fsx::create_new(&self.dir.join(RECORD), Access::Private)?;
        out.write_all(&record.encode())
    }

    /// Takes over the existing directory of an adopted connection (removed when the guard is dropped).
    pub fn adopt(runtime: &Path, nm_uuid: &str) -> Option<RuntimeFiles> {
        let dir = dir_for(runtime, nm_uuid);
        (is_plain_name(nm_uuid) && is_own_dir(&dir, current_uid())).then_some(RuntimeFiles { dir })
    }
}

/// `<runtime>/linvpn/nm/<nm_uuid>`.
pub fn dir_for(runtime: &Path, nm_uuid: &str) -> PathBuf {
    runtime.join("linvpn").join("nm").join(nm_uuid)
}

/// Writes `files` into a fresh [`dir_for`] (a stale one of a crashed run is replaced).
pub fn write(runtime: &Path, nm_uuid: &str, files: &[RuntimeFile]) -> io::Result<RuntimeFiles> {
    write_for_owner(runtime, nm_uuid, files, current_uid())
}

/// [`write`] with the owner every directory must have (tests: an unprivileged test cannot make a directory that is
/// not its own, so it asks for another owner).
#[doc(hidden)]
pub fn write_for_owner(runtime: &Path, nm_uuid: &str, files: &[RuntimeFile], owner: u32) -> io::Result<RuntimeFiles> {
    if !is_plain_name(nm_uuid) {
        return Err(io::Error::new(ErrorKind::InvalidInput, "the runtime directory's name is not one plain component"));
    }
    if let Some(bad) = files.iter().find(|f| !is_plain_name(&f.name)) {
        return Err(io::Error::new(ErrorKind::InvalidInput, format!("{:?} is not one plain file name", bad.name)));
    }
    let nm = runtime.join("linvpn").join("nm");
    private_dir(&runtime.join("linvpn"), owner)?;
    private_dir(&nm, owner)?;
    let dir = dir_for(runtime, nm_uuid);
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_dir() && m.uid() == owner => fs::remove_dir_all(&dir)?,
        Ok(_) => return Err(not_ours(&dir)),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    private_dir(&dir, owner)?;
    let guard = RuntimeFiles { dir };
    for f in files {
        let mut out = fsx::create_new(&guard.dir.join(&f.name), Access::Private)?;
        out.write_all(&f.data)?;
    }
    Ok(guard)
}

/// Every valid run record under `<runtime>/linvpn/nm` with its directory's name, sorted by name. Fail closed (R9):
/// `linvpn`, `nm` and each connection's directory must be real directories of ours, the record a regular file of
/// ours with mode 0600, never reached through a symlink; anything else is left out.
pub fn records(runtime: &Path) -> Vec<(String, RunRecord)> {
    let uid = current_uid();
    let nm = runtime.join("linvpn").join("nm");
    if !is_own_dir(&runtime.join("linvpn"), uid) || !is_own_dir(&nm, uid) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&nm) else { return Vec::new() };
    let mut out: Vec<(String, RunRecord)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok().filter(|n| is_plain_name(n))?;
            if !is_own_dir(&entry.path(), uid) {
                return None;
            }
            Some((name, read_record(&entry.path().join(RECORD), uid)?))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn read_record(path: &Path, uid: u32) -> Option<RunRecord> {
    let (file, stat) = fsx::open_regular(path, OpenFor::Read, Follow::No, true).ok()?;
    if fsx::owner(&stat).ok()? != FileOwner::from_uid(uid) || !fsx::has_access(&stat, Access::Private) {
        return None;
    }
    if stat.len() > MAX_RECORD {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1).read_to_end(&mut bytes).ok()?;
    RunRecord::decode(&bytes)
}

/// Removes every leftover under `<runtime>/linvpn/nm` (launch, after a crash or a "Keep Them Running" quit) except
/// the directories named in `keep` (the UUIDs of NM's active connections: a tunnel still up may need its files
/// again, as OpenVPN on a restart). Does nothing unless `linvpn` and `nm` are real directories of ours.
pub fn sweep(runtime: &Path, keep: &HashSet<String>) {
    let uid = current_uid();
    let nm = runtime.join("linvpn").join("nm");
    if !is_own_dir(&runtime.join("linvpn"), uid) || !is_own_dir(&nm, uid) {
        return;
    }
    let Ok(entries) = fs::read_dir(&nm) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(|n| keep.contains(n)) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if meta.uid() != uid {
            continue;
        }
        let _ = if meta.file_type().is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
    }
}

/// One component a directory may hold: not empty, no `/` or NUL, not starting with `.` (so never `.` or `..`).
fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && !name.starts_with('.') && !name.contains(['/', '\0'])
}

/// Creates `dir` 0700 if missing; refuses a symlink or anything but a directory, and a directory not owned by
/// `owner`; tightens its mode to 0700.
fn private_dir(dir: &Path, owner: u32) -> io::Result<()> {
    if fsx::ensure_private_dir(dir)? != FileOwner::from_uid(owner) {
        return Err(not_ours(dir));
    }
    Ok(())
}

fn is_own_dir(dir: &Path, uid: u32) -> bool {
    fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_dir() && m.uid() == uid)
}

fn not_ours(path: &Path) -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, format!("{} is not our own private directory", path.display()))
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { libc::getuid() }
}
