//! The sweep of WinVPN's RAS leftovers (WinVPN 2c Task 13), without a system call: which entries of the private
//! phonebook and which files of its folders belong to connections that no longer exist.
//!
//! Only what WinVPN itself names is ever chosen: an entry named exactly `WinVPN-<UUID upper case>`
//! (`macvpn_core::ras::names::connection_id`) and a file named exactly `<UUID upper case>.ras`, `.log` or
//! `.log.1`. Anything else (another name, another case, another suffix) is never touched. The caller passes the
//! connections of the **open** vault: an empty set from a locked vault would choose everything, so the app calls
//! the sweep only after an unlocked load (`ConnectionsModel::sync_native_profiles`).

use macvpn_core::models::{parse_uuid, uuid_string};
use macvpn_core::ras::names;
use std::collections::{BTreeSet, HashSet};
use uuid::Uuid;

/// The suffixes of the files WinVPN keeps per connection: the saved L2TP profile, the log and its rolled copy.
pub const FILE_SUFFIXES: [&str; 3] = [".ras", ".log", ".log.1"];

/// The connections of the phonebook entries `entry_names` that are not in `known` (each once, sorted).
pub fn orphan_entries<'a>(entry_names: impl IntoIterator<Item = &'a str>, known: &HashSet<Uuid>) -> Vec<Uuid> {
    let orphans: BTreeSet<Uuid> =
        entry_names.into_iter().filter_map(names::connection_id).filter(|id| !known.contains(id)).collect();
    orphans.into_iter().collect()
}

/// The connection of a file WinVPN wrote for it (`<UUID>.ras`, `<UUID>.log`, `<UUID>.log.1`, the UUID exactly as
/// WinVPN writes it), else `None`.
pub fn file_connection(file_name: &str) -> Option<Uuid> {
    FILE_SUFFIXES.iter().find_map(|suffix| {
        let stem = file_name.strip_suffix(suffix)?;
        let id = parse_uuid(stem)?;
        (uuid_string(&id) == stem).then_some(id)
    })
}

/// The connections of the files `file_names` that are not in `known` (each once, sorted).
pub fn orphan_files<'a>(file_names: impl IntoIterator<Item = &'a str>, known: &HashSet<Uuid>) -> Vec<Uuid> {
    let orphans: BTreeSet<Uuid> =
        file_names.into_iter().filter_map(file_connection).filter(|id| !known.contains(id)).collect();
    orphans.into_iter().collect()
}
