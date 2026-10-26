//! The names of WinVPN's RAS entries and its private phonebook.
//!
//! An entry is named `WinVPN-<UUID upper case>` from the connection ID only: stable across renames, never derived
//! from user text, never equal to an entry of the user's own phonebooks. The `RasEngine` writes, dials and
//! deletes only entries whose name [`connection_id`] recognises.

use crate::models::{parse_uuid, uuid_string};
use uuid::Uuid;

/// The prefix of every entry name.
pub const PREFIX: &str = "WinVPN-";
/// The phonebook's folder in WinVPN's data directory (`%LOCALAPPDATA%\WinVPN\ras`).
pub const PHONEBOOK_DIR: &str = "ras";
/// The phonebook's file name in [`PHONEBOOK_DIR`].
pub const PHONEBOOK_FILE: &str = "WinVPN.pbk";

/// The entry name of a connection: `WinVPN-` + its upper-case UUID (43 characters).
pub fn entry_name(id: &Uuid) -> String {
    format!("{PREFIX}{}", uuid_string(id))
}

/// The connection ID of an entry name WinVPN wrote: exactly [`entry_name`] of some ID (case and all), else
/// `None`.
pub fn connection_id(name: &str) -> Option<Uuid> {
    let rest = name.strip_prefix(PREFIX)?;
    let id = parse_uuid(rest)?;
    (uuid_string(&id) == rest).then_some(id)
}
