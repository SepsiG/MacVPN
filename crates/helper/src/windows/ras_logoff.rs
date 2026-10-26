//! Which RAS connections the WinVPN Service hangs up when a user logs off (2b decision 2 for the native VPNs, 2c
//! plan Task 10). Pure: it compiles and is tested on every OS; `sys::session` feeds it what Windows says.
//!
//! The app dials WinVPN's entries in the user's own context from the user's private phonebook
//! `<profile>\AppData\Local\WinVPN\ras\WinVPN.pbk`. Windows normally hangs those connections up at logoff; this is
//! the safety net for `KeepRasConnections` = 1 (or anything else that keeps them). Nothing here comes from a
//! request: the profiles are HKLM's `ProfileList`, the present users the sessions' tokens, the connections
//! `RasEnumConnectionsW`. A connection counts as the user's only when its entry name is `WinVPN-<UUID>` (exactly as
//! WinVPN writes it) and its phonebook is that user's WinVPN phonebook; the user's own system VPNs, another user's
//! connections and anything that only looks similar stay up. Anything uncertain keeps the connection (keeping is
//! safe: Windows' own logoff handling still applies).

use macvpn_core::ras::names;
use std::collections::{BTreeSet, HashSet};

/// The phonebook's folders below the profile folder (`%LOCALAPPDATA%\WinVPN` = `<profile>\AppData\Local\WinVPN`).
const BELOW_PROFILE: [&str; 3] = ["AppData", "Local", "WinVPN"];

/// A user profile of `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`: the key's name and its
/// `ProfileImagePath`, expanded.
#[derive(Debug, Clone, Copy)]
pub struct Profile<'a> {
    pub sid: &'a str,
    pub dir: &'a str,
}

/// A RAS connection as `RasEnumConnectionsW` lists it.
#[derive(Debug, Clone, Copy)]
pub struct RasConn<'a> {
    pub entry: &'a str,
    /// The phonebook path exactly as the dialler passed it.
    pub phonebook: &'a str,
}

/// A Windows path as upper-case components: `\\?\` stripped, `\` and `/` both separators, empty components (a
/// doubled or trailing separator) ignored. `None` for anything that is not a plain absolute drive path (`..`, `.`,
/// relative, empty): such a path is never anyone's phonebook here.
fn components(path: &str) -> Option<Vec<String>> {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let parts: Vec<String> = path.split(['\\', '/']).filter(|c| !c.is_empty()).map(str::to_uppercase).collect();
    let drive = parts.first()?;
    let is_drive = drive.len() == 2 && drive.ends_with(':') && drive.as_bytes()[0].is_ascii_alphabetic();
    if !is_drive || parts.iter().any(|c| c == "." || c == "..") {
        return None;
    }
    Some(parts)
}

/// The components of the WinVPN phonebook of the profile at `profile_dir`.
fn phonebook_components(profile_dir: &str) -> Option<Vec<String>> {
    let mut parts = components(profile_dir)?;
    parts.extend(BELOW_PROFILE.iter().chain(&[names::PHONEBOOK_DIR, names::PHONEBOOK_FILE]).map(|c| c.to_uppercase()));
    Some(parts)
}

/// The indexes of `conns` that are WinVPN's connections of the user whose profile folder is `profile_dir`: the
/// entry name is exactly `WinVPN-<UUID upper case>` and the phonebook is `<profile>\AppData\Local\WinVPN\ras\
/// WinVPN.pbk`, compared component by component without regard to letter case.
pub fn owned_connections(profile_dir: &str, conns: &[RasConn<'_>]) -> Vec<usize> {
    let Some(book) = phonebook_components(profile_dir) else { return Vec::new() };
    conns
        .iter()
        .enumerate()
        .filter(|(_, c)| names::connection_id(c.entry).is_some() && components(c.phonebook).as_ref() == Some(&book))
        .map(|(i, _)| i)
        .collect()
}

/// A key name of `ProfileList` that is a SID string (`S-1-<digits>-…`): not a `<SID>.bak` copy Windows leaves
/// next to a repaired profile.
fn is_sid(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("S-1-") else { return false };
    rest.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The indexes of `conns` to hang up when the users in `present` (SID strings, whatever the session's state) are
/// the only ones with a session: WinVPN's connections of every profile whose SID has no session left, except a
/// connection whose phonebook also belongs to a present user's profile (a profile folder listed twice). Sorted,
/// each once.
pub fn to_hang_up(profiles: &[Profile<'_>], present: &HashSet<String>, conns: &[RasConn<'_>]) -> Vec<usize> {
    let here = |sid: &str| present.iter().any(|p| p.eq_ignore_ascii_case(sid));
    let kept: HashSet<usize> =
        profiles.iter().filter(|p| here(p.sid)).flat_map(|p| owned_connections(p.dir, conns)).collect();
    let gone: BTreeSet<usize> = profiles
        .iter()
        .filter(|p| is_sid(p.sid) && !here(p.sid))
        .flat_map(|p| owned_connections(p.dir, conns))
        .filter(|i| !kept.contains(i))
        .collect();
    gone.into_iter().collect()
}

/// The `service.log` line for one hang-up (`error`: why it failed): the entry's prefix and the connection ID's
/// first 8 hex digits only.
pub fn hang_up_line(entry: &str, error: Option<&str>) -> String {
    let short: String = entry.chars().take(names::PREFIX.len() + 8).collect();
    match error {
        None => format!("RAS connection of a logged-off user ended: {short}"),
        Some(e) => format!("RAS connection of a logged-off user could not be ended: {short} ({e})"),
    }
}
