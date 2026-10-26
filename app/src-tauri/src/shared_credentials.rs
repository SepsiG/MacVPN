//! The shared credentials' commands (spec 3a, plan B Task 19): the Connections window's Credentials section (add,
//! edit, rename, delete with "Copy into each connection"), the editors' selector ("Own username and password" /
//! "Use credential: <name>"), "Create from connection…" and the import's credential choice. The logic is
//! `macvpn_app_core::connections` over `macvpn_app_core::shared_credentials`.
//!
//! Every argument is validated before use: ids are UUID-shaped (a credential must exist, a connection must be
//! listed), names, user names and passwords are bounded here and checked again by the vault's rules. A password
//! only ever travels from the web view to the vault (in a wiped buffer); no command returns one. While the vault
//! is locked (or not there yet), every command answers with the "locked" text, which the UI shows.

use macvpn_app_core::shared_credentials::Zeroizing;
use macvpn_core::models::parse_uuid;
use serde::Serialize;
use std::sync::Arc;
use tauri::{State, Window};
use uuid::Uuid;

use crate::commands::validate_key;
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// A name's bytes (the vault allows 64 characters; a character can take several bytes).
pub const MAX_NAME_BYTES: usize = 1024;
/// A user name's bytes (the vault's limit).
pub const MAX_USERNAME_BYTES: usize = 256;
/// A password's bytes (the vault's limit).
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// The connections "Create from connection…" may link at once.
pub const MAX_LINKS: usize = 512;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// A credential id (a UUID string).
pub fn parse_credential(id: &str) -> Result<Uuid, String> {
    validate_key(id).map_err(|_| "invalid credential id".to_string())?;
    parse_uuid(id).ok_or_else(|| "invalid credential id".into())
}

pub fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES { Err("invalid name".into()) } else { Ok(()) }
}

pub fn check_username(username: &str) -> Result<(), String> {
    if username.len() > MAX_USERNAME_BYTES { Err("invalid user name".into()) } else { Ok(()) }
}

/// A password input: `None` keeps the stored one, `Some("")` removes it, else it replaces it (wiped on drop).
pub fn password_input(password: Option<String>) -> Result<Option<Zeroizing<String>>, String> {
    let password = password.map(Zeroizing::new);
    if password.as_ref().is_some_and(|p| p.len() > MAX_PASSWORD_BYTES) {
        return Err("invalid password".into());
    }
    Ok(password)
}

/// The items "Create from connection…" links: UUID-shaped, unique, bounded (the vault checks that each one has
/// the same username and password).
pub fn check_links(link: &[String]) -> Result<(), String> {
    if link.len() > MAX_LINKS {
        return Err("too many connections".into());
    }
    let mut seen = std::collections::HashSet::new();
    for item in link {
        validate_key(item)?;
        if !seen.insert(item.as_str()) {
            return Err("duplicate connection".into());
        }
    }
    Ok(())
}

/// Whether a window may use these commands: only the Connections window (its capability grants them; checked here too).
fn is_manage(label: &str) -> bool {
    label == crate::manage::MANAGE_WINDOW
}

fn manage_only(window: &Window) -> Result<(), String> {
    if is_manage(window.label()) { Ok(()) } else { Err("not available in this window".into()) }
}

/// The credential must be one of the listed ones (an unknown id is refused before anything changes).
fn known(state: &AppState, id: &str) -> Result<Uuid, String> {
    let id = parse_credential(id)?;
    let view = state.connections.credentials_view();
    if !view.available {
        return Err(view.message.unwrap_or_default());
    }
    if view.items.iter().any(|c| parse_uuid(&c.id) == Some(id)) { Ok(id) } else { Err("unknown credential".into()) }
}

/// "Add": a new credential. The password may be missing (the credential prompt asks for it at connect).
#[tauri::command]
pub async fn credential_create(
    window: Window,
    state: Shared<'_>,
    name: String,
    username: String,
    password: Option<String>,
) -> Result<(), String> {
    // First: every early return below wipes the password.
    let password = password_input(password)?;
    manage_only(&window)?;
    check_name(&name)?;
    check_username(&username)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.add_credential(&name, &username, password)).await?
}

/// "Edit" / "Rename": `None` keeps a field; `password` `Some("")` removes the stored password.
#[tauri::command]
pub async fn credential_update(
    window: Window,
    state: Shared<'_>,
    id: String,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    // First: every early return below wipes the password.
    let password = password_input(password)?;
    manage_only(&window)?;
    let id = known(&state, &id)?;
    if let Some(name) = &name {
        check_name(name)?;
    }
    if let Some(username) = &username {
        check_username(username)?;
    }
    let shared = state.inner().clone();
    blocking(move || shared.connections.edit_credential(id, name.as_deref(), username.as_deref(), password)).await?
}

/// "Delete". While connections use it: without `copy_into` nothing changes and their names come back (the
/// question "Copy into each connection" or Cancel); with it each gets its own copy first.
#[tauri::command]
pub async fn credential_delete(
    window: Window,
    state: Shared<'_>,
    id: String,
    copy_into: bool,
) -> Result<Option<Vec<String>>, String> {
    manage_only(&window)?;
    let id = known(&state, &id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.delete_credential(id, copy_into)).await?
}

/// The editor's selector: a credential links the connection (its own username and password are deleted; the UI
/// asked first), `None` returns it to its own fields.
#[tauri::command]
pub async fn credential_link(
    window: Window,
    state: Shared<'_>,
    item: String,
    credential: Option<String>,
) -> Result<(), String> {
    manage_only(&window)?;
    validate_key(&item)?;
    let credential = credential.map(|c| known(&state, &c)).transpose()?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.link_credential(&item, credential)).await?
}

/// A connection with the same username and password ("Create from connection…"): never the values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMatch {
    /// The vault item (what `credential_from_connection` links).
    pub item: String,
    pub name: String,
}

/// "Create from connection…", step 2: the other connections with the same own username and password.
#[tauri::command]
pub async fn credential_matches(
    window: Window,
    state: Shared<'_>,
    item: String,
) -> Result<Vec<CredentialMatch>, String> {
    manage_only(&window)?;
    validate_key(&item)?;
    let shared = state.inner().clone();
    let matches = blocking(move || shared.connections.credential_matches(&item)).await??;
    Ok(matches.into_iter().map(|(item, name)| CredentialMatch { item, name }).collect())
}

/// "Create from connection…", step 3: the credential `name` from the connection's values, linked to it and to
/// the ticked matches.
#[tauri::command]
pub async fn credential_from_connection(
    window: Window,
    state: Shared<'_>,
    item: String,
    name: String,
    link: Vec<String>,
) -> Result<(), String> {
    manage_only(&window)?;
    validate_key(&item)?;
    check_name(&name)?;
    check_links(&link)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.credential_from_connection(&item, &name, &link)).await?
}

/// The answer to a choice question of an import (the shared credential to use): an option's index, or `None`
/// for the connection's own fields.
#[tauri::command]
pub async fn answer_question_choice(
    window: Window,
    state: Shared<'_>,
    id: u64,
    choice: Option<u32>,
) -> Result<(), String> {
    manage_only(&window)?;
    let choice = choice.map(|c| c as usize);
    if state.connections.questions().answer_choice(id, choice) { Ok(()) } else { Err("no such question".into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_connections_window_uses_them() {
        assert!(is_manage("manage"));
        for label in ["menu", "setup", "update", "backup", "vault-create", "cred-1", "manage2", ""] {
            assert!(!is_manage(label), "{label}");
        }
    }

    #[test]
    fn ids_are_uuid_shaped() {
        assert!(parse_credential("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4").is_ok());
        assert!(parse_credential("38b51e6d-5d77-4abe-bfdf-b0e5de45b1c4").is_ok());
        for bad in ["", "Office AD", "../38B51E6D", "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4x"] {
            assert!(parse_credential(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_user_names_and_passwords_are_bounded() {
        assert!(check_name("Office AD").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
        assert!(check_username("").is_ok());
        assert!(check_username(&"u".repeat(MAX_USERNAME_BYTES)).is_ok());
        assert!(check_username(&"u".repeat(MAX_USERNAME_BYTES + 1)).is_err());
        assert_eq!(password_input(None).unwrap(), None);
        assert_eq!(password_input(Some(String::new())).unwrap().as_deref().map(String::as_str), Some(""));
        assert!(password_input(Some("p".repeat(MAX_PASSWORD_BYTES))).is_ok());
        assert!(password_input(Some("p".repeat(MAX_PASSWORD_BYTES + 1))).is_err());
    }

    #[test]
    fn links_are_unique_uuid_shaped_and_bounded() {
        let a = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".to_string();
        let b = "48B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".to_string();
        assert!(check_links(&[]).is_ok());
        assert!(check_links(&[a.clone(), b]).is_ok());
        assert!(check_links(&[a.clone(), a.clone()]).is_err());
        assert!(check_links(&["not-an-id".into()]).is_err());
        assert!(check_links(&vec![a; MAX_LINKS + 1]).is_err());
    }
}
