//! Shared credentials in the app (spec 3a, plan B Task 18): the orchestration over the vault lifecycle that the
//! Credentials section, the editors' selector and the import use (their commands and views are Task 19).
//!
//! The values never leave the vault through here: the listing carries the username and whether a password is
//! stored, "Create from connection…" compares in the vault and returns item ids, and passwords come in as
//! `Zeroizing` strings. Reads go through [`VaultLifecycle::with_read`], writes through [`VaultLifecycle::with`].
//! Items are the upper-case UUID strings of managed connections or the service IDs of system VPNs.
//!
//! The connect-time resolution is not here: [`crate::vault_stores::VaultSecrets`] does it, transparently to the
//! manager.

use crate::deps::{SecretField, SecretReader};
use crate::vault::VaultLifecycle;
use macvpn_core::importer;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::mfa;
use macvpn_core::models::{CredentialRef, VPNKind, uuid_string};
use macvpn_core::vault::{
    MAX_CREDENTIAL_PASSWORD_BYTES, MAX_CREDENTIAL_USERNAME_BYTES, SharedCredential, VaultError,
    validate_credential_name,
};
use serde::Serialize;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;
/// Re-exported for the app shell, which wraps typed passwords before they reach the vault.
pub use zeroize::Zeroizing;

/// A credential in the Credentials section's list.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialSummary {
    pub credential: SharedCredential,
    /// "used by N".
    pub used_by: usize,
}

/// Why a delete did not happen.
#[derive(Debug)]
pub enum DeleteCredentialError {
    /// Items still use it (sorted ids): the UI asks "Copy into each connection" or Cancel, naming them.
    InUse(Vec<String>),
    Vault(VaultError),
}

impl fmt::Display for DeleteCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteCredentialError::InUse(items) => write!(f, "the credential is used by {} items", items.len()),
            DeleteCredentialError::Vault(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DeleteCredentialError {}

/// What an import does with the exported `credentialName` (the `# macvpn-meta` line). A file never links a
/// connection by itself: an imported config chooses its own server, so linking it silently would send a stored
/// shared password to whatever host the file names (spec 3a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportLink {
    /// A credential with exactly this name exists. The import question (Task 19) asks "Use the shared credential
    /// '<name>' for this connection to <remote>?" with "Use the connection's own fields" as the default answer;
    /// only a yes links it ([`SharedCredentials::link`]). `remote`: the server the config connects to
    /// ([`importer::remote_host`]), `None` when the config names none.
    Ask { credential: Uuid, name: String, remote: Option<String> },
    /// No credential has this name: the import question offers the credentials to pick from, or "Use the
    /// connection's own fields".
    Unknown {
        name: String,
        /// The config's server, as for [`ImportLink::Ask`].
        remote: Option<String>,
    },
    /// The export named no credential: the connection uses its own fields.
    Own,
}

/// The credential operations over the vault; cheap to clone around as part of the app state.
#[derive(Clone)]
pub struct SharedCredentials {
    vault: Arc<VaultLifecycle>,
}

impl SharedCredentials {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        SharedCredentials { vault }
    }

    /// Every credential with its use count, sorted by name.
    pub fn list(&self) -> Result<Vec<CredentialSummary>, VaultError> {
        self.vault.with_read(|v| {
            let usage = v.credential_usage()?;
            Ok(v.credentials()?
                .into_iter()
                .map(|credential| {
                    let used_by = usage.get(&credential.id).copied().unwrap_or(0);
                    CredentialSummary { credential, used_by }
                })
                .collect())
        })
    }

    /// A new credential; the name must be unused.
    pub fn create(&self, name: &str, username: &str, password: Option<Zeroizing<String>>) -> Result<Uuid, VaultError> {
        self.vault.with(|v| v.create_credential(name, username, password.as_deref().map(String::as_str)))
    }

    /// Rename, change the username, replace (`Some(Some(_))`) or remove (`Some(None)`) the password.
    pub fn update(
        &self,
        id: Uuid,
        name: Option<&str>,
        username: Option<&str>,
        password: Option<Option<Zeroizing<String>>>,
    ) -> Result<(), VaultError> {
        let password = password.as_ref().map(|p| p.as_deref().map(String::as_str));
        self.vault.with(|v| v.update_credential(id, name, username, password))
    }

    /// Deletes a credential. While it is linked: `copy_into` gives every linked item its own copy first ("Copy
    /// into each connection"); otherwise nothing changes and [`DeleteCredentialError::InUse`] lists the items.
    pub fn delete(&self, id: Uuid, copy_into: bool) -> Result<(), DeleteCredentialError> {
        let result = self.vault.with(|v| {
            if copy_into && !v.linked_items(id)?.is_empty() {
                return v.copy_into_connections(id).map(|()| None);
            }
            match v.delete_credential(id) {
                Ok(()) => Ok(None),
                Err(Ok(in_use)) => Ok(Some(in_use.items)),
                Err(Err(e)) => Err(e),
            }
        });
        match result {
            Ok(None) => Ok(()),
            Ok(Some(items)) => Err(DeleteCredentialError::InUse(items)),
            Err(e) => Err(DeleteCredentialError::Vault(e)),
        }
    }

    /// The editor's selector: `Some` links the item (its own username and password are deleted; the UI confirms
    /// first), `None` returns it to its own (now empty) fields.
    pub fn link(&self, item: &str, credential: Option<Uuid>) -> Result<(), VaultError> {
        self.vault.with(|v| match credential {
            Some(credential) => v.link(item, credential),
            None => v.unlink(item),
        })
    }

    pub fn credential_of(&self, item: &str) -> Result<Option<Uuid>, VaultError> {
        self.vault.with_read(|v| v.credential_of(item))
    }

    /// The items linked to a credential (for the delete question's names).
    pub fn linked_items(&self, credential: Uuid) -> Result<Vec<String>, VaultError> {
        self.vault.with_read(|v| v.linked_items(credential))
    }

    /// "Create from connection…", step 2: the other items with the same own username and password (ids only).
    pub fn matching_items(&self, item: &str) -> Result<Vec<String>, VaultError> {
        self.vault.with_read(|v| v.matching_items(item))
    }

    /// "Create from connection…", step 3: the credential from `item`'s own values, linked to `item` and the
    /// ticked matches, in one transaction.
    pub fn create_from_connection(&self, item: &str, name: &str, link: &[String]) -> Result<Uuid, VaultError> {
        self.vault.with(|v| v.create_credential_from(item, name, link))
    }

    /// What the import asks about the exported `credentialName` of a config of `kind` (spec 3a): never links
    /// anything itself (the vault is only read). A credential with exactly that name gives
    /// [`ImportLink::Ask`] with the config's server; an unknown name [`ImportLink::Unknown`]; no name
    /// [`ImportLink::Own`]. The user's yes goes through [`Self::link`].
    ///
    /// There is deliberately no automatic link, not even when another connection linked to the credential has the
    /// same `remote`: a config can name several servers (`remote` lines, `<connection>` blocks) and fall back to
    /// another one, so a same-host check would be easy to get wrong for an attacker's file.
    pub fn link_imported(
        &self,
        credential_name: Option<&str>,
        kind: VPNKind,
        config: &str,
    ) -> Result<ImportLink, VaultError> {
        let Some(name) = credential_name else { return Ok(ImportLink::Own) };
        self.vault.with_read(|v| match v.credential_by_name(name)? {
            Some(credential) => {
                Ok(ImportLink::Ask { credential, name: name.to_string(), remote: importer::remote_host(kind, config) })
            }
            None => Ok(ImportLink::Unknown { name: name.to_string(), remote: importer::remote_host(kind, config) }),
        })
    }
}

/// The credential the credential prompt names ("Password for Office AD — used by 4 connections"): the item's
/// linked credential, when the prompt asks for its password or its user name (a linked credential without one).
/// `None` otherwise: the window shows the connection's own fields heading.
pub fn prompt_credential(secrets: &dyn SecretReader, id: &Uuid, asked: &[SecretField]) -> Option<CredentialRef> {
    if !asked.iter().any(|f| matches!(f, SecretField::Password | SecretField::Username)) {
        return None;
    }
    secrets.credential_for(id)
}

// MARK: - The Credentials section (Task 19)

/// A credential as the Credentials section lists it: never the password, only whether one is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialItemView {
    pub id: String,
    pub name: String,
    pub username: String,
    pub has_password: bool,
    /// "used by N".
    pub used_by: usize,
}

/// The Credentials section's part of the view model.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsView {
    /// The vault is open: the list is real and the section's actions work.
    pub available: bool,
    /// Why it is not (the vault is locked), shown in place of the list.
    pub message: Option<String>,
    pub items: Vec<CredentialItemView>,
}

impl CredentialsView {
    /// No vault, or a locked one: an empty list with the reason.
    pub fn locked() -> Self {
        CredentialsView { available: false, message: Some(locked_message()), items: Vec::new() }
    }
}

/// The text for a credential action while the vault is locked (or not there yet): the stores' one text.
pub use crate::vault_stores::locked_message;

/// A vault error as the Credentials section, the editors' selector and the import show it. Never a value.
pub fn error_message(e: &VaultError) -> String {
    match e {
        VaultError::Locked => locked_message(),
        VaultError::ReadOnly => crate::vault_stores::read_only_message(),
        VaultError::NewerSchema { .. } => {
            l10n::tr("This data was saved by a newer MacVPN. Update the app to make changes.", &[])
        }
        other => l10n::tr("The shared credential could not be changed: %@", &[Arg::Str(&other.to_string())]),
    }
}

/// A credential name as stored (the vault's rule: 1 to 64 characters, no control characters, trimmed), or the
/// message.
pub fn check_name(name: &str) -> Result<String, String> {
    validate_credential_name(name)
        .map_err(|_| l10n::tr("A credential name must have 1 to 64 characters and no control characters.", &[]))
}

/// The credential's user name: at most 256 bytes, no control characters.
pub fn check_username(username: &str) -> Result<(), String> {
    if username.len() > MAX_CREDENTIAL_USERNAME_BYTES || mfa::has_control(username) {
        return Err(l10n::tr("The user name must have at most 256 bytes and no control characters.", &[]));
    }
    Ok(())
}

/// The credential's password: at most 1024 bytes, no control characters (the secret rules of the editors).
pub fn check_password(password: &str) -> Result<(), String> {
    if password.len() > MAX_CREDENTIAL_PASSWORD_BYTES || mfa::has_control(password) {
        return Err(l10n::tr("The password must have at most 1024 bytes and no control characters.", &[]));
    }
    Ok(())
}

/// The password input of the Credentials section's form, the editors' `SecretInput`: `None` keeps the stored
/// one, `Some("")` removes it, anything else replaces it.
pub type PasswordInput = Option<Zeroizing<String>>;

impl SharedCredentials {
    /// The Credentials section's list (sorted by name); a locked vault gives [`CredentialsView::locked`].
    pub fn view(&self) -> CredentialsView {
        // The legacy read-only mode: the 1.1 data has no shared credentials, and none may be made before the
        // migration.
        if matches!(self.vault.state(), crate::vault::VaultState::LegacyReadOnly { .. }) {
            return CredentialsView {
                available: false,
                message: Some(crate::vault_stores::read_only_message()),
                items: Vec::new(),
            };
        }
        match self.list() {
            Ok(list) => CredentialsView {
                available: true,
                message: None,
                items: list
                    .into_iter()
                    .map(|s| CredentialItemView {
                        id: uuid_string(&s.credential.id),
                        name: s.credential.name,
                        username: s.credential.username,
                        has_password: s.credential.has_password,
                        used_by: s.used_by,
                    })
                    .collect(),
            },
            Err(VaultError::Locked) => CredentialsView::locked(),
            Err(e) => CredentialsView { available: false, message: Some(error_message(&e)), items: Vec::new() },
        }
    }

    /// A name no other credential has (`except`: the one being renamed), or the message.
    fn unused_name(&self, name: &str, except: Option<Uuid>) -> Result<String, String> {
        let name = check_name(name)?;
        let list = self.list().map_err(|e| error_message(&e))?;
        if list.iter().any(|s| s.credential.name == name && Some(s.credential.id) != except) {
            return Err(l10n::tr("A credential named %@ already exists.", &[Arg::Str(&name)]));
        }
        Ok(name)
    }

    /// "Add": a new credential (the password may be empty: the credential prompt asks for it at connect).
    pub fn add(&self, name: &str, username: &str, password: PasswordInput) -> Result<Uuid, String> {
        let name = self.unused_name(name, None)?;
        check_username(username)?;
        if let Some(p) = &password {
            check_password(p)?;
        }
        let password = password.filter(|p| !p.is_empty());
        self.create(&name, username, password).map_err(|e| error_message(&e))
    }

    /// "Edit" / "Rename": `None` keeps a field; the password follows [`PasswordInput`].
    pub fn edit(
        &self,
        id: Uuid,
        name: Option<&str>,
        username: Option<&str>,
        password: PasswordInput,
    ) -> Result<(), String> {
        let name = name.map(|n| self.unused_name(n, Some(id))).transpose()?;
        if let Some(username) = username {
            check_username(username)?;
        }
        if let Some(p) = &password {
            check_password(p)?;
        }
        let password = password.map(|p| (!p.is_empty()).then_some(p));
        self.update(id, name.as_deref(), username, password).map_err(|e| error_message(&e))
    }

    /// "Create from connection…", checked first: the item must not be linked yet and must have its own user name
    /// (read through `secrets`, which never returns the value to the caller); the name must be free and every
    /// item of `link` one of [`Self::matching_items`].
    pub fn from_connection(
        &self,
        secrets: &dyn SecretReader,
        item: &Uuid,
        name: &str,
        link: &[String],
    ) -> Result<Uuid, String> {
        let name = self.unused_name(name, None)?;
        if secrets.credential_for(item).is_some() {
            return Err(l10n::tr("This connection already uses a shared credential.", &[]));
        }
        if secrets.get(item, SecretField::Username).is_none_or(|u| u.is_empty()) {
            return Err(l10n::tr("This connection has no stored user name to share.", &[]));
        }
        self.create_from_connection(&uuid_string(item), &name, link).map_err(|e| error_message(&e))
    }
}

/// The display names of vault items (managed connections' UUID strings, system VPNs' service IDs), in the given
/// order; an item that is not listed any more keeps its id.
pub fn item_names(items: &[String], names: &std::collections::HashMap<String, String>) -> Vec<String> {
    items.iter().map(|i| names.get(i).cloned().unwrap_or_else(|| i.clone())).collect()
}

// MARK: - The import's question (spec 3a)

/// "Use the shared credential '<name>' for this connection to <server>?" (title, message). The default answer is
/// the connection's own fields: a file chooses its own server, so only the user may send a shared password there.
pub fn import_question(name: &str, remote: Option<&str>) -> (String, String) {
    let title = match remote {
        Some(remote) => {
            l10n::tr("Use the shared credential '%@' for this connection to %@?", &[Arg::Str(name), Arg::Str(remote)])
        }
        None => l10n::tr("Use the shared credential '%@' for this connection?", &[Arg::Str(name)]),
    };
    let message = l10n::tr(
        "The imported file was exported with this shared credential. Its user name and password are sent to the server named in the file. Choose Use Shared Credential only if you trust the file; otherwise the connection uses its own user name and password.",
        &[],
    );
    (title, message)
}

/// The import's question when no credential has the exported name: pick one, or the connection's own fields. As
/// for [`import_question`]: the picked credential's password goes to the file's own server.
pub fn unknown_credential_question(name: &str, remote: Option<&str>) -> (String, String) {
    let message = match remote {
        Some(remote) => l10n::tr(
            "The imported file was exported with this shared credential. The user name and password you choose are sent to %@, the server named in the file. Choose a shared credential only if you trust the file; otherwise the connection uses its own user name and password.",
            &[Arg::Str(remote)],
        ),
        None => l10n::tr(
            "The imported file was exported with this shared credential. The user name and password you choose are sent to the server named in the file. Choose a shared credential only if you trust the file; otherwise the connection uses its own user name and password.",
            &[],
        ),
    };
    (l10n::tr("There is no shared credential named '%@'", &[Arg::Str(name)]), message)
}

/// The report note when no credential has the exported name and there is none to pick from.
pub fn unknown_credential_note(name: &str) -> String {
    l10n::tr(
        "There is no shared credential named '%@'. The connection uses its own user name and password.",
        &[Arg::Str(name)],
    )
}

/// The report note when the exported name could not be checked (a locked vault).
pub fn import_not_checked_note(name: &str, reason: &str) -> String {
    l10n::tr("The shared credential '%@' was not checked: %@", &[Arg::Str(name), Arg::Str(reason)])
}
