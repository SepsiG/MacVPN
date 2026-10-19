//! Vault-backed implementations of the store traits in [`crate::deps`] and of the control API's
//! [`RegistryStore`] (plan B Task 11): every store the app uses reads and writes the vault.
//!
//! - [`VaultConnections`] (`ConnectionRepository`): locked → an `io::Error` of kind `PermissionDenied` with the text
//!   "The vault is locked. Unlock it and try again." ([`locked_message`]).
//! - [`VaultSecrets`] (`SecretReader` + `SecretWriter`), added with the shared credentials (Task 18): it resolves
//!   credential links, so the manager's `secrets()` (the root layer's stdin, the native start options) gets a linked
//!   item's username and password from its credential and the item's own PSK and key password. Writes are split:
//!   the credential prompt's "Save" and re-prompt (`SecretWriter::save_prompted`) update the shared credential,
//!   while the editors' `SecretWriter::set` refuses a linked item's username and password
//!   (`Vault::set_item_secret`). Locked: reads give `None`, writes are dropped with a log line (the traits have no
//!   error).
//! - [`VaultRanking`] (`RankingPersistence`) and [`VaultSystemOtp`] (`SystemOTPPersistence`): locked, a load is
//!   empty and a save fails.
//! - [`VaultRegistry`] (`RegistryStore`): locked, a load **fails** (an empty registry would be saved over the real
//!   one at the next change and unpair every client).
//!
//! **Legacy read-only mode** (Task 13): while the lifecycle is [`VaultState::LegacyReadOnly`] (the create window
//! runs in migration mode, or the migration failed), each store with a legacy fallback reads the 1.1 storage and
//! refuses every write with "MacVPN is using the old storage in read-only mode until the migration succeeds"
//! ([`read_only_message`]). The fallbacks are the 1.1 stores wrapped in [`ReadOnly`].
//!
//! Nothing here logs a value.

use crate::control::RegistryStore;
use crate::deps::{
    ConnectionRepository, RankingPersistence, SecretField, SecretReader, SecretWriter, SystemOTPPersistence,
};
use crate::vault::{VaultLifecycle, VaultState};
use macvpn_core::control::registry::Registry;
use macvpn_core::l10n;
use macvpn_core::models::{Connection, CredentialRef, OTPSetting, uuid_string};
use macvpn_core::ranking::ConnectionRanking;
use macvpn_core::vault::{Vault, VaultError};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use uuid::Uuid;

/// "The vault is locked. Unlock it and try again.": every refusal while locked (stores, editors, import, export).
pub fn locked_message() -> String {
    l10n::tr("The vault is locked. Unlock it and try again.", &[])
}

/// The refusal of a write in the legacy read-only mode.
pub fn read_only_message() -> String {
    l10n::tr("MacVPN is using the old storage in read-only mode until the migration succeeds", &[])
}

fn read_only_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, read_only_message())
}

/// A vault error as the store traits' `io::Error`: locked is `PermissionDenied` with [`locked_message`]; nothing
/// else carries more than the error's own text (which never holds a value).
pub fn vault_io_error(e: VaultError) -> io::Error {
    match e {
        VaultError::Locked => io::Error::new(io::ErrorKind::PermissionDenied, locked_message()),
        VaultError::ReadOnly => read_only_error(),
        VaultError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// Whether the lifecycle runs from the 1.1 storage (read-only).
fn legacy_mode(vault: &VaultLifecycle) -> bool {
    matches!(vault.state(), VaultState::LegacyReadOnly { .. })
}

// MARK: - Read-only wrappers (legacy mode)

/// A 1.1 store in the legacy read-only mode: reads pass through, every write is refused with
/// [`read_only_message`] (or, for the secret writer, which has no error, dropped with a log line).
pub struct ReadOnly<T: ?Sized>(pub Arc<T>);

impl<T: ConnectionRepository + ?Sized> ConnectionRepository for ReadOnly<T> {
    fn list(&self) -> io::Result<Vec<Connection>> {
        self.0.list()
    }

    fn save(&self, _connection: &Connection, _config: Option<&str>) -> io::Result<()> {
        Err(read_only_error())
    }

    fn load_config(&self, id: &Uuid) -> io::Result<String> {
        self.0.load_config(id)
    }

    fn delete(&self, _id: &Uuid) -> io::Result<()> {
        Err(read_only_error())
    }
}

impl<T: SecretReader + ?Sized> SecretReader for ReadOnly<T> {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.get(id, field)
    }
}

impl<T: RankingPersistence + ?Sized> RankingPersistence for ReadOnly<T> {
    fn load(&self) -> ConnectionRanking {
        self.0.load()
    }

    fn save(&self, _ranking: &ConnectionRanking) -> io::Result<()> {
        Err(read_only_error())
    }
}

impl<T: SystemOTPPersistence + ?Sized> SystemOTPPersistence for ReadOnly<T> {
    fn load(&self) -> HashMap<String, OTPSetting> {
        self.0.load()
    }

    fn save(&self, _map: &HashMap<String, OTPSetting>) -> io::Result<()> {
        Err(read_only_error())
    }
}

impl<T: RegistryStore + ?Sized> RegistryStore for ReadOnly<T> {
    fn load(&self) -> io::Result<Registry> {
        self.0.load()
    }

    fn save(&self, _registry: &Registry) -> io::Result<()> {
        Err(read_only_error())
    }
}

// MARK: - Connections

/// The `connections` table (meta and config).
pub struct VaultConnections {
    vault: Arc<VaultLifecycle>,
    legacy: Option<Arc<dyn ConnectionRepository>>,
}

impl VaultConnections {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultConnections { vault, legacy: None }
    }

    /// Reads from `legacy` (a [`ReadOnly`] 1.1 store) in the legacy read-only mode.
    pub fn with_legacy(mut self, legacy: Arc<dyn ConnectionRepository>) -> Self {
        self.legacy = Some(legacy);
        self
    }

    fn legacy(&self) -> Option<&Arc<dyn ConnectionRepository>> {
        self.legacy.as_ref().filter(|_| legacy_mode(&self.vault))
    }
}

impl ConnectionRepository for VaultConnections {
    fn list(&self) -> io::Result<Vec<Connection>> {
        if let Some(legacy) = self.legacy() {
            return legacy.list();
        }
        self.vault
            .with_read(|v| Ok(v.connections()?.into_iter().map(|s| s.connection).collect()))
            .map_err(vault_io_error)
    }

    fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()> {
        if legacy_mode(&self.vault) {
            return Err(read_only_error());
        }
        self.vault.with(|v| v.save_connection(connection, config)).map_err(vault_io_error)
    }

    fn load_config(&self, id: &Uuid) -> io::Result<String> {
        if let Some(legacy) = self.legacy() {
            return legacy.load_config(id);
        }
        self.vault.with_read(|v| v.config(id)).map(|config| config.as_str().to_owned()).map_err(vault_io_error)
    }

    fn delete(&self, id: &Uuid) -> io::Result<()> {
        if legacy_mode(&self.vault) {
            return Err(read_only_error());
        }
        self.vault.with(|v| v.delete_connection(id)).map_err(vault_io_error)
    }
}

// MARK: - Ranking, system OTP, paired clients

/// The `ranking` and `pins` tables (`connection-order.json` before 1.2).
pub struct VaultRanking {
    vault: Arc<VaultLifecycle>,
    legacy: Option<Arc<dyn RankingPersistence>>,
}

impl VaultRanking {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultRanking { vault, legacy: None }
    }

    pub fn with_legacy(mut self, legacy: Arc<dyn RankingPersistence>) -> Self {
        self.legacy = Some(legacy);
        self
    }
}

impl RankingPersistence for VaultRanking {
    /// Locked (or unreadable): no pins and no scores.
    fn load(&self) -> ConnectionRanking {
        if let Some(legacy) = self.legacy.as_ref().filter(|_| legacy_mode(&self.vault)) {
            return legacy.load();
        }
        self.vault.with_read(Vault::ranking).unwrap_or_default()
    }

    fn save(&self, ranking: &ConnectionRanking) -> io::Result<()> {
        if legacy_mode(&self.vault) {
            return Err(read_only_error());
        }
        self.vault.with(|v| v.save_ranking(ranking)).map_err(vault_io_error)
    }
}

/// The `system_otp` table (`system-otp.json` before 1.2).
pub struct VaultSystemOtp {
    vault: Arc<VaultLifecycle>,
    legacy: Option<Arc<dyn SystemOTPPersistence>>,
}

impl VaultSystemOtp {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultSystemOtp { vault, legacy: None }
    }

    pub fn with_legacy(mut self, legacy: Arc<dyn SystemOTPPersistence>) -> Self {
        self.legacy = Some(legacy);
        self
    }
}

impl SystemOTPPersistence for VaultSystemOtp {
    /// Locked (or unreadable): none.
    fn load(&self) -> HashMap<String, OTPSetting> {
        if let Some(legacy) = self.legacy.as_ref().filter(|_| legacy_mode(&self.vault)) {
            return legacy.load();
        }
        self.vault.with_read(Vault::system_otp_map).unwrap_or_default()
    }

    fn save(&self, map: &HashMap<String, OTPSetting>) -> io::Result<()> {
        if legacy_mode(&self.vault) {
            return Err(read_only_error());
        }
        self.vault.with(|v| v.save_system_otp_map(map)).map_err(vault_io_error)
    }
}

/// The `control_clients` table (`control-clients.json` before 1.2): the control API's paired clients.
pub struct VaultRegistry {
    vault: Arc<VaultLifecycle>,
    legacy: Option<Arc<dyn RegistryStore>>,
}

impl VaultRegistry {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultRegistry { vault, legacy: None }
    }

    pub fn with_legacy(mut self, legacy: Arc<dyn RegistryStore>) -> Self {
        self.legacy = Some(legacy);
        self
    }
}

impl RegistryStore for VaultRegistry {
    /// Locked: an error, never an empty registry. A client row that does not decode is an error too.
    fn load(&self) -> io::Result<Registry> {
        if let Some(legacy) = self.legacy.as_ref().filter(|_| legacy_mode(&self.vault)) {
            return legacy.load();
        }
        let values = self.vault.with_read(Vault::control_clients).map_err(vault_io_error)?;
        Registry::from_client_values(&values)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a paired client in the vault cannot be read"))
    }

    fn save(&self, registry: &Registry) -> io::Result<()> {
        if legacy_mode(&self.vault) {
            return Err(read_only_error());
        }
        let values = registry.client_values();
        self.vault.with(|v| v.save_control_clients(&values)).map_err(vault_io_error)
    }
}

// MARK: - Secrets

/// The secrets in the vault's `secrets` table, with shared-credential links resolved. Item keys are the
/// upper-case UUID strings (a managed connection's id or a system VPN's service ID), like the Keychain accounts
/// before 1.2.
pub struct VaultSecrets {
    vault: Arc<VaultLifecycle>,
    legacy: Option<Arc<dyn SecretReader>>,
}

impl VaultSecrets {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultSecrets { vault, legacy: None }
    }

    /// Reads from `legacy` (the 1.1 Keychain) in the legacy read-only mode; writes are dropped then.
    pub fn with_legacy(mut self, legacy: Arc<dyn SecretReader>) -> Self {
        self.legacy = Some(legacy);
        self
    }

    fn legacy(&self) -> Option<&Arc<dyn SecretReader>> {
        self.legacy.as_ref().filter(|_| legacy_mode(&self.vault))
    }

    /// A write that failed: logged by kind only, never with a value.
    fn write(&self, what: &str, f: impl FnOnce(&mut Vault) -> Result<(), VaultError>) {
        if legacy_mode(&self.vault) {
            self.vault.log(&format!("{what} not saved: the old storage is read-only until the migration succeeds"));
            return;
        }
        if let Err(e) = self.vault.with(f) {
            let reason = match e {
                VaultError::Locked => "the vault is locked".to_string(),
                VaultError::NewerSchema { .. } => "the vault was saved by a newer MacVPN".to_string(),
                VaultError::Constraint(_) => "the value was refused".to_string(),
                VaultError::LinkedToCredential => "the item uses a shared credential".to_string(),
                _ => "vault error".to_string(),
            };
            self.vault.log(&format!("{what} not saved: {reason}"));
        }
    }
}

impl SecretReader for VaultSecrets {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        if let Some(legacy) = self.legacy() {
            return legacy.get(id, field);
        }
        let item = uuid_string(id);
        self.vault.with_read(|v| v.resolved_secret(&item, field)).ok().flatten().map(|value| value.as_str().to_owned())
    }

    fn credential_for(&self, id: &Uuid) -> Option<CredentialRef> {
        if legacy_mode(&self.vault) {
            return None;
        }
        let item = uuid_string(id);
        self.vault
            .with_read(|v| {
                let Some(credential) = v.credential_of(&item)? else { return Ok(None) };
                let Some(found) = v.credential(credential)? else { return Ok(None) };
                let used_by = v.linked_items(credential)?.len();
                Ok(Some(CredentialRef { name: found.name, used_by }))
            })
            .ok()
            .flatten()
    }
}

impl SecretWriter for VaultSecrets {
    /// The item's own value, where an empty value deletes. A non-empty username or password of a linked item is
    /// refused (`VaultError::LinkedToCredential`, logged without the value) and nothing changes.
    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        let item = uuid_string(id);
        self.write("a secret was", |v| v.set_item_secret(&item, field, value));
    }

    /// A linked item's username or password goes to its credential (an empty value is ignored there); every
    /// other field is the item's own, as [`Self::set`].
    fn save_prompted(&self, value: &str, id: &Uuid, field: SecretField) {
        let item = uuid_string(id);
        self.write("a secret was", |v| v.save_prompted_secret(&item, field, value));
    }

    /// The item's own secrets and its credential link (the credential stays).
    fn delete_all(&self, id: &Uuid) {
        let item = uuid_string(id);
        self.write("the deletion of the secrets was", |v| v.forget_item(&item));
    }

    /// Every secret, link and shared credential.
    fn remove_all(&self) {
        self.write("the deletion of all secrets was", |v| v.delete_all_secrets_and_credentials());
    }
}
