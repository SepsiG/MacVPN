//! Publishing team catalogs (spec 7, plan Task 14): the admin keys, the publish itself, team-key rotation, the
//! subscription string and the "published in catalog X (vN)" badge.
//!
//! - **Admin keys:** a primary key signs; a backup key is announced in every catalog as the successor (the header
//!   is covered by the primary's signature). The backup key can be exported to a password-sealed
//!   `.macvpnadminkey` file and, after the file is written and read back (it must open with the password and hold
//!   the same key), removed from this Mac: its public half stays, so it is still announced. Full backups made
//!   before that still hold the backup key's seed. "Switch to the backup key" ([`Publisher::promote_backup_key`]) needs it imported again; the
//!   next catalog is then signed by it and subscribers that saw the announcement follow. A successor is a planned
//!   rotation, not compromise recovery: whoever holds the old primary key can still sign until subscribers apply
//!   a catalog signed by the successor.
//! - **Publish** ([`Publisher::publish`]): needs a primary key. The first publish of a catalog makes its id and its
//!   team key (returned once in [`PublishResult::new_team_key`]); each publish takes the next version, builds the
//!   payload from the selection (`catalog::publish`), seals and signs it, stores the publication with the new
//!   version (and a new or rotated team key) and only then writes the file 0644 (it is meant to be served; it is
//!   encrypted and signed): nothing after the write can make a later publish reuse its version. A failed write puts
//!   the prior record back.
//!   MacVPN uploads nothing.
//! - **Rotate team key:** a new key, published at once as the next version and returned once. Rotating is the
//!   only way to revoke access to a catalog someone already has. It republishes without the wizard's review, so it
//!   is refused ([`PublishError::ReviewFirst`]) while a published item changed since the last publish.
//! - **Subscription string:** only after the master password is checked; the UI copies it without showing it.
//!
//! Secrets: the admin keys, team keys and passwords stay in `Zeroizing` buffers and in the vault; nothing here logs
//! a key, a password, a path's directory or catalog content. The log has events only.

use crate::deps::Clock;
use crate::vault::{UnlockError, VaultLifecycle};
use macvpn_core::catalog::admin_file::{self, AdminKeyFileError};
use macvpn_core::catalog::format::{CatalogError, CatalogHeaderInput, seal_catalog};
use macvpn_core::catalog::keys::{Fingerprint, TeamKey};
use macvpn_core::catalog::payload::InvalidCatalog;
use macvpn_core::catalog::publish::{
    self, BuildError, PublishPreview, changed_since_publish, clean_catalog_name, random_uuid,
};
use macvpn_core::catalog::selection::{InlineSecret, PublishSelection};
use macvpn_core::catalog::source::CatalogSource;
use macvpn_core::catalog::subscription::{SubscriptionString, format_subscription};
use macvpn_core::exporter;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::uuid_string;
use macvpn_core::vault::{AdminKeyRecord, AdminKeyRole, Entropy, KdfParams, PublicationRecord, Vault, VaultError};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The catalog file's mode: readable by everyone (it is served; it is encrypted and signed).
pub const CATALOG_FILE_MODE: u32 = 0o644;

/// One publish from the wizard: a new publication (`catalog_id: None`) or the next version of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishInput {
    pub catalog_id: Option<Uuid>,
    pub name: String,
    pub selection: PublishSelection,
    /// From the save panel (never from the web view).
    pub path: PathBuf,
}

/// What a publish wrote. The team key is there only on the first publish and on a rotation: shown once.
pub struct PublishResult {
    pub catalog_id: Uuid,
    pub version: u64,
    /// The key that signed it.
    pub fingerprint: Fingerprint,
    pub new_team_key: Option<Zeroizing<String>>,
}

impl fmt::Debug for PublishResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishResult")
            .field("catalog_id", &self.catalog_id)
            .field("version", &self.version)
            .field("fingerprint", &self.fingerprint)
            .field("new_team_key", &self.new_team_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Why a publishing action failed. No variant carries a key, a password or a config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    Locked,
    /// The vault refused the change (no value in it).
    Vault,
    /// There is no primary admin key yet.
    NoAdminKey,
    /// There is no backup admin key in the vault.
    NoBackupKey,
    /// An admin key for this role (or this key under the other role) is already stored.
    KeyExists,
    UnknownPublication,
    /// The catalog name breaks the name rule.
    InvalidName,
    /// Nothing to publish.
    Empty,
    /// A system VPN or a team catalog's item.
    NotSelectable(Uuid),
    /// Connections that cannot be published.
    Refused(Vec<(Uuid, InvalidCatalog)>),
    /// Inline key material that was not ticked.
    Unacknowledged(Vec<(Uuid, InlineSecret)>),
    Invalid(InvalidCatalog),
    Catalog(CatalogError),
    /// The file could not be written (the localized message).
    Write(String),
    /// The master password is wrong (or was tried too soon after a wrong one).
    WrongPassword,
    /// The admin key file password breaks the rule (the localized message).
    WeakPassword(String),
    /// A wrong admin key file password or a damaged file.
    CannotOpen,
    /// An admin key file made by a newer MacVPN.
    NewerVersion,
    /// Reading the admin key file failed, or randomness (the message).
    Io(String),
    /// "Rotate team key" republishes without a review: refused while a published item changed since the last
    /// publish (publish it with the review first).
    ReviewFirst,
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            PublishError::Locked => crate::vault_stores::locked_message(),
            PublishError::Vault => l10n::tr("The vault could not save the change.", &[]),
            PublishError::NoAdminKey => l10n::tr("Generate an admin key before publishing.", &[]),
            PublishError::NoBackupKey => l10n::tr("There is no backup admin key on this Mac.", &[]),
            PublishError::KeyExists => l10n::tr("An admin key with this role already exists.", &[]),
            PublishError::UnknownPublication => l10n::tr("This publication no longer exists.", &[]),
            PublishError::InvalidName => {
                l10n::tr("A catalog name must have 1 to 64 characters and no control characters.", &[])
            }
            PublishError::Empty => l10n::tr("Select at least one folder or connection to publish.", &[]),
            PublishError::NotSelectable(_) => {
                l10n::tr("System VPNs and connections of team catalogs cannot be published.", &[])
            }
            PublishError::Refused(list) => {
                l10n::tr("%d connections cannot be published.", &[Arg::Int(list.len() as i64)])
            }
            PublishError::Unacknowledged(_) => {
                l10n::tr("Confirm every key that is published inside a configuration.", &[])
            }
            PublishError::Invalid(e) | PublishError::Catalog(CatalogError::Invalid(e)) => e.to_string(),
            PublishError::Catalog(CatalogError::TooLarge) => l10n::tr("The team catalog file is too large.", &[]),
            PublishError::Catalog(_) => l10n::tr("The team catalog could not be written.", &[]),
            PublishError::Write(message) | PublishError::WeakPassword(message) | PublishError::Io(message) => {
                message.clone()
            }
            PublishError::WrongPassword => l10n::tr("The master password is wrong.", &[]),
            PublishError::CannotOpen => AdminKeyFileError::CannotOpen.to_string(),
            PublishError::NewerVersion => AdminKeyFileError::NewerVersion.to_string(),
            PublishError::ReviewFirst => l10n::tr(
                "The published connections changed since the last publish. Publish the catalog and review the changes first, then rotate the team key.",
                &[],
            ),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for PublishError {}

impl From<VaultError> for PublishError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => PublishError::Locked,
            _ => PublishError::Vault,
        }
    }
}

impl From<BuildError> for PublishError {
    fn from(e: BuildError) -> Self {
        match e {
            BuildError::Empty => PublishError::Empty,
            BuildError::NotSelectable(id) => PublishError::NotSelectable(id),
            BuildError::Refused(list) => PublishError::Refused(list),
            BuildError::Unacknowledged(list) => PublishError::Unacknowledged(list),
            BuildError::Invalid(e) => PublishError::Invalid(e),
            BuildError::Vault(e) => e.into(),
            BuildError::Io(message) => PublishError::Io(message),
        }
    }
}

impl From<AdminKeyFileError> for PublishError {
    fn from(e: AdminKeyFileError) -> Self {
        match e {
            AdminKeyFileError::CannotOpen => PublishError::CannotOpen,
            AdminKeyFileError::NewerVersion => PublishError::NewerVersion,
            AdminKeyFileError::WeakPassword(rule) => PublishError::WeakPassword(rule),
            AdminKeyFileError::TooLarge => PublishError::Io(e.to_string()),
            AdminKeyFileError::Io(message) => PublishError::Io(message),
        }
    }
}

/// A publication in the publisher's list. Never its team key.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationView {
    pub id: String,
    pub name: String,
    pub version: u64,
    /// Unix time (seconds).
    pub last_published: Option<f64>,
    /// The last file's name only.
    pub file_name: Option<String>,
    /// Published items that changed since (or are new in a published folder, or are gone).
    pub changed: usize,
    /// The saved selection ("Publish new version" and "Rotate team key" start from it): ids and field names
    /// only, never a value.
    pub selection: SelectionView,
    /// Its last version announced a successor key that its next version would no longer announce.
    pub successor_dropped: bool,
}

type PublisherKeyOpt = Option<macvpn_core::catalog::keys::PublisherKey>;

/// The successor the next publish announces (the backup key, unless it already signs) and the primary key.
fn successor_keys(v: &Vault) -> Result<(PublisherKeyOpt, PublisherKeyOpt), VaultError> {
    let primary = v.admin_key(AdminKeyRole::Primary)?.map(|k| k.public());
    let successor = v.admin_keys()?.into_iter().find(|k| k.role == AdminKeyRole::Backup).map(|k| k.public);
    Ok((successor.filter(|s| Some(*s) != primary), primary))
}

/// The publication's last version announced a successor that the next version would not announce (a promoted
/// successor signs now: followed, not dropped).
fn drops_successor(p: &PublicationRecord, announced: PublisherKeyOpt, primary: PublisherKeyOpt) -> bool {
    p.announced_successor.is_some_and(|k| Some(k) != announced && Some(k) != primary)
}

/// A publication's saved selection as the publish wizard sends it (`publish_preview`, `publish_catalog`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionView {
    pub folders: Vec<String>,
    pub connections: Vec<String>,
    pub secrets: Vec<SelectedField>,
    pub slots: Vec<String>,
    pub inline_secrets: Vec<SelectedInline>,
}

/// A ticked team secret: the connection and `psk` / `keypass`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedField {
    pub item: String,
    pub field: &'static str,
}

/// A ticked inline key of a config (`InlineSecret::as_str`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedInline {
    pub item: String,
    pub secret: &'static str,
}

impl From<&PublishSelection> for SelectionView {
    fn from(s: &PublishSelection) -> Self {
        let ids = |set: &std::collections::BTreeSet<Uuid>| set.iter().map(uuid_string).collect();
        SelectionView {
            folders: ids(&s.folders),
            connections: ids(&s.connections),
            secrets: s
                .secrets
                .iter()
                .map(|(id, f)| SelectedField { item: uuid_string(id), field: f.raw_value() })
                .collect(),
            slots: ids(&s.slots),
            inline_secrets: s
                .inline_secrets
                .iter()
                .map(|(id, x)| SelectedInline { item: uuid_string(id), secret: x.as_str() })
                .collect(),
        }
    }
}

/// "Published in catalog X (vN)" on a source connection's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedBadge {
    pub catalog_id: String,
    pub name: String,
    pub version: u64,
    /// Changed since that publish.
    pub changed: bool,
}

/// What the publisher works with.
pub struct PublisherDeps {
    pub vault: Arc<VaultLifecycle>,
    /// `SystemEntropy` in the app.
    pub entropy: Arc<dyn Entropy>,
    /// The parameters admin key files are sealed with (raised to at least `KdfParams::DEFAULT` by core).
    pub kdf: KdfParams,
    pub clock: Arc<dyn Clock>,
}

type Logger = Arc<dyn Fn(&str) + Send + Sync>;
type PathHook = Box<dyn Fn(&Path) + Send + Sync>;

pub struct Publisher {
    deps: PublisherDeps,
    /// One publishing action at a time (versions must not race).
    serial: Mutex<()>,
    log: RwLock<Option<Logger>>,
    /// A test hook right before the catalog file is written (after the version is reserved).
    before_write: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// A test hook right after an admin key file is written (before it is read back).
    after_key_write: Mutex<Option<PathHook>>,
}

/// What a publish reads from the vault in one go.
struct Prepared {
    admin: macvpn_core::catalog::keys::AdminKey,
    successor: Option<macvpn_core::catalog::keys::PublisherKey>,
    prior: Option<PublicationRecord>,
    /// The stored team key of an existing publication (not on a rotation).
    team_key: Option<TeamKey>,
    /// On a rotation: the stored team key, put back if the file cannot be written.
    prior_team_key: Option<TeamKey>,
    built: publish::BuiltPayload,
}

impl Publisher {
    pub fn new(deps: PublisherDeps) -> Self {
        Publisher {
            deps,
            serial: Mutex::new(()),
            log: RwLock::new(None),
            before_write: Mutex::new(None),
            after_key_write: Mutex::new(None),
        }
    }

    /// Runs right after an admin key file was written, before it is read back (tests).
    #[cfg(feature = "test-support")]
    pub fn set_after_key_write(&self, f: impl Fn(&Path) + Send + Sync + 'static) {
        *self.after_key_write.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(f));
    }

    /// Runs right before the catalog file is written, after the version was reserved (tests).
    #[cfg(feature = "test-support")]
    pub fn set_before_write(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.before_write.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(f));
    }

    /// The event log sink (the app log). Lines never carry key material, passwords or catalog content.
    pub fn set_logger(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        *self.log.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(f));
    }

    fn log(&self, line: &str) {
        let log = self.log.read().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(log) = log {
            log(&format!("team catalog publishing: {line}"));
        }
    }

    fn serial(&self) -> std::sync::MutexGuard<'_, ()> {
        self.serial.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // MARK: - admin keys

    /// The admin keys, primary first: roles, fingerprints, dates, and whether the backup key is offline.
    pub fn admin_keys(&self) -> Result<Vec<AdminKeyRecord>, VaultError> {
        self.deps.vault.with_read(|v| v.admin_keys())
    }

    /// Generates and stores an admin key; a role already held is [`VaultError::Constraint`].
    pub fn generate_admin_key(&self, role: AdminKeyRole) -> Result<Fingerprint, VaultError> {
        let _serial = self.serial();
        let key = macvpn_core::catalog::keys::AdminKey::generate(self.deps.entropy.as_ref())?;
        let now = self.deps.clock.now();
        self.deps.vault.with(|v| v.save_admin_key(&key, role, now))?;
        self.log(&format!("{} admin key generated", role.as_str()));
        Ok(key.public().fingerprint())
    }

    /// Writes the backup admin key to `path` sealed with `password` (0600). With `remove_after`, the file is read
    /// back and must open with `password` and hold this very key; only then is its seed removed from the vault (its
    /// public half stays and is still announced).
    ///
    /// Note: a full backup made before the key was taken offline still holds its seed; keep such backups as safe
    /// as the key file (or delete them).
    pub fn export_backup_key(
        &self,
        path: &Path,
        password: Zeroizing<String>,
        remove_after: bool,
    ) -> Result<(), PublishError> {
        let _serial = self.serial();
        admin_file::check_admin_key_password(&password)?;
        let (key, created) = self
            .deps
            .vault
            .with_read(|v| {
                let created = v.admin_keys()?.into_iter().find(|k| k.role == AdminKeyRole::Backup && !k.offline);
                Ok(v.admin_key(AdminKeyRole::Backup)?.zip(created.map(|k| k.created)))
            })?
            .ok_or(PublishError::NoBackupKey)?;
        let bytes = admin_file::export_admin_key(
            &key,
            AdminKeyRole::Backup,
            created,
            &password,
            self.deps.kdf,
            self.deps.entropy.as_ref(),
        )?;
        admin_file::write_admin_key_file(path, &bytes).map_err(|e| PublishError::Write(e.to_string()))?;
        self.log("backup admin key exported");
        if remove_after {
            if let Some(hook) = self.after_key_write.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
                hook(path);
            }
            // The only other copy must work before this one goes.
            let verified = admin_file::read_admin_key_file(path)
                .and_then(|written| admin_file::import_admin_key(&written, &password))
                .is_ok_and(|opened| opened.role == AdminKeyRole::Backup && opened.key.public() == key.public());
            if !verified {
                self.log("backup admin key kept: the written file could not be verified");
                return Err(PublishError::Write(l10n::tr(
                    "The admin key file could not be read back. The key was kept on this Mac.",
                    &[],
                )));
            }
            let fingerprint = key.public().fingerprint();
            self.deps.vault.with(|v| v.take_backup_key_offline(&fingerprint))?;
            self.log("backup admin key removed from this Mac");
        }
        Ok(())
    }

    /// Imports an admin key file under the role it was exported with.
    pub fn import_admin_key(&self, path: &Path, password: Zeroizing<String>) -> Result<Fingerprint, PublishError> {
        let _serial = self.serial();
        let bytes = admin_file::read_admin_key_file(path)?;
        let imported = admin_file::import_admin_key(&bytes, &password)?;
        drop(password);
        let fingerprint = imported.key.public().fingerprint();
        self.deps.vault.with(|v| v.save_admin_key(&imported.key, imported.role, imported.created)).map_err(
            |e| match e {
                VaultError::Constraint(_) => PublishError::KeyExists,
                other => other.into(),
            },
        )?;
        self.log(&format!("{} admin key imported", imported.role.as_str()));
        Ok(fingerprint)
    }

    /// "Switch to the backup key": the backup key becomes the primary and the old primary is deleted. The view
    /// then suggests generating a new backup key.
    pub fn promote_backup_key(&self) -> Result<Fingerprint, VaultError> {
        let _serial = self.serial();
        let fingerprint = self.deps.vault.with(|v| {
            v.promote_backup_key()?;
            v.admin_keys()?
                .into_iter()
                .find(|k| k.role == AdminKeyRole::Primary)
                .map(|k| k.fingerprint)
                .ok_or_else(|| VaultError::Constraint("there is no primary admin key".into()))
        })?;
        self.log("backup admin key promoted to primary");
        Ok(fingerprint)
    }

    // MARK: - publish

    /// The wizard's steps 1–3 and the review for `sel`.
    pub fn preview(&self, sel: &PublishSelection) -> Result<PublishPreview, PublishError> {
        let (preview, dropped) = self.deps.vault.with_read(|v| {
            let (announced, primary) = successor_keys(v)?;
            let dropped: Vec<String> = v
                .publications()?
                .into_iter()
                .filter(|p| drops_successor(p, announced, primary))
                .map(|p| p.name)
                .collect();
            Ok((publish::preview(v, sel), dropped))
        })?;
        let mut preview = preview?;
        preview.successor_dropped_in = dropped;
        Ok(preview)
    }

    /// A new publication or the next version of one (see the module docs).
    pub fn publish(&self, input: PublishInput) -> Result<PublishResult, PublishError> {
        let _serial = self.serial();
        let name = clean_catalog_name(&input.name).ok_or(PublishError::InvalidName)?;
        self.publish_locked(input.catalog_id, name, input.selection, &input.path, false)
    }

    /// A new team key, published at once as the next version to `path` (the save panel offers the last path).
    pub fn rotate_team_key(&self, catalog_id: Uuid, path: &Path) -> Result<PublishResult, PublishError> {
        let _serial = self.serial();
        let prior = self.publication(catalog_id)?;
        // The rotation publishes the stored selection as it is now, without the wizard's review: only when nothing
        // changed since the reviewed publish.
        let changed = self.deps.vault.with_read(|v| publish::changed_since_publish(v, &prior))?;
        if !changed.is_empty() {
            return Err(PublishError::ReviewFirst);
        }
        self.publish_locked(Some(catalog_id), prior.name, prior.selection, path, true)
    }

    fn publication(&self, catalog_id: Uuid) -> Result<PublicationRecord, PublishError> {
        self.deps
            .vault
            .with_read(|v| Ok(v.publications()?.into_iter().find(|p| p.catalog_id == catalog_id)))?
            .ok_or(PublishError::UnknownPublication)
    }

    fn prepare(
        &self,
        v: &Vault,
        catalog_id: Option<Uuid>,
        selection: &PublishSelection,
        rotate: bool,
    ) -> Result<Prepared, PublishError> {
        let admin = v.admin_key(AdminKeyRole::Primary)?.ok_or(PublishError::NoAdminKey)?;
        let successor = v.admin_keys()?.into_iter().find(|k| k.role == AdminKeyRole::Backup).map(|k| k.public);
        let prior = match catalog_id {
            None => None,
            Some(id) => Some(
                v.publications()?.into_iter().find(|p| p.catalog_id == id).ok_or(PublishError::UnknownPublication)?,
            ),
        };
        let team_key = match (&prior, rotate) {
            (Some(p), false) => Some(v.publication_team_key(p.catalog_id)?),
            _ => None,
        };
        let prior_team_key = match (&prior, rotate) {
            (Some(p), true) => Some(v.publication_team_key(p.catalog_id)?),
            _ => None,
        };
        let built = publish::build_payload(v, selection, prior.as_ref(), self.deps.entropy.as_ref())?;
        Ok(Prepared { admin, successor, prior, team_key, prior_team_key, built })
    }

    fn publish_locked(
        &self,
        catalog_id: Option<Uuid>,
        name: String,
        selection: PublishSelection,
        path: &Path,
        rotate: bool,
    ) -> Result<PublishResult, PublishError> {
        let prepared = self.deps.vault.with_read(|v| Ok(self.prepare(v, catalog_id, &selection, rotate)))??;
        let Prepared { admin, successor, prior, team_key, prior_team_key, built } = prepared;
        let entropy = self.deps.entropy.as_ref();
        let io = |e: std::io::Error| PublishError::Io(e.to_string());
        let catalog_id = match &prior {
            Some(p) => p.catalog_id,
            None => random_uuid(entropy).map_err(io)?,
        };
        let (team_key, new_key) = match team_key {
            Some(key) => (key, false),
            None => (TeamKey::generate(entropy).map_err(io)?, true),
        };
        let version = prior.as_ref().map_or(1, |p| p.version + 1);
        let now = self.deps.clock.now();
        let fingerprint = admin.public().fingerprint();
        let header = CatalogHeaderInput {
            catalog_id,
            name: name.clone(),
            version,
            created: now,
            successor_key: successor.filter(|s| *s != admin.public()),
        };
        let header_successor = header.successor_key;
        let bytes = seal_catalog(header, &built.payload, &team_key, &admin, entropy).map_err(PublishError::Catalog)?;
        drop(built.payload);
        let record = PublicationRecord {
            catalog_id,
            name,
            version,
            selection,
            secret_ids: built.secret_ids,
            item_hashes: built.item_hashes,
            last_path: Some(path.to_path_buf()),
            last_published: Some(now),
            announced_successor: header_successor,
        };
        // Reserved before the file is written: the version (and a new or rotated team key) is stored first, so
        // nothing after the write can make a later publish reuse this version with other content or another key.
        // A failed write puts the prior record (and team key) back; a gap in the versions is fine.
        self.deps.vault.with(|v| v.save_publication(&record, new_key.then_some(&team_key)))?;
        if let Some(hook) = self.before_write.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            hook();
        }
        if let Err(e) = exporter::write_with_mode(&bytes, path, CATALOG_FILE_MODE) {
            let restored = self.deps.vault.with(|v| match &prior {
                None => v.delete_publication(catalog_id),
                Some(p) => v.save_publication(p, prior_team_key.as_ref()),
            });
            if restored.is_err() {
                self.log(&format!("{} publish failed; the reserved version was kept", uuid_string(&catalog_id)));
            }
            return Err(PublishError::Write(e.message));
        }
        let id = uuid_string(&catalog_id);
        if rotate {
            self.log(&format!("{id} team key rotated"));
        }
        self.log(&format!("{id} published v{version}"));
        Ok(PublishResult { catalog_id, version, fingerprint, new_team_key: new_key.then(|| team_key.to_text()) })
    }

    // MARK: - subscription string, list, badges

    /// The subscription string of a publication (`source` is where subscribers fetch it), only after `master_password`
    /// is checked; no copy is kept. The UI puts it on the clipboard without showing it.
    pub fn subscription_string(
        &self,
        catalog_id: Uuid,
        master_password: Zeroizing<String>,
        source: CatalogSource,
    ) -> Result<Zeroizing<String>, PublishError> {
        self.deps.vault.verify_password(master_password, Instant::now()).map_err(|e| match e {
            UnlockError::Wrong { .. } | UnlockError::TooSoon { .. } => PublishError::WrongPassword,
            other => PublishError::Io(other.to_string()),
        })?;
        let (team_key, fingerprint, version) = self.deps.vault.with_read(|v| {
            let Some(p) = v.publications()?.into_iter().find(|p| p.catalog_id == catalog_id) else {
                return Ok(Err(PublishError::UnknownPublication));
            };
            let Some(admin) = v.admin_keys()?.into_iter().find(|k| k.role == AdminKeyRole::Primary) else {
                return Ok(Err(PublishError::NoAdminKey));
            };
            Ok(Ok((v.publication_team_key(catalog_id)?, admin.fingerprint, p.version)))
        })??;
        let text = format_subscription(&SubscriptionString {
            source,
            team_key,
            fingerprint,
            catalog_id: Some(catalog_id),
            min_version: Some(version),
        });
        self.log(&format!("{} subscription string copied", uuid_string(&catalog_id)));
        Ok(text)
    }

    /// Forgets a publication (the published file stays where it is).
    pub fn forget(&self, catalog_id: Uuid) -> Result<(), VaultError> {
        let _serial = self.serial();
        self.deps.vault.with(|v| v.delete_publication(catalog_id))?;
        self.log(&format!("{} publication forgotten", uuid_string(&catalog_id)));
        Ok(())
    }

    /// The publications with their change counts, sorted by name.
    pub fn publications(&self) -> Result<Vec<PublicationView>, VaultError> {
        self.deps.vault.with_read(|v| {
            let (announced, primary) = successor_keys(v)?;
            v.publications()?
                .into_iter()
                .map(|p| {
                    Ok(PublicationView {
                        successor_dropped: drops_successor(&p, announced, primary),
                        id: uuid_string(&p.catalog_id),
                        changed: changed_since_publish(v, &p)?.len(),
                        selection: SelectionView::from(&p.selection),
                        name: p.name,
                        version: p.version,
                        last_published: p.last_published.map(|d| d.time_interval_since_1970()),
                        file_name: p
                            .last_path
                            .as_deref()
                            .and_then(Path::file_name)
                            .map(|n| n.to_string_lossy().into_owned()),
                    })
                })
                .collect()
        })
    }

    /// The badges of the published source connections, by connection id string.
    pub fn published_badges(&self) -> Result<HashMap<String, Vec<PublishedBadge>>, VaultError> {
        self.deps.vault.with_read(|v| {
            let mut out: HashMap<String, Vec<PublishedBadge>> = HashMap::new();
            let connections: std::collections::HashSet<Uuid> =
                v.connections()?.into_iter().map(|c| c.connection.id).collect();
            for p in v.publications()? {
                let changed = changed_since_publish(v, &p)?;
                for id in p.item_hashes.keys().filter(|id| connections.contains(id)) {
                    out.entry(uuid_string(id)).or_default().push(PublishedBadge {
                        catalog_id: uuid_string(&p.catalog_id),
                        name: p.name.clone(),
                        version: p.version,
                        changed: changed.contains(id),
                    });
                }
            }
            Ok(out)
        })
    }
}
