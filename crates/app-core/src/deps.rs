//! The connection manager's dependencies, behind traits so the state machine is testable without the system
//! (and without macOS: the implementations over `macvpn-platform-mac` live in the app crate).
//!
//! Errors cross these traits as the user-facing (localized) message, the Swift `error.localizedDescription`.

use macvpn_core::date::Date;
use macvpn_core::models::{Connection, CredentialRef, OTPSetting, Secrets};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore};
use macvpn_core::store::ConnectionStore;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::vault::{DeleteMode, FolderColor, FolderNode, SystemItem};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The privileged helper, the system VPNs, the native profiles and the helper's UI state files: platform traits,
/// defined in `macvpn-platform-api` and re-exported here (their old home).
pub use macvpn_platform_api::{
    AuthStateReader, HelperClient, LegacySecrets, NativeController, NativeProfile, NativeProfiles, NativeSupport,
    NoAuthState, NoNativeSupport, SystemVpn,
};

/// The connection store (`connections/<UUID>/{meta.json,config}`).
pub trait ConnectionRepository: Send + Sync {
    fn list(&self) -> io::Result<Vec<Connection>>;
    /// `config` `None`: only `meta.json` is written.
    fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()>;
    fn load_config(&self, id: &Uuid) -> io::Result<String>;
    /// [`Self::load_config`], wiped when dropped: for reads whose text is only parsed (the search's server host).
    /// A store that holds the config wiped already (the vault) returns it without an unwiped copy.
    fn load_config_wiped(&self, id: &Uuid) -> io::Result<Zeroizing<String>> {
        self.load_config(id).map(Zeroizing::new)
    }
    /// Deletes the connection's directory (`meta.json`, `config`).
    fn delete(&self, id: &Uuid) -> io::Result<()>;

    /// The team catalog that manages the connection (team catalog spec 6): its config, name, folder and colour are
    /// read-only here. `None`: the user's own connection (and every store without team catalogs).
    fn team_managed(&self, _id: &Uuid) -> Option<TeamManaged> {
        None
    }

    /// Stores only the acknowledged risky directives of a connection (sorted, without duplicates). The one write
    /// a catalog connection's read-only editor makes (the acknowledgement is the subscriber's own). `seen_config`:
    /// the config the user reviewed; a different stored config (a team catalog changed it meanwhile) is refused
    /// with [`catalog_changed_message`].
    fn set_acknowledged_risky(&self, id: &Uuid, seen_config: &str, directives: &[String]) -> io::Result<()> {
        if self.load_config(id)? != seen_config {
            return Err(io::Error::other(catalog_changed_message()));
        }
        let mut c = self
            .list()?
            .into_iter()
            .find(|c| c.id == *id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        let mut sorted = directives.to_vec();
        sorted.sort();
        sorted.dedup();
        c.acknowledged_risky_directives = sorted;
        self.save(&c, None)
    }

    /// Stores only the native service binding of a native connection (`None`: unbound). Also for a team catalog's
    /// connection, whose other metadata is read-only (the binding is this Mac's own).
    fn set_native_service(&self, id: &Uuid, service_id: Option<&str>) -> io::Result<()> {
        let mut c = self
            .list()?
            .into_iter()
            .find(|c| c.id == *id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such connection"))?;
        c.native_service_id = service_id.map(str::to_string);
        self.save(&c, None)
    }

    /// A team catalog connection's native profile, built from the version with config hash `built_from`
    /// ([`TeamManaged::config_hash`]), shows as installed: clears [`TeamManaged::profile_outdated`] unless the
    /// catalog changed the connection again meanwhile (`Ok(false)`: the mark stays).
    fn profile_reinstalled(&self, _id: &Uuid, _built_from: &str) -> io::Result<bool> {
        Ok(true)
    }
}

/// "The team catalog changed this connection; review it again": an editor saved what the user saw of an older
/// version of a catalog connection.
pub fn catalog_changed_message() -> String {
    macvpn_core::l10n::tr("The team catalog changed this connection; review it again", &[])
}

/// A connection a team catalog manages ([`ConnectionRepository::team_managed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamManaged {
    /// The catalog's name ("Managed by the team catalog “Acme VPN”").
    pub catalog: String,
    /// The catalog changed this native connection's settings: its profile needs a reinstall before the next
    /// connect.
    pub profile_outdated: bool,
    /// The applied version's config hash: what a native profile is built from (compare-and-clear of the mark).
    pub config_hash: Option<String>,
}

impl ConnectionRepository for ConnectionStore {
    fn list(&self) -> io::Result<Vec<Connection>> {
        ConnectionStore::list(self)
    }

    fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()> {
        ConnectionStore::save(self, connection, config)
    }

    fn load_config(&self, id: &Uuid) -> io::Result<String> {
        ConnectionStore::load_config(self, id)
    }

    fn delete(&self, id: &Uuid) -> io::Result<()> {
        ConnectionStore::delete(self, id)
    }
}

/// A team catalog source (plan Tasks 9 and 10): `macvpn-platform-mac`'s `CurlCatalogFetcher` for an HTTPS URL,
/// [`crate::catalog_file::FileCatalogFetcher`] for a file path. Defined in core, because the platform layer does not
/// depend on this crate.
pub use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};

/// The secret fields the manager reads (defined in core, next to the vault's `secrets` table).
pub use macvpn_core::models::SecretField;

/// Read access to the secrets (the vault's `secrets` table; before 1.2 the Keychain items `local.macvpn.secrets`,
/// account `<UUID>.<field>`). A vault-backed reader resolves shared-credential links: a linked item's username
/// and password are the credential's.
pub trait SecretReader: Send + Sync {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String>;

    fn secrets(&self, id: &Uuid) -> Secrets {
        Secrets {
            username: self.get(id, SecretField::Username),
            password: self.get(id, SecretField::Password),
            psk: self.get(id, SecretField::Psk),
            key_password: self.get(id, SecretField::KeyPassword),
            client_cert: self.get(id, SecretField::ClientCert),
            ..Secrets::default()
        }
    }

    /// The shared credential the item's username and password come from (spec 3a), for the credential prompt's
    /// "Password for <name> — used by N connections". `None`: the item uses its own fields (and every store
    /// without shared credentials).
    fn credential_for(&self, _id: &Uuid) -> Option<CredentialRef> {
        None
    }
}

/// The 1.1 secrets as a [`SecretReader`] (the legacy read-only mode): reads exactly what the platform's
/// [`LegacySecrets`] gives.
pub struct LegacySecretReader(pub Arc<dyn LegacySecrets>);

impl SecretReader for LegacySecretReader {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.get(id, field)
    }
}

/// Write access to the Keychain items (the editors' save and forget, import, delete).
pub trait SecretWriter: Send + Sync {
    /// The editors' and the import's write: the item's own value; an empty value deletes the item. A vault-backed
    /// writer refuses (drops, with a log line) a non-empty username or password of an item linked to a shared
    /// credential, so editing one connection never changes the credential every linked connection uses; a linked
    /// editor sends `None` for those fields (Task 19), and the editor save handlers refuse them with a message.
    fn set(&self, value: &str, id: &Uuid, field: SecretField);
    /// The credential prompt's "Save" and the sign-in failure re-prompt only: a linked item's username or
    /// password goes to its shared credential (spec 3a). Without shared credentials this is [`Self::set`].
    fn save_prompted(&self, value: &str, id: &Uuid, field: SecretField) {
        self.set(value, id, field);
    }
    fn delete_all(&self, id: &Uuid);
    /// Every MacVPN item (uninstall with the user data; leftovers of deleted connections too).
    fn remove_all(&self);
}

/// Where an item (a managed connection or a system VPN, by its ranking key) sits in the folder tree, and its own
/// colour (`None`: the folder's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub key: String,
    pub folder: Option<Uuid>,
    pub color: Option<FolderColor>,
}

/// One change of the system-VPN placement retention (spec 5): a placed service macOS no longer lists keeps its
/// folder and colour for [`crate::folders::SYSTEM_ITEM_RETENTION_DAYS`] days.
#[derive(Debug, Clone, PartialEq)]
pub enum SystemItemChange {
    /// Not listed any more: `missing_since` is set to this date.
    MarkMissing { service_id: String, since: Date },
    /// Listed again: `missing_since` is cleared.
    Clear { service_id: String },
    /// Missing for longer than the retention: the placement is deleted.
    Remove { service_id: String },
}

/// One folder edit (spec 3). Names are validated by the store (`validate_folder_name`), moves by the tree's cycle
/// check.
#[derive(Debug, Clone, PartialEq)]
pub enum FolderOp {
    /// A new folder at the end of `parent` (`None`: the root).
    Create {
        parent: Option<Uuid>,
        name: String,
    },
    Rename {
        id: Uuid,
        name: String,
    },
    /// `None` clears the folder's own colour (it inherits again).
    SetColor {
        id: Uuid,
        color: Option<FolderColor>,
    },
    /// The menu's persisted collapsed state.
    SetCollapsed {
        id: Uuid,
        collapsed: bool,
    },
    /// Under `parent` at `position` among its subfolders (also a reorder in the same parent).
    Move {
        id: Uuid,
        parent: Option<Uuid>,
        position: usize,
    },
    Delete {
        id: Uuid,
        mode: DeleteMode,
    },
    /// An item into a folder (`None`: the root).
    MoveItem {
        key: String,
        folder: Option<Uuid>,
    },
    /// An item's own colour (`None`: "Use folder colour").
    SetItemColor {
        key: String,
        color: Option<FolderColor>,
    },
    /// The system-VPN placement retention.
    Retention(Vec<SystemItemChange>),
}

/// What a [`FolderOp`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderOpResult {
    Done,
    /// [`FolderOp::Create`]: the new folder.
    Created(Uuid),
    /// [`FolderOp::Delete`] with [`DeleteMode::DeleteContents`]: the keys of the managed connections of the deleted
    /// subtree, which the app deletes through its normal path (profiles, secrets). System VPNs are never in it:
    /// the store moved them to the root.
    Deleted(Vec<String>),
}

/// The folders and the placements (the vault's `folders` table and the `folder_id` / `color` columns; spec 3).
/// Errors carry the user-facing (localized) message.
pub trait FolderStore: Send + Sync {
    fn folders(&self) -> io::Result<Vec<FolderNode>>;
    /// Managed connections and system VPNs, every one with a folder or a colour (others are at the root).
    fn placements(&self) -> io::Result<Vec<Placement>>;
    /// The stored system-VPN placements (for the retention).
    fn system_items(&self) -> io::Result<Vec<SystemItem>>;
    fn apply(&self, op: FolderOp) -> io::Result<FolderOpResult>;
}

/// `connection-order.json`.
pub trait RankingPersistence: Send + Sync {
    fn load(&self) -> ConnectionRanking;
    fn save(&self, ranking: &ConnectionRanking) -> io::Result<()>;
}

impl RankingPersistence for ConnectionRankingStore {
    fn load(&self) -> ConnectionRanking {
        ConnectionRankingStore::load(self)
    }

    fn save(&self, ranking: &ConnectionRanking) -> io::Result<()> {
        ConnectionRankingStore::save(self, ranking)
    }
}

/// `system-otp.json` (the system VPNs' "code after the password" setting, by service ID).
pub trait SystemOTPPersistence: Send + Sync {
    fn load(&self) -> HashMap<String, OTPSetting>;
    fn save(&self, map: &HashMap<String, OTPSetting>) -> io::Result<()>;
}

impl SystemOTPPersistence for SystemOTPStore {
    fn load(&self) -> HashMap<String, OTPSetting> {
        SystemOTPStore::load(self)
    }

    fn save(&self, map: &HashMap<String, OTPSetting>) -> io::Result<()> {
        SystemOTPStore::save(self, map)
    }
}

/// The wall clock (Swift `Date()`), injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Date;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Date {
        Date::now()
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock(Mutex<Date>);

impl ManualClock {
    pub fn new(now: Date) -> Self {
        ManualClock(Mutex::new(now))
    }

    pub fn set(&self, now: Date) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }

    pub fn advance(&self, seconds: f64) {
        let mut d = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *d = d.adding(seconds);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Date {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}
