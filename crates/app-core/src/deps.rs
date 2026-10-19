//! The connection manager's dependencies, behind traits so the state machine is testable without the system
//! (and without macOS: the implementations over `macvpn-platform-mac` live in the app crate).
//!
//! Errors cross these traits as the user-facing (localized) message, the Swift `error.localizedDescription`.

use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthResponseKind, AuthUIState};
use macvpn_core::models::{Connection, ConnectionState, OTPSetting, Secrets, VPNKind, parse_uuid};
use macvpn_core::native::NativeKind;
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore};
use macvpn_core::status::RootStatus;
use macvpn_core::store::ConnectionStore;
use macvpn_core::system_otp::SystemOTPStore;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use uuid::Uuid;

/// The root helper (`sudo -n mvpn …`), the Swift `MvpnClient`.
pub trait RootClient: Send + Sync {
    fn status(&self) -> Result<Vec<RootStatus>, String>;
    /// `accept_risky`: the acknowledged risky OpenVPN directives (`--accept-risky`).
    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String>;
    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String>;
    /// `mvpn respond openvpn <id>` (MFA answer to the management bridge).
    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String>;
}

/// A VPN service listed by `scutil --nc list` (the Swift `SystemVPNService`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemService {
    /// The scutil service ID.
    pub id: String,
    pub name: String,
    /// `L2TP`, `Cisco IPsec`, `IKEv2`, `WireGuard (app)`, `OpenVPN (app)` or `VPN`.
    pub type_label: String,
    /// `Connected`, `Connecting`, `Disconnecting`, `Disconnected`, …
    pub status: String,
}

impl SystemService {
    pub fn new(id: &str, name: &str, type_label: &str, status: &str) -> Self {
        SystemService { id: id.into(), name: name.into(), type_label: type_label.into(), status: status.into() }
    }

    /// The MacVPN keychain key for this service's PSK / password (scutil IDs are UUIDs; `None` if not).
    pub fn secret_id(&self) -> Option<Uuid> {
        parse_uuid(&self.id)
    }

    /// The PSK / password can be stored in MacVPN and passed when starting (L2TP and Cisco IPsec only).
    pub fn supports_stored_secrets(&self) -> bool {
        self.secret_id().is_some() && NativeKind::from_type_label(&self.type_label).is_some()
    }

    pub fn connection_state(&self) -> ConnectionState {
        match self.status.as_str() {
            "Connected" => ConnectionState::Connected { ip: None, since: None },
            "Connecting" => ConnectionState::Connecting,
            "Disconnecting" => ConnectionState::Disconnecting,
            _ => ConnectionState::Disconnected,
        }
    }
}

/// The native VPN services (scutil listing + in-process `SCNetworkConnection`), the Swift `NativeVPNController`.
pub trait NativeController: Send + Sync {
    fn list(&self) -> Result<Vec<SystemService>, String>;
    /// The service's server address (`scutil --nc show`); `None` if it cannot be read.
    fn remote_address(&self, service_id: &str) -> Option<String>;
    /// `kind` `None` or no secrets: started with the stored configuration only.
    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String>;
    fn stop(&self, service_id: &str) -> Result<(), String>;
}

/// The connection store (`connections/<UUID>/{meta.json,config}`).
pub trait ConnectionRepository: Send + Sync {
    fn list(&self) -> io::Result<Vec<Connection>>;
    /// `config` `None`: only `meta.json` is written.
    fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()>;
    fn load_config(&self, id: &Uuid) -> io::Result<String>;
    /// Deletes the connection's directory (`meta.json`, `config`).
    fn delete(&self, id: &Uuid) -> io::Result<()>;
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

/// The secret fields the manager reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretField {
    Username,
    Password,
    Psk,
    KeyPassword,
}

/// Read access to the Keychain items (`local.macvpn.secrets`, account `<UUID>.<field>`).
pub trait SecretReader: Send + Sync {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String>;

    fn secrets(&self, id: &Uuid) -> Secrets {
        Secrets {
            username: self.get(id, SecretField::Username),
            password: self.get(id, SecretField::Password),
            psk: self.get(id, SecretField::Psk),
            key_password: self.get(id, SecretField::KeyPassword),
            ..Secrets::default()
        }
    }
}

/// Write access to the Keychain items (the editors' save and forget, import, delete).
pub trait SecretWriter: Send + Sync {
    /// An empty value deletes the item.
    fn set(&self, value: &str, id: &Uuid, field: SecretField);
    fn delete_all(&self, id: &Uuid);
    /// Every MacVPN item (uninstall with the user data; leftovers of deleted connections too).
    fn remove_all(&self);
}

/// Installs a generated native (L2TP / Cisco) profile: staged in a private temp directory, opened for the user
/// to approve, and deleted once the service is listed (the Swift `NativeProfileStaging` + `StagedProfiles`).
pub trait ProfileInstaller: Send + Sync {
    /// `service_existed`: the connection's service was already installed (a re-saved profile).
    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String>;
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

/// The management bridge's UI state file (`/var/run/macvpn-ui/<id>.json`), read safely.
pub trait AuthStateReader: Send + Sync {
    fn read(&self, id: &Uuid) -> Option<AuthUIState>;
}

/// No state file is ever present (no root layer, tests).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuthState;

impl AuthStateReader for NoAuthState {
    fn read(&self, _id: &Uuid) -> Option<AuthUIState> {
        None
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
