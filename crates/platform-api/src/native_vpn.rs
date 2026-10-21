//! The VPNs the operating system manages and their native profiles.

use macvpn_core::models::{Connection, ConnectionState, Secrets, parse_uuid};
use macvpn_core::native::NativeKind;
use std::collections::HashSet;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A VPN the operating system manages (on macOS a service listed by `scutil --nc list`; the Swift
/// `SystemVPNService`). Every platform produces the same labels, because the manager and the UI match on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemVpn {
    /// The system's ID of the VPN (on macOS the scutil service ID).
    pub id: String,
    pub name: String,
    /// One of `L2TP`, `Cisco IPsec`, `IKEv2`, `WireGuard (app)`, `OpenVPN (app)` or `VPN` (anything else).
    pub type_label: String,
    /// One of `Connected`, `Connecting`, `Disconnecting` or `Disconnected` (anything else counts as disconnected).
    pub status: String,
}

impl SystemVpn {
    pub fn new(id: &str, name: &str, type_label: &str, status: &str) -> Self {
        SystemVpn { id: id.into(), name: name.into(), type_label: type_label.into(), status: status.into() }
    }

    /// The MacVPN secret-store key for this VPN's PSK / password (scutil IDs are UUIDs; `None` if not).
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
    fn list(&self) -> Result<Vec<SystemVpn>, String>;
    /// The service's server address (`scutil --nc show`); `None` if it cannot be read.
    fn remote_address(&self, service_id: &str) -> Option<String>;
    /// `kind` `None` or no secrets: started with the stored configuration only.
    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String>;
    fn stop(&self, service_id: &str) -> Result<(), String>;
}

/// A native connection's profile in the platform's format, ready for [`NativeProfiles::install`].
pub struct NativeProfile {
    /// The profile's bytes (they can contain the PSK: wiped when dropped).
    pub data: Zeroizing<Vec<u8>>,
    /// The file name the profile is staged under.
    pub file_name: String,
}

/// The native (L2TP / Cisco) profiles of the operating system. On macOS a `.mobileconfig` profile is built,
/// staged in a private temp directory, opened for the user to approve, and deleted once the service is listed
/// (the Swift `NativeProfileStaging` + `StagedProfiles`).
pub trait NativeProfiles: Send + Sync {
    /// The profile of a native connection with `psk` (the password never goes into it). Errors carry the
    /// user-facing (localized) message.
    fn build(&self, connection: &Connection, psk: &str) -> Result<NativeProfile, String>;
    /// `service_existed`: the connection's service was already installed (a re-saved profile).
    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String>;
    /// At launch, before anything is staged: deletes the profiles a previous run left staged.
    fn sweep_leftovers(&self) {}
    /// After each successful listing of the system's VPNs, with the connections whose service is listed: their
    /// staged profiles are deleted (the Swift `stagedProfiles.servicesSeen`).
    fn services_seen(&self, _ids: &HashSet<Uuid>) {}
}
