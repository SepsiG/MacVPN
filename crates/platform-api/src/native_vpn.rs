//! The VPNs the operating system manages and their native profiles.

use macvpn_core::log::LogSource;
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
    /// The listed service the platform made for the managed connection `connection` (WinVPN: its private RAS
    /// entry `WinVPN-<UUID>`): the connection binds to it before anything else, and it is never a system VPN.
    /// `None` (macOS): bound by its stored ID, or by name and server address.
    fn managed_service_id(&self, _connection: &Uuid) -> Option<String> {
        None
    }
    /// The platform's own log of the managed native connection `connection` (WinVPN: its RAS log), which the Log
    /// tab tails as it tails a helper kind's log. `None` (macOS): the native log exists only while a debug connect
    /// collects the system log.
    fn log_source(&self, _connection: &Uuid) -> Option<Box<dyn LogSource>> {
        None
    }
    /// "Clear Log…" of the platform's own log of `connection` ([`Self::log_source`]), in place, `note` as its first
    /// line. `Ok(true)`: the platform keeps that log (cleared, or there was nothing to clear); `Ok(false)` (macOS):
    /// it keeps none, the debug collection is the log.
    fn clear_log(&self, _connection: &Uuid, _note: &str) -> Result<bool, String> {
        Ok(false)
    }
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
    /// After a managed connection was deleted (by the user, a folder delete or a team catalog): its profile is
    /// removed, whatever its kind (the platform knows what exists; WinVPN: the RAS entry and its stored PSK).
    /// Nothing on macOS (the user removes the profile in System Settings).
    fn remove(&self, _id: &Uuid) {}
    /// With every connection of the open vault (never while it is locked): the profiles of connections that are no
    /// longer there are removed (WinVPN: the private phonebook's leftover entries). Nothing on macOS.
    fn reconcile(&self, _known: &HashSet<Uuid>) {}
    /// [`Self::remove`] removes the profile itself: no system settings page is opened after a delete, and the
    /// delete confirmation says so. `false` (macOS): the user removes it in System Settings.
    fn removes_profiles(&self) -> bool {
        false
    }
    /// [`Self::install`] needs the user's approval before the profile is in use (macOS: the staged profile is
    /// approved in System Settings). `false` (WinVPN: the RAS entry is written at once): a restore, a team catalog
    /// apply and an unlock install the native profiles by themselves, and an install that returned `Ok` is in use.
    fn needs_approval(&self) -> bool {
        true
    }
}

/// The platform's answer whether it can connect a managed connection with these settings (WinVPN 2c: an IKEv2
/// `swanctl.conf` or an SSTP setting Windows lacks), so its row is unavailable with the reason.
pub trait NativeSupport: Send + Sync {
    /// `config`: the connection's stored config (empty for L2TP / Cisco, whose settings are in `connection`); never
    /// a secret. `None`: it can be connected (as far as the settings tell). Otherwise the localized reason.
    fn unsupported_reason(&self, connection: &Connection, config: &[u8]) -> Option<String>;

    /// What the connection's editor shows about how this platform runs these settings (`config` and `connection`
    /// are the editor's draft, so the notes follow the typing; never a secret). Default: nothing (macOS).
    fn editor_notes(&self, _connection: &Connection, _config: &[u8]) -> PlatformNotes {
        PlatformNotes::default()
    }

    /// The system VPN editor's note under a stored PSK (WinVPN: Windows keeps it for that VPN too, as it has no
    /// per-dial PSK). Default: none (macOS passes it at each start).
    fn system_psk_note(&self) -> Option<String> {
        None
    }
}

/// [`NativeSupport::editor_notes`]: the platform's view of one connection's settings, every text localized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformNotes {
    /// Why the platform cannot connect these settings (all reasons; the yellow note). The config stays valid and
    /// is saved: it still runs on other systems.
    pub reasons: Vec<String>,
    /// One line on what the platform makes of the settings (WinVPN IKEv2: authentication, IPsec policy, routing).
    pub summary: Option<String>,
    /// Settings the platform ignores; the connection still runs (grey notes).
    pub warnings: Vec<String>,
    /// SSTP: why "No verification" cannot be chosen here (shown as its title; the option is disabled).
    pub insecure_cert: Option<String>,
    /// The editor offers to trust the server's CA in the system (WinVPN: SSTP and IKEv2, through
    /// [`AdminSteps::trust_ca`]).
    pub trust_ca: bool,
    /// The editor offers **Make an L2TP/IPsec Copy** (WinVPN: Cisco IPsec, which Windows cannot run).
    pub l2tp_copy: bool,
    /// Saving an L2TP / Cisco connection installs its profile without an approval step (WinVPN: the RAS entry is
    /// written at once): the button reads "Save" and no "approve the profile" note is shown.
    pub no_install_step: bool,
}

impl PlatformNotes {
    /// Nothing to show (macOS, OpenVPN, WireGuard).
    pub fn is_empty(&self) -> bool {
        *self == PlatformNotes::default()
    }
}

/// Every connection is supported (macOS).
pub struct NoNativeSupport;

impl NativeSupport for NoNativeSupport {
    fn unsupported_reason(&self, _connection: &Connection, _config: &[u8]) -> Option<String> {
        None
    }
}

/// A CA certificate as the confirmation of **Trust This CA in Windows…** shows it before an administrator confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaSummary {
    /// The subject's distinguished name (`CN=Lab CA, O=Example`).
    pub subject: String,
    /// The validity, Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// The SHA-256 fingerprint: upper-case hexadecimal pairs separated by `:`.
    pub sha256: String,
}

/// The administrator steps the native VPNs need on some systems (WinVPN 2c: trusting an SSTP / IKEv2 server's CA
/// in the computer's Trusted Root store, and allowing L2TP/IPsec to a server behind NAT). Each runs one fixed
/// system tool that an administrator confirms (Windows: a UAC prompt), started by the app itself: never through a
/// privileged service, so a standard user cannot make the computer trust anything without an administrator.
/// The steps block until the tool ends: call them off the UI thread. Every answer is a localized text. The
/// defaults answer "Not available on this system" (macOS has no such step).
pub trait AdminSteps: Send + Sync {
    /// The first certificate of `pem` for the confirmation, or why it cannot be trusted (no certificate, not a CA,
    /// expired or not yet valid).
    fn ca_summary(&self, _pem: &str) -> Result<CaSummary, String> {
        Err(not_available())
    }

    /// Whether the system trusts the first certificate of `pem` for its VPNs (Windows: it is in the computer's
    /// Trusted Root store). `None`: it cannot tell.
    fn ca_trusted(&self, _pem: &str) -> Option<bool> {
        None
    }

    /// **Trust This CA in Windows…**, after the user confirmed [`Self::ca_summary`]: the done message, or why not
    /// (cancelled at the prompt, the tool failed, the store does not have it afterwards).
    fn trust_ca(&self, _pem: &str) -> Result<String, String> {
        Err(not_available())
    }

    /// **Allow L2TP Behind NAT…**: the done message (it says that a restart is needed), or why not.
    fn allow_l2tp_behind_nat(&self) -> Result<String, String> {
        Err(not_available())
    }

    /// The step a connection's error text offers (WinVPN: the text names the step's label, e.g. "… after Allow
    /// L2TP Behind NAT…"): its id (`allow-l2tp-behind-nat` / `trust-ca-in-windows`), so the error banner shows the
    /// button. `None`: no step (macOS).
    fn offered_action(&self, _error: &str) -> Option<&'static str> {
        None
    }
}

fn not_available() -> String {
    macvpn_core::l10n::tr("Not available on this system", &[])
}

/// No administrator step (macOS).
pub struct NoAdminSteps;

impl AdminSteps for NoAdminSteps {}
