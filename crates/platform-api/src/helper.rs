//! The privileged helper (on macOS the root layer `mvpn`), its UI state files and the 1.1 secrets.

use macvpn_core::mfa::{AuthResponseKind, AuthUIState};
use macvpn_core::models::{SecretField, Secrets, VPNKind};
use macvpn_core::status::RootStatus;
use std::path::PathBuf;
use uuid::Uuid;

/// The privileged helper that runs the VPN clients (on macOS the root layer, `sudo -n mvpn …`; the Swift
/// `MvpnClient`).
pub trait HelperClient: Send + Sync {
    fn status(&self) -> Result<Vec<RootStatus>, String>;
    /// `config`: the connection's stored config, sent on stdin ahead of the secrets (root layer 8 opens no user
    /// file). `accept_risky`: the acknowledged risky OpenVPN directives (`--accept-risky`).
    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String>;
    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String>;
    /// `mvpn respond openvpn <id>` (MFA answer to the management bridge).
    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String>;
    /// The helper's log file of the connection (the Log tab reads it); `None`: this helper keeps none.
    fn log_path(&self, _id: &Uuid) -> Option<PathBuf> {
        None
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

/// The 1.1 secrets as the legacy read-only mode reads them (macOS: the Keychain items `local.macvpn.secrets`,
/// account `<UUID>.<field>`). app-core's `LegacySecretReader` turns it into a `SecretReader`.
pub trait LegacySecrets: Send + Sync {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String>;
}
