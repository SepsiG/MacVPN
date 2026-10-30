//! The privileged helper (on macOS the root layer `mvpn`), its UI state files and the 1.1 secrets.

use macvpn_core::log::{FileLogSource, LogSource};
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
    /// The connection's log as the Log tab reads it. Default: the file at [`Self::log_path`] (macOS); `None`: no
    /// log.
    fn log_source(&self, id: &Uuid) -> Option<Box<dyn LogSource>> {
        self.log_path(id).map(|path| Box::new(FileLogSource { path }) as Box<dyn LogSource>)
    }
    /// "Clear Log…": empties the connection's log as the Log tab reads it (its rotated part too), in place, so a
    /// running connection keeps logging; `note` (`═══ Log cleared at <time> ═══`) becomes its first line. `Ok`
    /// also when there is no log. Default: this helper keeps none.
    fn clear_log(&self, _id: &Uuid, _note: &str) -> Result<(), String> {
        Ok(())
    }
    /// Dead-tunnel detection: the running tunnel's liveness facts (macOS root layer 10 `mvpn liveness <id>`, the
    /// WinVPN Service's `liveness <id>`). `None`: not known (an older root layer or service, nothing running, an
    /// engine without such facts, any error): nothing is decided then. Default: this helper has none.
    fn liveness(&self, _id: &Uuid) -> Option<macvpn_core::liveness::Liveness> {
        None
    }
    /// Live traffic: the running tunnel's byte counters, read cheaply as the user (never through the root layer
    /// or the service). `None`: not known (no interface reported, an engine without such counters, any error):
    /// nothing is shown then. Default: this helper has none.
    fn traffic(&self, _tunnel: &crate::traffic::HelperTunnel<'_>) -> Option<crate::traffic::TrafficReading> {
        None
    }
    /// Whether the running tunnel's log needs the connection's secrets to mask them (LinVPN: a tunnel an earlier
    /// process left running, adopted without them). Default: never.
    fn wants_log_secrets(&self, _id: &Uuid) -> bool {
        false
    }
    /// The connection's secrets for [`Self::wants_log_secrets`] (read from the unlocked vault), used only to mask
    /// its log lines. Default: ignored.
    fn set_log_secrets(&self, _id: &Uuid, _secrets: &Secrets) {}
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
