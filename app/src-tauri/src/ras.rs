//! The native VPNs' commands on Windows (WinVPN 2c Task 11): **Trust This CA in Windows…** (its confirmation, then
//! the administrator step), **Allow L2TP Behind NAT…** and **Make an L2TP/IPsec Copy**. The steps are the
//! platform's (`AdminSteps`; macOS answers "Not available on this system"); each blocks until the elevated tool
//! ends, so it runs off the UI thread. No command takes a file path or a certificate: the CA is the SSTP config's
//! (the open editor's or the saved one) or the PEM file the user picks in the open panel shown here (IKEv2), and
//! the one trusted is exactly the one whose summary the user confirmed.

use macvpn_app_core::import_export;
use macvpn_core::l10n;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::sstp::SSTPConfig;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use tauri::{AppHandle, State, Window};

use crate::commands::validate_key;
use crate::manage::{MANAGE_WINDOW, managed};
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// The CA whose summary was shown last, per connection: **Trust** trusts exactly that one (once).
#[derive(Default)]
pub struct PendingCa(Mutex<HashMap<String, String>>);

impl PendingCa {
    fn put(&self, id: &str, pem: String) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        // One confirmation at a time is shown; older ones are dropped.
        map.clear();
        map.insert(id.to_string(), pem);
    }

    fn take(&self, id: &str) -> Option<String> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).remove(id)
    }
}

fn pending() -> &'static PendingCa {
    static PENDING: std::sync::OnceLock<PendingCa> = std::sync::OnceLock::new();
    PENDING.get_or_init(PendingCa::default)
}

/// The confirmation before **Trust This CA in Windows…**: the CA's subject, validity (Unix seconds) and SHA-256
/// fingerprint, and the warning that every program on the PC will trust it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaConfirmView {
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
    pub sha256: String,
    pub warning: String,
}

/// The CA of `id` for the confirmation: an SSTP connection's custom CA (`pick` false), or a PEM file the user picks
/// now for an IKEv2 connection (`pick` true; a cancelled panel answers `None`). An error (no CA, not a CA,
/// expired, not available on this system) comes back as the alert.
#[tauri::command]
pub async fn ras_ca_summary(
    app: AppHandle,
    state: Shared<'_>,
    id: String,
    pick: bool,
) -> Result<Option<CaConfirmView>, String> {
    let c = managed(&state, &id)?;
    let pem = if pick {
        if c.kind != VPNKind::Strongswan {
            return Err("not an IKEv2 connection".into());
        }
        let paths = crate::dialogs::choose_files(&app, &state, MANAGE_WINDOW, false).await?;
        let Some(path) = paths.first().cloned() else { return Ok(None) };
        let text = blocking(move || import_export::read_import_file(&path)).await?;
        text.as_deref().and_then(SSTPConfig::extract_certificates).ok_or_else(|| {
            l10n::tr(
                "The file contains no PEM certificate (-----BEGIN CERTIFICATE-----). Convert a binary (DER) .cer file to PEM first.",
                &[],
            )
        })?
    } else {
        state.connections.sstp_ca_pem(&id)?
    };
    let admin = crate::platform::get().admin_steps();
    let (summary, pem) = blocking(move || admin.ca_summary(&pem).map(|s| (s, pem))).await??;
    pending().put(&id, pem);
    Ok(Some(CaConfirmView {
        subject: summary.subject,
        not_before: summary.not_before,
        not_after: summary.not_after,
        sha256: summary.sha256,
        warning: l10n::tr(
            "Every program on this PC will trust server and client certificates from this CA (not software it signs).",
            &[],
        ),
    }))
}

/// **Trust** in the confirmation: the confirmed CA into the computer's trusted roots (an administrator confirms
/// the system's prompt). The done message, or why not (cancelled, failed, not in the store afterwards).
#[tauri::command]
pub async fn ras_trust_ca(window: Window, state: Shared<'_>, id: String) -> Result<String, String> {
    crate::guard::only(&window, "ras_trust_ca", MANAGE_WINDOW)?;
    validate_key(&id)?;
    let pem = pending().take(&id).ok_or("no CA to trust")?;
    let admin = crate::platform::get().admin_steps();
    let outcome = blocking(move || admin.trust_ca(&pem)).await?;
    // "Trusted by Windows" is asked again (also after a cancel: the store is what it is).
    state.connections.ca_trust_changed();
    state.publisher.mark();
    outcome
}

/// **Allow L2TP Behind NAT…** (offered with an L2TP error 809): the done message ("Restart Windows…") or why not.
#[tauri::command]
pub async fn ras_allow_l2tp_nat(window: Window) -> Result<String, String> {
    crate::guard::only(&window, "ras_allow_l2tp_nat", MANAGE_WINDOW)?;
    let admin = crate::platform::get().admin_steps();
    blocking(move || admin.allow_l2tp_behind_nat()).await?
}

/// **Make an L2TP/IPsec Copy** of a Cisco IPsec connection: the copy is made and selected (its editor opens).
/// `Some`: its profile could not be installed (the message; the copy stays).
#[tauri::command]
pub async fn make_l2tp_copy(window: Window, state: Shared<'_>, id: String) -> Result<Option<String>, String> {
    crate::guard::only(&window, "make_l2tp_copy", MANAGE_WINDOW)?;
    managed(&state, &id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.make_l2tp_copy(&id).map(|(_, install_error)| install_error)).await?
}

#[cfg(test)]
mod tests {
    use super::PendingCa;

    /// Trust takes exactly the CA of the last confirmation, once, and only for its connection.
    #[test]
    fn the_confirmed_ca_is_trusted_once() {
        let p = PendingCa::default();
        let a = "6A3F0B1E-2C4D-4E5F-8A9B-0C1D2E3F4A5B";
        let b = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
        p.put(a, "first".into());
        p.put(b, "second".into());
        assert_eq!(p.take(a), None, "an older confirmation is gone");
        assert_eq!(p.take(b).as_deref(), Some("second"));
        assert_eq!(p.take(b), None, "once");
    }
}
