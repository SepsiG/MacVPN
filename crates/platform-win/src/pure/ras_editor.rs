//! What the connection editors show about Windows (WinVPN 2c Task 11): the reasons a setting cannot run here (all
//! of them, live from the draft), the IKEv2 entry's one-line summary and ignored settings, the SSTP certificate
//! mode Windows cannot use, the buttons the editors offer (trust the CA, the Cisco IPsec copy), that saving an
//! L2TP connection needs no approval, the system VPN's PSK note, and the administrator step an error names.

use super::cisco;
use super::ras_errors::AdminAction;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, VPNKind};
use macvpn_core::ras::{self, Auth, DefaultRoute, RasEntryPlan};
use macvpn_platform_api::PlatformNotes;

/// The editor's notes for the draft `connection` / `config` (`NativeSupport::editor_notes`).
pub fn editor_notes(connection: &Connection, config: &[u8]) -> PlatformNotes {
    let mut notes = PlatformNotes::default();
    let Some(plan) = ras::plan_for(connection, config) else { return notes };
    match connection.kind {
        VPNKind::L2tp => notes.no_install_step = true,
        VPNKind::Cisco => {
            notes.no_install_step = true;
            notes.l2tp_copy = true;
        }
        VPNKind::Sstp => {
            notes.trust_ca = true;
            notes.insecure_cert = Some(insecure_reason());
        }
        VPNKind::Strongswan => notes.trust_ca = true,
        VPNKind::Openvpn | VPNKind::Wireguard => {}
    }
    match plan {
        Ok(plan) => {
            if connection.kind == VPNKind::Strongswan {
                notes.summary = Some(summary(&plan));
            }
            notes.warnings = plan.warnings;
        }
        // An invalid config is the validator's: the editor shows its issues as on macOS.
        Err(u) if u.invalid_config => {}
        Err(u) => notes.reasons = u.reasons,
    }
    if connection.kind == VPNKind::Cisco && notes.reasons.is_empty() {
        notes.reasons.push(cisco::unsupported());
    }
    notes
}

/// SSTP "No verification" (core's `plan_sstp` reason, the same key).
fn insecure_reason() -> String {
    l10n::tr("Windows always checks the SSTP server's certificate. Choose System CA or Custom CA file.", &[])
}

/// "On Windows: EAP-MSCHAPv2 · AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256 · split tunnel".
pub fn summary(plan: &RasEntryPlan) -> String {
    let auth = match plan.auth {
        Auth::MsChapV2 { .. } => "MS-CHAP v2".to_string(),
        Auth::EapMsChapV2 => "EAP-MSCHAPv2".to_string(),
        Auth::Ikev2Psk => "PSK".to_string(),
        Auth::MachineCertificate => l10n::tr("computer certificate", &[]),
    };
    let mut parts = vec![auth];
    if let Some(policy) = &plan.policy {
        parts.push(policy.describe());
    }
    parts.push(match plan.default_route {
        DefaultRoute::None => l10n::tr("split tunnel", &[]),
        DefaultRoute::Ipv4 | DefaultRoute::Both => l10n::tr("all traffic", &[]),
    });
    l10n::tr("On Windows: %@", &[Arg::Str(&parts.join(" · "))])
}

/// `NativeSupport::system_psk_note`: a PSK stored in WinVPN for a system L2TP VPN is written into Windows' RAS
/// credential store at connect only when Windows has none for that VPN (Task 9: an existing one is never
/// overwritten).
pub fn system_psk_note() -> String {
    l10n::tr("Windows uses its own PSK for this VPN if it has one; otherwise WinVPN stores this one there.", &[])
}

/// The administrator step an error text offers: the one whose label it contains (Task 12 pins that each offering
/// text contains its label, EN and HU).
pub fn offered_action(error: &str) -> Option<AdminAction> {
    [AdminAction::AllowL2tpBehindNat, AdminAction::TrustCaInWindows]
        .into_iter()
        .find(|a| !error.is_empty() && error.contains(&a.label()))
}
