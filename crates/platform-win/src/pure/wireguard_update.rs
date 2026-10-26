//! System Status' wireguard-nt update (2b plan, decision 6 as amended 2026-10-24, "As built (fix4)"): the app only
//! asks the WinVPN Service (`wireguard-check`, `wireguard-update`); the service finds, downloads, verifies and loads
//! the newest wireguard-nt itself. Here: which answers mean what, and the texts. Nothing here runs anything.

use crate::pure::engine::Reach;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::service_proto::{EngineUpdate, SERVICE_VERSION, UPDATE_BUSY};

/// How long the app waits for the service's check (it asks upstream with a 30 s limit itself).
pub const CHECK_SECS: u64 = 45;
/// How long the app waits for the service's update (the listing, a zip of a few MB with a 120 s limit, the checks).
pub const UPDATE_SECS: u64 = 240;

/// Whether a newer wireguard-nt than the loaded one is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offer {
    /// Not asked, or no reliable answer (an older service, no network, an unexpected answer). Never an error row.
    Unknown,
    /// Nothing newer.
    None,
    /// `installed` → `available` (as the service names them, `1.1.0` → `1.2.0`).
    Available { installed: String, available: String },
}

/// Only a green WireGuard row (this version's service, not degraded, a loaded DLL) gets a check.
pub fn check_for(reach: &Reach) -> bool {
    let Reach::Facts(f) = reach else { return false };
    f.service_version == SERVICE_VERSION
        && f.problem.is_none()
        && f.wireguard.problem.is_none()
        && f.wireguard.dll_version.is_some()
}

/// The service's answer to `wireguard-check` (`None`: no answer at all).
pub fn offer_from(answer: Option<(i32, &[u8])>) -> Offer {
    let Some((0, stdout)) = answer else { return Offer::Unknown };
    match EngineUpdate::parse(stdout) {
        Some(EngineUpdate { installed: Some(installed), available: Some(available) }) => {
            Offer::Available { installed, available }
        }
        Some(EngineUpdate { available: None, .. }) => Offer::None,
        _ => Offer::Unknown,
    }
}

/// The outcome of `wireguard-update`, as System Status' output says it: `Ok(the line)` or `Err(the reason)` (the
/// service's own message, also for "busy"; no answer at all is `service_unreachable`).
pub fn update_outcome(answer: Option<(i32, &[u8], &str)>, unreachable: String) -> Result<String, String> {
    match answer {
        Some((0, stdout, _)) => match EngineUpdate::parse(stdout) {
            Some(EngineUpdate { installed: Some(v), .. }) => Ok(installed(&v)),
            _ => Err(unreachable),
        },
        Some((code, _, message)) if code == UPDATE_BUSY || !message.trim().is_empty() => Err(message.trim().into()),
        _ => Err(unreachable),
    }
}

pub fn updating() -> String {
    l10n::tr("Updating wireguard-nt…", &[])
}

pub fn installed(version: &str) -> String {
    l10n::tr("wireguard-nt %@ is installed.", &[Arg::Str(version)])
}
