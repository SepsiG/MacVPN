//! System Status and availability on Windows from the WinVPN Service's `engine` answer (pure).
//!
//! Fail closed: the engine-missing state when the service is absent, unreachable (not provably the service), of
//! another version or degraded; otherwise the three rows, where a row is green only on facts that say so (a fact
//! that is missing or cannot be read is red).

use crate::pure::cisco;
use crate::pure::openvpn_install::Upgrade;
use crate::pure::texts;
use crate::pure::wireguard_update::Offer;
use macvpn_core::service_proto::{EngineFacts, SERVICE_VERSION, Version};
use macvpn_platform_api::{EngineReport, EngineRow, PackageIndexUpdate, SetupReport};

/// The engine one click of System Status' engine buttons runs (`SystemSetup::install_tools`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolsTarget {
    /// The OpenVPN row's "Install" / "Repair" / "Update" (`openvpn_install`).
    OpenVpn,
    /// The WireGuard row's "Update" (fix4: the WinVPN Service updates wireguard-nt itself).
    WireGuard,
}

/// Each engine row has its own button (OpenVPN's and WireGuard's update are two clicks, each with its own
/// confirmation and busy rule): the OpenVPN row's button sends the report as it is, the WireGuard row's without the
/// OpenVPN action (app `setup_install_tools`). So the OpenVPN row's action when there is one, else the WireGuard
/// row's "Update"; without either, OpenVPN (its installer answers).
pub fn tools_target(report: &SetupReport) -> ToolsTarget {
    match &report.engine {
        Some(e) if e.openvpn.action.is_none() && e.wireguard.action == Some("update") => ToolsTarget::WireGuard,
        _ => ToolsTarget::OpenVpn,
    }
}

/// What the app learned about the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// No service is installed (the pipe does not exist).
    Absent,
    /// The pipe exists but no trusted answer came (the localized reason).
    Unreachable(String),
    Facts(EngineFacts),
}

/// The OpenVPN data-channel drivers System Status lists (decision 4: DCO and TAP-Windows6; no Wintun).
const DCO: &str = "OpenVPN DCO";
const TAP_WINDOWS6: &str = "TAP-Windows6";

/// The installed OpenVPN's version when its row would be green (installed, accepted by the service, both drivers):
/// only then is an update check worth asking for (a missing driver's "Repair" takes precedence over "Update").
pub fn update_check_for(reach: &Reach) -> Option<Version> {
    let Reach::Facts(f) = reach else { return None };
    let o = &f.openvpn;
    let green = f.service_version == SERVICE_VERSION
        && f.problem.is_none()
        && o.problem.is_none()
        && o.dco.is_some()
        && o.tap_windows6.is_some();
    green.then(|| o.version.as_deref().and_then(Version::parse)).flatten()
}

/// The daily background refresh (`SystemSetup::update_package_index`, scheduled by the app as macOS's `brew update`).
/// Windows has no package index to download: the "refresh" is the next check asking winget for OpenVPN and the
/// service for wireguard-nt again (the app checks the system after `Updated`). Worth it only with a usable service
/// (one of this version, not degraded) and never in the sandbox; otherwise `Unavailable` (asked again at the next
/// wake).
pub fn index_refresh(reach: &Reach, sandbox: bool) -> PackageIndexUpdate {
    match reach {
        Reach::Facts(f) if !sandbox && f.service_version == SERVICE_VERSION && f.problem.is_none() => {
            PackageIndexUpdate::Updated
        }
        _ => PackageIndexUpdate::Unavailable,
    }
}

/// `recommended_openvpn`: the pinned OpenVPN version (an installed one the service refuses and that is older offers
/// "Update", else "Repair"). `upgrade`: the update check of a green row ([`update_check_for`]; decision 4 as amended
/// 2026-10-24): an available update keeps the row green and usable, names both versions and offers "Update".
/// `wireguard`: the service's wireguard-nt check of a green WireGuard row (`wireguard_update::check_for`; decision 6
/// as amended 2026-10-24), shown the same way.
pub fn report(reach: Reach, recommended_openvpn: &str, upgrade: &Upgrade, wireguard: &Offer) -> SetupReport {
    let missing = |reason: String| SetupReport {
        engine_missing: Some(reason),
        ras_unsupported_kinds: cisco::unsupported_kinds(),
        ..SetupReport::unknown()
    };
    let f = match reach {
        Reach::Absent => return missing(texts::service_missing()),
        Reach::Unreachable(reason) => return missing(reason),
        Reach::Facts(f) => f,
    };
    if f.service_version != SERVICE_VERSION {
        return missing(texts::service_missing());
    }
    if let Some(p) = f.problem {
        return missing(p);
    }
    let recommended = Version::parse(recommended_openvpn);
    let o = &f.openvpn;
    let installed = o.version.as_deref().and_then(Version::parse);
    let older = |v: Version| recommended.is_some_and(|r| v < r);
    let drivers = [(DCO, o.dco.clone()), (TAP_WINDOWS6, o.tap_windows6.clone())];
    let absent: Vec<&str> = drivers.iter().filter(|(_, v)| v.is_none()).map(|(n, _)| *n).collect();
    let openvpn = match (&o.problem, installed) {
        (None, Some(v)) => {
            let detail = texts::openvpn_ok(&v.to_string(), &drivers);
            if absent.is_empty() {
                match upgrade {
                    Upgrade::Available { shown, .. } => EngineRow {
                        ok: true,
                        usable: true,
                        detail: format!("{detail} {}", texts::update_available(&v.to_string(), shown)),
                        action: Some("update"),
                    },
                    Upgrade::None | Upgrade::Unknown => EngineRow { ok: true, usable: true, detail, action: None },
                }
            } else {
                EngineRow {
                    ok: false,
                    usable: absent.len() < drivers.len(),
                    detail: format!("{detail} {}", texts::drivers_missing(&absent.join(", "))),
                    action: Some("repair"),
                }
            }
        }
        (Some(p), None) => EngineRow { ok: false, usable: false, detail: p.clone(), action: Some("install") },
        // Installed but refused by the service: too old → "Update"; otherwise (its signer, its folder) → "Repair".
        (Some(p), Some(v)) => EngineRow {
            ok: false,
            usable: false,
            detail: p.clone(),
            action: Some(if older(v) { "update" } else { "repair" }),
        },
        // No problem and no readable version: not a fact the row can be green on, nor "not installed" (only a row
        // that offers "install" is: OpenVPN's optional state, `SetupReport::is_complete`). Nothing to install or
        // repair from here: "Not ready", and the report is incomplete.
        (None, None) => EngineRow { ok: false, usable: false, detail: texts::service_unreachable(), action: None },
    };
    let wireguard = match (&f.wireguard.problem, &f.wireguard.dll_version) {
        (None, Some(v)) => match wireguard {
            Offer::Available { installed, available } => EngineRow {
                ok: true,
                usable: true,
                detail: format!("wireguard-nt {v} {}", texts::update_available(installed, available)),
                action: Some("update"),
            },
            Offer::None | Offer::Unknown => {
                EngineRow { ok: true, usable: true, detail: format!("wireguard-nt {v}"), action: None }
            }
        },
        (Some(p), _) => EngineRow { ok: false, usable: false, detail: p.clone(), action: None },
        (None, None) => EngineRow { ok: false, usable: false, detail: texts::service_unreachable(), action: None },
    };
    SetupReport {
        engine: Some(EngineReport {
            service: EngineRow {
                ok: true,
                usable: true,
                detail: texts::service_running(&SERVICE_VERSION.to_string()),
                action: None,
            },
            openvpn,
            wireguard,
        }),
        ras_unsupported_kinds: cisco::unsupported_kinds(),
        ..SetupReport::unknown()
    }
}

/// The WinVPN Service's answer to `clear-log` (code, stderr): exit 0 = cleared; the usage error (exit 2) = a service
/// older than the request ([`texts::service_cannot_clear_log`]); any other failure = its message (or the exit code).
pub fn clear_log_answer(code: i32, message: &str) -> Result<(), String> {
    match code {
        0 => Ok(()),
        2 => Err(texts::service_cannot_clear_log()),
        _ if !message.trim().is_empty() => Err(message.trim().to_string()),
        _ => Err(macvpn_core::l10n::tr("mvpn error (exit code: %d)", &[macvpn_core::l10n::Arg::Int(i64::from(code))])),
    }
}
