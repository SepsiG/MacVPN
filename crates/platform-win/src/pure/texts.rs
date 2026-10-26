//! The texts of the Windows platform: the WinVPN Service's rows, the RAS engine's own, the app's notes (the
//! literals are the l10n keys).

use macvpn_core::l10n::{self, Arg};

/// The reason Windows shows while the quit questions hold up a logoff or shutdown.
pub fn closing() -> String {
    l10n::tr("Closing WinVPN…", &[])
}

/// Settings: launch at login is registered, but the user turned it off in Startup apps.
pub fn startup_disabled() -> String {
    l10n::tr("Turned off in Settings → Apps → Startup.", &[])
}

/// System Status: WinVPN is uninstalled through Windows (the MSI), not in the app.
pub fn uninstall_in_settings() -> String {
    l10n::tr(
        "Uninstall WinVPN in Windows: Settings → Apps → Installed apps → WinVPN → Uninstall. Your connections and the vault are kept until you delete them (see the user guide).",
        &[],
    )
}

// MARK: - The WinVPN Service (2b)

/// The engine-missing state: no service, or one of another WinVPN version (a broken install).
pub fn service_missing() -> String {
    l10n::tr(
        "The WinVPN Service is missing or from another WinVPN version. Repair WinVPN: Settings → Apps → Installed apps → WinVPN → Modify → Repair.",
        &[],
    )
}

/// The engine-missing state: the pipe exists but no trusted answer came (a squatter, a hung service).
pub fn service_unreachable() -> String {
    l10n::tr("The WinVPN Service is not reachable.", &[])
}

/// System Status' service row.
pub fn service_running(version: &str) -> String {
    l10n::tr("Running (version %@)", &[Arg::Str(version)])
}

/// The RAS engine's answer to every L2TP/IPsec, IKEv2 and SSTP request when WinVPN's data folder (its private
/// phonebook, profiles and logs) cannot be found: neither `%LOCALAPPDATA%` nor the user's profile is known.
pub fn data_folder_missing() -> String {
    l10n::tr("WinVPN's data folder could not be found.", &[])
}

/// System Status' OpenVPN row: the version and each installed driver with its version (`OpenVPN DCO 2.8.13.0,
/// TAP-Windows6 9.27.0.0`); a driver that is not installed is left out ([`drivers_missing`] names it).
pub fn openvpn_ok(version: &str, drivers: &[(&str, Option<String>)]) -> String {
    let installed: Vec<String> =
        drivers.iter().filter_map(|(name, v)| v.as_ref().map(|v| format!("{name} {v}"))).collect();
    if installed.is_empty() {
        return l10n::tr("Version %@", &[Arg::Str(version)]);
    }
    l10n::tr("Version %@ · drivers: %@", &[Arg::Str(version), Arg::Str(&installed.join(", "))])
}

/// System Status' OpenVPN row: the drivers that are not installed ("Repair" adds them).
pub fn drivers_missing(list: &str) -> String {
    l10n::tr("Missing: %@. Repair adds them.", &[Arg::Str(list)])
}

/// System Status' OpenVPN row: a newer OpenVPN Community is available ("Update" installs it).
pub fn update_available(installed: &str, new: &str) -> String {
    l10n::tr("Update available: %@ → %@", &[Arg::Str(installed), Arg::Str(new)])
}

/// Updating WinVPN (the MSI) stops the service, and with it every connection.
pub fn upgrade_disconnects() -> String {
    l10n::tr("Updating WinVPN disconnects active VPN connections.", &[])
}
