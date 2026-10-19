//! MacVPN macOS platform layer (port of the macOS-specific parts of the Swift `MacVPNCore` and `MacVPN`):
//! Keychain, native VPN (SCNetworkConnection + scutil), launch at login (SMAppService + LaunchAgent), the root
//! installer / uninstaller, the update installer, Homebrew, the process runner, the `mvpn` client and the setup
//! check, and the system VPN change watcher. The core's locale hooks (collation, preferred languages) are installed by [`install_core_hooks`].
//!
//! `unsafe` code is confined to the small FFI modules `sys`, `control_socket`, `cf`, `keychain_ffi`, `sc_ffi`, `sc_watch`,
//! `preferences`, `smappservice_ffi`, `dialogs`, `notifications`, `app_hooks`, `window_fit` and `window_shape`, each with an audit note and a `SAFETY` comment
//! per block.

pub mod app_hooks;
pub mod brew;
mod cf;
pub mod command;
pub mod control_socket;
pub mod dialogs;
pub mod http;
mod keychain_ffi;
pub mod log_stream;
pub mod login_item;
pub mod mvpn_client;
pub mod native_vpn;
pub mod notifications;
pub mod preferences;
pub mod profile_staging;
pub mod root_installer;
mod sc_ffi;
pub mod sc_watch;
pub mod secrets;
pub mod setup_checker;
mod smappservice_ffi;
mod sys;
pub mod system;
pub mod temp_dir;
pub mod testing;
pub mod update_installer;
pub mod window_fit;
pub mod window_shape;

/// The core version this platform layer is built against.
pub fn core_version() -> &'static str {
    macvpn_core::VERSION
}

/// Installs the macOS implementations of the core's locale hooks: the CoreFoundation localized comparison (so
/// connection names sort exactly as in the Swift app, Hungarian included) and the user's preferred languages.
pub fn install_core_hooks() {
    macvpn_core::collation::set_localized_compare(Some(cf::localized_case_insensitive_compare));
    macvpn_core::l10n::AppLanguage::set_preferred_languages(cf::preferred_languages());
}
