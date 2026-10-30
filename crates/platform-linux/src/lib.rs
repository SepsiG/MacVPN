//! The Linux platform (LinVPN). L-a: the desktop integration (Secret Service, notifications, the portal, the tray,
//! autostart, the control socket, single instance, the `.deb` updater); L-b: the VPNs through NetworkManager (the
//! engine `lin::nm`; the sandbox still answers every start with [`pure::texts::not_yet`]).
//!
//! `pure`: the logic without system calls (paths, texts, the autostart file, the update rules, placement), compiled
//! and tested on every OS. `lin`: the Linux implementation (D-Bus through `zbus`, GTK, libc), Linux only. The storage
//! identifiers (the Secret Service attributes, the bus names, the autostart file name, the socket name) are literals
//! here and never derive from `Product`.

pub mod pure;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod lin;

#[cfg(target_os = "linux")]
pub use lin::control::LinTransport;
#[cfg(target_os = "linux")]
pub use lin::keystore::SecretServiceKeyStore;
#[cfg(target_os = "linux")]
pub use lin::platform::LinPlatform;
#[cfg(target_os = "linux")]
pub use lin::tray::{SniTray, TrayEvent};

/// The NetworkManager engine's building blocks for the integration tests (`tests/nm_*.rs`, `tests/net_*.rs`),
/// which run against fakes on a private bus. Not an API.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod lin_for_tests {
    pub use crate::lin::net;
    pub use crate::lin::nm;
}

#[cfg(target_os = "linux")]
pub use lin::instance::{Claim, InstanceGuard, Listener};
#[cfg(target_os = "linux")]
pub use lin::lifecycle::set_exit_hook;
#[cfg(target_os = "linux")]
pub use lin::login_item::AutostartItem;
#[cfg(target_os = "linux")]
pub use lin::package_watch::watch_package_upgrade;
/// A PKCS#12 client certificate and its password → the checked PEM form (`/usr/bin/openssl pkcs12`).
#[cfg(target_os = "linux")]
pub use lin::pkcs12::{convert as convert_pkcs12, convert_with as convert_pkcs12_with};
#[cfg(target_os = "linux")]
pub use lin::supervisor::supervise;

/// First thing in `main`, before any thread and before GTK starts: the program name `linvpn`, which GTK gives every
/// window as its Wayland app id and X11 class (the desktop entry `linvpn.desktop`, `StartupWMClass=linvpn`: the dock
/// shows LinVPN's icon for each window, the panel's overlay too; without it GTK's `gtk_init(NULL, NULL)` leaves the
/// app id empty and the dock shows a generic icon), and the application name `LinVPN`.
#[cfg(target_os = "linux")]
pub fn prepare_process() {
    glib::set_prgname(Some("linvpn"));
    glib::set_application_name("LinVPN");
}

/// Claims this session's single-instance name (`pure::instance::bus_name`: the installed name, or the sandbox's):
/// `First` keeps it for the process' life, `Forwarded` handed `files` to the running LinVPN. `after_update` waits up
/// to 20 s for the old process to let go of the name.
#[cfg(target_os = "linux")]
pub fn claim_instance(
    sandbox: Option<&std::path::Path>,
    files: &[std::path::PathBuf],
    after_update: bool,
) -> zbus::Result<Claim> {
    lin::instance::claim(&pure::instance::bus_name(sandbox), files, after_update)
}

/// [`claim_instance`] by `name` over a fresh session connection, so two calls are two bus clients (two processes).
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn claim_instance_for_tests(name: &str, files: &[std::path::PathBuf], after_update: bool) -> zbus::Result<Claim> {
    lin::instance::claim_on(zbus::blocking::Connection::session()?, name, files, after_update)
}

/// logind's `PrepareForSleep` over a fresh session connection (a fake logind on a private bus; nothing suspends).
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn watch_sleep_for_tests(on: Box<dyn Fn(bool) + Send + Sync>) -> zbus::Result<zbus::blocking::Connection> {
    let bus = zbus::blocking::Connection::session()?;
    lin::lifecycle::watch_sleep_on(&bus, on)?;
    Ok(bus)
}

/// The smoke run's stand-in for the system's quit request (Task 23).
#[cfg(all(target_os = "linux", debug_assertions))]
#[allow(unsafe_code)]
pub mod smoke {
    /// Raises SIGTERM in this process: the GLib signal source hands it to the terminate handler.
    pub fn send_terminate() {
        // SAFETY: raise(2) with a constant signal number.
        unsafe { libc::raise(libc::SIGTERM) };
    }
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use lin::notify::LinNotifier;

/// The portal's light/dark setting, for the desktop test.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn portal_system_dark_for_tests() -> Option<bool> {
    lin::portal::system_dark()
}
