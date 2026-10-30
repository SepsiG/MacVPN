//! The plugin facts of the real system (`scripts/lin-remote.sh desktop`, after CP-plugins): read-only (the `.name`
//! files, LinVPN's service files, `openvpn --version`, NM's `Version` property); nothing is installed, no dialog.
#![cfg(target_os = "linux")]

use macvpn_platform_linux::lin_for_tests::nm::plugins::facts;
use macvpn_platform_linux::pure::nm::plugins::report;

#[test]
#[ignore = "desktop: the NM plugins of this system"]
fn desktop_nm_plugins_on_this_system() {
    let nm_version = zbus::blocking::Connection::system().ok().and_then(|bus| {
        let nm = zbus::blocking::Proxy::new(
            &bus,
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        )
        .ok()?;
        nm.get_property::<String>("Version").ok()
    });
    let facts = facts(nm_version);
    println!("{facts:#?}");
    let r = report(&facts);
    println!("NetworkManager: {:?}", r.networkmanager);
    for (kind, row, packages) in &r.kinds {
        println!("{kind:?}: {row:?} packages {packages:?}");
    }
}
