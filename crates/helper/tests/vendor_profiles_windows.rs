//! The UniFi, pfSense and OPNsense profiles (`Tests/Fixtures/{unifi,pfsense,opnsense}/`) on the WinVPN Service's
//! pure parts: every WireGuard file gives a wireguard-nt plan, and the OpenVPN driver the service chooses for each
//! export is pinned (a CBC fallback cipher or compression means TAP-Windows6; the docs say which export setting
//! keeps DCO). Validation itself is `crates/core/tests/vendor_profiles.rs`. Tested on every OS.

use macvpn_helper::windows::ovpn_args::{self, Driver};
use macvpn_helper::windows::wg_plan::{self, Prefix};
use std::path::{Path, PathBuf};

fn fixture(path: &str) -> String {
    let full: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Tests/Fixtures").join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

#[test]
fn every_vendor_wireguard_file_gives_a_plan() {
    for (path, default_route, search) in [
        ("unifi/wireguard-full-tunnel.conf", true, &[][..]),
        ("unifi/wireguard-split-tunnel.conf", false, &[][..]),
        ("pfsense/wireguard.conf", false, &["corp.example.com", "example.com"][..]),
        ("opnsense/wireguard.conf", true, &["lan.example.com"][..]),
    ] {
        let plan = wg_plan::parse(&fixture(path)).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        assert_eq!(plan.peers.len(), 1, "{path}");
        assert!(plan.peers[0].endpoint.is_some(), "{path}: endpoint");
        assert!(!plan.dns_servers.is_empty(), "{path}: DNS");
        assert_eq!(plan.dns_search, search, "{path}: search domains");
        let routes = plan.routes();
        assert_eq!(routes.contains(&Prefix::parse("0.0.0.0/0").unwrap()), default_route, "{path}: {routes:?}");
    }
}

#[test]
fn the_driver_each_vendor_export_gets() {
    for (path, driver) in [
        // `cipher AES-256-CBC` (and `comp-lzo` in older exports): DCO cannot run them.
        ("unifi/openvpn-server.ovpn", Driver::TapWindows6),
        ("unifi/openvpn-server-legacy-lzo.ovpn", Driver::TapWindows6),
        // pfSense's default Fallback Data Encryption Algorithm is AES-256-CBC.
        ("pfsense/openvpn-inline-most-clients.ovpn", Driver::TapWindows6),
        // … with an AES-GCM fallback the export runs on DCO.
        ("pfsense/openvpn-inline-connect-tls-crypt.ovpn", Driver::Dco),
        ("pfsense/openvpn-inline-android-user-auth.ovpn", Driver::TapWindows6),
        ("opnsense/openvpn-file-only.ovpn", Driver::TapWindows6),
        // `compress lz4-v2`.
        ("opnsense/openvpn-tcp-tls-crypt-v2.ovpn", Driver::TapWindows6),
    ] {
        assert_eq!(ovpn_args::choose_driver(&fixture(path)), driver, "{path}");
    }
    let gcm = fixture("pfsense/openvpn-inline-most-clients.ovpn")
        .replace("data-ciphers-fallback AES-256-CBC", "data-ciphers-fallback AES-256-GCM");
    assert_eq!(ovpn_args::choose_driver(&gcm), Driver::Dco);
}
