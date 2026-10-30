#![cfg(target_os = "linux")]

use macvpn_core::models::VPNKind;
use macvpn_platform_api::{LINVPN, Platform};
use macvpn_platform_linux::LinPlatform;
use macvpn_platform_linux::pure::texts;
use std::path::Path;

/// The sandbox keeps L-a's "not yet" state: no NetworkManager is asked, nothing is installed or watched. Its check
/// reports the engine note as the missing engine (System Status shows it in place of the rows); the platform has no
/// note of its own, so a smoke run's stand-in report shows its NetworkManager rows.
#[test]
fn identity_and_the_sandboxs_not_yet_state() {
    let p = LinPlatform::new(true);
    assert_eq!(p.product(), &LINVPN);
    let report = p.setup().check(None);
    assert_eq!(report.engine_missing, Some(texts::engine_note()));
    assert!(report.nm.is_none());
    assert!(!report.is_available(VPNKind::Openvpn));
    assert_eq!(p.setup().engine_note(), None);
    // No root helper to uninstall: System Status shows the package's removal instead of "Uninstall".
    assert_eq!(p.setup().system_uninstall_note(), Some(texts::uninstall_note()));
    assert!(!p.setup().account_cleanup());
    assert_eq!(p.helper_client().status().unwrap(), vec![]);
    assert!(p.native_controller().list().unwrap().is_empty());
    let mut out = String::new();
    p.setup().install_tools(&report, &mut |t| out.push_str(t)).unwrap();
    assert_eq!(out, "(sandbox: PackageKit is not asked)\n");
    assert!(p.network().snapshot().is_err(), "no network probe in the sandbox");
    let _guard = p.system_vpn_watch().start(Box::new(|| {})).unwrap();
}

/// LinVPN has no system log stream (a debug connect starts no collection; the Log tab reads the connection log).
#[test]
fn no_log_stream() {
    assert!(!LinPlatform::new(true).log_streams().is_available());
    assert!(!LinPlatform::new(false).log_streams().is_available());
}

/// The real check: NetworkManager's rows and PackageKit, never the engine note (read-only: NM's version and the
/// plugin files; on a system without NetworkManager its row is red).
#[test]
fn the_check_reports_networkmanager_rows() {
    let p = LinPlatform::new(false);
    let report = p.setup().check(None);
    assert_eq!(report.engine_missing, None);
    assert_eq!(report.package_manager.as_deref(), Some("PackageKit"));
    let nm = report.nm.as_ref().expect("the NetworkManager rows");
    assert_eq!(nm.kinds.len(), 6);
    assert!(nm.networkmanager.usable || !report.is_available(VPNKind::Wireguard));
    assert_eq!(p.setup().engine_note(), None);
    assert_eq!(p.setup().system_uninstall_note(), Some(texts::uninstall_note()));
    // Nothing offers Install: the platform refuses without asking PackageKit.
    let mut clean = report.clone();
    for (_, row, _) in &mut clean.nm.as_mut().unwrap().kinds {
        row.action = None;
    }
    assert!(p.setup().install_tools(&clean, &mut |_| {}).is_err());
}

#[test]
fn the_sandbox_keeps_its_data_under_its_home() {
    let p = LinPlatform::new(true);
    let root = p.system().app_data_root(Path::new("/tmp/sb"));
    assert_eq!(root, Path::new("/tmp/sb/.local/share"));
    assert_eq!(LINVPN.data_dir(&root), Path::new("/tmp/sb/.local/share/LinVPN"));
}

#[test]
fn entropy_and_dates() {
    let p = LinPlatform::new(true);
    let mut a = [0u8; 64];
    p.entropy().fill(&mut a).unwrap();
    assert!(a.iter().any(|&b| b != 0));
    assert_eq!(p.system().local_timestamp(f64::NAN), "");
    assert_eq!(p.system().local_timestamp(0.0).len(), "1970-01-01 00:00:00".len());
}

#[test]
fn no_app_location_in_a_test_binary() {
    assert_eq!(LinPlatform::new(true).system().app_location(), None);
}
