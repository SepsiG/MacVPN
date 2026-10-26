//! WinPlatform on a real Windows system. Nothing here touches the user's real data: the key store test uses its own
//! uniquely named credential and deletes it; the registry test uses its own key and deletes it; the launch-at-login
//! tests use their own `WinVPN-test-<uuid>` Run value and delete it.

#![cfg(windows)]

use macvpn_core::fsx::FileOwner;
use macvpn_core::models::{Secrets, VPNKind};
use macvpn_core::vault::{KeyStore, KeyStoreError};
use macvpn_platform_api::{LoginItemView, NativeWindow, Platform, PlatformError, WINVPN};
use macvpn_platform_win::WinPlatform;
use std::cell::RefCell;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use uuid::Uuid;

/// A `WinPlatform` that holds the clipboard lock for as long as it lives (bind it with `let p = platform();` so the
/// lock covers the whole test). The clipboard is global, and every clipboard write names the message window of the
/// first thread that made a `WinPlatform` as its owner (the app's main thread; here whichever test thread came first,
/// a thread that ends with its test). So the tests that copy, and the tests whose thread may own that window, never
/// run at the same time; everything else stays parallel, without `--test-threads=1`.
struct Locked {
    platform: WinPlatform,
    _clipboard: MutexGuard<'static, ()>,
}

impl Deref for Locked {
    type Target = WinPlatform;
    fn deref(&self) -> &WinPlatform {
        &self.platform
    }
}

fn platform_with(sandbox: bool) -> Locked {
    static CLIPBOARD: Mutex<()> = Mutex::new(());
    // A failed test must not fail the others: the lock guards no data.
    let guard = CLIPBOARD.lock().unwrap_or_else(PoisonError::into_inner);
    Locked { platform: WinPlatform::new(sandbox), _clipboard: guard }
}

fn platform() -> Locked {
    platform_with(true)
}

#[test]
fn identity_and_folders() {
    let p = platform_with(false);
    assert!(!p.is_sandbox());
    assert_eq!(p.product(), &WINVPN);
    let home = p.system().home_directory().expect("a profile folder");
    assert!(home.is_absolute());
    let root = p.system().app_data_root(&home);
    assert!(root.ends_with("AppData\\Local") || root.ends_with("AppData/Local"), "{root:?}");
    assert_eq!(p.system().user_owner().unwrap(), FileOwner::current_user().unwrap());
    assert!(p.system().temporary_directory().unwrap().is_absolute());
    assert_eq!(p.system().app_location(), None, "a test binary is not WinVPN.exe");
}

#[test]
fn the_sandbox_keeps_its_data_under_the_sandbox_home() {
    let p = platform();
    assert!(p.is_sandbox());
    let home = Path::new(r"C:\sandbox-home");
    assert_eq!(p.system().app_data_root(home), home.join("AppData").join("Local"));
}

#[test]
fn local_dates_are_formatted() {
    let p = platform();
    // 2026-10-18 12:00:00 UTC is the 18th in every time zone between UTC-12 and UTC+11.
    assert_eq!(p.system().local_date(1_792_324_800.0), "2026-10-18");
    let en = p.system().local_date_time(1_792_324_800.0, macvpn_core::l10n::AppLanguage::En);
    assert!(en.starts_with("10/18/2026, ") && (en.ends_with("\u{202f}AM") || en.ends_with("\u{202f}PM")), "{en}");
    assert_eq!(p.system().local_date(f64::NAN), "");
}

/// Credential Manager needs the user's logon session, which a public-key SSH logon (the Windows test machine's
/// `scripts/win-remote.sh`) does not have: every call answers `ERROR_NO_SUCH_LOGON_SESSION`, which the store maps to
/// `Unavailable` (checked here). Such a run skips the round trip; an interactive or CI logon runs it.
fn has_logon_session(store: &dyn KeyStore) -> bool {
    match store.exists() {
        Err(KeyStoreError::Unavailable(e)) => {
            assert!(e.contains("1312"), "{e}");
            eprintln!("skipped: no Credential Manager logon session (an SSH key logon)");
            false
        }
        _ => true,
    }
}

#[test]
fn entropy_is_real() {
    let mut a = [0u8; 32];
    let p = platform();
    p.entropy().fill(&mut a).unwrap();
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn the_credential_key_store_round_trips_and_deletes() {
    let store = macvpn_platform_win::credential_key_store_for_tests(&format!("local.winvpn.test.{}", Uuid::new_v4()));
    if !has_logon_session(store.as_ref()) {
        return;
    }
    assert!(store.get().unwrap().is_none());
    assert!(!store.exists().unwrap());
    store.set(&[7u8; 32]).unwrap();
    assert!(store.exists().unwrap());
    assert_eq!(store.get().unwrap().as_deref().map(|k| k.to_vec()), Some(vec![7u8; 32]));
    store.set(&[9u8; 32]).unwrap();
    assert_eq!(store.get().unwrap().as_deref().map(|k| k.to_vec()), Some(vec![9u8; 32]));
    store.delete().unwrap();
    assert!(store.get().unwrap().is_none());
    store.delete().unwrap();
    assert!(store.set(&[]).is_err(), "an empty key is refused");
    assert!(!store.exists().unwrap());
}

#[test]
fn the_sandbox_key_store_never_reaches_credential_manager() {
    let p = platform();
    let store = p.key_store();
    store.set(&[1u8; 32]).unwrap();
    assert!(store.exists().unwrap());
    assert!(p.key_store().exists().unwrap(), "every caller gets the same sandbox store");
    // A fresh real store does not see the sandbox's item.
    let real = macvpn_platform_win::credential_key_store_for_tests("local.winvpn.vault.sandbox-check");
    if has_logon_session(real.as_ref()) {
        assert!(!real.exists().unwrap());
    }
}

#[test]
fn the_sandbox_preferences_are_one_memory_store() {
    let p = platform();
    p.preferences().set_bool("test", true);
    assert_eq!(p.preferences().bool("test"), Some(true));
    assert!(Arc::ptr_eq(&p.preferences(), &p.preferences()));
}

#[test]
fn without_the_service_the_vpn_parts_say_so() {
    // Without the WinVPN Service (`\\.\pipe\WinVPN` does not exist) OpenVPN and WireGuard say "missing". On a test
    // machine where the real service is installed, the pipe exists but refuses this session (an SSH logon is a
    // network logon, which the pipe denies), so they say "not reachable" instead. Since 2c the native kinds (RAS)
    // do not need the service.
    let installed =
        !matches!(std::fs::metadata(r"\\.\pipe\WinVPN"), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    let p = platform();
    macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        let missing = if installed {
            macvpn_platform_win::pure::texts::service_unreachable()
        } else {
            macvpn_platform_win::pure::texts::service_missing()
        };
        assert!(macvpn_platform_win::pure::texts::service_missing().starts_with("The WinVPN Service is missing"));
        assert_eq!(p.helper_client().status().unwrap_err(), missing);
        assert_eq!(
            p.helper_client().up(VPNKind::Openvpn, &Uuid::new_v4(), b"", &Secrets::default(), false, &[]).unwrap_err(),
            missing
        );
        assert_eq!(p.auth_state().read(&Uuid::new_v4()), None);
        assert_eq!(p.setup().engine_note(), None);
        assert_eq!(p.setup().later_note(), None);
        let report = p.setup().check(None);
        assert_eq!(report.engine_missing.as_deref(), Some(missing.as_str()));
        assert!(report.engine.is_none());
        assert!(!report.is_complete());
        assert!(!report.is_available(VPNKind::Openvpn) && !report.is_available(VPNKind::Wireguard));
        assert_eq!(report.later_reason(VPNKind::L2tp), None);
        assert!(p.setup().system_uninstall_note().unwrap().contains("Settings → Apps → Installed apps"));
        assert!(p.setup().helper_upgrade_notice().contains("disconnects"));
        assert!(p.system_vpn_watch().start(Box::new(|| {})).is_ok());
    });
}

/// G-9: "Remove WinVPN from This Account…" is offered next to the Installed apps note; its helper step removes
/// nothing (the WinVPN Service and Program Files belong to the MSI) and never fails.
#[test]
fn the_account_cleanup_is_offered_and_leaves_the_service_to_the_msi() {
    let p = platform();
    assert!(p.setup().account_cleanup());
    assert!(p.setup().system_uninstall_note().is_some());
    assert!(p.setup().uninstall_helper("winvpn-dev").is_ok());
}

#[test]
fn https_catalogs_and_updates_are_not_available_yet() {
    let p = platform();
    assert!(p.release_source().latest_release(1, "SepsiG/MacVPN").is_err());
    assert!(matches!(
        p.shell().open_url("http://example.com"),
        Err(PlatformError::Failed(_)) | Err(PlatformError::Unsupported { .. })
    ));
    assert!(p.shell().open_path(Path::new("relative")).is_err());
}

#[test]
fn a_file_without_a_zone_stream_is_not_marked() {
    let dir = std::env::temp_dir().join(format!("winvpn-zone-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.ovpn");
    std::fs::write(&file, b"client\n").unwrap();
    let p = platform();
    assert!(!p.download_mark().is_marked(&file));
    let mut stream = file.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::write(&stream, b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    assert!(p.download_mark().is_marked(&file), "a real alternate data stream is read");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_registry_round_trips() {
    assert!(macvpn_platform_win::registry_round_trip_for_tests());
}

/// Launch at login over a test-named Run value (`WinVPN-test-<uuid>`, never WinVPN's own), removed at the end with
/// its StartupApproved twin.
#[test]
fn the_run_key_item_round_trips_and_honours_settings() {
    let name = format!("WinVPN-test-{}", Uuid::new_v4());
    let exe = Path::new(r"C:\WinVPN test\WinVPN.exe");
    let mut item = macvpn_platform_win::run_key_item_for_tests(exe, &name);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(!item.state().is_on);
        assert!(item.state().can_toggle);
        item.set_enabled(true).unwrap();
        assert_eq!(macvpn_platform_win::run_value_for_tests(&name).as_deref(), Some(r#""C:\WinVPN test\WinVPN.exe""#));
        assert_eq!(
            item.state(),
            LoginItemView { is_on: true, can_toggle: true, note: None, shows_open_settings: false }
        );
        // Turned off in Settings → Apps → Startup: off, with the note and the button.
        macvpn_platform_win::startup_approved_for_tests(&name, Some(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        let view = item.state();
        assert!(!view.is_on && view.shows_open_settings && view.note.is_some(), "{view:?}");
        macvpn_platform_win::startup_approved_for_tests(&name, Some(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(item.state().is_on);
        // Switching it on here turns the Settings switch back on too.
        macvpn_platform_win::startup_approved_for_tests(&name, Some(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        item.set_enabled(true).unwrap();
        assert!(item.state().is_on);
        // Another program's command under our name is not ours.
        macvpn_platform_win::set_run_value_for_tests(&name, r"C:\elsewhere\WinVPN.exe");
        assert!(!item.state().is_on);
        item.set_enabled(false).unwrap();
        assert_eq!(macvpn_platform_win::run_value_for_tests(&name), None);
        assert!(!item.state().is_on);
        assert!(!item.unregister_if_registered().unwrap());
        item.set_enabled(true).unwrap();
        assert!(item.unregister_if_registered().unwrap());
        assert_eq!(macvpn_platform_win::run_value_for_tests(&name), None);
    }));
    macvpn_platform_win::remove_run_values_for_tests(&name);
    assert_eq!(macvpn_platform_win::run_value_for_tests(&name), None);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn a_relative_or_quoted_executable_is_never_registered() {
    let name = format!("WinVPN-test-{}", Uuid::new_v4());
    for exe in [Path::new("WinVPN.exe"), Path::new("C:\\x\" -evil\\WinVPN.exe")] {
        let mut item = macvpn_platform_win::run_key_item_for_tests(exe, &name);
        assert!(item.set_enabled(true).is_err());
    }
    assert_eq!(macvpn_platform_win::run_value_for_tests(&name), None);
    macvpn_platform_win::remove_run_values_for_tests(&name);
}

#[test]
fn the_platform_login_item_without_an_installed_app_cannot_toggle() {
    let p = platform_with(false);
    let home = Path::new(r"C:\Users\nobody");
    assert!(!p.login_items(home, None, false).state().can_toggle);
    assert!(!p.login_items(home, Some(Path::new(r"C:\Program Files\WinVPN")), true).state().can_toggle);
}

/// The forwarding pipe. An SSH session is a network logon, which the production pipe refuses: the test listens with
/// network logons allowed; everything else is the production path. Fails if WinVPN itself runs in this session.
#[test]
fn a_second_claim_forwards_to_the_first() {
    use macvpn_platform_win::{Claim, claim};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;
    let Claim::First(guard) = claim(&[]).unwrap() else { panic!("another WinVPN runs for this user: close it first") };
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    guard
        .listen_allowing_network_logons_for_tests(Box::new(move |paths| tx.lock().unwrap().send(paths).unwrap()))
        .unwrap();
    let file = std::env::temp_dir().join("forwarded.ovpn");
    assert!(matches!(claim(std::slice::from_ref(&file)).unwrap(), Claim::Forwarded));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), vec![file.clone()]);
    // An empty list: "show yourself".
    assert!(matches!(claim(&[]).unwrap(), Claim::Forwarded));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Vec::<PathBuf>::new());
    // A message with a relative path is dropped as a whole.
    assert!(matches!(claim(&[file, PathBuf::from("relative.ovpn")]).unwrap(), Claim::Forwarded));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Vec::<PathBuf>::new());
    // A path the format cannot carry is refused by the sender.
    assert!(claim(&[PathBuf::from("C:\\a\nb.ovpn")]).is_err());
    drop(guard);
}

/// The clipboard is global: `platform()` holds the clipboard lock, so no other test copies or owns the clipboard's
/// window meanwhile.
#[test]
fn the_secret_clipboard_clears_only_its_own_text() {
    let p = platform();
    let mark = p.clipboard().write_secret("fixture-secret").unwrap();
    assert_eq!(macvpn_platform_win::clipboard_excludes_for_tests(), [true; 3], "kept out of history and sync");
    assert!(p.clipboard().clear_if_unchanged(mark));
    assert_eq!(macvpn_platform_win::clipboard_excludes_for_tests(), [false; 3], "cleared");
    let mark = p.clipboard().write_secret("fixture-secret").unwrap();
    p.shell().copy_text("the user's own text").unwrap();
    assert_eq!(macvpn_platform_win::clipboard_excludes_for_tests(), [false; 3], "plain text is plain");
    assert!(!p.clipboard().clear_if_unchanged(mark), "the user's copy stays");
}

#[test]
fn the_tray_tint_is_black_or_white() {
    let p = platform();
    let tint = p.windows().tray_tint().unwrap();
    assert!(tint == [0, 0, 0] || tint == [255, 255, 255]);
}

#[test]
fn without_a_window_the_ui_services_do_nothing() {
    let p = platform();
    let none = NativeWindow(std::ptr::null_mut());
    assert_eq!(p.windows().popover_corner_radius(), 8.0);
    assert_eq!(p.windows().window_corner_radius(), Some(8.0), "every window is rounded on Windows 11");
    assert!(!p.windows().round_corners(none, 8.0));
    assert_eq!(p.windows().fit_viewport(none, 320.0, 400.0, true), None);
    assert!(!p.windows().set_outer_frame(none, 0, 0, 330, 400));
    p.windows().order_front_regardless(none);
    let files = Rc::new(RefCell::new(None));
    let f = files.clone();
    p.file_panels().choose_files(none, true, Box::new(move |paths| *f.borrow_mut() = Some(paths)));
    assert_eq!(files.borrow_mut().take(), Some(Vec::new()), "answered at once, as cancel");
    let saved = Rc::new(RefCell::new(None));
    let s = saved.clone();
    p.file_panels().choose_save_path(
        none,
        "a.ovpn",
        Some("Export"),
        Box::new(move |path| *s.borrow_mut() = Some(path)),
    );
    assert_eq!(saved.borrow_mut().take(), Some(None));
}

/// Without the Start-menu shortcut (a test run) Windows may refuse the toast: errors are swallowed, never a panic.
#[test]
fn toasts_post_and_remove_without_failing() {
    let p = platform();
    p.notifier().start(Box::new(|_| {}));
    let long = "x".repeat(100);
    for id in ["winvpn-test-toast", long.as_str()] {
        p.notifier().post(id, "Office VPN", "Test <toast> & more", ("connection", "test"));
        p.notifier().remove_delivered(id);
    }
}

#[test]
fn the_sandbox_has_no_network_probe_and_the_watch_starts_and_stops() {
    assert!(matches!(platform_with(true).network().snapshot(), Err(PlatformError::Unsupported { .. })));
    let p = platform_with(false);
    for _ in 0..5 {
        drop(p.network().watch(Box::new(|| {})).unwrap());
    }
}

/// Read-only live probe (sends one ARP / NDP request to the default gateway): prints the snapshot, the MAC cut to
/// its vendor part. Run by hand: `cargo test -p macvpn-platform-win --test windows -- --ignored --nocapture probe_`.
#[test]
#[ignore = "live network: run by hand with --ignored"]
fn probe_the_network_snapshot() {
    let s = platform_with(false).network().snapshot().unwrap();
    let g = s.gateway.as_ref().expect("a default gateway");
    eprintln!(
        "gateway {} on {:?}: MAC {}, SSID {:?}",
        g.ip,
        g.interface,
        g.mac.map(|m| format!("{:02x}:{:02x}:{:02x}:xx:xx:xx", m[0], m[1], m[2])).unwrap_or("none".into()),
        g.ssid
    );
    eprintln!("connected: {:?}", s.connected.iter().map(|p| format!("{}/{}", p.addr, p.len)).collect::<Vec<_>>());
    assert!(g.mac.is_some());
    assert!(s.connected.iter().any(|p| p.contains(&g.ip)), "the gateway is on a connected subnet");
}
