//! The Windows stub (phase 1): every `Platform` accessor is called once and gives either its documented inert
//! value or "not supported". Nothing panics, nothing touches the system.

use macvpn_core::catalog::fetch::FetchRequest;
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, AppLanguage, TextPlatform};
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Connection, SecretField, Secrets, VPNKind};
use macvpn_core::vault::{KeyStoreError, LegacyRead, SourceValidators};
use macvpn_core::{TargetOs, update};
use macvpn_platform_api::{
    BootstrapTexts, LoginItemView, NativeWindow, Platform, PlatformError, SetupReport, TerminateReply, WINVPN,
};
use macvpn_platform_win::WinPlatform;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

const UNSUPPORTED_EN: &str = "Not available on this system yet";

fn platform() -> &'static dyn Platform {
    static PLATFORM: WinPlatform = WinPlatform;
    &PLATFORM
}

/// Runs `f` in English, so the message is the table's key.
fn en<T>(f: impl FnOnce() -> T) -> T {
    l10n::with_language(AppLanguage::En, f)
}

fn assert_unsupported(result: Result<impl std::fmt::Debug, PlatformError>) {
    match result {
        Err(PlatformError::Unsupported { what }) => assert!(!what.is_empty()),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

fn assert_unsupported_message<T: std::fmt::Debug>(result: Result<T, String>) {
    assert_eq!(result.unwrap_err(), UNSUPPORTED_EN);
}

fn assert_io_unsupported<T>(result: io::Result<T>) {
    match result {
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
        Ok(_) => panic!("expected an Unsupported I/O error"),
    }
}

fn window() -> NativeWindow {
    NativeWindow(ptr::null_mut())
}

fn id() -> Uuid {
    Uuid::parse_str("6F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9").expect("a valid UUID")
}

// MARK: - Identity and hooks

#[test]
fn product_is_winvpn() {
    let product = platform().product();
    assert_eq!(product, &WINVPN);
    assert_eq!(product.name, "WinVPN");
    assert_eq!(product.os, TargetOs::Windows);
}

#[test]
fn install_core_hooks_sets_only_the_text_platform() {
    platform().install_core_hooks();
    assert_eq!(l10n::text_platform(), TextPlatform { os: TargetOs::Windows, product: "WinVPN" });
}

// MARK: - System

#[test]
fn system_info_is_inert_or_unsupported() {
    let system = platform().system();
    assert_eq!(system.home_directory(), None);
    assert_eq!(system.user_name(), None);
    assert_eq!(system.app_data_root(Path::new("C:/Users/someone")), PathBuf::from("C:/Users/someone/AppData/Roaming"));
    assert_unsupported(system.temporary_directory());
    assert!(!system.local_date(0.0).is_empty());
    assert!(!system.local_date_time(0.0, AppLanguage::En).is_empty());
    assert_eq!(system.app_location(), None);
    assert_eq!(system.bundled_helper_dir(Path::new("C:/Program Files/WinVPN")), None);
    assert!(system.update_info(Path::new("C:/Program Files/WinVPN")).is_none());
}

#[test]
fn shell_does_nothing() {
    let shell = platform().shell();
    assert_unsupported(shell.open_path(Path::new("C:/Users/someone/report.txt")));
    assert_unsupported(shell.open_url("https://github.com/SepsiG/MacVPN"));
    shell.open_native_profile_settings();
    assert_unsupported(shell.copy_text("text"));
}

#[test]
fn setup_reports_nothing_and_installs_nothing() {
    let setup = platform().setup();
    let report = setup.check(None);
    assert_eq!(report, SetupReport::unknown());
    assert!(!report.is_available(VPNKind::Openvpn));
    let texts = BootstrapTexts { start: "start".into(), done: "done".into(), failed: "failed".into() };
    assert_unsupported(setup.install_package_manager(&texts, Path::new("C:/temp"), false));
    let mut output = String::new();
    assert_unsupported(setup.install_tools(&report, &mut |text| output.push_str(text)));
    assert!(output.is_empty(), "the stub prints nothing");
    assert_unsupported(setup.install_helper(Path::new("C:/helper"), "someone"));
    assert_unsupported(setup.uninstall_helper("someone"));
    assert_eq!(en(|| setup.helper_upgrade_notice()), UNSUPPORTED_EN);
}

#[test]
fn updater_installs_nothing() {
    let updater = platform().updater();
    let asset = |name: &str| update::ReleaseAsset { name: name.into(), url: format!("https://example.com/{name}") };
    let release = update::Release {
        tag: "v1.5.0".into(),
        version: "1.5.0".into(),
        notes: String::new(),
        page_url: None,
        published_at: None,
        package: asset("WinVPN-1.5.0-x64.msi"),
        checksum: asset("WinVPN-1.5.0-x64.msi.sha256"),
        signature: None,
    };
    let quit_asked = AtomicBool::new(false);
    let result = en(|| {
        updater.install(
            &release,
            Path::new("C:/Program Files/WinVPN"),
            Path::new("C:/Users/someone"),
            &|_| {},
            Box::new(|| {
                quit_asked.store(true, Ordering::SeqCst);
                true
            }),
        )
    });
    assert_unsupported_message(result);
    assert!(!quit_asked.load(Ordering::SeqCst));
    let (removed, notice) =
        updater.launch_housekeeping(Path::new("C:/Program Files/WinVPN"), Path::new("C:/Users/someone"), None);
    assert!(removed.is_empty());
    assert_eq!(notice, None);
    assert_eq!(updater.cache_directory(Path::new("C:/Users/someone")), None);
}

// MARK: - UI

#[test]
fn window_chrome_is_inert() {
    let windows = platform().windows();
    assert_eq!(windows.popover_corner_radius(), 0.0);
    assert!(!windows.round_corners(window(), 12.0));
    assert_eq!(windows.fit_viewport(window(), 400.0, 300.0, true), None);
    windows.order_front_regardless(window());
}

#[test]
fn file_panels_answer_cancel_at_once() {
    let panels = platform().file_panels();
    let chosen = Arc::new(std::sync::Mutex::new(None));
    let sink = chosen.clone();
    panels.choose_files(window(), true, Box::new(move |files| *sink.lock().unwrap() = Some(files)));
    assert_eq!(*chosen.lock().unwrap(), Some(Vec::new()));
    let saved = Arc::new(std::sync::Mutex::new(Some(Some(PathBuf::new()))));
    let sink = saved.clone();
    panels.choose_save_path(window(), "export.macvpn", None, Box::new(move |path| *sink.lock().unwrap() = Some(path)));
    assert_eq!(*saved.lock().unwrap(), Some(None));
}

#[test]
fn notifier_posts_nothing() {
    let notifier = platform().notifier();
    notifier.start(Box::new(|_| panic!("no notification can be clicked")));
    notifier.post("id", "title", "body", ("key", "value"));
    notifier.remove_delivered("id");
}

#[test]
fn clipboard_takes_no_secret() {
    let clipboard = platform().clipboard();
    assert_unsupported(clipboard.write_secret("secret"));
    assert!(!clipboard.clear_if_unchanged(macvpn_platform_api::ClipboardMark(0)));
}

#[test]
fn lifecycle_stores_nothing() {
    let lifecycle = platform().lifecycle();
    assert!(!lifecycle.install_terminate_handler(Box::new(|| TerminateReply::Now)));
    lifecycle.reply_to_terminate(true);
    let wake = Arc::new(());
    let held = wake.clone();
    lifecycle.observe_wake(Box::new(move || {
        let _ = &held;
    }));
    // The closure was dropped, not stored.
    assert_eq!(Arc::strong_count(&wake), 1);
}

#[test]
fn download_mark_is_never_read() {
    assert!(!platform().download_mark().is_marked(Path::new("C:/Users/someone/Downloads/office.ovpn")));
}

#[test]
fn system_vpn_watch_does_not_start() {
    assert_io_unsupported(platform().system_vpn_watch().start(Box::new(|| {})));
}

// MARK: - Control endpoint

#[test]
fn control_transport_binds_nothing() {
    let transport = platform().control_transport();
    let dir = std::env::temp_dir().join("macvpn-platform-win-never-created");
    assert_io_unsupported(transport.bind(&dir));
    assert_io_unsupported(transport.prepare_dir(&dir));
    assert!(!dir.exists());
    assert_io_unsupported(transport.random_32());
    assert!(!transport.is_already_closed(&io::Error::from(io::ErrorKind::ConnectionReset)));
}

// MARK: - VPNs

#[test]
fn helper_client_does_nothing() {
    let helper = platform().helper_client();
    en(|| {
        assert_unsupported_message(helper.status());
        assert_unsupported_message(helper.up(VPNKind::Openvpn, &id(), b"client\n", &Secrets::default(), false, &[]));
        assert_unsupported_message(helper.down(VPNKind::Openvpn, &id()));
        assert_unsupported_message(helper.respond(&id(), AuthResponseKind::Static, "123456"));
    });
}

#[test]
fn native_controller_does_nothing() {
    let native = platform().native_controller();
    en(|| {
        assert_unsupported_message(native.list());
        assert_eq!(native.remote_address("service"), None);
        assert_unsupported_message(native.start("service", None, &Secrets::default()));
        assert_unsupported_message(native.stop("service"));
    });
}

#[test]
fn native_profiles_build_and_install_nothing() {
    let staging = std::env::temp_dir().join("macvpn-platform-win-no-staging");
    let profiles = platform().native_profiles(&staging, true);
    let connection = Connection::new("Office VPN", VPNKind::L2tp);
    en(|| {
        assert_unsupported_message(profiles.build(&connection, "psk").map(|p| p.file_name));
        assert_unsupported_message(profiles.install(&id(), b"profile", "office.mobileconfig", false));
    });
    assert!(!staging.exists());
}

#[test]
fn auth_state_reads_nothing() {
    assert!(platform().auth_state().read(&id()).is_none());
}

#[test]
fn log_streams_start_nothing() {
    let logs = platform().log_streams();
    assert_eq!(logs.command_line(), "");
    let result = en(|| logs.spawn(Box::new(|_| {}), Box::new(|| {})));
    assert_eq!(result.err().as_deref(), Some(UNSUPPORTED_EN));
}

// MARK: - Network

#[test]
fn release_source_fetches_nothing() {
    let result = en(|| platform().release_source().latest_release(1, "SepsiG/MacVPN"));
    assert_eq!(result.unwrap_err(), UNSUPPORTED_EN);
}

#[test]
fn catalog_fetcher_fetches_nothing() {
    let source = CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/team.macvpncatalog").unwrap());
    let previous = SourceValidators::default();
    let request = FetchRequest { source: &source, bearer: Some("token"), previous: &previous };
    let result = en(|| platform().https_catalog_fetcher().fetch(&request));
    assert_eq!(result.unwrap_err(), CatalogError::Unavailable(UNSUPPORTED_EN.into()));
}

// MARK: - Keys and storage

#[test]
fn key_store_is_empty_and_refuses_a_key() {
    let store = platform().key_store();
    assert_eq!(store.get(), Ok(None));
    assert_eq!(store.exists(), Ok(false));
    assert!(matches!(store.set(&[7; 32]), Err(KeyStoreError::Unavailable(_))));
    assert_eq!(store.get(), Ok(None));
    assert_eq!(store.delete(), Ok(()));
}

#[test]
fn entropy_fails() {
    let mut buf = [0u8; 32];
    assert_io_unsupported(platform().entropy().fill(&mut buf));
    assert_eq!(buf, [0u8; 32]);
}

#[test]
fn legacy_keychain_is_empty() {
    let legacy = platform().legacy_keychain();
    legacy.prepare();
    assert!(legacy.items().is_empty());
    assert!(matches!(legacy.read("item", SecretField::Password), LegacyRead::Missing));
    legacy.delete("item", SecretField::Password);
    assert_eq!(platform().legacy_secrets().get(&id(), SecretField::Password), None);
    platform().migrate_legacy_service();
}

#[test]
fn preferences_live_in_memory() {
    let prefs = platform().preferences();
    assert_eq!(prefs.bool("flag"), None);
    prefs.set_bool("flag", true);
    assert_eq!(prefs.bool("flag"), Some(true));
    let date = Date::from_time_interval_since_1970(1_700_000_000.0);
    prefs.set_date("when", date);
    assert_eq!(prefs.date("when"), Some(date));
    prefs.set_string("name", "Acme VPN");
    assert_eq!(prefs.string("name").as_deref(), Some("Acme VPN"));
    assert_eq!(prefs.string("flag"), None);
    prefs.remove_all();
    assert_eq!(prefs.bool("flag"), None);
    assert_eq!(prefs.string("name"), None);
}

#[test]
fn login_items_cannot_be_turned_on() {
    let mut items = platform().login_items(Path::new("C:/Users/someone"), None, false);
    assert_eq!(items.state(), LoginItemView::default());
    assert_unsupported(items.set_enabled(true));
    assert_eq!(items.unregister_if_registered(), Ok(false));
    items.open_settings();
    assert_eq!(items.remove_stale_entries(), Ok(()));
}

#[test]
fn messages_are_localized() {
    let result = l10n::with_language(AppLanguage::Hu, || platform().helper_client().status());
    assert_eq!(result.unwrap_err(), "Ezen a rendszeren még nem érhető el");
}

/// `FileOwner` has no value on Windows in phase 1 (core's `fsx`): `user_owner` fails closed, it never panics.
#[test]
fn user_owner_is_unsupported() {
    assert!(matches!(platform().system().user_owner(), Err(PlatformError::Unsupported { what: "file owner" })));
}
