//! `MacPlatform` and the platform-api adapters (moved from the app in 1.5). Network-free; the sandbox platform
//! never touches the real Keychain or the real preferences, and the real one is only asked for values that read
//! nothing from the system.
#![cfg(target_os = "macos")]

use macvpn_core::l10n::{self, AppLanguage, TextPlatform};
use macvpn_core::models::{Connection, NativeSettings, SecretField, VPNKind};
use macvpn_core::{exporter, mobileconfig};
use macvpn_platform_api::{
    Accepted, ControlTransport, LegacySecrets, LogStreamSpawner, MACVPN, PeerUser, Platform, ReleaseSource,
};
use macvpn_platform_mac::api::{GitHubReleases, Keychain, LogStreams, MacPlatform, Transport, app_bundle};
use macvpn_platform_mac::control_socket;
use macvpn_platform_mac::http::HttpResponse;
use macvpn_platform_mac::secrets::{InMemoryKeychain, KeychainSecretStore, SecretStore};
use macvpn_platform_mac::testing::MockHttpClient;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn bundle_detection() {
    assert_eq!(
        app_bundle(Path::new("/Applications/MacVPN.app/Contents/MacOS/macvpn-app")),
        Some(PathBuf::from("/Applications/MacVPN.app"))
    );
    assert_eq!(app_bundle(Path::new("/repo/target/debug/macvpn-app")), None);
    assert_eq!(app_bundle(Path::new("/x/Contents/MacOS/macvpn-app")), None);
}

#[test]
fn keychain_fields_map_to_the_platform_store() {
    let store = KeychainSecretStore::new(InMemoryKeychain::new());
    let id = Uuid::new_v4();
    store.set("pw", &id, SecretField::Password);
    store.set("k", &id, SecretField::Psk);
    let reader = Keychain(store);
    assert_eq!(reader.get(&id, SecretField::Password).as_deref(), Some("pw"));
    assert_eq!(reader.get(&id, SecretField::Psk).as_deref(), Some("k"));
    assert_eq!(reader.get(&id, SecretField::Username), None);
}

#[test]
fn log_stream_command_line_is_the_1_4_text() {
    assert_eq!(
        LogStreams.command_line(),
        r#"log stream --style compact --predicate 'process IN {"racoon","pppd","neagent","nesessionmanager"} OR subsystem == "com.apple.networkextension"'"#
    );
    assert_eq!(MacPlatform::new(true).log_streams().command_line(), LogStreams.command_line());
}

#[test]
fn the_product_is_macvpn_and_its_data_lives_in_application_support() {
    let platform = MacPlatform::new(false);
    assert_eq!(platform.product(), &MACVPN);
    let home = Path::new("/Users/x");
    let root = platform.system().app_data_root(home);
    assert_eq!(root, Path::new("/Users/x/Library/Application Support"));
    assert_eq!(MACVPN.data_dir(&root), Path::new("/Users/x/Library/Application Support/MacVPN"));
    assert_eq!(platform.system().bundled_helper_dir(Path::new("/nonexistent/MacVPN.app")), None, "no bundled mvpn");
    platform.install_core_hooks();
    assert_eq!(l10n::text_platform(), TextPlatform::MACOS);
}

/// The paths the app used to take from platform-mac directly: the root layer's log of a connection, the update
/// cache (removed with the user data), the user's name for the root installer.
#[test]
fn the_helper_log_the_update_cache_and_the_user_name_are_the_1_4_ones() {
    use macvpn_platform_mac::mvpn_client::MvpnClient;
    use macvpn_platform_mac::update_installer::UpdateInstaller;
    let platform = MacPlatform::new(false);
    let id = Uuid::parse_str("31111111-2222-4333-8444-555555555555").unwrap();
    assert_eq!(platform.helper_client().log_path(&id), Some(MvpnClient::log_path(&id)));
    assert_eq!(
        platform.helper_client().log_path(&id),
        Some(PathBuf::from("/var/log/macvpn/31111111-2222-4333-8444-555555555555.log"))
    );
    let home = Path::new("/Users/x");
    assert_eq!(platform.updater().cache_directory(home), Some(UpdateInstaller::default_cache_directory(home)));
    assert_eq!(platform.updater().cache_directory(home), Some(PathBuf::from("/Users/x/Library/Caches/MacVPN")));
    assert_eq!(platform.system().user_name(), macvpn_platform_mac::root_installer::current_user_name());
    assert!(platform.system().user_name().is_some_and(|name| !name.is_empty()));
}

/// The control audit file's directory is prepared as the socket's: created 0700, a symlink refused.
#[test]
fn the_transport_prepares_the_private_directory() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("mvpd-{}", &Uuid::new_v4().simple().to_string()[..8]));
    let dir = root.join("control");
    let transport = MacPlatform::new(true).control_transport();
    transport.prepare_dir(&dir).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777, 0o700);
    let link = root.join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    assert!(transport.prepare_dir(&link).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

/// A staged profile goes once its service is listed; the launch sweep deletes what a previous run left.
#[test]
fn staged_profiles_are_swept_and_dropped_once_their_service_is_listed() {
    let parent = std::env::temp_dir().join(format!("mvps-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&parent).unwrap();
    let staged = || {
        std::fs::read_dir(&parent)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("macvpn-profile."))
            .count()
    };
    let platform = MacPlatform::new(true);
    let profiles = platform.native_profiles(&parent, false);
    let id = Uuid::new_v4();
    profiles.install(&id, b"profile", "Office.mobileconfig", false).unwrap();
    assert_eq!(staged(), 1);
    profiles.services_seen(&std::collections::HashSet::from([Uuid::new_v4()]));
    assert_eq!(staged(), 1, "another connection's service");
    profiles.services_seen(&std::collections::HashSet::from([id]));
    assert_eq!(staged(), 0, "its service is listed");
    // A leftover of a previous run (not tracked by this one).
    MacPlatform::new(true).native_profiles(&parent, false).install(&id, b"profile", "Old.mobileconfig", false).unwrap();
    assert_eq!(staged(), 1);
    profiles.sweep_leftovers();
    assert_eq!(staged(), 0);
    let _ = std::fs::remove_dir_all(&parent);
}

#[test]
fn native_profiles_build_the_same_mobileconfig_bytes() {
    let profiles = MacPlatform::new(true).native_profiles(Path::new("/nonexistent"), false);
    for (kind, group) in [(VPNKind::L2tp, ""), (VPNKind::Cisco, "Staff")] {
        let mut c = Connection::new("Office VPN: Branch/1", kind);
        c.native_service_name = Some("Office VPN".into());
        c.native = Some(NativeSettings {
            server: "vpn.example.com".into(),
            account: "alice".into(),
            group_name: group.into(),
            send_all_traffic: true,
        });
        let built = profiles.build(&c, "shared-psk").unwrap();
        assert_eq!(*built.data, mobileconfig::generate(&c, "shared-psk").unwrap(), "{kind:?}");
        assert_eq!(built.file_name, exporter::file_name(&c), "{kind:?}");
    }
    let openvpn = Connection::new("Not native", VPNKind::Openvpn);
    assert!(profiles.build(&openvpn, "").is_err());
}

#[test]
fn the_sandbox_keeps_the_auto_unlock_key_and_the_preferences_in_memory() {
    let platform = MacPlatform::new(true);
    assert!(platform.is_sandbox());
    let keys = platform.key_store();
    assert!(Arc::ptr_eq(&keys, &platform.key_store()), "one store per platform");
    assert!(!keys.exists().unwrap());
    keys.set(b"0123456789abcdef0123456789abcdef").unwrap();
    assert_eq!(keys.get().unwrap().as_deref().map(|k| k.len()), Some(32));
    assert!(!MacPlatform::new(true).key_store().exists().unwrap(), "another sandbox has its own");

    let prefs = platform.preferences();
    assert!(Arc::ptr_eq(&prefs, &platform.preferences()));
    prefs.set_bool("api-test-key", true);
    prefs.set_string("api-test-string", "x");
    assert_eq!(prefs.bool("api-test-key"), Some(true));
    assert_eq!(prefs.string("api-test-key"), None, "typed values");
    assert_eq!(MacPlatform::new(true).preferences().bool("api-test-key"), None, "not the real domain");
    prefs.remove_all();
    assert_eq!(prefs.string("api-test-string"), None);
}

#[test]
fn the_sandbox_login_item_cannot_be_registered() {
    let platform = MacPlatform::new(true);
    let home = std::env::temp_dir().join(format!("macvpn-api-{}", Uuid::new_v4()));
    let mut items = platform.login_items(&home, Some(Path::new("/Applications/MacVPN.app")), true);
    let state = items.state();
    assert!(!state.is_on);
    assert!(state.can_toggle, "from the Applications folder");
    let error = items.set_enabled(true).unwrap_err();
    assert_eq!(error.message(), "sandbox: launch at login is not registered");
    assert!(!items.state().is_on);
    assert_eq!(items.unregister_if_registered(), Ok(false));
    assert_eq!(items.remove_stale_entries(), Ok(()));
    assert!(!home.exists(), "nothing written");
}

#[test]
fn the_sandbox_never_runs_the_root_installer() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let platform = MacPlatform::new(true);
    let setup = platform.setup();
    assert_eq!(
        setup.install_helper(Path::new("/nonexistent"), "nobody").unwrap_err().message(),
        "Installation cancelled"
    );
    assert_eq!(setup.uninstall_helper("nobody").unwrap_err().message(), "Uninstall cancelled");
    assert!(setup.helper_upgrade_notice().contains("disconnect active VPN connections"));
    AppLanguage::set_thread_override(None);
}

/// The sandbox refuses every HTTPS catalog source, with the text the smoke run expects (debug builds only:
/// release builds have no sandbox).
#[cfg(debug_assertions)]
#[test]
fn the_sandbox_refuses_https_catalog_sources() {
    use macvpn_core::catalog::fetch::FetchRequest;
    use macvpn_core::catalog::format::CatalogError;
    use macvpn_core::catalog::source::CatalogSource;
    use macvpn_core::vault::SourceValidators;
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let source = CatalogSource::File(PathBuf::from("/nonexistent/acme.macvpncatalog"));
    let previous = SourceValidators::default();
    let request = FetchRequest { source: &source, bearer: None, previous: &previous };
    let refused = MacPlatform::new(true).https_catalog_fetcher().fetch(&request);
    assert!(
        matches!(&refused, Err(CatalogError::Io(m)) if m == "HTTPS sources are not available in the sandbox"),
        "{refused:?}"
    );
    AppLanguage::set_thread_override(None);
}

/// The sandbox does not run brew: the System Status window gets the installer's header, one line and the footer.
#[test]
fn the_sandbox_never_runs_brew() {
    use macvpn_platform_api::SetupReport;
    use macvpn_platform_mac::brew::BrewInstaller;
    // The header and footer are localized: pin the language (other tests in this binary change it).
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let report = SetupReport { package_manager: Some("/nonexistent/homebrew".into()), ..SetupReport::unknown() };
    let mut output = String::new();
    MacPlatform::new(true).setup().install_tools(&report, &mut |text| output.push_str(text)).unwrap();
    assert_eq!(output, format!("{}(sandbox: brew is not run)\n{}", BrewInstaller::header(), BrewInstaller::footer(0)));
    // Without Homebrew nothing runs and nothing is printed.
    let mut nothing = String::new();
    assert!(
        MacPlatform::new(true).setup().install_tools(&SetupReport::unknown(), &mut |t| nothing.push_str(t)).is_err()
    );
    assert!(nothing.is_empty());
    AppLanguage::set_thread_override(None);
}

/// The sandbox's old Keychain: the migration (`legacy_keychain`) and the read-only mode (`legacy_secrets`) read
/// the one memory keychain the smoke run seeds.
#[cfg(debug_assertions)]
#[test]
fn the_sandbox_shares_one_memory_keychain_for_the_old_items() {
    use macvpn_core::vault::LegacyRead;
    use macvpn_platform_api::SmokeHooks;
    const PSK_ITEM: &str = "31111111-2222-4333-8444-555555555555";
    let platform = MacPlatform::new(true);
    let id = Uuid::parse_str(PSK_ITEM).unwrap();
    assert_eq!(platform.legacy_secrets().get(&id, SecretField::Psk), None);
    platform.seed_legacy_keychain(&[(
        "local.macvpn.secrets".to_string(),
        format!("{PSK_ITEM}.psk"),
        b"seeded-psk".to_vec(),
    )]);
    assert_eq!(platform.legacy_secrets().get(&id, SecretField::Psk).as_deref(), Some("seeded-psk"));
    let keychain = platform.legacy_keychain();
    assert_eq!(keychain.items(), [(PSK_ITEM.to_string(), SecretField::Psk)]);
    assert!(matches!(keychain.read(PSK_ITEM, SecretField::Psk), LegacyRead::Value(v) if v.as_str() == "seeded-psk"));
    // A migration in the sandbox is a no-op (never the real Keychain).
    platform.migrate_legacy_service();
    // Another sandbox platform has its own keychain.
    assert_eq!(MacPlatform::new(true).legacy_secrets().get(&id, SecretField::Psk), None);
}

fn release_json(assets: &[&str]) -> Vec<u8> {
    let assets: Vec<String> = assets
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","browser_download_url":"https://github.com/SepsiG/MacVPN/releases/download/v1.5.0/{name}"}}"#
            )
        })
        .collect();
    format!(
        r#"{{"tag_name":"v1.5.0","name":"MacVPN 1.5.0","draft":false,"prerelease":false,"html_url":"https://github.com/SepsiG/MacVPN/releases/tag/v1.5.0","published_at":"2026-10-20T10:00:00Z","body":"","assets":[{}]}}"#,
        assets.join(",")
    )
    .into_bytes()
}

#[test]
fn the_release_source_wants_the_macvpn_dmg() {
    let url = "https://api.github.com/repositories/42/releases/latest";
    let http = MockHttpClient::new();
    http.respond(url, HttpResponse::new(200, &release_json(&["WinVPN-1.5.0-x64.msi", "WinVPN-1.5.0-x64.msi.sha256"])));
    assert!(GitHubReleases(http).latest_release(42, "SepsiG/MacVPN").is_err(), "no MacVPN DMG");

    let http = MockHttpClient::new();
    http.respond(
        url,
        HttpResponse::new(200, &release_json(&["MacVPN-1.5.0.dmg", "MacVPN-1.5.0.dmg.sha256", "MacVPN-1.5.0.dmg.sig"])),
    );
    let release = GitHubReleases(http).latest_release(42, "SepsiG/MacVPN").unwrap();
    assert_eq!(release.version, "1.5.0");
    assert_eq!(release.package.name, "MacVPN-1.5.0.dmg");

    let http = MockHttpClient::new();
    assert!(GitHubReleases(http).latest_release(42, "SepsiG/MacVPN").is_err(), "HTTP 404");
}

/// The macOS transport: the socket path is the endpoint, an accepted client is a blocking stream with this
/// process as its peer, and `peer_connected` follows the client.
#[test]
fn the_transport_accepts_and_identifies_a_client() {
    // A short directory: the socket path must fit `sun_path`.
    let root = PathBuf::from(format!("/tmp/mvtr-{}", &Uuid::new_v4().simple().to_string()[..8]));
    let dir = root.join("control");
    let transport = MacPlatform::new(true).control_transport();
    let endpoint = transport.bind(&dir).unwrap();
    let path = dir.join(control_socket::SOCKET_NAME);
    assert_eq!(endpoint.display, path.display().to_string());
    assert_eq!(endpoint.socket_file.as_deref(), Some(path.as_path()));
    assert!(matches!(endpoint.listener.accept(Duration::from_millis(1)).unwrap(), Accepted::Idle));
    let client = UnixStream::connect(&path).unwrap();
    let (stream, peer) = loop {
        if let Accepted::Client { stream, peer } = endpoint.listener.accept(Duration::from_millis(5)).unwrap() {
            break (stream, peer.unwrap());
        }
    };
    assert!(peer.same_user);
    assert_eq!(peer.pid, std::process::id() as i32);
    assert!(matches!(peer.user, PeerUser::Uid(_)));
    assert!(stream.peer_connected());
    assert!(stream.peer_connected(), "the check leaves the stream blocking and usable");
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while stream.peer_connected() {
        assert!(std::time::Instant::now() < deadline, "still connected after the close");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(Transport.is_already_closed(&io::Error::from_raw_os_error(22)), "EINVAL");
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&root);
}
