//! The Windows platform, phase 1: a stub. Every fallible call answers [`PlatformError::Unsupported`] (or its
//! localized message, "Not available on this system yet"); every call that cannot fail is inert. It fails closed:
//! no auto-unlock key, no entropy (so no vault can be created by mistake), no control endpoint, no helper or
//! native VPN action, no catalog fetch, no file written.
//!
//! No `cfg`, no `unsafe` and no `windows-sys`: it compiles on every OS, so the macOS checks cover it. Phase 2
//! replaces it with the real Windows platform. The Windows app exits at `platform::supported()` before any window
//! opens, so none of this is shown in phase 1.

#![forbid(unsafe_code)]

use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::date::Date;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Connection, SecretField, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_core::update::{self, Release};
use macvpn_core::vault::{Entropy, KeyStore, KeyStoreError, LegacyKeychain, LegacyRead};
use macvpn_platform_api::{
    AppLifecycle, AuthStateReader, BootstrapTexts, BoundEndpoint, ClipboardMark, ControlTransport, DownloadMark,
    FilePanels, HelperClient, LegacySecrets, LogStreamSpawner, LoginItemView, LoginItems, MemoryPreferences,
    NativeController, NativeProfile, NativeProfiles, NativeWindow, NoAuthState, Notifier, Platform, PlatformError,
    PreferenceStore, Product, ReleaseSource, SecretClipboard, SetupReport, Shell, StreamHandle, SystemInfo,
    SystemSetup, SystemVpn, SystemVpnWatch, TerminateReply, UpdateOutcome, Updater, WINVPN, WindowChrome,
};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The Windows platform of phase 1.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinPlatform;

/// `what` of every unsupported facility (for the code; the message never shows it).
fn unsupported(what: &'static str) -> PlatformError {
    PlatformError::Unsupported { what }
}

/// The localized "Not available on this system yet", for the traits whose errors are messages.
fn message(what: &'static str) -> String {
    unsupported(what).message()
}

/// An I/O error of kind `Unsupported` (the message is not shown to the user).
fn io_unsupported(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{what}: not supported on this platform yet"))
}

impl Platform for WinPlatform {
    fn product(&self) -> &'static Product {
        &WINVPN
    }

    /// Only the text platform: collation and the preferred languages keep core's defaults.
    fn install_core_hooks(&self) {
        l10n::set_text_platform(WINVPN.text_platform());
    }

    fn system(&self) -> &dyn SystemInfo {
        self
    }

    fn shell(&self) -> &dyn Shell {
        self
    }

    fn setup(&self) -> &dyn SystemSetup {
        self
    }

    fn updater(&self) -> &dyn Updater {
        self
    }

    fn windows(&self) -> &dyn WindowChrome {
        self
    }

    fn file_panels(&self) -> &dyn FilePanels {
        self
    }

    fn notifier(&self) -> &dyn Notifier {
        self
    }

    fn clipboard(&self) -> &dyn SecretClipboard {
        self
    }

    fn lifecycle(&self) -> &dyn AppLifecycle {
        self
    }

    fn download_mark(&self) -> &dyn DownloadMark {
        self
    }

    fn system_vpn_watch(&self) -> &dyn SystemVpnWatch {
        self
    }

    fn control_transport(&self) -> Arc<dyn ControlTransport> {
        Arc::new(WinPlatform)
    }

    fn helper_client(&self) -> Arc<dyn HelperClient> {
        Arc::new(WinPlatform)
    }

    fn native_controller(&self) -> Arc<dyn NativeController> {
        Arc::new(WinPlatform)
    }

    fn native_profiles(&self, _staging: &Path, _open: bool) -> Arc<dyn NativeProfiles> {
        Arc::new(WinPlatform)
    }

    fn auth_state(&self) -> Arc<dyn AuthStateReader> {
        Arc::new(NoAuthState)
    }

    fn log_streams(&self) -> Arc<dyn LogStreamSpawner> {
        Arc::new(WinPlatform)
    }

    fn release_source(&self) -> Arc<dyn ReleaseSource> {
        Arc::new(WinPlatform)
    }

    fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher> {
        Arc::new(WinPlatform)
    }

    fn key_store(&self) -> Arc<dyn KeyStore> {
        Arc::new(WinPlatform)
    }

    fn entropy(&self) -> Arc<dyn Entropy> {
        Arc::new(WinPlatform)
    }

    fn legacy_keychain(&self) -> Arc<dyn LegacyKeychain> {
        Arc::new(WinPlatform)
    }

    fn legacy_secrets(&self) -> Arc<dyn LegacySecrets> {
        Arc::new(WinPlatform)
    }

    fn migrate_legacy_service(&self) {}

    fn preferences(&self) -> Arc<dyn PreferenceStore> {
        Arc::new(MemoryPreferences::default())
    }

    fn login_items(&self, _home: &Path, _app: Option<&Path>, _sandbox: bool) -> Box<dyn LoginItems> {
        Box::new(WinPlatform)
    }
}

// MARK: - System

impl SystemInfo for WinPlatform {
    fn home_directory(&self) -> Option<PathBuf> {
        None
    }

    /// Windows' roaming app data under `home` (phase 2 reads the known folder).
    fn app_data_root(&self, home: &Path) -> PathBuf {
        home.join("AppData").join("Roaming")
    }

    /// No owner can be read on Windows in phase 1 (`FileOwner` has no value there, core's `fsx`).
    fn user_owner(&self) -> Result<FileOwner, PlatformError> {
        Err(unsupported("file owner"))
    }

    fn user_name(&self) -> Option<String> {
        None
    }

    fn temporary_directory(&self) -> Result<PathBuf, PlatformError> {
        Err(unsupported("temporary directory"))
    }

    /// `YYYY-MM-DD` (UTC; phase 2 uses the system's format).
    fn local_date(&self, unix: f64) -> String {
        Date::from_time_interval_since_1970(unix).iso8601().chars().take(10).collect()
    }

    /// ISO 8601 (UTC; phase 2 uses the system's format).
    fn local_date_time(&self, unix: f64, _language: AppLanguage) -> String {
        Date::from_time_interval_since_1970(unix).iso8601()
    }

    fn app_location(&self) -> Option<PathBuf> {
        None
    }

    fn bundled_helper_dir(&self, _app: &Path) -> Option<PathBuf> {
        None
    }

    fn update_info(&self, _app: &Path) -> Option<update::Info> {
        None
    }
}

impl Shell for WinPlatform {
    fn open_path(&self, _path: &Path) -> Result<(), PlatformError> {
        Err(unsupported("open file"))
    }

    fn open_url(&self, _url: &str) -> Result<(), PlatformError> {
        Err(unsupported("open URL"))
    }

    fn open_native_profile_settings(&self) {}

    fn copy_text(&self, _text: &str) -> Result<(), PlatformError> {
        Err(unsupported("clipboard"))
    }
}

impl SystemSetup for WinPlatform {
    /// Nothing found: no helper-run kind is available.
    fn check(&self, _bundled_helper_dir: Option<&Path>) -> SetupReport {
        SetupReport::unknown()
    }

    fn install_package_manager(
        &self,
        _texts: &BootstrapTexts,
        _parent: &Path,
        _sandbox: bool,
    ) -> Result<(), PlatformError> {
        Err(unsupported("package manager"))
    }

    fn install_tools(&self, _report: &SetupReport, _output: &mut dyn FnMut(&str)) -> Result<(), PlatformError> {
        Err(unsupported("VPN tools"))
    }

    fn install_helper(&self, _source_dir: &Path, _user: &str) -> Result<(), PlatformError> {
        Err(unsupported("helper"))
    }

    fn uninstall_helper(&self, _user: &str) -> Result<(), PlatformError> {
        Err(unsupported("helper"))
    }

    fn helper_upgrade_notice(&self) -> String {
        message("helper")
    }
}

impl Updater for WinPlatform {
    fn install(
        &self,
        _release: &Release,
        _app: &Path,
        _home: &Path,
        _stage: &dyn Fn(String),
        _confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Result<UpdateOutcome, String> {
        Err(message("update installer"))
    }

    fn launch_housekeeping(
        &self,
        _app: &Path,
        _home: &Path,
        _noticed: Option<&str>,
    ) -> (Vec<PathBuf>, Option<(String, String)>) {
        (Vec::new(), None)
    }

    fn cache_directory(&self, _home: &Path) -> Option<PathBuf> {
        None
    }
}

impl DownloadMark for WinPlatform {
    fn is_marked(&self, _path: &Path) -> bool {
        false
    }
}

impl SystemVpnWatch for WinPlatform {
    fn start(&self, _on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        Err(io_unsupported("system VPN watch"))
    }
}

// MARK: - UI

impl WindowChrome for WinPlatform {
    fn popover_corner_radius(&self) -> f64 {
        0.0
    }

    fn round_corners(&self, _w: NativeWindow, _radius: f64) -> bool {
        false
    }

    fn fit_viewport(&self, _w: NativeWindow, _width: f64, _viewport: f64, _center: bool) -> Option<f64> {
        None
    }

    fn order_front_regardless(&self, _w: NativeWindow) {}
}

/// No panel opens: `done` is called at once, as on cancel.
impl FilePanels for WinPlatform {
    fn choose_files(&self, _parent: NativeWindow, _multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>) {
        done(Vec::new());
    }

    fn choose_save_path(
        &self,
        _parent: NativeWindow,
        _suggested: &str,
        _message: Option<&str>,
        done: Box<dyn FnOnce(Option<PathBuf>)>,
    ) {
        done(None);
    }
}

impl Notifier for WinPlatform {
    fn start(&self, _on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>) {}

    fn post(&self, _identifier: &str, _title: &str, _body: &str, _user_info: (&str, &str)) {}

    fn remove_delivered(&self, _identifier: &str) {}
}

impl SecretClipboard for WinPlatform {
    fn write_secret(&self, _text: &str) -> Result<ClipboardMark, PlatformError> {
        Err(unsupported("secret clipboard"))
    }

    fn clear_if_unchanged(&self, _mark: ClipboardMark) -> bool {
        false
    }
}

impl AppLifecycle for WinPlatform {
    fn install_terminate_handler(&self, _handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        false
    }

    fn reply_to_terminate(&self, _terminate: bool) {}

    fn observe_wake(&self, _on_wake: Box<dyn Fn() + Send + Sync>) {}
}

// MARK: - Control endpoint

impl ControlTransport for WinPlatform {
    fn bind(&self, _dir: &Path) -> io::Result<BoundEndpoint> {
        Err(io_unsupported("control endpoint"))
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        Err(io_unsupported("system randomness"))
    }

    fn is_already_closed(&self, _e: &io::Error) -> bool {
        false
    }

    fn prepare_dir(&self, _dir: &Path) -> io::Result<()> {
        Err(io_unsupported("control endpoint"))
    }
}

// MARK: - VPNs

impl HelperClient for WinPlatform {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        Err(message("helper"))
    }

    fn up(
        &self,
        _kind: VPNKind,
        _id: &Uuid,
        _config: &[u8],
        _secrets: &Secrets,
        _debug: bool,
        _accept_risky: &[String],
    ) -> Result<(), String> {
        Err(message("helper"))
    }

    fn down(&self, _kind: VPNKind, _id: &Uuid) -> Result<(), String> {
        Err(message("helper"))
    }

    fn respond(&self, _id: &Uuid, _kind: AuthResponseKind, _response: &str) -> Result<(), String> {
        Err(message("helper"))
    }
}

impl NativeController for WinPlatform {
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        Err(message("native VPN"))
    }

    fn remote_address(&self, _service_id: &str) -> Option<String> {
        None
    }

    fn start(&self, _service_id: &str, _kind: Option<NativeKind>, _secrets: &Secrets) -> Result<(), String> {
        Err(message("native VPN"))
    }

    fn stop(&self, _service_id: &str) -> Result<(), String> {
        Err(message("native VPN"))
    }
}

impl NativeProfiles for WinPlatform {
    fn build(&self, _connection: &Connection, _psk: &str) -> Result<NativeProfile, String> {
        Err(message("native VPN profile"))
    }

    fn install(&self, _id: &Uuid, _profile: &[u8], _file_name: &str, _service_existed: bool) -> Result<(), String> {
        Err(message("native VPN profile"))
    }
}

impl LogStreamSpawner for WinPlatform {
    /// No command runs.
    fn command_line(&self) -> String {
        String::new()
    }

    fn spawn(
        &self,
        _on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        _on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String> {
        Err(message("system log stream"))
    }
}

// MARK: - Network

impl ReleaseSource for WinPlatform {
    fn latest_release(&self, _repo_id: i64, _repo: &str) -> Result<Release, String> {
        Err(message("update check"))
    }
}

/// `Unavailable`: the catalog service shows the source as unavailable, without an error notification.
impl CatalogFetcher for WinPlatform {
    fn fetch(&self, _req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        Err(CatalogError::Unavailable(message("HTTPS catalog fetch")))
    }
}

// MARK: - Keys and storage

/// No item is ever stored, so there is no auto-unlock (fail closed).
impl KeyStore for WinPlatform {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Ok(None)
    }

    fn exists(&self) -> Result<bool, KeyStoreError> {
        Ok(false)
    }

    fn set(&self, _key: &[u8]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unavailable(message("key store")))
    }

    /// A missing item is not an error.
    fn delete(&self) -> Result<(), KeyStoreError> {
        Ok(())
    }
}

/// No randomness, so no key, salt or nonce, and no vault, can be made by mistake.
impl Entropy for WinPlatform {
    fn fill(&self, _buf: &mut [u8]) -> io::Result<()> {
        Err(io_unsupported("system randomness"))
    }
}

/// The 1.1 Keychain items exist only on macOS: an empty source.
impl LegacyKeychain for WinPlatform {
    fn items(&self) -> Vec<(String, SecretField)> {
        Vec::new()
    }

    fn read(&self, _item: &str, _field: SecretField) -> LegacyRead {
        LegacyRead::Missing
    }

    fn delete(&self, _item: &str, _field: SecretField) {}
}

impl LegacySecrets for WinPlatform {
    fn get(&self, _id: &Uuid, _field: SecretField) -> Option<String> {
        None
    }
}

/// No login item can be registered.
impl LoginItems for WinPlatform {
    fn state(&self) -> LoginItemView {
        LoginItemView::default()
    }

    fn set_enabled(&mut self, _on: bool) -> Result<(), PlatformError> {
        Err(unsupported("login item"))
    }

    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError> {
        Ok(false)
    }

    fn open_settings(&self) {}

    fn remove_stale_entries(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
