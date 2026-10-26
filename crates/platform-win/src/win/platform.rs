//! The Windows platform of WinVPN: known folders, the user, dates, the shell, entropy, the Credential Manager key
//! store, file preferences, the Mark of the Web, the WinVPN Service's client (OpenVPN and WireGuard, System
//! Status), the native VPNs' RAS engine (`ras_engine`) and the UI services (window chrome, file panels, toasts, the
//! secret clipboard). The lifecycle window and launch at login live in
//! `lifecycle` and `login_item`; the control API listens on `\\.\pipe\WinVPN-control-<SID>` (`control`).

use super::admin_steps::WinAdminSteps;
use super::chrome::Chrome;
use super::clipboard::{self, Clipboard};
use super::control::PipeTransport;
use super::https::{self, WinReleases};
use super::keystore::{CredentialKeyStore, VAULT_TARGET, VAULT_USER};
use super::lifecycle::Lifecycle;
use super::login_item::RunKeyItem;
use super::net::WinNetwork;
use super::panels::Panels;
use super::ras_engine::{RasEngine, RasHelper};
use super::ras_watch::{self, RasWatch};
use super::service_client::ServiceClient;
use super::toast::{self, Toasts};
use super::updater::WinUpdater;
use super::{lifecycle, locale, msgwin, openvpn_install, shell, system};
use crate::pure::openvpn_install::Upgrade;
use crate::pure::openvpn_pins::OPENVPN_VERSION;
use crate::pure::wireguard_update::{self, Offer};
use crate::pure::{dates, engine, ras_connect, system_vpn, texts, update_check, zone};
use macvpn_core::catalog::fetch::CatalogFetcher;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::models::SecretField;
use macvpn_core::update;
use macvpn_core::vault::{Entropy, KeyStore, LegacyKeychain, LegacyRead, MemoryKeyStore};
use macvpn_platform_api::{
    AdminSteps, AppLifecycle, AuthStateReader, BootstrapTexts, BoundEndpoint, ControlTransport, DownloadMark,
    FilePanels, FilePreferences, HelperClient, LegacySecrets, LogStreamSpawner, LoginItemView, LoginItems,
    MemoryPreferences, NativeController, NativeProfiles, NativeSupport, NetworkProbe, NoAdminSteps, NoNetworkProbe,
    Notifier, PackageIndexUpdate, Platform, PlatformError, PreferenceStore, Product, ReleaseSource, SecretClipboard,
    SetupReport, Shell, StreamHandle, SystemInfo, SystemSetup, SystemVpnWatch, Updater, WINVPN, WindowChrome,
};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// The Windows platform. Created once by the app (`platform::init`).
pub struct WinPlatform {
    sandbox: Option<Sandbox>,
    /// The one preference store of the process (created on first use: every caller shares its cache).
    preferences: OnceLock<Arc<dyn PreferenceStore>>,
    toasts: Toasts,
    updater: WinUpdater,
    /// The first system check (the launch's) has run: later ones (System Status opening, "Check Again", after an
    /// install) also ask winget for an OpenVPN update; the launch check does not wait for winget.
    checked_once: AtomicBool,
    /// The native VPNs' engine (one per process: its dials and their states), made on first use.
    ras: OnceLock<Arc<RasEngine>>,
}

/// The sandbox's stores (`MACVPN_SANDBOX_HOME`, debug builds): memory only, never Credential Manager or a file.
struct Sandbox {
    key_store: Arc<MemoryKeyStore>,
    preferences: Arc<MemoryPreferences>,
}

impl WinPlatform {
    /// `sandbox` (debug builds, `MACVPN_SANDBOX_HOME`): memory key store and preferences, data under the sandbox
    /// home; never Credential Manager. Call it on the main thread, before any window exists: it records the main
    /// thread (the file panels run there) and sets the process' AppUserModelID (the toasts').
    pub fn new(sandbox: bool) -> WinPlatform {
        msgwin::remember_main_thread();
        // The clipboard's owner window (secrets copied from other threads name it).
        let _ = msgwin::ensure_main_window();
        toast::set_app_id();
        WinPlatform {
            sandbox: sandbox.then(|| Sandbox {
                key_store: Arc::new(MemoryKeyStore::new()),
                preferences: Arc::new(MemoryPreferences::new()),
            }),
            preferences: OnceLock::new(),
            toasts: Toasts::default(),
            updater: WinUpdater { sandbox },
            checked_once: AtomicBool::new(false),
            ras: OnceLock::new(),
        }
    }

    /// The RAS engine over WinVPN's data directory (the sandbox's: under `MACVPN_SANDBOX_HOME`). At a logoff it
    /// hangs up WinVPN's RAS connections (Windows does it too unless an administrator set `KeepRasConnections`).
    fn ras(&self) -> Arc<RasEngine> {
        self.ras
            .get_or_init(|| {
                // The sandbox exists only in debug builds; its variable's name must not be in a release binary.
                #[cfg(debug_assertions)]
                let sandbox_home = || {
                    std::env::var_os("MACVPN_SANDBOX_HOME")
                        .map(PathBuf::from)
                        .filter(|h| h.is_absolute())
                        .map(|h| default_local_app_data(&h))
                };
                #[cfg(not(debug_assertions))]
                let sandbox_home = || None;
                let root = if self.sandbox.is_some() {
                    sandbox_home()
                } else {
                    system::local_app_data().or_else(|| system::profile().map(|h| default_local_app_data(&h)))
                };
                let engine = Arc::new(RasEngine::open(root.map(|r| WINVPN.data_dir(&r)).as_deref()));
                let at_logoff = engine.clone();
                lifecycle::observe_logoff(Box::new(move || at_logoff.hang_up_all()));
                engine
            })
            .clone()
    }

    pub fn is_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }
}

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

/// `<home>\AppData\Local`, where Windows keeps it by default.
fn default_local_app_data(home: &Path) -> PathBuf {
    home.join("AppData").join("Local")
}

/// System Status' one Windows VPN client row from the Windows services RAS needs (read-only SCM queries; a service
/// that cannot be read counts as not disabled; it replaces `complete_report`'s green row), and the kinds a disabled
/// one makes unavailable (next to Cisco IPsec's entry, each kind once).
fn fill_ras_row(report: &mut SetupReport) {
    system_vpn::apply_ras_row(report, |name| {
        macvpn_winsys::scm::query(name).is_ok_and(|s| s.start_type == macvpn_winsys::scm::START_DISABLED)
    });
}

/// The facilities that are inert in 2a (the update parts come in 2b), and the control transport when the user's SID
/// cannot be read.
struct Inert;

/// The system CSPRNG (`BCryptGenRandom`, system-preferred RNG), the same call as the control pipe's `random_32`.
struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&self, buf: &mut [u8]) -> io::Result<()> {
        macvpn_winsys::random::fill(buf)
    }
}

impl Platform for WinPlatform {
    fn product(&self) -> &'static Product {
        &WINVPN
    }

    /// The preferred UI languages, the locale-aware name comparison and the text platform.
    fn install_core_hooks(&self) {
        locale::install();
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

    /// The signed MSI of this architecture, installed by msiexec after a UAC prompt (`updater`).
    fn updater(&self) -> &dyn Updater {
        &self.updater
    }

    fn windows(&self) -> &dyn WindowChrome {
        &Chrome
    }

    fn file_panels(&self) -> &dyn FilePanels {
        &Panels
    }

    fn notifier(&self) -> &dyn Notifier {
        &self.toasts
    }

    fn clipboard(&self) -> &dyn SecretClipboard {
        &Clipboard
    }

    fn lifecycle(&self) -> &dyn AppLifecycle {
        &Lifecycle
    }

    fn download_mark(&self) -> &dyn DownloadMark {
        self
    }

    fn system_vpn_watch(&self) -> &dyn SystemVpnWatch {
        self
    }

    /// The physical network (`net`); the sandbox has none (never reconnects), as on macOS.
    fn network(&self) -> &dyn NetworkProbe {
        if self.sandbox.is_some() { &NoNetworkProbe } else { &WinNetwork }
    }

    /// `\\.\pipe\WinVPN-control-<SID>`. Without the user's SID: the inert transport, which binds nothing (fail
    /// closed: the control API stays off and says why).
    fn control_transport(&self) -> Arc<dyn ControlTransport> {
        match PipeTransport::for_user() {
            Ok(transport) => Arc::new(transport),
            Err(_) => Arc::new(Inert),
        }
    }

    /// The WinVPN Service over `\\.\pipe\WinVPN`, trusted only when the pipe is owned by SYSTEM (OpenVPN,
    /// WireGuard); IKEv2 and SSTP through the RAS engine in this process.
    fn helper_client(&self) -> Arc<dyn HelperClient> {
        Arc::new(RasHelper { service: ServiceClient::production(), ras: self.ras() })
    }

    /// WinVPN's RAS entries (L2TP) and the user's own Windows VPNs (the engine hands every other ID to
    /// `SystemVpns`).
    fn native_controller(&self) -> Arc<dyn NativeController> {
        self.ras()
    }

    /// Save writes the RAS entry at once (no profile to stage or approve).
    fn native_profiles(&self, _staging: &Path, _open: bool) -> Arc<dyn NativeProfiles> {
        self.ras()
    }

    /// The RAS kinds' settings Windows lacks: Cisco IPsec (option A, `cisco::unsupported`'s text, from the
    /// connection's plan), IKEv2 / SSTP settings.
    fn native_support(&self) -> Arc<dyn NativeSupport> {
        self.ras()
    }

    /// The two UAC steps (trust a CA, allow L2TP behind NAT); none in the sandbox (it runs no elevated program).
    fn admin_steps(&self) -> Arc<dyn AdminSteps> {
        if self.sandbox.is_some() { Arc::new(NoAdminSteps) } else { Arc::new(WinAdminSteps { trust_exe: None }) }
    }

    /// The service's `auth-state` (macOS: the bridge's state file).
    fn auth_state(&self) -> Arc<dyn AuthStateReader> {
        Arc::new(ServiceClient::production())
    }

    fn log_streams(&self) -> Arc<dyn LogStreamSpawner> {
        Arc::new(Inert)
    }

    /// GitHub's `releases/latest` through System32's `curl.exe`, with WinVPN's MSI for this machine.
    fn release_source(&self) -> Arc<dyn ReleaseSource> {
        Arc::new(WinReleases::new())
    }

    /// System32's `curl.exe` through the shared curl layer; the sandbox refuses every HTTPS source (debug builds
    /// only: release builds have no sandbox).
    fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher> {
        #[cfg(debug_assertions)]
        if self.sandbox.is_some() {
            return Arc::new(https::SandboxHttps);
        }
        Arc::new(https::catalog_fetcher())
    }

    /// The sandbox's memory store, else the generic credential `local.winvpn.vault`.
    fn key_store(&self) -> Arc<dyn KeyStore> {
        match &self.sandbox {
            Some(s) => s.key_store.clone(),
            None => Arc::new(CredentialKeyStore::new(VAULT_TARGET, VAULT_USER)),
        }
    }

    fn entropy(&self) -> Arc<dyn Entropy> {
        Arc::new(SystemEntropy)
    }

    fn legacy_keychain(&self) -> Arc<dyn LegacyKeychain> {
        Arc::new(Inert)
    }

    fn legacy_secrets(&self) -> Arc<dyn LegacySecrets> {
        Arc::new(Inert)
    }

    /// The older Keychain service exists only on macOS.
    fn migrate_legacy_service(&self) {}

    /// The sandbox's memory store, else `%LOCALAPPDATA%\WinVPN\preferences.json`. Without a known folder or a
    /// profile, a memory store (nothing is written to a guessed place).
    fn preferences(&self) -> Arc<dyn PreferenceStore> {
        self.preferences
            .get_or_init(|| {
                if let Some(s) = &self.sandbox {
                    return s.preferences.clone();
                }
                let root = system::local_app_data().or_else(|| system::profile().map(|h| default_local_app_data(&h)));
                match root {
                    Some(root) => Arc::new(FilePreferences::new(WINVPN.data_dir(&root).join("preferences.json"))),
                    None => Arc::new(MemoryPreferences::new()),
                }
            })
            .clone()
    }

    /// The Run value `WinVPN` for an installed `WinVPN.exe`; the sandbox and a development build get an item that
    /// cannot be switched on.
    fn login_items(&self, _home: &Path, app: Option<&Path>, sandbox: bool) -> Box<dyn LoginItems> {
        match app {
            Some(app) if !sandbox => Box::new(RunKeyItem::new(app.join("WinVPN.exe"))),
            _ => Box::new(Inert),
        }
    }
}

// MARK: - System

impl SystemInfo for WinPlatform {
    /// `FOLDERID_Profile`.
    fn home_directory(&self) -> Option<PathBuf> {
        system::profile()
    }

    /// The sandbox: `<home>\AppData\Local`; else `FOLDERID_LocalAppData` (or `<home>\AppData\Local` when it
    /// cannot be read).
    fn app_data_root(&self, home: &Path) -> PathBuf {
        if self.sandbox.is_some() {
            return default_local_app_data(home);
        }
        system::local_app_data().unwrap_or_else(|| default_local_app_data(home))
    }

    fn user_owner(&self) -> Result<FileOwner, PlatformError> {
        FileOwner::current_user().map_err(|e| PlatformError::Failed(format!("the current user: {e}")))
    }

    /// Only the helper's installer uses it (2b).
    fn user_name(&self) -> Option<String> {
        None
    }

    fn temporary_directory(&self) -> Result<PathBuf, PlatformError> {
        Ok(std::env::temp_dir())
    }

    fn local_date(&self, unix: f64) -> String {
        system::local_time(unix).map(|(y, mo, d, ..)| dates::date((y, mo, d))).unwrap_or_default()
    }

    fn local_date_time(&self, unix: f64, language: AppLanguage) -> String {
        system::local_time(unix).map(|t| dates::date_time(t, language)).unwrap_or_default()
    }

    /// The directory of `WinVPN.exe` (an installed or bundled build); `None` for a development build.
    fn app_location(&self) -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let name = exe.file_name()?.to_str()?;
        if !name.eq_ignore_ascii_case("WinVPN.exe") {
            return None;
        }
        exe.parent().map(Path::to_path_buf)
    }

    /// The MSI installs the WinVPN Service (there is no in-app installer).
    fn bundled_helper_dir(&self, _app: &Path) -> Option<PathBuf> {
        None
    }

    /// The update source of an installed `WinVPN.exe` (`app` is its folder): the repository and its ID, compiled in
    /// (the MSI has no Info.plist). A development build has none (no update check).
    fn update_info(&self, app: &Path) -> Option<update::Info> {
        (self.app_location().as_deref() == Some(app)).then(update_check::update_info)
    }
}

impl Shell for WinPlatform {
    /// Absolute directories only (Explorer); a file is never opened (that would run it).
    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        shell::open_directory(path)
    }

    /// `https://` only.
    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        shell::open_https(url)
    }

    fn open_native_profile_settings(&self) {
        shell::open_settings("ms-settings:network-vpn");
    }

    /// Plain text (no exclusion formats: the user's own copy, e.g. a log line).
    fn copy_text(&self, text: &str) -> Result<(), PlatformError> {
        clipboard::write(text, false).map(|_| ())
    }
}

impl SystemSetup for WinPlatform {
    /// The WinVPN Service's `engine` facts: the service, OpenVPN and WireGuard rows; the engine-missing state only
    /// when the service is absent, unreachable, of another version or degraded. The native kinds follow the
    /// Windows VPN client row (`ras_connect::complete_report`, then `fill_ras_row`: the Windows services RAS
    /// needs; they need no service). A green OpenVPN row also gets the update check (`openvpn_install::upgrade`;
    /// winget not at launch nor in the sandbox). A green WireGuard row gets the service's wireguard-nt check (fix4),
    /// also not at launch nor in the sandbox; both checks run side by side.
    fn check(&self, _bundled_helper_dir: Option<&Path>) -> SetupReport {
        let client = ServiceClient::production();
        let reach = client.reach();
        let launch = !self.checked_once.swap(true, Ordering::SeqCst);
        let ask = !launch && self.sandbox.is_none();
        let (upgrade, wireguard) = std::thread::scope(|scope| {
            let wireguard =
                (ask && wireguard_update::check_for(&reach)).then(|| scope.spawn(|| client.wireguard_check()));
            let upgrade = engine::update_check_for(&reach)
                .map_or(Upgrade::Unknown, |installed| openvpn_install::upgrade(installed, ask));
            (upgrade, wireguard.and_then(|w| w.join().ok()).unwrap_or(Offer::Unknown))
        });
        let mut report = engine::report(reach, OPENVPN_VERSION, &upgrade, &wireguard);
        ras_connect::complete_report(&mut report);
        fill_ras_row(&mut report);
        report
    }

    fn install_package_manager(
        &self,
        _texts: &BootstrapTexts,
        _parent: &Path,
        _sandbox: bool,
    ) -> Result<(), PlatformError> {
        Err(unsupported("package manager"))
    }

    /// The OpenVPN row's "Install" / "Repair" / "Update" (`openvpn_install`), else the WireGuard row's "Update"
    /// (fix4: the WinVPN Service updates wireguard-nt itself); the sandbox runs no installer.
    fn install_tools(&self, report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), PlatformError> {
        if self.sandbox.is_some() {
            output("(sandbox: the OpenVPN installer is not run)\n");
            return Ok(());
        }
        let engine = report.engine.as_ref();
        if engine.is_some_and(|e| e.openvpn.action.is_none() && e.wireguard.action == Some("update")) {
            output(&format!("{}\n", wireguard_update::updating()));
            let result = ServiceClient::production().wireguard_update();
            output(&format!("{}\n", result.as_ref().unwrap_or_else(|e| e)));
            return result.map(|_| ()).map_err(PlatformError::Failed);
        }
        openvpn_install::install(report, output).map_err(PlatformError::Failed)
    }

    fn install_helper(&self, _source_dir: &Path, _user: &str) -> Result<(), PlatformError> {
        Err(unsupported("helper"))
    }

    /// "Remove WinVPN from This Account…" (G-9): nothing to remove here. The WinVPN Service and Program Files are
    /// the MSI's (uninstalled in Settings → Apps); the app disconnects its connections itself.
    fn uninstall_helper(&self, _user: &str) -> Result<(), PlatformError> {
        Ok(())
    }

    fn helper_upgrade_notice(&self) -> String {
        texts::upgrade_disconnects()
    }

    /// The engine rows replace the note; without a usable service System Status shows the engine-missing reason.
    fn engine_note(&self) -> Option<String> {
        None
    }

    /// Nothing comes later: the native VPNs run through RAS (2c).
    fn later_note(&self) -> Option<String> {
        None
    }

    /// The MSI is removed in Settings → Apps (the app cannot uninstall itself).
    fn system_uninstall_note(&self) -> Option<String> {
        Some(texts::uninstall_in_settings())
    }

    fn open_system_uninstall(&self) {
        shell::open_settings("ms-settings:appsfeatures");
    }

    /// "Remove WinVPN from This Account…" (G-9) before the MSI's uninstall.
    fn account_cleanup(&self) -> bool {
        true
    }

    /// G-1: no index to download; with a usable service the app's next check (after `Updated`) asks winget and the
    /// service again, so a newer OpenVPN or wireguard-nt shows in System Status without opening it.
    fn update_package_index(&self) -> PackageIndexUpdate {
        engine::index_refresh(&ServiceClient::production().reach(), self.sandbox.is_some())
    }

    fn package_index_task(&self) -> &'static str {
        "engine update check"
    }
}

/// The `Zone.Identifier` stream (fail closed: unreadable is marked).
impl DownloadMark for WinPlatform {
    fn is_marked(&self, path: &Path) -> bool {
        zone::is_marked(path)
    }
}

/// The RAS connections and the phonebook folders (`ras_watch`): each change reloads the system VPN list.
impl SystemVpnWatch for WinPlatform {
    fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        RasWatch { dirs: ras_watch::folders() }.start(on_change)
    }
}

// MARK: - Inert until later tasks

impl ControlTransport for Inert {
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

impl LogStreamSpawner for Inert {
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

/// The 1.1 Keychain items exist only on macOS: an empty source.
impl LegacyKeychain for Inert {
    fn items(&self) -> Vec<(String, SecretField)> {
        Vec::new()
    }

    fn read(&self, _item: &str, _field: SecretField) -> LegacyRead {
        LegacyRead::Missing
    }

    fn delete(&self, _item: &str, _field: SecretField) {}
}

impl LegacySecrets for Inert {
    fn get(&self, _id: &Uuid, _field: SecretField) -> Option<String> {
        None
    }
}

/// The sandbox's and a development build's login item: off, cannot be switched on.
impl LoginItems for Inert {
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
