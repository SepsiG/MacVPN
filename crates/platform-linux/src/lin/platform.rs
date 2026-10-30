//! `LinPlatform`: every `platform-api` trait for Linux. L-a's stand-ins (`Inert`) are replaced by the later tasks,
//! each in its own accessor: the key store (Task 13), the control transport (14), the lifecycle and login items
//! (16), the release source, HTTPS catalogs and updater (20). The VPN parts go through the NetworkManager engine
//! ([`Engine`], L-b), created on first use.

use crate::lin::chrome::Chrome;
use crate::lin::clipboard::{self, Clipboard};
use crate::lin::control::LinTransport;
use crate::lin::net::LinNetwork;
use crate::lin::nm::engine::Engine;
use crate::lin::nm::{packagekit, plugins, system_vpns};
use crate::lin::notify::LinNotifier;
use crate::lin::portal::Panels;
use crate::lin::{curl_runner, shell, system, updater, xattr};
use crate::pure::paths::Xdg;
use crate::pure::{languages, mark, texts, update_check};
use macvpn_core::catalog::fetch::CatalogFetcher;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::models::SecretField;
use macvpn_core::update::{self, Release};
use macvpn_core::vault::{Entropy, KeyStore, LegacyKeychain, LegacyRead, MemoryKeyStore};
use macvpn_platform_api::dates;
use macvpn_platform_api::{
    AppLifecycle, AuthStateReader, BootstrapTexts, BoundEndpoint, ControlTransport, DownloadMark, FilePanels,
    FilePreferences, HelperClient, LINVPN, LegacySecrets, LogStreamSpawner, LoginItemView, LoginItems,
    MemoryPreferences, NativeController, NativeProfiles, NativeSupport, NetworkProbe, NoNetworkProbe, Notifier,
    Platform, PlatformError, PreferenceStore, Product, ReleaseSource, SecretClipboard, SetupReport, Shell,
    StreamHandle, SystemInfo, SystemSetup, SystemVpnWatch, TerminateReply, UpdateOutcome, Updater, WindowChrome,
};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

/// The installed binary (the `.deb`'s `/usr/bin/linvpn`).
const INSTALLED_BINARY: &str = "/usr/bin/linvpn";

/// The physical network from NetworkManager on the system bus (auto-reconnect).
static NETWORK: LinNetwork = LinNetwork { bus: crate::lin::bus::system };

/// The Linux platform. Created once by the app (`platform::init`).
pub struct LinPlatform {
    sandbox: Option<Sandbox>,
    /// The one preference store of the process (created on first use: every caller shares its cache).
    preferences: OnceLock<Arc<dyn PreferenceStore>>,
    /// `org.freedesktop.Notifications` (the session bus is opened at the first post, never here).
    notifier: LinNotifier,
    /// The NetworkManager engine (created on first use: never a D-Bus connection at construction).
    engine: OnceLock<Arc<Engine>>,
}

/// The sandbox's stores (`MACVPN_SANDBOX_HOME`, debug builds): memory only, never the Secret Service or a file.
struct Sandbox {
    key_store: Arc<MemoryKeyStore>,
    preferences: Arc<MemoryPreferences>,
}

impl LinPlatform {
    /// `sandbox` (debug builds, `MACVPN_SANDBOX_HOME`): memory key store and preferences, data under the sandbox
    /// home; never the Secret Service, never the real XDG directories, no D-Bus at construction.
    pub fn new(sandbox: bool) -> LinPlatform {
        LinPlatform {
            sandbox: sandbox.then(|| Sandbox {
                key_store: Arc::new(MemoryKeyStore::new()),
                preferences: Arc::new(MemoryPreferences::new()),
            }),
            preferences: OnceLock::new(),
            notifier: LinNotifier::production(),
            engine: OnceLock::new(),
        }
    }

    pub fn is_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }

    /// The XDG directories under `home`: the sandbox's all under its home (the environment is not read), the real
    /// user's from the environment.
    pub(crate) fn xdg(&self, home: &Path) -> Xdg {
        if self.is_sandbox() { Xdg::sandbox(home) } else { Xdg::from_env(home, |k| std::env::var_os(k)) }
    }

    /// The NetworkManager engine (created on first use: never a D-Bus connection at construction). The sandbox's
    /// keeps its files (the managed plan records, the logs) under the sandbox home, never the real user's.
    pub(crate) fn engine(&self) -> Arc<Engine> {
        self.engine
            .get_or_init(|| {
                let home = if self.is_sandbox() { sandbox_home() } else { system::home() }
                    .unwrap_or_else(|| PathBuf::from("/nonexistent"));
                let xdg = self.xdg(&home);
                // SAFETY: getuid has no arguments and cannot fail.
                let uid = unsafe { libc::getuid() };
                Engine::new(
                    crate::lin::bus::system,
                    self.is_sandbox(),
                    system::user_name().unwrap_or_default(),
                    uid,
                    xdg.runtime_dir.clone(),
                    xdg.data_home.join("LinVPN"),
                )
            })
            .clone()
    }

    /// LinVPN's strongSwan credential folder (`$XDG_DATA_HOME/LinVPN/swanctl`, resolved point 18): the IKEv2
    /// editor shows the `x509` / `x509ca` files a config names from it, as the plan uses them.
    pub fn swanctl_folder(&self) -> PathBuf {
        self.engine().data.join("swanctl")
    }

    /// At the app's setup, on a background thread (never in the sandbox): adopts the connections an earlier run
    /// left up and removes the runtime files of the ones that are gone (`Engine::adopt`), and registers the
    /// engine's secret agent, so a system VPN started with stored secrets is answered from its first start. Without
    /// NetworkManager the agent registers at the first connect instead.
    pub fn prepare_engine(&self) {
        if self.is_sandbox() {
            return;
        }
        let engine = self.engine();
        engine.adopt();
        let _ = engine.nm();
    }
}

/// The sandbox's home (`MACVPN_SANDBOX_HOME`, an absolute path; debug builds only), read here because the platform
/// is created before the app's environment.
fn sandbox_home() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    return std::env::var_os("MACVPN_SANDBOX_HOME").map(PathBuf::from).filter(|h| h.is_absolute());
    #[cfg(not(debug_assertions))]
    None
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

/// The facilities that are inert until their L-a task replaces them.
struct Inert;

/// The kernel's CSPRNG (`getrandom(2)`), the same call as the control socket's `random_32`.
struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&self, buf: &mut [u8]) -> io::Result<()> {
        macvpn_unixsys::random::fill(buf)
    }
}

impl Platform for LinPlatform {
    fn product(&self) -> &'static Product {
        &LINVPN
    }

    /// The preferred languages from the environment and the text platform. Collation: the core's built-in.
    fn install_core_hooks(&self) {
        AppLanguage::set_preferred_languages(languages::preferred_languages(|k| std::env::var(k).ok()));
        l10n::set_text_platform(LINVPN.text_platform());
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

    /// The signed `.deb` through pkexec; the sandbox installs nothing (the smoke run has its own update path).
    fn updater(&self) -> &dyn Updater {
        if self.is_sandbox() {
            return &Inert;
        }
        updater::installed()
    }

    /// GTK's window sizes, square corners, the portal's light/dark setting.
    fn windows(&self) -> &dyn WindowChrome {
        &Chrome
    }

    /// The desktop portal's file chooser.
    fn file_panels(&self) -> &dyn FilePanels {
        &Panels
    }

    /// `org.freedesktop.Notifications`; the sandbox posts none (the smoke run records notices itself).
    fn notifier(&self) -> &dyn Notifier {
        if self.is_sandbox() { &Inert } else { &self.notifier }
    }

    /// GTK's clipboard.
    fn clipboard(&self) -> &dyn SecretClipboard {
        &Clipboard
    }

    /// SIGTERM and SIGINT on the GTK main loop, logind's sleep and wake, the portal's appearance changes (the
    /// sandbox too: the smoke run's quit request is its own SIGTERM).
    fn lifecycle(&self) -> &dyn AppLifecycle {
        &crate::lin::lifecycle::Lifecycle
    }

    fn download_mark(&self) -> &dyn DownloadMark {
        self
    }

    fn system_vpn_watch(&self) -> &dyn SystemVpnWatch {
        self
    }

    /// `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock`; the sandbox: `<sandbox>/run/linvpn/control/linvpn.sock`
    /// (`MACVPN_SANDBOX_HOME`, read here because the transport is created before the environment).
    fn control_transport(&self) -> Arc<dyn ControlTransport> {
        if self.is_sandbox() {
            return match sandbox_home() {
                Some(home) => Arc::new(LinTransport::sandbox(home.join("run"))),
                None => Arc::new(LinTransport::without_runtime_dir()),
            };
        }
        let home = system::home().unwrap_or_else(|| PathBuf::from("/nonexistent"));
        Arc::new(LinTransport::production(Xdg::from_env(&home, |k| std::env::var_os(k)).runtime_dir))
    }

    /// OpenVPN, WireGuard, IKEv2 and SSTP through NetworkManager (the engine; L-b resolved point 1).
    fn helper_client(&self) -> Arc<dyn HelperClient> {
        self.engine()
    }

    /// L2TP, Cisco IPsec and the system VPNs through NetworkManager (the engine).
    fn native_controller(&self) -> Arc<dyn NativeController> {
        self.engine()
    }

    /// The managed L2TP / Cisco plan records (the engine; no NM connection is written).
    fn native_profiles(&self, _staging: &Path, _open: bool) -> Arc<dyn NativeProfiles> {
        self.engine()
    }

    /// Whether Linux can run a connection's settings, and the editor's notes (the engine).
    fn native_support(&self) -> Arc<dyn NativeSupport> {
        self.engine()
    }

    /// The pending dynamic challenge from the engine's secret agent.
    fn auth_state(&self) -> Arc<dyn AuthStateReader> {
        self.engine()
    }

    /// No system log stream (WinVPN's model): a debug connect starts no collection, and the Log tab reads the
    /// connection's own log (the engine's lines and `linvpn-logd`'s journal lines).
    fn log_streams(&self) -> Arc<dyn LogStreamSpawner> {
        Arc::new(Inert)
    }

    /// GitHub's `releases/latest` through `/usr/bin/curl`.
    fn release_source(&self) -> Arc<dyn ReleaseSource> {
        Arc::new(curl_runner::LinReleases::new())
    }

    /// The shared curl layer over `/usr/bin/curl`; the sandbox refuses every HTTPS source.
    fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher> {
        if self.is_sandbox() {
            return Arc::new(curl_runner::SandboxHttps);
        }
        Arc::new(curl_runner::catalog_fetcher())
    }

    /// The sandbox's memory store; else the user's Secret Service (gnome-keyring).
    fn key_store(&self) -> Arc<dyn KeyStore> {
        match &self.sandbox {
            Some(s) => s.key_store.clone(),
            None => Arc::new(crate::lin::keystore::SecretServiceKeyStore::production()),
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

    /// The sandbox's memory store, else `$XDG_CONFIG_HOME/LinVPN/preferences.json` (`FilePreferences` creates the
    /// directory private). Without a home in the user database, a memory store (nothing is written to a guessed
    /// place).
    fn preferences(&self) -> Arc<dyn PreferenceStore> {
        self.preferences
            .get_or_init(|| {
                if let Some(s) = &self.sandbox {
                    return s.preferences.clone();
                }
                match system::home() {
                    Some(home) => {
                        Arc::new(FilePreferences::new(Xdg::from_env(&home, |k| std::env::var_os(k)).preferences_file()))
                    }
                    None => Arc::new(MemoryPreferences::new()),
                }
            })
            .clone()
    }

    /// `$XDG_CONFIG_HOME/autostart/linvpn.desktop`; only the installed `/usr/bin/linvpn` can toggle it. The
    /// sandbox: the no-op item (nothing is written).
    fn login_items(&self, home: &Path, _app: Option<&Path>, sandbox: bool) -> Box<dyn LoginItems> {
        if sandbox || self.is_sandbox() {
            return Box::new(Inert);
        }
        Box::new(crate::lin::login_item::AutostartItem {
            file: self.xdg(home).autostart_file(),
            installed: self.system().app_location().is_some(),
        })
    }

    /// NetworkManager's devices (the auto-reconnect); the sandbox watches no network.
    fn network(&self) -> &dyn NetworkProbe {
        if self.is_sandbox() { &NoNetworkProbe } else { &NETWORK }
    }
}

// MARK: - System

impl SystemInfo for LinPlatform {
    /// From the user database (`getpwuid_r`), not `$HOME`.
    fn home_directory(&self) -> Option<PathBuf> {
        system::home()
    }

    /// `$XDG_DATA_HOME` (default `<home>/.local/share`); the sandbox: `<home>/.local/share`.
    fn app_data_root(&self, home: &Path) -> PathBuf {
        self.xdg(home).data_home
    }

    fn user_owner(&self) -> Result<FileOwner, PlatformError> {
        // SAFETY: getuid has no arguments and cannot fail.
        Ok(FileOwner::from_uid(unsafe { libc::getuid() }))
    }

    /// From the user database.
    fn user_name(&self) -> Option<String> {
        system::user_name()
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

    fn local_timestamp(&self, unix: f64) -> String {
        system::local_time(unix)
            .map(|(y, mo, d, h, mi, s)| format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"))
            .unwrap_or_default()
    }

    /// `/usr/bin/linvpn` when this process is the installed binary; `None` for a development build.
    fn app_location(&self) -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        (exe == Path::new(INSTALLED_BINARY)).then_some(exe)
    }

    /// No bundled helper on Linux (the engines are NetworkManager's, L-b).
    fn bundled_helper_dir(&self, _app: &Path) -> Option<PathBuf> {
        None
    }

    /// The compiled-in update source of an installed LinVPN (`/usr/bin/linvpn`); a development build has none.
    fn update_info(&self, app: &Path) -> Option<update::Info> {
        (self.app_location().as_deref() == Some(app)).then(update_check::update_info)
    }
}

impl Shell for LinPlatform {
    /// Absolute directories only (`xdg-open`); a file is never opened.
    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        shell::open_directory(path)
    }

    /// `https://` only.
    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        shell::open_https(url)
    }

    /// No native profiles on Linux.
    fn open_native_profile_settings(&self) {}

    /// GTK's clipboard.
    fn copy_text(&self, text: &str) -> Result<(), PlatformError> {
        clipboard::write_plain(text)
    }
}

impl SystemSetup for LinPlatform {
    /// NetworkManager (its version through the engine's client; not on the bus: its row red) and the plugin of each
    /// kind (`plugins::facts`, read-only); PackageKit installs the missing ones. The sandbox has no engine (every start
    /// answers [`texts::not_yet`]): System Status shows [`texts::engine_note`] in place of the rows; the smoke run has
    /// its own report.
    fn check(&self, _bundled_helper_dir: Option<&Path>) -> SetupReport {
        if self.is_sandbox() {
            return SetupReport { engine_missing: Some(texts::engine_note()), ..SetupReport::unknown() };
        }
        let version = self.engine().nm_client().ok().and_then(|c| c.version());
        let nm = crate::pure::nm::plugins::report(&plugins::facts(version));
        SetupReport { package_manager: Some("PackageKit".into()), nm: Some(nm), ..SetupReport::unknown() }
    }

    fn install_package_manager(
        &self,
        _texts: &BootstrapTexts,
        _parent: &Path,
        _sandbox: bool,
    ) -> Result<(), PlatformError> {
        Err(unsupported("package manager"))
    }

    /// The packages of the one NetworkManager row that offers Install (the app keeps only the clicked row's
    /// action) through PackageKit on the system bus: PackageKit asks for the administrator password itself. The
    /// sandbox asks nothing.
    fn install_tools(&self, report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), PlatformError> {
        if self.is_sandbox() {
            output("(sandbox: PackageKit is not asked)\n");
            return Ok(());
        }
        let Some(nm) = &report.nm else { return Err(unsupported("tools")) };
        let Some((_, _, packages)) = nm.kinds.iter().find(|(_, row, _)| row.action == Some("install")) else {
            return Err(unsupported("tools"));
        };
        let packages: Vec<&str> = packages.split_whitespace().collect();
        let mut lines = |text: &str| output(&format!("{text}\n"));
        let result = crate::lin::bus::system()
            .map_err(|e| l10n::tr("PackageKit is not available: %@", &[l10n::Arg::Str(&e.to_string())]))
            .and_then(|bus| packagekit::install(&bus, &packages, &mut lines));
        if let Err(message) = &result {
            lines(message);
        }
        result.map_err(PlatformError::Failed)
    }

    fn install_helper(&self, _source_dir: &Path, _user: &str) -> Result<(), PlatformError> {
        Err(unsupported("helper"))
    }

    fn uninstall_helper(&self, _user: &str) -> Result<(), PlatformError> {
        Err(unsupported("helper"))
    }

    fn helper_upgrade_notice(&self) -> String {
        String::new()
    }

    /// None: the NetworkManager rows replace it; the sandbox's check reports the note as its missing engine (the
    /// smoke run's stand-in report has the rows instead).
    fn engine_note(&self) -> Option<String> {
        None
    }

    /// LinVPN is removed as a package (`apt remove linvpn`): no root helper of its own, so no "Uninstall" button.
    fn system_uninstall_note(&self) -> Option<String> {
        Some(texts::uninstall_note())
    }

    /// Never run (PackageKit refreshes its own cache).
    fn package_index_task(&self) -> &'static str {
        "apt"
    }
}

/// The `user.xdg.origin.url` attribute browsers set (fail closed: an unreadable attribute counts as marked).
impl DownloadMark for LinPlatform {
    fn is_marked(&self, path: &Path) -> bool {
        mark::is_marked(xattr::origin(path))
    }
}

/// NetworkManager's profiles and active connections (the user's system VPNs); the sandbox watches nothing.
impl SystemVpnWatch for LinPlatform {
    fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        system_vpns::watch(&self.engine(), on_change)
    }
}

// MARK: - Inert until later tasks

/// The sandbox's updater: nothing is downloaded or installed.
impl Updater for Inert {
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

/// The sandbox's notifier: nothing is posted.
impl Notifier for Inert {
    fn start(&self, _on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>) {}

    fn post(&self, _identifier: &str, _title: &str, _body: &str, _user_info: (&str, &str)) {}

    fn remove_delivered(&self, _identifier: &str) {}
}

/// Unused since Task 16 (`lin::lifecycle`).
impl AppLifecycle for Inert {
    fn install_terminate_handler(&self, _handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        false
    }

    fn reply_to_terminate(&self, _terminate: bool) {}

    fn observe_wake(&self, _on_wake: Box<dyn Fn() + Send + Sync>) {}
}

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

    /// No stream on Linux: a debug connect starts no collection.
    fn is_available(&self) -> bool {
        false
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

/// The sandbox's login item: nothing is registered.
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
