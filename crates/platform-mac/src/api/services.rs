//! The [`Platform`](macvpn_platform_api::Platform) facilities over this crate's modules: each type wraps the
//! existing functions, so the behaviour is the one the app had when it called them directly.

use super::adapters::{app_bundle, copy_to_pasteboard, open_path, open_profiles_settings, open_url};
use crate::brew::{BREW_GUARD, BrewBootstrap, BrewInstaller, BrewOutdated, BrewUpdate};
use crate::command::ProcessCommandRunner;
use crate::http::CurlHttpClient;
use crate::net_probe::MacNetworkProbe;
use crate::root_installer::{self, InstallError};
use crate::setup_checker::SetupChecker;
use crate::update_installer::{self, UpdateInstaller};
use crate::{
    app_hooks, dialogs, net_watch, notifications, pasteboard, quarantine, sc_watch, system, temp_dir, window_fit,
    window_shape,
};
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::update::{Info, Release};
use macvpn_platform_api::{
    AppLifecycle, BootstrapTexts, ClipboardMark, DownloadMark, FilePanels, NativeWindow, NetworkProbe, NetworkSnapshot,
    NoNetworkProbe, Notifier, PackageIndexUpdate, PlatformError, SecretClipboard, SetupReport, Shell, SystemInfo,
    SystemSetup, SystemVpnWatch, TerminateReply, UpdateOutcome, Updater, WindowChrome,
};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

// MARK: - System

/// The user database, the app's locations and the local date formats (`system`, `temp_dir`).
pub struct MacSystem;

impl SystemInfo for MacSystem {
    fn home_directory(&self) -> Option<PathBuf> {
        system::home_directory()
    }

    /// `<home>/Library/Application Support`.
    fn app_data_root(&self, home: &Path) -> PathBuf {
        home.join("Library/Application Support")
    }

    fn user_owner(&self) -> Result<FileOwner, PlatformError> {
        Ok(FileOwner::from_uid(system::user_id()))
    }

    /// From the user database (`getpwuid(getuid())`).
    fn user_name(&self) -> Option<String> {
        root_installer::current_user_name()
    }

    /// `$TMPDIR` as the system gives it (`confstr(_CS_DARWIN_USER_TEMP_DIR)`).
    fn temporary_directory(&self) -> Result<PathBuf, PlatformError> {
        temp_dir::temporary_directory().map_err(|e| PlatformError::Failed(e.0))
    }

    fn local_date(&self, unix: f64) -> String {
        system::local_date(unix)
    }

    fn local_timestamp(&self, unix: f64) -> String {
        system::local_timestamp(unix)
    }

    fn local_date_time(&self, unix: f64, language: AppLanguage) -> String {
        system::local_date_time(unix, language)
    }

    /// The `.app` bundle the running executable is in.
    fn app_location(&self) -> Option<PathBuf> {
        std::env::current_exe().ok().and_then(|exe| app_bundle(&exe))
    }

    /// `<app>/Contents/Resources/root` when it holds `mvpn`.
    fn bundled_helper_dir(&self, app: &Path) -> Option<PathBuf> {
        system::bundled_root_directory(&app.join("Contents/Resources"))
    }

    /// The bundle's Info.plist.
    fn update_info(&self, app: &Path) -> Option<Info> {
        system::bundle_info(app)
    }
}

/// `/usr/bin/open` and `/usr/bin/pbcopy`.
pub struct MacShell;

impl Shell for MacShell {
    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        open_path(path).map_err(PlatformError::Failed)
    }

    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        open_url(url).map_err(PlatformError::Failed)
    }

    /// System Settings → General → Device Management.
    fn open_native_profile_settings(&self) {
        open_profiles_settings();
    }

    fn copy_text(&self, text: &str) -> Result<(), PlatformError> {
        copy_to_pasteboard(text).map_err(PlatformError::Failed)
    }
}

// MARK: - Setup

/// Homebrew, the VPN tools and the root layer (`setup_checker`, `brew`, `root_installer`). The sandbox never
/// touches the system: `brew` is not run, and the root installer / uninstaller answer as if the administrator
/// prompt had been cancelled.
pub struct MacSetup {
    pub sandbox: bool,
}

impl SystemSetup for MacSetup {
    /// The system check, then (outside the sandbox, which never runs brew) `brew outdated` when the tools are
    /// all there.
    fn check(&self, bundled_helper_dir: Option<&Path>) -> SetupReport {
        let runner = ProcessCommandRunner::default();
        let mut report = SetupChecker::new(&runner, bundled_helper_dir.map(Path::to_path_buf)).check();
        if !self.sandbox
            && let Some(prefix) = report.package_manager.clone()
        {
            let environment: BTreeMap<String, String> = std::env::vars().collect();
            let brew_runner = ProcessCommandRunner::new(BrewOutdated::TIMEOUT)
                .with_environment(BrewOutdated::environment(&environment, &prefix));
            SetupChecker::check_outdated(&mut report, &brew_runner);
        }
        report
    }

    /// Homebrew's official installer in Terminal, from a script in a fresh private directory under `parent` (the
    /// sandbox writes it but does not open it).
    fn install_package_manager(
        &self,
        texts: &BootstrapTexts,
        parent: &Path,
        sandbox: bool,
    ) -> Result<(), PlatformError> {
        let script =
            BrewBootstrap::write(|dir| BrewBootstrap::script(&texts.start, &texts.done, &texts.failed, dir), parent)
                .map_err(|e| PlatformError::Failed(e.0))?;
        if sandbox {
            eprintln!("MacVPN (sandbox): Homebrew installer written, not opened: {}", script.display());
            return Ok(());
        }
        open_path(&script).map_err(PlatformError::Failed)
    }

    /// `brew install …` as the user, its output streamed between `BrewInstaller`'s header and footer; with no
    /// tool missing but outdated formulae (the row's "Update"), `brew upgrade <those formulae>` instead. The sandbox
    /// does not run brew: a short simulated output instead.
    fn install_tools(&self, report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), PlatformError> {
        let prefix = report.package_manager.as_deref().ok_or(PlatformError::Failed("no Homebrew".into()))?;
        let upgrade: Vec<String> = if report.missing_tools.is_empty() {
            report.outdated_packages.iter().map(|p| p.name.clone()).collect()
        } else {
            Vec::new()
        };
        if self.sandbox {
            output(&if upgrade.is_empty() { BrewInstaller::header() } else { BrewInstaller::upgrade_header(&upgrade) });
            output("(sandbox: brew is not run)\n");
            output(&BrewInstaller::footer(0));
            return Ok(());
        }
        let environment: BTreeMap<String, String> = std::env::vars().collect();
        // Waits for a running daily `brew update` (at most its time limit).
        let _held = BREW_GUARD.lock();
        let result = if upgrade.is_empty() {
            BrewInstaller::install(prefix, &environment, output)
        } else {
            BrewInstaller::upgrade(prefix, &upgrade, &environment, output)
        };
        match result {
            Ok(0) => Ok(()),
            Ok(status) => Err(PlatformError::Failed(l10n::tr("brew error (%d)", &[Arg::Int(i64::from(status))]))),
            Err(e) => Err(PlatformError::Failed(e.to_string())),
        }
    }

    fn install_helper(&self, source_dir: &Path, user: &str) -> Result<(), PlatformError> {
        if self.sandbox {
            return Err(PlatformError::Failed(l10n::tr("Installation cancelled", &[])));
        }
        root_installer::install(source_dir, user).map_err(|e| installer_error(e, "Installation error"))
    }

    fn uninstall_helper(&self, user: &str) -> Result<(), PlatformError> {
        if self.sandbox {
            return Err(PlatformError::Failed(l10n::tr("Uninstall cancelled", &[])));
        }
        root_installer::uninstall(user).map_err(|e| installer_error(e, "Uninstall error"))
    }

    fn helper_upgrade_notice(&self) -> String {
        root_installer::upgrade_disconnect_notice()
    }

    /// `brew update` as the user (the app runs as the user; no `sudo`), with the minimal environment and a 120 s
    /// limit, under the brew guard. Nothing in the sandbox or without Homebrew.
    fn update_package_index(&self) -> PackageIndexUpdate {
        if self.sandbox {
            return PackageIndexUpdate::Unavailable;
        }
        let Some(prefix) = SetupChecker::installed_brew_prefix() else { return PackageIndexUpdate::Unavailable };
        let environment: BTreeMap<String, String> = std::env::vars().collect();
        let runner = ProcessCommandRunner::new(BrewUpdate::TIMEOUT)
            .with_environment(BrewUpdate::environment(&environment, &prefix));
        BrewUpdate::run(&runner, &prefix, &BREW_GUARD)
    }
}

/// The installer's error as the window shows it: its own messages are localized already; a failure to run
/// `osascript` gets the localized prefix.
fn installer_error(error: InstallError, prefix: &str) -> PlatformError {
    PlatformError::Failed(match error {
        InstallError::Message(message) => message,
        InstallError::Command(e) => format!("{}: {e}", l10n::tr(prefix, &[])),
    })
}

// MARK: - Updates

/// The DMG update (`update_installer`) over curl and the process runner.
pub struct MacUpdater;

impl Updater for MacUpdater {
    fn install(
        &self,
        release: &Release,
        app: &Path,
        home: &Path,
        stage: &dyn Fn(String),
        confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Result<UpdateOutcome, String> {
        let http = CurlHttpClient::default();
        let runner = ProcessCommandRunner::default();
        let installer = UpdateInstaller::new(&http, &runner, UpdateInstaller::default_cache_directory(home));
        let pid = i32::try_from(std::process::id()).map_err(|e| e.to_string())?;
        update_installer::install_update(&installer, release, app, pid, |s| stage(s.message()), confirm_quit)
            .map_err(|e| e.to_string())
    }

    fn launch_housekeeping(
        &self,
        app: &Path,
        home: &Path,
        noticed: Option<&str>,
    ) -> (Vec<PathBuf>, Option<(String, String)>) {
        let cache = UpdateInstaller::default_cache_directory(home);
        update_installer::launch_housekeeping(app, &cache, home, noticed)
    }

    /// `<home>/Library/Caches/MacVPN`.
    fn cache_directory(&self, home: &Path) -> Option<PathBuf> {
        Some(UpdateInstaller::default_cache_directory(home))
    }
}

// MARK: - Windows, panels, notifications, clipboard, lifecycle

/// `window_shape`, `window_fit`, `app_hooks::order_front_regardless`.
pub struct MacWindows;

impl WindowChrome for MacWindows {
    fn popover_corner_radius(&self) -> f64 {
        window_shape::POPOVER_CORNER_RADIUS
    }

    fn round_corners(&self, w: NativeWindow, radius: f64) -> bool {
        window_shape::round_corners(w.0, radius)
    }

    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64> {
        window_fit::fit_viewport(w.0, width, viewport, center)
    }

    fn order_front_regardless(&self, w: NativeWindow) {
        app_hooks::order_front_regardless(w.0);
    }
}

/// `NSOpenPanel` / `NSSavePanel` sheets (`dialogs`).
pub struct MacFilePanels;

impl FilePanels for MacFilePanels {
    fn choose_files(&self, parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>) {
        dialogs::choose_files(parent.0, multiple, done);
    }

    fn choose_save_path(
        &self,
        parent: NativeWindow,
        suggested: &str,
        message: Option<&str>,
        done: Box<dyn FnOnce(Option<PathBuf>)>,
    ) {
        dialogs::choose_save_path(parent.0, suggested, message, done);
    }
}

/// `UNUserNotificationCenter` (`notifications`).
pub struct MacNotifier;

impl Notifier for MacNotifier {
    fn start(&self, on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>) {
        notifications::start(on_click);
    }

    fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str)) {
        notifications::post(identifier, title, body, user_info);
    }

    fn remove_delivered(&self, identifier: &str) {
        notifications::remove_delivered(identifier);
    }
}

/// The concealed, transient, this-Mac-only pasteboard string (`pasteboard`).
pub struct MacClipboard;

impl SecretClipboard for MacClipboard {
    fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError> {
        pasteboard::write_secret(text).map_err(PlatformError::Failed)
    }

    fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool {
        pasteboard::clear_if_unchanged(mark)
    }
}

/// `applicationShouldTerminate:` and the wake and will-sleep notifications (`app_hooks`).
pub struct MacLifecycle;

impl AppLifecycle for MacLifecycle {
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        app_hooks::install_terminate_handler(handler)
    }

    fn reply_to_terminate(&self, terminate: bool) {
        app_hooks::reply_to_terminate(terminate);
    }

    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>) {
        app_hooks::observe_wake(on_wake);
    }

    fn observe_sleep(&self, on_sleep: Box<dyn Fn() + Send + Sync>) {
        app_hooks::observe_sleep(on_sleep);
    }
}

/// `com.apple.quarantine` (`quarantine`).
pub struct MacDownloadMark;

impl DownloadMark for MacDownloadMark {
    fn is_marked(&self, path: &Path) -> bool {
        quarantine::is_quarantined(path)
    }
}

/// The SystemConfiguration watcher (`sc_watch`); dropping the returned box stops it.
pub struct MacSystemVpnWatch;

impl SystemVpnWatch for MacSystemVpnWatch {
    fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        sc_watch::SystemVpnWatcher::start(on_change).map(|watcher| Box::new(watcher) as Box<dyn Send>)
    }
}

/// The physical network (`net_probe`, `net_watch`). The sandbox has none: its snapshot is unsupported (the
/// auto-reconnect never reconnects) and its watch is an inert guard.
pub struct MacNetwork {
    pub sandbox: bool,
    probe: MacNetworkProbe<ProcessCommandRunner>,
}

impl MacNetwork {
    /// Each probe command's time limit (seconds).
    pub const COMMAND_TIMEOUT: f64 = 3.0;

    pub fn new(sandbox: bool) -> MacNetwork {
        MacNetwork { sandbox, probe: MacNetworkProbe::new(ProcessCommandRunner::new(Self::COMMAND_TIMEOUT)) }
    }
}

impl NetworkProbe for MacNetwork {
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        if self.sandbox {
            return NoNetworkProbe.snapshot();
        }
        self.probe.snapshot()
    }

    fn watch(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        if self.sandbox {
            return NoNetworkProbe.watch(on_change);
        }
        net_watch::NetworkWatcher::start(on_change).map(|watcher| Box::new(watcher) as Box<dyn Send>)
    }
}
