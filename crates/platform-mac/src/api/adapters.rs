//! The platform-api adapters over this crate's modules (moved from the app's `platform.rs` in 1.5): the helper
//! client, the native VPN controller, the 1.1 Keychain secrets, the native profiles, opening files and URLs, the
//! plain pasteboard, the native debug log stream, the MFA bridge's state files, the preferences, the release
//! source and the login item.
//!
//! Every call here is synchronous (processes with time limits, Keychain, SystemConfiguration); the connection
//! manager calls them from worker threads, never from the main thread.

use crate::command::{CommandRunner, ProcessCommandRunner, RunnerTimeouts};
use crate::http::{CurlHttpClient, HttpClient};
use crate::log_stream::{LOG_EXECUTABLE, LineStream};
use crate::login_item::{
    FallbackLoginItemService, LaunchAgentLoginItem, LoginItemController, LoginItemLocation, LoginItemService,
    LoginItemState, LoginItemStatus, SMAppServiceLoginItem,
};
use crate::mvpn_client::MvpnClient;
use crate::native_vpn::{BoxError, NativeVPNController, SystemConfigurationDriver};
use crate::preferences::CFPreferencesStore;
use crate::profile_staging::{self, StagedProfiles};
use crate::secrets::{InMemoryKeychain, KeychainBackend, KeychainSecretStore, SecretStore};
use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthResponseKind, AuthUIState};
use macvpn_core::models::{Connection, SecretField, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_core::update::{Release, UpdateChecker};
use macvpn_core::{exporter, mobileconfig};
use macvpn_platform_api::{
    AuthStateReader, HelperClient, LegacySecrets, LogStreamSpawner, LoginItemView, LoginItems, MACVPN,
    NativeController, NativeProfile, NativeProfiles, PlatformError, PreferenceStore, ReleaseSource, StreamHandle,
    SystemVpn,
};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use uuid::Uuid;
use zeroize::Zeroizing;

// MARK: - The root layer and the native VPNs

/// `sudo -n mvpn …` with the Swift app's time limits: `up` long, `status` / `respond` quick, the rest standard.
pub struct Helper {
    standard: ProcessCommandRunner,
    up: ProcessCommandRunner,
    quick: ProcessCommandRunner,
}

impl Helper {
    pub fn new() -> Self {
        Helper {
            standard: ProcessCommandRunner::new(RunnerTimeouts::STANDARD),
            up: ProcessCommandRunner::new(RunnerTimeouts::UP),
            quick: ProcessCommandRunner::new(RunnerTimeouts::QUICK),
        }
    }

    fn client(&self) -> MvpnClient<'_> {
        MvpnClient::with_runners(&self.standard, Some(&self.up), Some(&self.quick), None)
    }
}

impl Default for Helper {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperClient for Helper {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        self.client().status().map_err(|e| e.to_string())
    }

    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String> {
        self.client().up(kind, id, config, secrets, debug, accept_risky).map_err(|e| e.to_string())
    }

    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
        self.client().down(kind, id).map_err(|e| e.to_string())
    }

    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        self.client().respond(id, kind, response).map_err(|e| e.to_string())
    }

    /// `/var/log/macvpn/<UUID>.log`.
    fn log_path(&self, id: &Uuid) -> Option<PathBuf> {
        Some(MvpnClient::log_path(id))
    }

    /// The user's own log and its `.1`, emptied in place by the app (no root call; see
    /// [`crate::mvpn_client::clear_log_in`]).
    fn clear_log(&self, id: &Uuid, note: &str) -> Result<(), String> {
        let owner = macvpn_core::fsx::FileOwner::from_uid(crate::system::user_id());
        crate::mvpn_client::clear_log_in(Path::new(crate::mvpn_client::LOG_DIR), id, &owner, note)
    }
}

/// `scutil --nc list / show` (quick time limit) and the in-process `SCNetworkConnection` driver.
pub struct Native(NativeVPNController<ProcessCommandRunner, SystemConfigurationDriver>);

impl Native {
    pub fn new() -> Self {
        Native(NativeVPNController::new(ProcessCommandRunner::new(RunnerTimeouts::QUICK), SystemConfigurationDriver))
    }
}

impl Default for Native {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeController for Native {
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        self.0
            .list()
            .map(|services| {
                services
                    .into_iter()
                    .map(|s| SystemVpn { id: s.id, name: s.name, type_label: s.type_label, status: s.status })
                    .collect()
            })
            .map_err(|e| e.to_string())
    }

    fn remote_address(&self, service_id: &str) -> Option<String> {
        self.0.remote_address(service_id)
    }

    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        self.0.start(service_id, kind, secrets).map_err(|e| e.to_string())
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        self.0.stop(service_id).map_err(|e| e.to_string())
    }
}

// MARK: - The 1.1 Keychain items

/// The 1.1 Keychain items (`local.macvpn.secrets`), as the legacy read-only mode reads them.
pub struct Keychain<B: KeychainBackend>(pub KeychainSecretStore<B>);

impl<B: KeychainBackend> LegacySecrets for Keychain<B> {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.get(id, field)
    }
}

/// One in-memory Keychain shared by several stores (the sandbox's old Keychain items: the migration reads them
/// and the legacy read-only mode shows them).
pub struct SharedKeychain(pub Arc<InMemoryKeychain>);

impl KeychainBackend for SharedKeychain {
    fn read(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        self.0.read(service, account)
    }

    fn read_checked(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, i32> {
        self.0.read_checked(service, account)
    }

    fn write(&self, data: &[u8], service: &str, account: &str) -> bool {
        self.0.write(data, service, account)
    }

    fn delete(&self, service: &str, account: &str) {
        self.0.delete(service, account);
    }

    fn accounts(&self, service: &str) -> Vec<String> {
        self.0.accounts(service)
    }
}

// MARK: - Native profiles, files and URLs

/// The native profiles: staged in a private temp directory, tracked until the service is listed, and opened
/// with `/usr/bin/open` (the sandbox stages but never opens: no profile reaches the real system).
pub struct ProfileFiles {
    pub parent: PathBuf,
    pub staged: Arc<Mutex<StagedProfiles>>,
    pub open: bool,
}

impl NativeProfiles for ProfileFiles {
    /// A `.mobileconfig` profile (`mobileconfig::generate`) under the export's file name.
    fn build(&self, connection: &Connection, psk: &str) -> Result<NativeProfile, String> {
        let data = Zeroizing::new(mobileconfig::generate(connection, psk).map_err(|e| e.message())?);
        Ok(NativeProfile { data, file_name: exporter::file_name(connection) })
    }

    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String> {
        let path = profile_staging::stage(profile, file_name, &self.parent).map_err(|e| e.to_string())?;
        self.staged.lock().unwrap_or_else(PoisonError::into_inner).track(*id, path.clone(), service_existed);
        if !self.open {
            eprintln!("MacVPN (sandbox): profile staged, not opened: {}", path.display());
            return Ok(());
        }
        open_path(&path)
    }

    /// `profile_staging::sweep` of the staging parent.
    fn sweep_leftovers(&self) {
        profile_staging::sweep(&self.parent);
    }

    fn services_seen(&self, ids: &HashSet<Uuid>) {
        self.staged.lock().unwrap_or_else(PoisonError::into_inner).services_seen(ids);
    }
}

/// `/usr/bin/open <absolute path>` (the path cannot look like an option).
pub fn open_file(path: &Path) -> Result<(), String> {
    open_path(path)
}

/// `/usr/bin/open <absolute path>`; a relative path is refused.
pub fn open_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("refused path".into());
    }
    let result = ProcessCommandRunner::new(RunnerTimeouts::QUICK)
        .run("/usr/bin/open", &[path.to_string_lossy().into_owned()], None)
        .map_err(|e| e.to_string())?;
    if result.exit_code == 0 { Ok(()) } else { Err(result.stderr.trim().to_string()) }
}

/// `/usr/bin/open <url>` in the default browser. The caller validates the URL (`is_safe_github_url`); here only an
/// `https://` URL is accepted, so it cannot look like an option.
pub fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("refused URL".into());
    }
    let result = ProcessCommandRunner::new(RunnerTimeouts::QUICK)
        .run("/usr/bin/open", &[url.to_string()], None)
        .map_err(|e| e.to_string())?;
    if result.exit_code == 0 { Ok(()) } else { Err(result.stderr.trim().to_string()) }
}

/// System Settings → General → Device Management (Profiles), after a native connection was deleted.
pub fn open_profiles_settings() {
    let _ = ProcessCommandRunner::new(RunnerTimeouts::QUICK).run(
        "/usr/bin/open",
        &["x-apple.systempreferences:com.apple.Profiles-Settings.extension".to_string()],
        None,
    );
}

/// Puts the text on the general pasteboard (`/usr/bin/pbcopy`, UTF-8).
pub fn copy_to_pasteboard(text: &str) -> Result<(), String> {
    let environment = BTreeMap::from([("LANG".to_string(), "en_US.UTF-8".to_string())]);
    let result = ProcessCommandRunner::new(RunnerTimeouts::QUICK)
        .with_environment(environment)
        .run("/usr/bin/pbcopy", &[], Some(text))
        .map_err(|e| e.to_string())?;
    if result.exit_code == 0 { Ok(()) } else { Err(result.stderr.trim().to_string()) }
}

// MARK: - The native debug log

/// `log stream --style compact --predicate …` for the native debug log.
pub struct LogStreams;

/// The `log stream` predicate (the native VPN daemons and NetworkExtension).
const LOG_PREDICATE: &str =
    r#"process IN {"racoon","pppd","neagent","nesessionmanager"} OR subsystem == "com.apple.networkextension""#;

struct LogStreamHandle(LineStream);

impl StreamHandle for LogStreamHandle {
    fn stop(&self) {
        self.0.stop();
    }
}

impl LogStreamSpawner for LogStreams {
    fn command_line(&self) -> String {
        format!("log stream --style compact --predicate '{LOG_PREDICATE}'")
    }

    fn spawn(
        &self,
        on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String> {
        let arguments = ["stream", "--style", "compact", "--predicate", LOG_PREDICATE];
        LineStream::spawn(LOG_EXECUTABLE, &arguments, on_lines, on_exit)
            .map(|s| Box::new(LogStreamHandle(s)) as Box<dyn StreamHandle>)
            .map_err(|e| e.to_string())
    }
}

// MARK: - The MFA bridge's state files

/// `<UI_STATE_DIR>/<id>.json` (`/var/run/macvpn-ui`): a regular file owned by this user, at most 8 KB (no symlink
/// followed).
pub struct AuthStateFiles {
    pub uid: u32,
}

impl AuthStateReader for AuthStateFiles {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        let path = AuthUIState::path(Path::new(crate::mvpn_client::UI_STATE_DIR), id);
        AuthUIState::read(&path, &macvpn_core::fsx::FileOwner::from_uid(self.uid))
    }
}

// MARK: - Preferences

/// The app's `UserDefaults` (domain `local.macvpn`), shared with the Swift app's keys.
pub struct Preferences(pub CFPreferencesStore);

impl PreferenceStore for Preferences {
    fn bool(&self, key: &str) -> Option<bool> {
        self.0.bool(key)
    }

    fn set_bool(&self, key: &str, value: bool) {
        self.0.set_bool(key, value);
    }

    fn date(&self, key: &str) -> Option<Date> {
        self.0.date(key)
    }

    fn set_date(&self, key: &str, value: Date) {
        self.0.set_date(key, value);
    }

    fn string(&self, key: &str) -> Option<String> {
        self.0.string(key)
    }

    fn set_string(&self, key: &str, value: &str) {
        self.0.set_string(key, value);
    }

    fn remove_all(&self) {
        self.0.remove_all();
    }
}

// MARK: - Releases

/// `releases/latest` over the HTTP client (curl: HTTPS, allowed hosts, redirects checked) and the core's parser,
/// with MacVPN's asset for this machine (`MacVPN-<version>.dmg`).
pub struct GitHubReleases<H: HttpClient = CurlHttpClient>(pub H);

impl<H: HttpClient> ReleaseSource for GitHubReleases<H> {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<Release, String> {
        let response = self.0.get(&UpdateChecker::latest_release_url(repo_id)).map_err(|e| e.to_string())?;
        let asset_for = |version: &str| MACVPN.update_asset(version, std::env::consts::ARCH);
        UpdateChecker::release_from_response(response.status, &response.data, repo, &asset_for).map_err(|e| e.message())
    }
}

// MARK: - Launch at login

/// The sandbox's login item: never registered, cannot be registered (no real login item in development).
struct SandboxLoginItem;

impl LoginItemService for SandboxLoginItem {
    fn status(&self) -> LoginItemStatus {
        LoginItemStatus::NotRegistered
    }

    fn register(&self) -> Result<(), BoxError> {
        Err("sandbox: launch at login is not registered".into())
    }

    fn unregister(&self) -> Result<(), BoxError> {
        Ok(())
    }

    fn open_system_settings_login_items(&self) {}
}

/// A fresh controller over the system state (the controller is not `Send`: one per use, on the calling thread).
/// SMAppService first, the per-user LaunchAgent as the fallback (the Swift `FallbackLoginItemService`); the
/// sandbox's item is never registered. `bundle`: the running `MacVPN.app`, if any.
pub fn login_items(home: &Path, bundle: Option<&Path>, sandbox: bool) -> LoginItemController {
    let location = match bundle {
        Some(bundle) => LoginItemLocation::current(bundle, home),
        None => LoginItemLocation::NotInApplications,
    };
    let service: Box<dyn LoginItemService> = if sandbox {
        Box::new(SandboxLoginItem)
    } else {
        Box::new(FallbackLoginItemService::new(Box::new(SMAppServiceLoginItem), LaunchAgentLoginItem::new(home)))
    };
    LoginItemController::new(service, Box::new(move || location))
}

pub fn login_item_view(state: LoginItemState) -> LoginItemView {
    LoginItemView {
        is_on: state.is_on,
        can_toggle: state.can_toggle,
        note: state.note.map(|n| n.message()),
        shows_open_settings: state.shows_open_settings,
    }
}

/// [`login_items`] as platform-api's [`LoginItems`]; the stale entries are the per-user LaunchAgent (none in the
/// sandbox).
pub struct MacLoginItems {
    controller: LoginItemController,
    home: PathBuf,
    sandbox: bool,
}

impl MacLoginItems {
    pub fn new(home: &Path, bundle: Option<&Path>, sandbox: bool) -> Self {
        MacLoginItems { controller: login_items(home, bundle, sandbox), home: home.to_path_buf(), sandbox }
    }
}

impl LoginItems for MacLoginItems {
    fn state(&self) -> LoginItemView {
        login_item_view(self.controller.state())
    }

    fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError> {
        self.controller.set_enabled(on).map_err(|e| PlatformError::Failed(e.to_string()))
    }

    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError> {
        self.controller.unregister_if_registered().map_err(|e| PlatformError::Failed(e.to_string()))
    }

    fn open_settings(&self) {
        self.controller.open_system_settings();
    }

    fn remove_stale_entries(&self) -> Result<(), PlatformError> {
        if self.sandbox {
            return Ok(());
        }
        LaunchAgentLoginItem::new(&self.home).remove().map(|_| ()).map_err(|e| PlatformError::Failed(e.to_string()))
    }
}

// MARK: - The running app

/// `…/X.app` if `exe` is `…/X.app/Contents/MacOS/<binary>`.
pub fn app_bundle(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension().is_some_and(|e| e == "app"))
    .then(|| bundle.to_path_buf())
}
