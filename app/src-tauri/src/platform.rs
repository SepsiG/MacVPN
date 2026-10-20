//! The app-core dependencies over the real macOS implementations (`macvpn-platform-mac`), and where the app's
//! data lives.
//!
//! Every call here is synchronous (processes with time limits, Keychain, SystemConfiguration); the connection
//! manager calls them from worker threads, never from the main thread.

use macvpn_app_core::LoginItemView;
use macvpn_app_core::app::PreferenceStore;
use macvpn_app_core::deps::{
    AuthStateReader, NativeController, ProfileInstaller, RootClient, SecretField, SecretReader, SecretWriter,
    SystemService,
};
use macvpn_app_core::logs::{LogStreamSpawner, StreamHandle};
use macvpn_app_core::updates::{ReleaseSource, UpdateSource};
use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthResponseKind, AuthUIState};
use macvpn_core::models::{Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_core::update::{Info, UpdateChecker};
use macvpn_platform_mac::command::{CommandRunner, ProcessCommandRunner, RunnerTimeouts};
use macvpn_platform_mac::http::{CurlHttpClient, HttpClient};
use macvpn_platform_mac::log_stream::{LOG_EXECUTABLE, LineStream};
use macvpn_platform_mac::login_item::{
    FallbackLoginItemService, LaunchAgentLoginItem, LoginItemController, LoginItemLocation, LoginItemService,
    LoginItemState, LoginItemStatus, SMAppServiceLoginItem,
};
use macvpn_platform_mac::mvpn_client::MvpnClient;
use macvpn_platform_mac::native_vpn::BoxError;
use macvpn_platform_mac::native_vpn::{NativeVPNController, SystemConfigurationDriver};
use macvpn_platform_mac::preferences::CFPreferencesStore;
use macvpn_platform_mac::profile_staging::{self, StagedProfiles};
use macvpn_platform_mac::secrets::{KeychainBackend, KeychainSecretStore, SecretStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use uuid::Uuid;

/// `sudo -n mvpn …` with the Swift app's time limits: `up` long, `status` / `respond` quick, the rest standard.
pub struct Root {
    standard: ProcessCommandRunner,
    up: ProcessCommandRunner,
    quick: ProcessCommandRunner,
}

impl Root {
    pub fn new() -> Self {
        Root {
            standard: ProcessCommandRunner::new(RunnerTimeouts::STANDARD),
            up: ProcessCommandRunner::new(RunnerTimeouts::UP),
            quick: ProcessCommandRunner::new(RunnerTimeouts::QUICK),
        }
    }

    fn client(&self) -> MvpnClient<'_> {
        MvpnClient::with_runners(&self.standard, Some(&self.up), Some(&self.quick), None)
    }
}

impl RootClient for Root {
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
}

/// `scutil --nc list / show` (quick time limit) and the in-process `SCNetworkConnection` driver.
pub struct Native(NativeVPNController<ProcessCommandRunner, SystemConfigurationDriver>);

impl Native {
    pub fn new() -> Self {
        Native(NativeVPNController::new(ProcessCommandRunner::new(RunnerTimeouts::QUICK), SystemConfigurationDriver))
    }
}

impl NativeController for Native {
    fn list(&self) -> Result<Vec<SystemService>, String> {
        self.0
            .list()
            .map(|services| {
                services
                    .into_iter()
                    .map(|s| SystemService { id: s.id, name: s.name, type_label: s.type_label, status: s.status })
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

/// The Keychain items (`local.macvpn.secrets`): read by the manager, written by the editors, import and delete.
pub struct Keychain<B: KeychainBackend>(pub KeychainSecretStore<B>);

impl<B: KeychainBackend> SecretReader for Keychain<B> {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.get(id, field)
    }
}

impl<B: KeychainBackend> SecretWriter for Keychain<B> {
    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        self.0.set(value, id, field);
    }

    fn delete_all(&self, id: &Uuid) {
        self.0.delete_all(id);
    }

    fn remove_all(&self) {
        self.0.remove_all();
    }
}

/// One in-memory Keychain shared by several stores (the sandbox's old Keychain items: the migration reads them
/// and the legacy read-only mode shows them).
pub struct SharedKeychain(pub Arc<macvpn_platform_mac::secrets::InMemoryKeychain>);

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

/// The native profiles: staged in a private temp directory, tracked until the service is listed, and opened
/// with `/usr/bin/open` (the sandbox stages but never opens: no profile reaches the real system).
pub struct ProfileFiles {
    pub parent: PathBuf,
    pub staged: Arc<Mutex<StagedProfiles>>,
    pub open: bool,
}

impl ProfileInstaller for ProfileFiles {
    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String> {
        let path = profile_staging::stage(profile, file_name, &self.parent).map_err(|e| e.to_string())?;
        self.staged.lock().unwrap_or_else(PoisonError::into_inner).track(*id, path.clone(), service_existed);
        if !self.open {
            eprintln!("MacVPN (sandbox): profile staged, not opened: {}", path.display());
            return Ok(());
        }
        open_path(&path)
    }
}

/// `/usr/bin/open <absolute path>` (the path cannot look like an option).
pub fn open_file(path: &Path) -> Result<(), String> {
    open_path(path)
}

fn open_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("refused path".into());
    }
    let result = ProcessCommandRunner::new(RunnerTimeouts::QUICK)
        .run("/usr/bin/open", &[path.to_string_lossy().into_owned()], None)
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

/// `log stream --style compact --predicate …` for the native debug log.
pub struct LogStreams;

struct LogStreamHandle(LineStream);

impl StreamHandle for LogStreamHandle {
    fn stop(&self) {
        self.0.stop();
    }
}

impl LogStreamSpawner for LogStreams {
    fn spawn(
        &self,
        on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String> {
        let arguments = ["stream", "--style", "compact", "--predicate", macvpn_app_core::logs::PREDICATE];
        LineStream::spawn(LOG_EXECUTABLE, &arguments, on_lines, on_exit)
            .map(|s| Box::new(LogStreamHandle(s)) as Box<dyn StreamHandle>)
            .map_err(|e| e.to_string())
    }
}

/// `/var/run/macvpn-ui/<id>.json`: a regular file owned by this user, at most 8 KB (no symlink followed).
pub struct AuthStateFiles {
    pub uid: u32,
}

impl AuthStateReader for AuthStateFiles {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        AuthUIState::read(Path::new(&AuthUIState::path(id)), self.uid)
    }
}

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

/// `releases/latest` over the curl client (HTTPS, allowed hosts, redirects checked) and the core's parser.
pub struct GitHubReleases(pub CurlHttpClient);

impl ReleaseSource for GitHubReleases {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<macvpn_core::update::Release, String> {
        let response = self.0.get(&UpdateChecker::latest_release_url(repo_id)).map_err(|e| e.to_string())?;
        UpdateChecker::release_from_response(response.status, &response.data, repo).map_err(|e| e.message())
    }
}

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
/// SMAppService first, the per-user LaunchAgent as the fallback (the Swift `FallbackLoginItemService`).
pub fn login_items(env: &Environment) -> LoginItemController {
    let location = match &env.bundle {
        Some(bundle) => LoginItemLocation::current(bundle, &env.home),
        None => LoginItemLocation::NotInApplications,
    };
    let service: Box<dyn LoginItemService> = if env.sandbox {
        Box::new(SandboxLoginItem)
    } else {
        Box::new(FallbackLoginItemService::new(Box::new(SMAppServiceLoginItem), LaunchAgentLoginItem::new(&env.home)))
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

/// Opens a validated `https://github.com/…` URL in the default browser (`/usr/bin/open <url>`; the URL cannot
/// look like an option).
pub fn open_github_url(url: &str) -> Result<(), String> {
    if !macvpn_app_core::app::is_safe_github_url(url) {
        return Err("refused URL".into());
    }
    let result = ProcessCommandRunner::new(RunnerTimeouts::QUICK)
        .run("/usr/bin/open", &[url.to_string()], None)
        .map_err(|e| e.to_string())?;
    if result.exit_code == 0 { Ok(()) } else { Err(result.stderr.trim().to_string()) }
}

/// Where the app runs and keeps its data.
#[derive(Debug, Clone)]
pub struct Environment {
    /// The user's home (from the user database, not `$HOME`); the data is under its
    /// `Library/Application Support/MacVPN`.
    pub home: PathBuf,
    /// The running `MacVPN.app`, if started from a bundle (update housekeeping, bundled root layer).
    pub bundle: Option<PathBuf>,
    /// Development only: the data under a throwaway home, secrets in memory (see [`Environment::detect`]).
    pub sandbox: bool,
    /// The bundle's Info.plist (update source, Help repo).
    pub info: Option<Info>,
}

impl Environment {
    /// Debug builds honour `MACVPN_SANDBOX_HOME=<absolute dir>`: the store, the ranking and the system OTP file
    /// go under that directory instead of the real Application Support, and the Keychain is replaced by an
    /// in-memory store (no migration, no prompt). Release builds ignore it.
    pub fn detect() -> Result<Environment, String> {
        let bundle = std::env::current_exe().ok().and_then(|exe| app_bundle(&exe));
        #[cfg(debug_assertions)]
        if let Some(home) = std::env::var_os("MACVPN_SANDBOX_HOME").map(PathBuf::from) {
            if !home.is_absolute() {
                return Err("MACVPN_SANDBOX_HOME must be an absolute path".into());
            }
            let info = bundle.as_deref().and_then(macvpn_platform_mac::system::bundle_info);
            return Ok(Environment { home, bundle, sandbox: true, info });
        }
        let home = macvpn_platform_mac::system::home_directory().ok_or("no home directory for this user")?;
        let info = bundle.as_deref().and_then(macvpn_platform_mac::system::bundle_info);
        Ok(Environment { home, bundle, sandbox: false, info })
    }

    /// Only from a bundle whose Info.plist names the repo by ID and name (the Swift `UpdateController.enabled`).
    pub fn update_source(&self) -> Option<UpdateSource> {
        let (repo_id, repo) = UpdateChecker::source_from_info(self.info.as_ref())?;
        Some(UpdateSource { repo_id, repo })
    }

    /// `MacVPNUpdateRepo` for the Help link (the core falls back to the default repo).
    pub fn repo(&self) -> Option<String> {
        UpdateChecker::repo_from_info(self.info.as_ref())
    }

    pub fn application_support(&self) -> PathBuf {
        macvpn_core::store::application_support_directory(&self.home)
    }

    pub fn connections_dir(&self) -> PathBuf {
        macvpn_core::store::default_base_dir(&self.home)
    }

    /// Where native profiles are staged: the user's private temp directory (`$TMPDIR`, as the Swift app); the
    /// sandbox uses `<sandbox>/tmp` so its launch sweep never touches a real app's staged profiles.
    pub fn staging_parent(&self) -> Option<PathBuf> {
        if self.sandbox {
            let dir = self.home.join("tmp");
            std::fs::create_dir_all(&dir).ok()?;
            return Some(dir);
        }
        macvpn_platform_mac::temp_dir::temporary_directory().ok()
    }

    /// `<bundle>/Contents/Resources/root` when it holds `mvpn`.
    pub fn bundled_root_dir(&self) -> Option<PathBuf> {
        self.bundle
            .as_ref()
            .and_then(|b| macvpn_platform_mac::system::bundled_root_directory(&b.join("Contents/Resources")))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
        let store = KeychainSecretStore::new(macvpn_platform_mac::secrets::InMemoryKeychain::new());
        let id = Uuid::new_v4();
        store.set("pw", &id, SecretField::Password);
        store.set("k", &id, SecretField::Psk);
        let reader = Keychain(store);
        assert_eq!(reader.get(&id, SecretField::Password).as_deref(), Some("pw"));
        assert_eq!(reader.get(&id, SecretField::Psk).as_deref(), Some("k"));
        assert_eq!(reader.get(&id, SecretField::Username), None);
    }
}
