//! `macvpn-platform-api` on macOS: [`MacPlatform`] and the adapters it hands out.
//!
//! Every accessor wraps this crate's existing modules, so the behaviour is the 1.4 app's. The sandbox
//! (`MacPlatform::new(true)`, the app's `MACVPN_SANDBOX_HOME`) never reaches the real Keychain or the real
//! preferences: the auto-unlock key and the preferences are in memory, and the old Keychain items (the
//! migration's source and the legacy read-only mode's secrets) are one shared in-memory keychain.
//!
//! The storage identifiers stay literals of their modules (`local.macvpn.vault`, `local.macvpn.secrets`, the
//! preferences domain `local.macvpn`, the LaunchAgent label, `macvpn.sock`); they never derive from
//! [`MACVPN`](macvpn_platform_api::MACVPN).

mod adapters;
mod control;
mod services;

pub use adapters::{
    AuthStateFiles, GitHubReleases, Helper, Keychain, LogStreams, MacLoginItems, Native, Preferences, ProfileFiles,
    SharedKeychain, app_bundle, copy_to_pasteboard, login_item_view, login_items, open_file, open_path,
    open_profiles_settings, open_url,
};
pub use control::{Transport, UnixControlListener, UnixControlStream};
pub use services::{
    MacClipboard, MacDownloadMark, MacFilePanels, MacLifecycle, MacNetwork, MacNotifier, MacSetup, MacShell, MacSystem,
    MacSystemVpnWatch, MacUpdater, MacWindows,
};

use crate::catalog_http::CurlCatalogFetcher;
use crate::http::CurlHttpClient;
use crate::legacy_store::KeychainLegacy;
use crate::preferences::CFPreferencesStore;
use crate::profile_staging::StagedProfiles;
use crate::secrets::{InMemoryKeychain, KeychainSecretStore};
use crate::vault_keys::{KeychainKeyStore, SystemEntropy};
use macvpn_core::vault::MemoryKeyStore;
use macvpn_platform_api::prefs::MemoryPreferences;
use macvpn_platform_api::{
    AppLifecycle, AuthStateReader, CatalogFetcher, ControlTransport, DownloadMark, Entropy, FilePanels, HelperClient,
    KeyStore, LegacyKeychain, LegacySecrets, LogStreamSpawner, LoginItems, MACVPN, NativeController, NativeProfiles,
    NetworkProbe, Notifier, Platform, PreferenceStore, Product, ReleaseSource, SecretClipboard, Shell, SystemInfo,
    SystemSetup, SystemVpnWatch, Updater, WindowChrome,
};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The sandbox's stores, created once so every accessor hands out the same ones.
struct Sandbox {
    /// The old Keychain items: [`MacPlatform::legacy_keychain`] and [`MacPlatform::legacy_secrets`] share it.
    keychain: Arc<InMemoryKeychain>,
    key_store: Arc<MemoryKeyStore>,
    preferences: Arc<MemoryPreferences>,
}

/// The macOS platform (MacVPN).
pub struct MacPlatform {
    sandbox: Option<Sandbox>,
    setup: MacSetup,
    /// The physical network probe and watch (inert in the sandbox).
    network: MacNetwork,
    /// The staged native profiles, tracked until their service is listed (shared by every
    /// [`MacPlatform::native_profiles`] and [`MacPlatform::staged_profiles`]).
    staged: Arc<Mutex<StagedProfiles>>,
}

impl MacPlatform {
    /// `sandbox`: the development sandbox (`MACVPN_SANDBOX_HOME`, debug builds): memory stores instead of the
    /// Keychain and the preferences domain, no migration of the older Keychain service, no root installer.
    pub fn new(sandbox: bool) -> MacPlatform {
        let sandbox = sandbox.then(|| Sandbox {
            keychain: Arc::new(InMemoryKeychain::new()),
            key_store: Arc::new(MemoryKeyStore::new()),
            preferences: Arc::new(MemoryPreferences::new()),
        });
        MacPlatform {
            setup: MacSetup { sandbox: sandbox.is_some() },
            network: MacNetwork::new(sandbox.is_some()),
            sandbox,
            staged: Arc::new(Mutex::new(StagedProfiles::default())),
        }
    }

    pub fn is_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }

    /// The staged native profiles of [`MacPlatform::native_profiles`] (the launch deletes a profile once its
    /// service is listed: `StagedProfiles::services_seen`).
    pub fn staged_profiles(&self) -> Arc<Mutex<StagedProfiles>> {
        self.staged.clone()
    }
}

impl Platform for MacPlatform {
    fn product(&self) -> &'static Product {
        &MACVPN
    }

    /// The CoreFoundation collation, the preferred languages and MacVPN's text platform.
    fn install_core_hooks(&self) {
        crate::install_core_hooks();
        macvpn_core::l10n::set_text_platform(MACVPN.text_platform());
    }

    fn system(&self) -> &dyn SystemInfo {
        &MacSystem
    }

    fn shell(&self) -> &dyn Shell {
        &MacShell
    }

    fn setup(&self) -> &dyn SystemSetup {
        &self.setup
    }

    fn updater(&self) -> &dyn Updater {
        &MacUpdater
    }

    fn windows(&self) -> &dyn WindowChrome {
        &MacWindows
    }

    fn file_panels(&self) -> &dyn FilePanels {
        &MacFilePanels
    }

    fn notifier(&self) -> &dyn Notifier {
        &MacNotifier
    }

    fn clipboard(&self) -> &dyn SecretClipboard {
        &MacClipboard
    }

    fn lifecycle(&self) -> &dyn AppLifecycle {
        &MacLifecycle
    }

    fn download_mark(&self) -> &dyn DownloadMark {
        &MacDownloadMark
    }

    /// The physical network (auto-reconnect); the sandbox has none.
    fn network(&self) -> &dyn NetworkProbe {
        &self.network
    }

    fn system_vpn_watch(&self) -> &dyn SystemVpnWatch {
        &MacSystemVpnWatch
    }

    fn control_transport(&self) -> Arc<dyn ControlTransport> {
        Arc::new(Transport)
    }

    fn helper_client(&self) -> Arc<dyn HelperClient> {
        Arc::new(Helper::new())
    }

    fn native_controller(&self) -> Arc<dyn NativeController> {
        Arc::new(Native::new())
    }

    fn native_profiles(&self, staging: &Path, open: bool) -> Arc<dyn NativeProfiles> {
        Arc::new(ProfileFiles { parent: staging.to_path_buf(), staged: self.staged.clone(), open })
    }

    fn auth_state(&self) -> Arc<dyn AuthStateReader> {
        Arc::new(AuthStateFiles { uid: crate::system::user_id() })
    }

    fn log_streams(&self) -> Arc<dyn LogStreamSpawner> {
        Arc::new(LogStreams)
    }

    fn release_source(&self) -> Arc<dyn ReleaseSource> {
        Arc::new(GitHubReleases(CurlHttpClient::default()))
    }

    /// curl; the sandbox refuses every HTTPS source (debug builds only: release builds have no sandbox).
    fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher> {
        #[cfg(debug_assertions)]
        if self.sandbox.is_some() {
            return Arc::new(SandboxHttps);
        }
        Arc::new(CurlCatalogFetcher::default())
    }

    fn key_store(&self) -> Arc<dyn KeyStore> {
        match &self.sandbox {
            Some(sandbox) => sandbox.key_store.clone(),
            None => Arc::new(KeychainKeyStore::new()),
        }
    }

    fn entropy(&self) -> Arc<dyn Entropy> {
        Arc::new(SystemEntropy)
    }

    fn legacy_keychain(&self) -> Arc<dyn LegacyKeychain> {
        match &self.sandbox {
            Some(sandbox) => {
                Arc::new(KeychainLegacy::new(KeychainSecretStore::new(SharedKeychain(sandbox.keychain.clone()))))
            }
            None => Arc::new(KeychainLegacy::system()),
        }
    }

    fn legacy_secrets(&self) -> Arc<dyn LegacySecrets> {
        match &self.sandbox {
            Some(sandbox) => Arc::new(Keychain(KeychainSecretStore::new(SharedKeychain(sandbox.keychain.clone())))),
            None => Arc::new(Keychain(KeychainSecretStore::system())),
        }
    }

    fn migrate_legacy_service(&self) {
        if self.sandbox.is_none() {
            KeychainSecretStore::system().migrate_legacy_items();
        }
    }

    fn preferences(&self) -> Arc<dyn PreferenceStore> {
        match &self.sandbox {
            Some(sandbox) => sandbox.preferences.clone(),
            None => Arc::new(Preferences(CFPreferencesStore::app())),
        }
    }

    fn login_items(&self, home: &Path, app: Option<&Path>, sandbox: bool) -> Box<dyn LoginItems> {
        Box::new(MacLoginItems::new(home, app, sandbox))
    }
}

/// The sandbox's HTTPS source: refused (smoke runs use a file source; HTTPS is covered by the fetcher's own
/// tests and the manual checklist). Debug builds only: release builds have no sandbox.
#[cfg(debug_assertions)]
pub struct SandboxHttps;

#[cfg(debug_assertions)]
impl CatalogFetcher for SandboxHttps {
    fn fetch(
        &self,
        _: &macvpn_core::catalog::fetch::FetchRequest,
    ) -> Result<macvpn_core::catalog::fetch::FetchOutcome, macvpn_core::catalog::format::CatalogError> {
        Err(macvpn_core::catalog::format::CatalogError::Io(macvpn_core::l10n::tr(
            "HTTPS sources are not available in the sandbox",
            &[],
        )))
    }
}

/// The smoke run's hooks (debug builds only).
#[cfg(debug_assertions)]
impl macvpn_platform_api::SmokeHooks for MacPlatform {
    fn force_appearance(&self, dark: bool) -> bool {
        crate::app_hooks::force_appearance(dark)
    }

    fn window_shape(&self, w: macvpn_platform_api::NativeWindow) -> Option<macvpn_platform_api::WindowShape> {
        crate::window_shape::shape(w.0)
    }

    fn window_number(&self, w: macvpn_platform_api::NativeWindow) -> Option<isize> {
        crate::window_shape::number(w.0)
    }

    fn activation_policy_is_regular(&self) -> Option<bool> {
        crate::app_hooks::activation_policy_is_regular()
    }

    /// Only the sandbox's memory keychain is seeded; outside the sandbox nothing is written.
    fn seed_legacy_keychain(&self, items: &[(String, String, Vec<u8>)]) {
        use crate::secrets::KeychainBackend;
        if let Some(sandbox) = &self.sandbox {
            for (service, account, data) in items {
                sandbox.keychain.write(data, service, account);
            }
        }
    }
}
