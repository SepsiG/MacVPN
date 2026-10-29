//! The platform layer's interface (spec 3): the traits every platform implements (`macvpn-platform-mac`, the
//! Windows stub), the shared types, and the product identity ([`Product`]).
//!
//! The app reaches every platform service through one [`Platform`] handle. Traits the app implements over its own
//! state stay in app-core; core's own traits ([`KeyStore`], [`Entropy`], [`LegacyKeychain`], [`CatalogFetcher`])
//! stay in core, because core's vault and catalog code call them, and are re-exported here.
//!
//! Platform-independent: no `cfg(target_os)` and no `unsafe` here.

#![forbid(unsafe_code)]

pub mod control;
pub mod curl;
#[cfg(debug_assertions)]
pub mod debug;
pub mod error;
pub mod helper;
pub mod login_item;
pub mod logs;
pub mod native_vpn;
pub mod network;
pub mod prefs;
pub mod product;
pub mod setup;
pub mod system;
pub mod traffic;
pub mod ui;
pub mod updates;

pub use control::{Accepted, BoundEndpoint, ControlListener, ControlStream, ControlTransport, PeerIdentity, PeerUser};
#[cfg(debug_assertions)]
pub use debug::{SmokeHooks, WindowShape};
pub use error::PlatformError;
pub use helper::{AuthStateReader, HelperClient, LegacySecrets, NoAuthState};
pub use login_item::{LoginItemView, LoginItems};
pub use logs::{LogStreamSpawner, StreamHandle};
pub use native_vpn::{
    AdminSteps, CaSummary, NativeController, NativeProfile, NativeProfiles, NativeSupport, NoAdminSteps,
    NoNativeSupport, PlatformNotes, SystemVpn,
};
pub use network::{Gateway, NetworkProbe, NetworkSnapshot, NoNetworkProbe};
pub use prefs::{FilePreferences, MemoryPreferences, PreferenceStore};
pub use product::{MACVPN, Product, WINVPN};
pub use setup::{
    BootstrapTexts, EngineReport, EngineRow, MissingEngine, OutdatedPackage, PackageIndexUpdate, SetupReport,
    SystemSetup,
};
pub use system::{DownloadMark, Shell, SystemInfo, SystemVpnWatch};
pub use traffic::{CounterWidth, HelperTunnel, TrafficReading};
pub use ui::{
    AppLifecycle, ClipboardMark, FilePanels, NativeWindow, Notifier, SecretClipboard, TerminateReply, WindowChrome,
};
pub use updates::{ReleaseSource, UpdateOutcome, UpdateSource, Updater};

pub use macvpn_core::TargetOs;
pub use macvpn_core::catalog::fetch::CatalogFetcher;
pub use macvpn_core::vault::{Entropy, KeyStore, LegacyKeychain};

use std::path::Path;
use std::sync::Arc;

/// One handle per platform crate; the app's `platform` module returns `&'static dyn Platform`.
pub trait Platform: Send + Sync {
    fn product(&self) -> &'static Product;
    /// Collation, preferred languages and the text platform.
    fn install_core_hooks(&self);
    fn system(&self) -> &dyn SystemInfo;
    fn shell(&self) -> &dyn Shell;
    fn setup(&self) -> &dyn SystemSetup;
    fn updater(&self) -> &dyn Updater;
    fn windows(&self) -> &dyn WindowChrome;
    fn file_panels(&self) -> &dyn FilePanels;
    fn notifier(&self) -> &dyn Notifier;
    fn clipboard(&self) -> &dyn SecretClipboard;
    fn lifecycle(&self) -> &dyn AppLifecycle;
    fn download_mark(&self) -> &dyn DownloadMark;
    fn system_vpn_watch(&self) -> &dyn SystemVpnWatch;
    fn control_transport(&self) -> Arc<dyn ControlTransport>;
    fn helper_client(&self) -> Arc<dyn HelperClient>;
    fn native_controller(&self) -> Arc<dyn NativeController>;
    /// `staging`: the private parent directory of staged profiles; `open`: open a staged profile for approval.
    fn native_profiles(&self, staging: &Path, open: bool) -> Arc<dyn NativeProfiles>;
    /// Which managed connections the platform cannot connect with their settings. Default: every one can (macOS).
    fn native_support(&self) -> Arc<dyn NativeSupport> {
        Arc::new(NoNativeSupport)
    }
    /// The administrator steps of the native VPNs (WinVPN 2c: trust a CA, allow L2TP behind NAT). Default: none
    /// (macOS).
    fn admin_steps(&self) -> Arc<dyn AdminSteps> {
        Arc::new(NoAdminSteps)
    }
    fn auth_state(&self) -> Arc<dyn AuthStateReader>;
    fn log_streams(&self) -> Arc<dyn LogStreamSpawner>;
    fn release_source(&self) -> Arc<dyn ReleaseSource>;
    fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher>;
    fn key_store(&self) -> Arc<dyn KeyStore>;
    fn entropy(&self) -> Arc<dyn Entropy>;
    fn legacy_keychain(&self) -> Arc<dyn LegacyKeychain>;
    /// The 1.1 secrets as the legacy read-only mode reads them (macOS: `KeychainSecretStore`; the sandbox shares
    /// one memory keychain with `legacy_keychain`).
    fn legacy_secrets(&self) -> Arc<dyn LegacySecrets>;
    /// The one-time move of the older service's Keychain items (`KeychainSecretStore::migrate_legacy_items`; a
    /// no-op in the sandbox and on other platforms).
    fn migrate_legacy_service(&self);
    fn preferences(&self) -> Arc<dyn PreferenceStore>;
    fn login_items(&self, home: &Path, app: Option<&Path>, sandbox: bool) -> Box<dyn LoginItems>;
    /// The physical network (auto-reconnect). Default: none.
    fn network(&self) -> &dyn NetworkProbe {
        &NoNetworkProbe
    }
}
