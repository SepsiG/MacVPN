//! Where the app runs and keeps its data, from the platform's [`SystemInfo`] and the product's identity.

use macvpn_app_core::updates::UpdateSource;
use macvpn_core::update::{Info, UpdateChecker};
use macvpn_platform_api::Platform;
use std::path::PathBuf;

/// Where the app runs and keeps its data.
#[derive(Debug, Clone)]
pub struct Environment {
    /// The user's home (from the user database, not `$HOME`); the data is in the product's data directory below
    /// the platform's app-data root (`Product::data_dir`).
    pub home: PathBuf,
    /// The running app bundle (`MacVPN.app`), if started from one (update housekeeping, bundled root layer).
    pub bundle: Option<PathBuf>,
    /// Development only: the data under a throwaway home, secrets in memory (see [`Environment::sandbox_home`]).
    pub sandbox: bool,
    /// The bundle's Info.plist (update source, Help repo).
    pub info: Option<Info>,
}

impl Environment {
    /// Debug builds honour `MACVPN_SANDBOX_HOME=<absolute dir>`: the store, the ranking and the system OTP file
    /// go under that directory instead of the real Application Support, and the Keychain is replaced by an
    /// in-memory store (no migration, no prompt; `platform::init(true)`). Release builds ignore it.
    pub fn sandbox_home() -> Result<Option<PathBuf>, String> {
        #[cfg(debug_assertions)]
        if let Some(home) = std::env::var_os("MACVPN_SANDBOX_HOME").map(PathBuf::from) {
            if !home.is_absolute() {
                return Err("MACVPN_SANDBOX_HOME must be an absolute path".into());
            }
            return Ok(Some(home));
        }
        Ok(None)
    }

    /// The environment over `platform`; `sandbox_home` from [`Environment::sandbox_home`].
    pub fn detect(platform: &dyn Platform, sandbox_home: Option<PathBuf>) -> Result<Environment, String> {
        let system = platform.system();
        let bundle = system.app_location();
        if let Some(home) = sandbox_home {
            let info = bundle.as_deref().and_then(|b| system.update_info(b));
            return Ok(Environment { home, bundle, sandbox: true, info });
        }
        let home = system.home_directory().ok_or("no home directory for this user")?;
        let info = bundle.as_deref().and_then(|b| system.update_info(b));
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

    /// The app's data directory: the product's data directory under the platform's app-data root (MacVPN:
    /// `<home>/Library/Application Support/MacVPN`).
    pub fn application_support(&self) -> PathBuf {
        let platform = super::get();
        platform.product().data_dir(&platform.system().app_data_root(&self.home))
    }

    pub fn connections_dir(&self) -> PathBuf {
        macvpn_core::store::ConnectionStore::default_base_dir(&self.application_support())
    }

    /// Where native profiles are staged: the user's private temp directory (`$TMPDIR`, as the Swift app); the
    /// sandbox uses `<sandbox>/tmp` so its launch sweep never touches a real app's staged profiles.
    pub fn staging_parent(&self) -> Option<PathBuf> {
        if self.sandbox {
            let dir = self.home.join("tmp");
            std::fs::create_dir_all(&dir).ok()?;
            return Some(dir);
        }
        super::get().system().temporary_directory().ok()
    }

    /// The privileged helper shipped in the bundle (macOS: `<bundle>/Contents/Resources/root` when it holds
    /// `mvpn`).
    pub fn bundled_root_dir(&self) -> Option<PathBuf> {
        self.bundle.as_ref().and_then(|b| super::get().system().bundled_helper_dir(b))
    }
}
