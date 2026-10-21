//! The update source and the installer.

use macvpn_core::update::Release;
use std::path::{Path, PathBuf};

/// GitHub's `releases/latest` (the platform layer's HTTP client over the core's parser).
pub trait ReleaseSource: Send + Sync {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<Release, String>;
}

/// `MacVPNUpdateRepoID` (the query) and `MacVPNUpdateRepo` (the asset checks, Help): both or no update check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSource {
    pub repo_id: i64,
    pub repo: String,
}

/// How an [`Updater::install`] ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The helper runs and waits for this process: the app must quit now.
    HelperLaunched,
    /// The user declined to quit; everything was cleaned up.
    Cancelled,
}

/// The platform's update installer.
pub trait Updater: Send + Sync {
    /// Download, verify (SHA-256 + Ed25519), install, relaunch, in the one allowed order (macOS: today's
    /// `update_installer::install_update` over the real `UpdateInstaller`). `app` is the running app (macOS: the
    /// `.app` bundle); `stage` gets the localized step text; `confirm_quit` asks the quit questions. The error is
    /// the localized message.
    fn install(
        &self,
        release: &Release,
        app: &Path,
        home: &Path,
        stage: &dyn Fn(String),
        confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Result<UpdateOutcome, String>;

    /// Once at launch (macOS: `update_installer::launch_housekeeping(app, cache, home, noticed)` with the cache
    /// directory derived from `home` inside the platform): the removed leftovers, and the previous run's
    /// `(run id, message)` notice unless `noticed` is that run.
    fn launch_housekeeping(
        &self,
        app: &Path,
        home: &Path,
        noticed: Option<&str>,
    ) -> (Vec<PathBuf>, Option<(String, String)>);

    /// The installer's download cache under `home` (removed with the user data); `None`: the platform keeps none.
    fn cache_directory(&self, home: &Path) -> Option<PathBuf>;
}
