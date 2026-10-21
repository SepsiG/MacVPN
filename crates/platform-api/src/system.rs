//! The system's facts, the shell, the download mark and the system VPN watch.

use crate::PlatformError;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::AppLanguage;
use std::io;
use std::path::{Path, PathBuf};

/// The user, the app's locations and the local date formats.
pub trait SystemInfo: Send + Sync {
    fn home_directory(&self) -> Option<PathBuf>;
    /// The root of the per-user app data (macOS: `<home>/Library/Application Support`); the product's data
    /// directory is `Product::data_dir` of it.
    fn app_data_root(&self, home: &Path) -> PathBuf;
    /// The owner the helper's UI state files must have (the user running the app). `Err` where the platform cannot
    /// name one yet (Windows in phase 1): the caller then reads no state file.
    fn user_owner(&self) -> Result<FileOwner, PlatformError>;
    /// The login name of the user running the app (the helper's installer grants it the helper); `None`: unknown.
    fn user_name(&self) -> Option<String>;
    fn temporary_directory(&self) -> Result<PathBuf, PlatformError>;
    fn local_date(&self, unix: f64) -> String;
    fn local_date_time(&self, unix: f64, language: AppLanguage) -> String;
    /// The running app (macOS: the `.app` bundle); `None`: not run from an app bundle (a development build).
    fn app_location(&self) -> Option<PathBuf>;
    /// The privileged helper shipped inside `app`.
    fn bundled_helper_dir(&self, app: &Path) -> Option<PathBuf>;
    /// The update source and version information of `app` (macOS: its Info.plist).
    fn update_info(&self, app: &Path) -> Option<macvpn_core::update::Info>;
}

/// Opening files and URLs with the system, and the plain clipboard.
pub trait Shell: Send + Sync {
    /// Absolute paths only.
    fn open_path(&self, path: &Path) -> Result<(), PlatformError>;
    /// Callers validate the URL first (`is_safe_github_url`).
    fn open_url(&self, url: &str) -> Result<(), PlatformError>;
    /// The system settings where native profiles are approved (macOS: Device Management).
    fn open_native_profile_settings(&self);
    fn copy_text(&self, text: &str) -> Result<(), PlatformError>;
}

/// The mark the system puts on downloaded files (macOS: `com.apple.quarantine`).
pub trait DownloadMark: Send + Sync {
    /// Marked, or the mark could not be read (the import is then confirmed); a missing file is not marked.
    fn is_marked(&self, path: &Path) -> bool;
}

/// Watches the system's VPN configuration.
pub trait SystemVpnWatch: Send + Sync {
    /// Calls `on_change` (on the watcher's own thread) when the system's VPN setup changes. Dropping the returned
    /// box stops the watch.
    fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>>;
}
