//! "Launch at Login".

use crate::PlatformError;
use serde::Serialize;

/// "Launch at Login" (the platform layer's `LoginItemState`, mapped by the app).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginItemView {
    pub is_on: bool,
    pub can_toggle: bool,
    /// The note under the switch (already translated).
    pub note: Option<String>,
    /// The "Open Login Items Settings…" button.
    pub shows_open_settings: bool,
}

/// The app's login item (macOS: `SMAppService` with the LaunchAgent fallback; the sandbox: a no-op item).
pub trait LoginItems {
    fn state(&self) -> LoginItemView;
    fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError>;
    /// Unregisters the item if it is registered (uninstall); `true`: it was registered.
    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError>;
    /// Opens the system's login item settings.
    fn open_settings(&self);
    /// Removes the leftover entries of earlier versions (macOS: a stale LaunchAgent).
    fn remove_stale_entries(&self) -> Result<(), PlatformError>;
}
