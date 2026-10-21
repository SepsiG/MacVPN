//! The smoke run's hooks into the platform (debug builds only).

use crate::NativeWindow;

/// What `WindowChrome::round_corners` set, read back from the window (for the smoke test).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowShape {
    pub radius: f64,
    pub masks: bool,
    pub opaque: bool,
    pub shadow: bool,
    /// The window server's number (`screencapture -l`).
    pub number: isize,
}

/// The smoke run's platform hooks. A platform without them returns `false` / `None` and seeds nothing.
pub trait SmokeHooks {
    /// Forces the light or dark appearance; `false`: not applied.
    fn force_appearance(&self, dark: bool) -> bool;
    fn window_shape(&self, w: NativeWindow) -> Option<WindowShape>;
    fn window_number(&self, w: NativeWindow) -> Option<isize>;
    fn activation_policy_is_regular(&self) -> Option<bool>;
    /// Writes `(service, account, data)` items into the sandbox's memory keychain.
    fn seed_legacy_keychain(&self, items: &[(String, String, Vec<u8>)]);
}
