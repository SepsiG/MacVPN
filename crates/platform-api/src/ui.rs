//! The native UI services: window chrome, file panels, notifications, the secret clipboard and the app's
//! lifecycle.

use crate::PlatformError;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::path::PathBuf;

/// A native window handle (macOS: an `NSWindow *`; Windows: an `HWND`), as the app's window gives it. Never
/// dereferenced outside a platform crate.
///
/// Neither `Send` nor `Sync`: a raw pointer is neither, and nothing needs it to be. The traits take it by value
/// on the thread that owns the window (window calls are main-thread only), and the trait objects stay
/// `Send + Sync` regardless of their argument types. Making it `Send` would need an `unsafe impl`, which this
/// crate does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeWindow(pub *mut c_void);

/// The windows' shape and placement. Main thread only.
pub trait WindowChrome: Send + Sync {
    /// The menu popover's corner radius.
    fn popover_corner_radius(&self) -> f64;
    /// Rounds the window's corners; `false`: not applied (not the main thread, no window).
    fn round_corners(&self, w: NativeWindow, radius: f64) -> bool;
    /// Fits the window to the web view's content `viewport` height at `width`; the height set, if any.
    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64>;
    /// Brings the window to the front even when the app is not active.
    fn order_front_regardless(&self, w: NativeWindow);
}

/// Open and save panels, as sheets on `parent`. Main thread only; they return at once and call `done` later
/// (with nothing on cancel, or when not on the main thread or without a window).
pub trait FilePanels: Send + Sync {
    fn choose_files(&self, parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>);
    /// `suggested`: the proposed file name; `message`: the panel's message line.
    fn choose_save_path(
        &self,
        parent: NativeWindow,
        suggested: &str,
        message: Option<&str>,
        done: Box<dyn FnOnce(Option<PathBuf>)>,
    );
}

/// The system's notifications.
pub trait Notifier: Send + Sync {
    /// Starts the notification service; `on_click` gets the clicked notification's user info.
    fn start(&self, on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>);
    fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str));
    fn remove_delivered(&self, identifier: &str);
}

/// What a secret write left (macOS: the pasteboard's change count after it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClipboardMark(pub isize);

/// Secrets on the clipboard: kept off clipboard managers and other devices where the system allows it, and
/// cleared later only if nothing was copied since.
pub trait SecretClipboard: Send + Sync {
    fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError>;
    /// Clears the clipboard if it still holds what was written with `mark`; `true`: cleared.
    fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool;
}

/// The answer to the system's request to quit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateReply {
    Now,
    /// The app answers later with [`AppLifecycle::reply_to_terminate`].
    Later,
    Cancel,
}

/// The app's quit request and the system's wake.
pub trait AppLifecycle: Send + Sync {
    /// Routes the system's quit request to `handler` (called on the main thread). `false`: not installed.
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool;
    /// The later answer to a quit request answered with [`TerminateReply::Later`].
    fn reply_to_terminate(&self, terminate: bool);
    /// Calls `on_wake` when the system wakes from sleep.
    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>);
}
