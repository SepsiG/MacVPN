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
    /// The radius [`round_corners`](Self::round_corners) gives every window once it is created; `None`: the
    /// system's own corners stay (macOS: AppKit rounds its windows by itself). Windows 11: rounded (8); on Windows
    /// 10 the call fails and the corners stay square.
    fn window_corner_radius(&self) -> Option<f64> {
        None
    }
    /// Fits the window to the web view's content `viewport` height at `width`; the height set, if any.
    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64>;
    /// Brings the window to the front even when the app is not active.
    fn order_front_regardless(&self, w: NativeWindow);
    /// Moves and resizes the window's outer frame in one step (physical pixels, screen coordinates), so it never
    /// shows the new size at the old place; main thread only. `false`: not done here (the caller moves and
    /// resizes in two steps). Windows: the popover above the taskbar keeps its bottom edge while it resizes.
    fn set_outer_frame(&self, _w: NativeWindow, _x: i32, _y: i32, _width: u32, _height: u32) -> bool {
        false
    }
    /// The colour the tray icon is drawn in: `None` keeps the template image (the system tints it: macOS);
    /// `Some(rgb)` recolours its opaque pixels (Windows: white on a dark taskbar, black on a light one).
    fn tray_tint(&self) -> Option<[u8; 3]> {
        None
    }
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

/// The app's quit request and the system's sleep and wake.
pub trait AppLifecycle: Send + Sync {
    /// Routes the system's quit request to `handler` (called on the main thread). `false`: not installed.
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool;
    /// The later answer to a quit request answered with [`TerminateReply::Later`].
    fn reply_to_terminate(&self, terminate: bool);
    /// Calls `on_wake` when the system wakes from sleep.
    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>);
    /// Calls `on_sleep` when the system is about to sleep (it may not be called at all, e.g. Windows Modern Standby
    /// without a registration). Default: never.
    fn observe_sleep(&self, _on_sleep: Box<dyn Fn() + Send + Sync>) {}
    /// Calls `on_change` when the system's light/dark theme changes (Windows: the taskbar's, which the tray icon's
    /// tint follows), on the platform's event thread. Default: never (macOS: the template image is tinted by the
    /// system).
    fn observe_appearance(&self, _on_change: Box<dyn Fn() + Send + Sync>) {}
}
