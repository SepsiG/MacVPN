//! AppKit hooks the Tauri runtime does not offer:
//!
//! - `applicationShouldTerminate:` on the app delegate. Tauri's macOS runtime (tao) does not implement it, so a
//!   system quit (logout, restart, shutdown, a quit Apple Event) would terminate at once, past the quit
//!   questions. The method is added to the delegate's class at run time and asks a Rust handler: now, cancel, or
//!   later (the Swift `.terminateLater`, answered with [`reply_to_terminate`]). Tauri's own `app.exit` stops the
//!   event loop without `terminate:`, so it does not come through here.
//! - the `NSWorkspace` wake notification (the Swift `didWakeNotification` refresh);
//! - activating the app and ordering a window front without making it key (the MFA prompt does not steal the
//!   focus: the Swift `orderFrontRegardless`).
//!
//! Audit notes: `class_addMethod` adds (never replaces) the method on the live delegate's class, with the type
//! encoding of `- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender` (`Q@:@`); the
//! IMP has exactly that C signature. It is only added when the class does not respond to the selector already.
//! The window pointer comes from Tauri's `ns_window()` for an open window, used on the main thread only. The wake
//! observer's token is kept for the rest of the process.
#![allow(unsafe_code)]

use block2::RcBlock;
use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::sel;
use objc2_app_kit::{NSApplication, NSWindow, NSWorkspace, NSWorkspaceDidWakeNotification};
use objc2_foundation::NSNotification;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::OnceLock;

/// The handler's answer (platform-api's), mapped to `NSApplicationTerminateReply` when AppKit asks.
pub use macvpn_platform_api::TerminateReply;

/// `NSApplicationTerminateReply`: `NSTerminateCancel` 0, `NSTerminateNow` 1, `NSTerminateLater` 2 (answered later
/// with [`reply_to_terminate`]).
fn ns_reply(reply: TerminateReply) -> usize {
    match reply {
        TerminateReply::Cancel => 0,
        TerminateReply::Now => 1,
        TerminateReply::Later => 2,
    }
}

type TerminateHandler = Box<dyn Fn() -> TerminateReply + Send + Sync>;

static ON_TERMINATE: OnceLock<TerminateHandler> = OnceLock::new();

extern "C-unwind" fn should_terminate(_this: &AnyObject, _cmd: Sel, _sender: *mut AnyObject) -> usize {
    // A panic must not unwind into AppKit: then the app just terminates, as without the handler.
    let reply = std::panic::catch_unwind(|| ON_TERMINATE.get().map_or(TerminateReply::Now, |handler| handler()));
    ns_reply(reply.unwrap_or(TerminateReply::Now))
}

/// Routes `applicationShouldTerminate:` to `handler` (called on the main thread). Call on the main thread after
/// the app finished launching (Tauri's `setup`). False: not on the main thread, no delegate, the delegate already
/// answers it, or a handler was installed before.
pub fn install_terminate_handler(handler: impl Fn() -> TerminateReply + Send + Sync + 'static) -> bool {
    let Some(mtm) = MainThreadMarker::new() else { return false };
    let Some(delegate) = NSApplication::sharedApplication(mtm).delegate() else { return false };
    let selector = sel!(applicationShouldTerminate:);
    let object: &AnyObject = delegate.as_ref();
    let class: &AnyClass = object.class();
    if class.responds_to(selector) || ON_TERMINATE.set(Box::new(handler)).is_err() {
        return false;
    }
    let function: extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> usize = should_terminate;
    // SAFETY: an IMP is any C function pointer; it is only called through the selector whose encoding is given
    // below, which matches `function`'s signature (object, selector, object) -> NSUInteger.
    let imp: Imp =
        unsafe { std::mem::transmute::<extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> usize, Imp>(function) };
    // SAFETY: a live class (the delegate's), a valid selector, the IMP above and its NUL-terminated encoding.
    unsafe { objc2::ffi::class_addMethod((class as *const AnyClass).cast_mut(), selector, imp, c"Q@:@".as_ptr()) }
        .as_bool()
}

/// The answer to a terminate request that got [`TerminateReply::Later`]. Main thread only.
pub fn reply_to_terminate(terminate: bool) {
    if let Some(mtm) = MainThreadMarker::new() {
        NSApplication::sharedApplication(mtm).replyToApplicationShouldTerminate(terminate);
    }
}

/// Brings the app to the front (a click on an "authentication needed" notification). Main thread only.
pub fn activate_app() {
    if let Some(mtm) = MainThreadMarker::new() {
        #[allow(deprecated)]
        NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
    }
}

/// Whether the app is a regular app (Dock icon, Cmd+Tab) rather than an accessory one: `NSApp.activationPolicy`.
/// For the smoke test (debug builds only). Main thread only; `None` elsewhere.
#[cfg(debug_assertions)]
pub fn activation_policy_is_regular() -> Option<bool> {
    let mtm = MainThreadMarker::new()?;
    Some(
        NSApplication::sharedApplication(mtm).activationPolicy()
            == objc2_app_kit::NSApplicationActivationPolicy::Regular,
    )
}

/// Puts the whole app in dark mode (`NSApp.appearance = darkAqua`), or light mode (`aqua`), whatever the system's
/// setting, which is not touched. For the smoke test's screenshots (debug builds only). Main thread only; false
/// elsewhere.
#[cfg(debug_assertions)]
pub fn force_appearance(dark: bool) -> bool {
    let Some(mtm) = MainThreadMarker::new() else { return false };
    // SAFETY: immutable AppKit string constants.
    let name =
        unsafe { if dark { objc2_app_kit::NSAppearanceNameDarkAqua } else { objc2_app_kit::NSAppearanceNameAqua } };
    let appearance = objc2_app_kit::NSAppearance::appearanceNamed(name);
    NSApplication::sharedApplication(mtm).setAppearance(appearance.as_deref());
    appearance.is_some()
}

/// Shows `window` (an `NSWindow *`) above the others without making it key or activating the app. Main thread
/// only; a null pointer does nothing.
pub fn order_front_regardless(window: *mut c_void) {
    if MainThreadMarker::new().is_none() {
        return;
    }
    // SAFETY: the pointer is Tauri's `ns_window()` of an open window, used on the main thread (windows are only
    // closed by the event loop running this). Null gives `None`.
    if let Some(window) = unsafe { window.cast::<NSWindow>().as_ref() } {
        window.orderFrontRegardless();
    }
}

/// Calls `on_wake` whenever the Mac wakes from sleep (on the thread that posts the notification). Once per
/// process; a second call does nothing.
pub fn observe_wake(on_wake: impl Fn() + Send + Sync + 'static) {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let block = RcBlock::new(move |_note: NonNull<NSNotification>| on_wake());
    let center = NSWorkspace::sharedWorkspace().notificationCenter();
    // SAFETY: a valid notification name, no object filter, no queue (the posting thread), and a block that only
    // calls `on_wake`.
    let token = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(NSWorkspaceDidWakeNotification), None, None, &block)
    };
    // The observer lives as long as the process.
    std::mem::forget::<Retained<_>>(token);
}
