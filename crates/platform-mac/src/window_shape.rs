//! Rounded corners for a borderless window (the menu bar popover), without the private API and without a
//! transparent webview: the window is made non-opaque with a clear background, its content view gets a layer
//! with a corner radius (continuous curve, like the system's popovers) that masks its subviews (the web view
//! included), and the shadow is recomputed from the rounded shape.
//!
//! Audit notes: the only unsafe steps are turning the window pointer Tauri gives (`ns_window`) into a reference
//! (an open window, used on the main thread, where windows are only closed by the event loop running this) and
//! reading the `kCACornerCurveContinuous` constant (an immutable QuartzCore string). Everything else goes through
//! the safe `objc2` bindings.
#![allow(unsafe_code)]

use objc2::MainThreadMarker;
use objc2_app_kit::{NSColor, NSWindow};
use objc2_quartz_core::kCACornerCurveContinuous;
use std::ffi::c_void;

/// The radius the system uses for its popovers and Control Center panels (points).
pub const POPOVER_CORNER_RADIUS: f64 = 12.0;

/// The radius that fits a `width` × `height` window: at most half its shorter side, never negative (0 for
/// values that are not finite).
pub fn fitted_radius(radius: f64, width: f64, height: f64) -> f64 {
    if !(radius.is_finite() && width.is_finite() && height.is_finite()) {
        return 0.0;
    }
    radius.min(width.min(height) / 2.0).max(0.0)
}

/// SAFETY contract of the callers: `window` is Tauri's `ns_window()` of an open window and we are on the main
/// thread. Null gives `None`.
fn window_ref<'a>(window: *mut c_void) -> Option<&'a NSWindow> {
    MainThreadMarker::new()?;
    // SAFETY: see above; the reference does not outlive the main-thread call that made it.
    unsafe { window.cast::<NSWindow>().as_ref() }
}

/// Gives `window` (an `NSWindow *`, borderless) rounded corners of `radius` points and a shadow that follows
/// them. Idempotent: call it again after a resize (it recomputes the shadow). Main thread only; false when not on
/// the main thread, for a null pointer, or when the window has no content view.
pub fn round_corners(window: *mut c_void, radius: f64) -> bool {
    let Some(window) = window_ref(window) else { return false };
    let Some(content) = window.contentView() else { return false };
    let size = content.frame().size;
    let radius = fitted_radius(radius, size.width, size.height);
    window.setOpaque(false);
    window.setBackgroundColor(Some(&NSColor::clearColor()));
    window.setHasShadow(true);
    content.setWantsLayer(true);
    let Some(layer) = content.layer() else { return false };
    layer.setCornerRadius(radius);
    // SAFETY: an immutable string constant exported by QuartzCore (macOS 10.15+; the app needs 14).
    layer.setCornerCurve(unsafe { kCACornerCurveContinuous });
    layer.setMasksToBounds(true);
    window.invalidateShadow();
    true
}

/// What [`round_corners`] set, read back from the window (for the smoke test).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowShape {
    pub radius: f64,
    pub masks: bool,
    pub opaque: bool,
    pub shadow: bool,
    /// The window server's number (`screencapture -l`).
    pub number: isize,
}

/// `window`'s number in the window server (`screencapture -l`). Main thread only; `None` elsewhere or for null.
pub fn number(window: *mut c_void) -> Option<isize> {
    window_ref(window).map(|w| w.windowNumber())
}

/// Reads `window`'s shape. Main thread only; `None` elsewhere, for a null pointer or without a content layer.
pub fn shape(window: *mut c_void) -> Option<WindowShape> {
    let window = window_ref(window)?;
    let layer = window.contentView()?.layer()?;
    Some(WindowShape {
        radius: layer.cornerRadius(),
        masks: layer.masksToBounds(),
        opaque: window.isOpaque(),
        shadow: window.hasShadow(),
        number: window.windowNumber(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_radius_is_the_popovers() {
        assert_eq!(POPOVER_CORNER_RADIUS, 12.0);
    }

    #[test]
    fn the_radius_fits_the_window() {
        assert_eq!(fitted_radius(12.0, 330.0, 360.0), 12.0);
        assert_eq!(fitted_radius(12.0, 330.0, 16.0), 8.0);
        assert_eq!(fitted_radius(-3.0, 330.0, 360.0), 0.0);
        assert_eq!(fitted_radius(f64::NAN, 330.0, 360.0), 0.0);
        assert_eq!(fitted_radius(12.0, f64::INFINITY, 360.0), 0.0);
    }

    #[test]
    fn off_the_main_thread_or_without_a_window_nothing_happens() {
        // The test harness runs tests off the main thread; a null window does nothing on any thread.
        assert!(!round_corners(std::ptr::null_mut(), POPOVER_CORNER_RADIUS));
        assert!(shape(std::ptr::null_mut()).is_none());
        assert!(number(std::ptr::null_mut()).is_none());
    }
}
