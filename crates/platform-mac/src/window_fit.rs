//! Sizing a titled window so its web page's viewport is exactly a given height.
//!
//! Tauri's default title bar style (`Visible`) gives every titled window `NSFullSizeContentViewWindowMask`: the
//! content view reaches under the title bar, and the web view keeps its page below it (the safe area). So a
//! window's "inner" size (`setContentSize:`, Tauri's `set_size`) includes the title bar, and the page sees that
//! much less: a page measured at 300 points needs a content size of 300 plus the title bar. The inset is read from
//! the window itself (`contentView` height minus `contentLayoutRect` height: 0 for a window without a title bar
//! or without the full-size mask), and the result is kept on the window's screen.
//!
//! Audit notes: the only unsafe step is turning the window pointer Tauri gives (`ns_window`) into a reference (an
//! open window, used on the main thread, where windows are only closed by the event loop running this).
#![allow(unsafe_code)]

use objc2::MainThreadMarker;
use objc2_app_kit::NSWindow;
use objc2_foundation::NSSize;
use std::ffi::c_void;

/// The content size (`setContentSize:` height) that gives a page of `viewport` points: the viewport plus the
/// title bar inset, at most `screen_height` (the screen's visible height, when known) for the whole window.
pub fn content_height(viewport: f64, inset: f64, screen_height: Option<f64>) -> f64 {
    let inset = if inset.is_finite() { inset.max(0.0) } else { 0.0 };
    let wanted = viewport + inset;
    match screen_height {
        Some(limit) if limit.is_finite() && limit > inset => wanted.min(limit),
        _ => wanted,
    }
}

/// Resizes `window` (an `NSWindow *`) so its page's viewport is `width` × `viewport` points, and centres it when
/// `center`. Returns the title bar inset it added. Main thread only; `None` when not on the main thread, for a
/// null pointer or without a content view.
pub fn fit_viewport(window: *mut c_void, width: f64, viewport: f64, center: bool) -> Option<f64> {
    MainThreadMarker::new()?;
    // SAFETY: Tauri's `ns_window()` of an open window, on the main thread (see the audit notes). Null: `None`.
    let window = unsafe { window.cast::<NSWindow>().as_ref() }?;
    let content = window.contentView()?.frame().size.height;
    let inset = content - window.contentLayoutRect().size.height;
    let screen = window.screen().map(|s| s.visibleFrame().size.height);
    // The visible frame holds the whole window: the title bar's own height is the frame's minus the content's.
    let chrome = window.frame().size.height - content;
    let height = content_height(viewport, inset, screen.map(|h| h - chrome.max(0.0)));
    window.setContentSize(NSSize::new(width, height));
    if center {
        window.center();
    }
    Some(inset.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_title_bar_is_added() {
        assert_eq!(content_height(300.0, 28.0, None), 328.0);
        assert_eq!(content_height(300.0, 0.0, None), 300.0);
        // A negative or broken inset adds nothing.
        assert_eq!(content_height(300.0, -4.0, None), 300.0);
        assert_eq!(content_height(300.0, f64::NAN, None), 300.0);
    }

    #[test]
    fn the_window_stays_on_the_screen() {
        assert_eq!(content_height(900.0, 28.0, Some(800.0)), 800.0);
        assert_eq!(content_height(300.0, 28.0, Some(800.0)), 328.0);
        // A screen too small to tell: no limit.
        assert_eq!(content_height(300.0, 28.0, Some(10.0)), 328.0);
    }

    #[test]
    fn off_the_main_thread_or_without_a_window_nothing_happens() {
        assert!(fit_viewport(std::ptr::null_mut(), 420.0, 300.0, true).is_none());
    }
}
