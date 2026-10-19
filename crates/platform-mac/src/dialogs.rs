//! The open and save panels (`NSOpenPanel` / `NSSavePanel`), presented as a sheet on an app window. They replace
//! SwiftUI's `fileImporter` and `NSSavePanel.runModal`: the chosen paths stay in the app's Rust side and are
//! never handed to the web view.
//!
//! Audit notes: the only unsafe step is turning the window pointer Tauri gives (`ns_window`) into a reference;
//! the caller guarantees it is a live `NSWindow` (we are on the main thread, where windows are only closed by the
//! event loop we are running in). The panels are configured and presented with safe `objc2` bindings, and the
//! completion handler only reads the chosen URLs. Never called from tests.
#![allow(unsafe_code)]

use block2::RcBlock;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSModalResponse, NSModalResponseOK, NSOpenPanel, NSSavePanel, NSWindow};
use objc2_foundation::NSString;
use std::cell::RefCell;
use std::ffi::c_void;
use std::path::PathBuf;

/// Shows an open panel for files as a sheet on `window` (an `NSWindow *`). `done` gets the chosen file paths
/// (empty on cancel, or if this is not the main thread or there is no window). Returns at once.
pub fn choose_files(window: *mut c_void, multiple: bool, done: impl FnOnce(Vec<PathBuf>) + 'static) {
    let (Some(mtm), Some(window)) = (MainThreadMarker::new(), window_ref(window)) else {
        done(Vec::new());
        return;
    };
    let panel = NSOpenPanel::openPanel(mtm);
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(multiple);
    panel.setResolvesAliases(true);
    let done = RefCell::new(Some(done));
    let chosen = panel.clone();
    let handler = RcBlock::new(move |response: NSModalResponse| {
        let Some(done) = done.borrow_mut().take() else { return };
        let paths = if response == NSModalResponseOK {
            chosen.URLs().iter().filter_map(|url| url.to_file_path()).collect()
        } else {
            Vec::new()
        };
        done(paths);
    });
    panel.beginSheetModalForWindow_completionHandler(window, &handler);
}

/// Shows a save panel as a sheet on `window` with the proposed file name and the message line. `done` gets the
/// chosen path (`None` on cancel, or if this is not the main thread or there is no window). Returns at once.
pub fn choose_save_path(
    window: *mut c_void,
    file_name: &str,
    message: Option<&str>,
    done: impl FnOnce(Option<PathBuf>) + 'static,
) {
    let (Some(mtm), Some(window)) = (MainThreadMarker::new(), window_ref(window)) else {
        done(None);
        return;
    };
    let panel = NSSavePanel::savePanel(mtm);
    panel.setNameFieldStringValue(&NSString::from_str(file_name));
    panel.setCanCreateDirectories(true);
    if let Some(message) = message {
        panel.setMessage(Some(&NSString::from_str(message)));
    }
    let done = RefCell::new(Some(done));
    let chosen = panel.clone();
    let handler = RcBlock::new(move |response: NSModalResponse| {
        let Some(done) = done.borrow_mut().take() else { return };
        let path = if response == NSModalResponseOK { chosen.URL().and_then(|url| url.to_file_path()) } else { None };
        done(path);
    });
    panel.beginSheetModalForWindow_completionHandler(window, &handler);
}

fn window_ref<'a>(window: *mut c_void) -> Option<&'a NSWindow> {
    // SAFETY: the pointer comes from Tauri's `ns_window()` for a window that is open; we are on the main thread
    // (checked by the caller through `MainThreadMarker`), so it cannot be released while the panel is set up.
    // A null pointer gives `None`.
    unsafe { window.cast::<NSWindow>().as_ref() }
}
