//! The open / save panels as sheets on an app window (the platform's
//! [`FilePanels`](macvpn_platform_api::FilePanels)), awaited from a command.
//! The chosen paths stay here: no command takes or returns a file path, so the web view can neither name a file
//! to read or write nor learn where the user's files are.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use tauri::{AppHandle, Manager};

use crate::platform;
use crate::state::AppState;

/// One panel at a time; released when the panel's answer arrives.
struct Busy<'a>(&'a AppState);

impl<'a> Busy<'a> {
    fn take(state: &'a AppState) -> Result<Self, String> {
        if state.dialog_open.swap(true, Ordering::SeqCst) {
            return Err("a panel is already open".into());
        }
        Ok(Busy(state))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.dialog_open.store(false, Ordering::SeqCst);
    }
}

async fn receive<T: Send + 'static>(rx: mpsc::Receiver<T>) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || rx.recv().map_err(|_| "the panel closed".to_string()))
        .await
        .map_err(|e| e.to_string())?
}

/// The files chosen in an open panel on `window` (empty: cancelled).
pub async fn choose_files(
    app: &AppHandle,
    state: &AppState,
    window: &str,
    multiple: bool,
) -> Result<Vec<PathBuf>, String> {
    let _busy = Busy::take(state)?;
    let window = app.get_webview_window(window).ok_or("no window")?;
    let (tx, rx) = mpsc::channel();
    let target = window.clone();
    window
        .run_on_main_thread(move || {
            let done: Box<dyn FnOnce(Vec<PathBuf>)> = Box::new(move |paths| {
                let _ = tx.send(paths);
            });
            match platform::native_window(&target) {
                Some(native) => platform::get().file_panels().choose_files(native, multiple, done),
                // No window: as a cancelled panel.
                None => done(Vec::new()),
            }
        })
        .map_err(|e| e.to_string())?;
    receive(rx).await
}

/// The path chosen in a save panel on `window` (`None`: cancelled).
pub async fn choose_save_path(
    app: &AppHandle,
    state: &AppState,
    window: &str,
    file_name: String,
    message: Option<String>,
) -> Result<Option<PathBuf>, String> {
    let _busy = Busy::take(state)?;
    let window = app.get_webview_window(window).ok_or("no window")?;
    let (tx, rx) = mpsc::channel();
    let target = window.clone();
    window
        .run_on_main_thread(move || {
            let done: Box<dyn FnOnce(Option<PathBuf>)> = Box::new(move |path| {
                let _ = tx.send(path);
            });
            match platform::native_window(&target) {
                Some(native) => {
                    platform::get().file_panels().choose_save_path(native, &file_name, message.as_deref(), done);
                }
                // No window: as a cancelled panel.
                None => done(None),
            }
        })
        .map_err(|e| e.to_string())?;
    receive(rx).await
}
