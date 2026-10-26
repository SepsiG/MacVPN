//! IFileOpenDialog / IFileSaveDialog, owned by the parent window, shown from the message window's queue (so the
//! trait's calls return at once and the modal loop never runs inside a caller's lock).

use super::msgwin;
use macvpn_platform_api::{FilePanels, NativeWindow};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
};
use windows::Win32::UI::Shell::{
    FOS_ALLOWMULTISELECT, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
    FOS_PATHMUSTEXIST, FileOpenDialog, FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem, SIGDN_FILESYSPATH,
};
use windows::core::{HRESULT, HSTRING};

fn cancelled(e: &windows::core::Error) -> bool {
    e.code() == HRESULT::from_win32(ERROR_CANCELLED.0)
}

fn path_of(item: &IShellItem) -> windows::core::Result<PathBuf> {
    // SAFETY: GetDisplayName returns a CoTaskMemAlloc'ed, NUL-terminated string, freed after the copy.
    unsafe {
        let name = item.GetDisplayName(SIGDN_FILESYSPATH)?;
        let text = name.to_string();
        CoTaskMemFree(Some(name.0 as *const _));
        // A path that is not valid UTF-16 is refused (the app works with UTF-8 paths).
        Ok(PathBuf::from(text.map_err(|_| windows::core::Error::from(HRESULT::from_win32(87)))?))
    }
}

fn open(owner: HWND, multiple: bool) -> windows::core::Result<Vec<PathBuf>> {
    // SAFETY: COM on the main (STA) thread; a second initialization is harmless (S_FALSE / RPC_E_CHANGED_MODE).
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
        let mut options = dialog.GetOptions()? | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST;
        if multiple {
            options |= FOS_ALLOWMULTISELECT;
        }
        dialog.SetOptions(options)?;
        match dialog.Show(Some(owner)) {
            Err(e) if cancelled(&e) => return Ok(Vec::new()),
            other => other?,
        }
        let items = dialog.GetResults()?;
        (0..items.GetCount()?).map(|i| path_of(&items.GetItemAt(i)?)).collect()
    }
}

fn save(owner: HWND, suggested: &str, message: Option<&str>) -> windows::core::Result<Option<PathBuf>> {
    // SAFETY: as in `open`.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)?;
        dialog.SetOptions(
            dialog.GetOptions()? | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_NOREADONLYRETURN | FOS_PATHMUSTEXIST,
        )?;
        dialog.SetFileName(&HSTRING::from(suggested))?;
        if let Some(message) = message {
            dialog.SetTitle(&HSTRING::from(message))?;
        }
        match dialog.Show(Some(owner)) {
            Err(e) if cancelled(&e) => return Ok(None),
            other => other?,
        }
        Ok(Some(path_of(&dialog.GetResult()?)?))
    }
}

/// Posts `show` to the main thread's queue. `done` runs exactly once: with the dialog's answer, or at once with
/// `fallback` (as on cancel) without a parent window or when the job cannot be posted (not the main thread).
fn later<T: 'static>(parent: NativeWindow, show: impl FnOnce() -> T + 'static, done: Box<dyn FnOnce(T)>, fallback: T) {
    if parent.0.is_null() {
        done(fallback);
        return;
    }
    let slot = Rc::new(RefCell::new(Some(done)));
    let job_slot = slot.clone();
    let posted = msgwin::post(Box::new(move || {
        let done = job_slot.borrow_mut().take();
        if let Some(done) = done {
            done(show());
        }
    }));
    if !posted {
        let done = slot.borrow_mut().take();
        if let Some(done) = done {
            done(fallback);
        }
    }
}

pub(crate) struct Panels;

impl FilePanels for Panels {
    /// An error (no window, COM failure) reads as cancel.
    fn choose_files(&self, parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>) {
        let owner = HWND(parent.0);
        later(parent, move || open(owner, multiple).unwrap_or_default(), done, Vec::new());
    }

    fn choose_save_path(
        &self,
        parent: NativeWindow,
        suggested: &str,
        message: Option<&str>,
        done: Box<dyn FnOnce(Option<PathBuf>)>,
    ) {
        let owner = HWND(parent.0);
        let (suggested, message) = (suggested.to_string(), message.map(str::to_string));
        later(parent, move || save(owner, &suggested, message.as_deref()).ok().flatten(), done, None);
    }
}
