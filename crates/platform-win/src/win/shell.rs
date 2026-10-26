//! Opening folders, URLs and Settings pages with the shell. Never a file: on Windows "open" runs an executable.

use macvpn_platform_api::PlatformError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::UI::Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn shell_open(target: &OsStr) -> Result<(), PlatformError> {
    shell_execute("open", target)
}

/// `ShellExecuteExW` with `verb`; no error dialog (`SEE_MASK_FLAG_NO_UI`): a failure is the result.
fn shell_execute(verb: &str, target: &OsStr) -> Result<(), PlatformError> {
    let (verb, target) = (wide(OsStr::new(verb)), wide(target));
    // SAFETY: plain data (integers, pointers, handles); all zero is valid (no parameters, no directory, no window).
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = target.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` is initialized with its size; the strings are NUL-terminated and outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        Ok(())
    } else {
        Err(PlatformError::Failed(format!("ShellExecute failed ({})", std::io::Error::last_os_error())))
    }
}

/// Absolute directories only (Explorer opens them); a file is refused. The shell gets the folder verb `explore`,
/// not `open` (review I6): the check above and the call are two steps, and if the folder is swapped for a file in
/// between, `open` would run or open that file, while `explore` exists for folders only and fails.
pub(crate) fn open_directory(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() || !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err(PlatformError::Failed("refused path".into()));
    }
    explore(path)
}

/// `ShellExecute` with the verb `explore`: a folder opens in Explorer; anything else fails.
fn explore(path: &Path) -> Result<(), PlatformError> {
    shell_execute("explore", path.as_os_str())
}

/// `https://` URLs only (the caller validated it already).
pub(crate) fn open_https(url: &str) -> Result<(), PlatformError> {
    if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"') {
        return Err(PlatformError::Failed("refused URL".into()));
    }
    shell_open(OsStr::new(url))
}

/// A fixed `ms-settings:` page.
pub(crate) fn open_settings(page: &'static str) {
    debug_assert!(page.starts_with("ms-settings:"));
    let _ = shell_open(OsStr::new(page));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that took the folder's place after the check is not opened, let alone run: the `explore` verb fails
    /// for it (review I6). A batch file that would leave a marker if it ran.
    #[test]
    fn explore_never_runs_a_file() {
        let dir = std::env::temp_dir().join(format!("winvpn-explore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("ran.txt");
        let script = dir.join("swapped.cmd");
        std::fs::write(&script, format!("@echo ran> \"{}\"\r\n", marker.display())).unwrap();
        assert!(explore(&script).is_err());
        assert!(open_directory(&script).is_err(), "refused by the check");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(!marker.exists(), "the file ran");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
