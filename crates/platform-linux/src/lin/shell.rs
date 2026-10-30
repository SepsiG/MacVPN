//! Opening folders and URLs with the desktop's handler (`/usr/bin/xdg-open`, which GNOME routes to `gio open`),
//! detached; never a file (that would run or open it with an unknown app).

use macvpn_platform_api::PlatformError;
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

const XDG_OPEN: &str = "/usr/bin/xdg-open";

/// Starts `xdg-open <argument>` (one argument, no options) and reaps it on a thread of its own (no zombie).
fn spawn(argument: &OsStr) -> Result<(), PlatformError> {
    let mut child = Command::new(XDG_OPEN)
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| PlatformError::Failed(format!("{XDG_OPEN}: {e}")))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Absolute directories only (not a symbolic link to one, as on Windows); a file is refused.
pub fn open_directory(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() || !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err(PlatformError::Failed("not an absolute directory".into()));
    }
    spawn(path.as_os_str())
}

/// `https://` only (the callers validate the URL first: `is_safe_github_url`). `xdg-open` takes no options, and a
/// URL starting with `https://` cannot look like one.
pub fn open_https(url: &str) -> Result<(), PlatformError> {
    if !url.starts_with("https://") {
        return Err(PlatformError::Failed("refused URL".into()));
    }
    spawn(OsStr::new(url))
}
