//! The files a second launch hands to the running instance: absolute paths, one per line, UTF-8, at most
//! [`MAX_PATHS`] paths and [`MAX_BYTES`] bytes. An empty message means "show yourself".
//!
//! The receiver trusts nothing: a message that is too large, not UTF-8, or has a single line that is not an
//! absolute file path (relative, a device or verbatim path such as `\\.\pipe\…`, a control character) is dropped
//! as a whole. What remains goes through the same import confirmation as a double-click.

use std::path::{Path, PathBuf};

pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_PATHS: usize = 256;

/// One path as a line, or why not.
fn line(p: &Path) -> Result<&str, &'static str> {
    let s = p.to_str().ok_or("a path that is not UTF-8")?;
    if s.contains(['\n', '\r', '\0']) {
        return Err("a line break in a path");
    }
    Ok(s)
}

pub fn encode(paths: &[PathBuf]) -> Result<Vec<u8>, &'static str> {
    if paths.len() > MAX_PATHS {
        return Err("too many paths");
    }
    let mut out = String::new();
    for p in paths {
        out.push_str(line(p)?);
        out.push('\n');
    }
    if out.len() > MAX_BYTES {
        return Err("too many paths");
    }
    Ok(out.into_bytes())
}

/// A device or verbatim path (`\\.\`, `\\?\`, `\??\`, in either slash): never a plain file.
fn is_device_path(s: &str) -> bool {
    let b = s.as_bytes();
    let sep = |c: u8| c == b'\\' || c == b'/';
    b.len() >= 4 && sep(b[0]) && (sep(b[1]) || b[1] == b'?') && matches!(b[2], b'.' | b'?') && sep(b[3])
}

fn acceptable(l: &str) -> bool {
    !l.chars().any(char::is_control) && !is_device_path(l) && Path::new(l).is_absolute()
}

/// The paths of a message; anything malformed or too large is dropped as a whole (an empty list).
pub fn decode(bytes: &[u8]) -> Vec<PathBuf> {
    if bytes.len() > MAX_BYTES {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(bytes) else { return Vec::new() };
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    if lines.len() > MAX_PATHS || !lines.iter().all(|l| acceptable(l)) {
        return Vec::new();
    }
    lines.into_iter().map(PathBuf::from).collect()
}
