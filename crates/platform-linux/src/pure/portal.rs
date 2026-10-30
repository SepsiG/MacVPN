//! The desktop portal's values: `org.freedesktop.appearance` `color-scheme` (0 no preference, 1 dark, 2 light) and
//! the FileChooser's `uris` (only `file:///…`, percent-decoded; anything else is dropped).
//!
//! `pure` compiles on every OS (the CI windows job's clippy and ARM64 check build the whole workspace): a decoded
//! path's bytes become an `OsString` as they are on Unix; elsewhere (Windows) only a UTF-8 path is kept.

use std::path::PathBuf;

pub fn dark_from_color_scheme(value: u32) -> Option<bool> {
    match value {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// `None` for a broken escape or an escaped NUL (no path can hold it).
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            if byte == 0 {
                return None;
            }
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// The local paths of `file:///…` URIs (no host), in order.
pub fn paths_from_uris(uris: &[String]) -> Vec<PathBuf> {
    uris.iter()
        .filter_map(|u| u.strip_prefix("file://"))
        .filter(|rest| rest.starts_with('/'))
        .filter_map(percent_decode)
        .filter_map(path_from_bytes)
        .collect()
}

#[cfg(unix)]
fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    String::from_utf8(bytes).ok().map(PathBuf::from)
}
