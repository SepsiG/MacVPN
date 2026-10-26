use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::core::BOOL;

/// A NUL-terminated UTF-16 copy; an interior NUL is refused (it would cut the path short).
pub(crate) fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = s.encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a NUL character in a path or name"));
    }
    w.push(0);
    Ok(w)
}

pub(crate) fn wide_path(p: &Path) -> io::Result<Vec<u16>> {
    wide(p.as_os_str())
}

/// `Err(last OS error)` for a FALSE result.
pub(crate) fn check(ok: BOOL) -> io::Result<()> {
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Memory the system allocated with `LocalAlloc` (security descriptors from `GetSecurityInfo`), freed on drop.
pub(crate) struct LocalBox(pub(crate) *mut core::ffi::c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a system call documented to allocate with LocalAlloc; freed once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Refuses every path but a plain absolute path on a drive letter: `X:\dir\file`, written with backslashes, with no
/// `.` or `..`, no empty component and no `:` after the drive (an alternate data stream). UNC paths (another
/// machine decides what they contain), `\\?\` and device paths are refused too. The checks that need a path to
/// name exactly one object (trust, admin-only, DLL loading) start here: every ancestor of such a path is a prefix
/// of its text, so the chain they check is the chain Windows resolves.
pub(crate) fn plain_absolute(p: &Path) -> io::Result<()> {
    use std::path::{Component, Prefix};
    let refuse = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a plain absolute path (X:\\…) is required: {}", p.display()),
        )
    };
    let mut parts = p.components();
    match (parts.next(), parts.next()) {
        (Some(Component::Prefix(prefix)), Some(Component::RootDir)) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
        _ => return Err(refuse()),
    }
    let mut rebuilt = p.components().take(2).collect::<std::path::PathBuf>().into_os_string();
    for part in parts {
        let Component::Normal(name) = part else { return Err(refuse()) };
        if name.encode_wide().any(|c| c == u16::from(b':') || c == u16::from(b'/')) {
            return Err(refuse());
        }
        if !rebuilt.as_encoded_bytes().ends_with(b"\\") {
            rebuilt.push("\\");
        }
        rebuilt.push(name);
    }
    // No forward slash, no doubled separator, no trailing separator: the text is exactly the components.
    if rebuilt != *p.as_os_str() {
        return Err(refuse());
    }
    Ok(())
}
