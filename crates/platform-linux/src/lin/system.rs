//! The user from the user database (`getpwuid_r`, not `$HOME`), the local time (`localtime_r`).

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// One string field of the current user's `passwd` entry, copied out of the call's buffer.
fn passwd_field(field: fn(&libc::passwd) -> *const libc::c_char) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: a plain C struct of integers and pointers; all-zero is a valid value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`, `buf` and `result` live on this stack frame for the call; `buf`'s length is passed.
    let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let p = field(&pwd);
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` points into `buf`, NUL-terminated by getpwuid_r, valid while `buf` lives.
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// The home directory of the user running the app (absolute, else `None`).
pub fn home() -> Option<PathBuf> {
    passwd_field(|p| p.pw_dir.cast_const()).map(|b| PathBuf::from(OsStr::from_bytes(&b))).filter(|p| p.is_absolute())
}

/// The login name.
pub fn user_name() -> Option<String> {
    passwd_field(|p| p.pw_name.cast_const()).and_then(|b| String::from_utf8(b).ok())
}

/// `(year, month, day, hour, minute, second)` in local time (the shape `macvpn_platform_api::dates` takes); `None`
/// if it cannot be converted.
pub fn local_time(unix: f64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    if !unix.is_finite() {
        return None;
    }
    let t = unix.floor() as libc::time_t;
    // SAFETY: a plain C struct of integers (and a pointer on glibc); all-zero is a valid value.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `t` and `tm` live on this stack frame for the call.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    let field = |v: libc::c_int| u32::try_from(v).ok();
    Some((
        tm.tm_year.checked_add(1900)?,
        field(tm.tm_mon)? + 1,
        field(tm.tm_mday)?,
        field(tm.tm_hour)?,
        field(tm.tm_min)?,
        field(tm.tm_sec)?,
    ))
}
