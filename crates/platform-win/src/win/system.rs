//! Known folders and the local time.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData, FOLDERID_System, FOLDERID_Windows,
    KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows_sys::core::{GUID, PWSTR};

pub(crate) fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut path: PWSTR = std::ptr::null_mut();
    // SAFETY: a valid GUID and out pointer, no token (the current user); on success and on failure the string is
    // CoTaskMemAlloc'ed (or null) and freed below.
    let hr = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut path) };
    let result = if hr >= 0 && !path.is_null() {
        // SAFETY: a NUL-terminated wide string from the system.
        let len = unsafe { (0..).take_while(|&i| *path.add(i) != 0).count() };
        // SAFETY: `len` u16s are readable.
        let wide = unsafe { std::slice::from_raw_parts(path, len) };
        Some(PathBuf::from(OsString::from_wide(wide))).filter(|p| p.is_absolute())
    } else {
        None
    };
    // SAFETY: CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

/// `FOLDERID_Profile` (`C:\Users\<name>`).
pub(crate) fn profile() -> Option<PathBuf> {
    known_folder(&FOLDERID_Profile)
}

/// `FOLDERID_LocalAppData` (`C:\Users\<name>\AppData\Local`).
pub(crate) fn local_app_data() -> Option<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

/// `FOLDERID_RoamingAppData` (`C:\Users\<name>\AppData\Roaming`): the user's default RAS phonebook's folder.
pub(crate) fn roaming_app_data() -> Option<PathBuf> {
    known_folder(&FOLDERID_RoamingAppData)
}

/// `FOLDERID_System` (`C:\Windows\System32`): where `curl.exe` and `msiexec.exe` are run from, never `PATH`.
pub(crate) fn system32() -> Option<PathBuf> {
    known_folder(&FOLDERID_System)
}

/// `FOLDERID_Windows` (`C:\Windows`): `SystemRoot` of the curl runner's environment.
pub(crate) fn windows_dir() -> Option<PathBuf> {
    known_folder(&FOLDERID_Windows)
}

/// The local (y, m, d, h, mi, s) of a Unix time; `None` before 1601 or past the system's range.
pub(crate) fn local_time(unix: f64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    if !unix.is_finite() || unix.abs() > 1e15 {
        return None;
    }
    // 100 ns ticks since 1601-01-01.
    let ticks = (unix.floor() as i64).checked_add(11_644_473_600)?.checked_mul(10_000_000)?;
    let ticks = u64::try_from(ticks).ok()?;
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let (mut utc, mut local) = (SYSTEMTIME::default(), SYSTEMTIME::default());
    // SAFETY: valid in and out pointers to plain structs.
    if unsafe { FileTimeToSystemTime(&ft, &mut utc) } == 0
        // SAFETY: as above; no time zone pointer: the current one.
        || unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) } == 0
    {
        return None;
    }
    Some((
        i32::from(local.wYear),
        u32::from(local.wMonth),
        u32::from(local.wDay),
        u32::from(local.wHour),
        u32::from(local.wMinute),
        u32::from(local.wSecond),
    ))
}
