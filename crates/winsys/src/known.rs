//! Known folders (`SHGetKnownFolderPath`): where Windows says a folder is, never an environment variable (which
//! the caller's environment could change).

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, FOLDERID_System, FOLDERID_Windows, SHGetKnownFolderPath};
use windows_sys::core::{GUID, PWSTR};

/// `C:\ProgramData` (`FOLDERID_ProgramData`), as this machine has it.
pub fn program_data() -> io::Result<PathBuf> {
    known(&FOLDERID_ProgramData)
}

/// `C:\Windows\System32` (`FOLDERID_System`): where the WinVPN Service runs `curl.exe` from, never `PATH`.
pub fn system32() -> io::Result<PathBuf> {
    known(&FOLDERID_System)
}

/// `C:\Windows` (`FOLDERID_Windows`): `SystemRoot` of a child's bare environment.
pub fn windows_dir() -> io::Result<PathBuf> {
    known(&FOLDERID_Windows)
}

fn known(id: &GUID) -> io::Result<PathBuf> {
    let mut path: PWSTR = std::ptr::null_mut();
    // SAFETY: a GUID constant that lives across the call; no flags; no token (the machine's folder); `path` is a
    // valid out pointer. The buffer is allocated with CoTaskMemAlloc, even on failure (then freed below too).
    let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut path) };
    let result = if hr < 0 || path.is_null() {
        Err(io::Error::from_raw_os_error(hr))
    } else {
        // SAFETY: on success `path` is a NUL-terminated UTF-16 string the call allocated; read up to the NUL.
        let wide = unsafe {
            let len = (0..).take_while(|&i| *path.add(i) != 0).count();
            std::slice::from_raw_parts(path, len)
        };
        let p = PathBuf::from(OsString::from_wide(wide));
        if p.is_absolute() { Ok(p) } else { Err(io::Error::new(io::ErrorKind::InvalidData, "not an absolute path")) }
    };
    // SAFETY: null or the buffer SHGetKnownFolderPath allocated; freed once, here, after the copy.
    unsafe { CoTaskMemFree(path as *const core::ffi::c_void) };
    result
}
