//! Running a program elevated: `ShellExecuteExW` with the `runas` verb (the UAC prompt; a standard user enters an
//! administrator's credentials). Two callers:
//!
//! - [`run_elevated`] waits for the program and returns its exit code: the OpenVPN install runs only its own
//!   installed `WinVPN.exe` this way (the elevated step of `pure::openvpn_install`), after checking that only
//!   administrators can change that file.
//! - [`start_elevated`] does not wait and hands back the process handle: the updater starts
//!   `<System32>\msiexec.exe` this way and quits while it runs (its relauncher waits for msiexec instead).
//!
//! **The elevated program is another account.** On a standard user's account the UAC prompt is over the shoulder:
//! it asks for an administrator's credentials, and the elevated program runs as *that* administrator, not as the
//! signed-in user. Every file the app hands across (one the elevated program reads, or writes: a log) must
//! therefore be open to that account. The app keeps its own folders private (this user and SYSTEM) and opens only
//! the file itself: [`readable_by_the_elevated_step`] ([`Protection::Shared`]: `BUILTIN\Users` read, for public
//! inputs: an installer, a CA certificate) and [`writable_by_the_elevated_step`] ([`Protection::AdminsReadWrite`]:
//! `BUILTIN\Administrators` read and write, never delete or `WRITE_DAC`). The private folders above need not
//! change: every account has "Bypass traverse checking" (`SeChangeNotifyPrivilege`), so a full path opens a file
//! whose own DACL allows it. On an administrator's own account (consent prompt) the elevated program is the same
//! user and a private file would do: the tests prove the other case by the DACL's shape and the system's access
//! check for another account (`macvpn_winsys::file::access_for`).

use macvpn_winsys::file::{self as wfile, Protection};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, GetLastError, WAIT_OBJECT_0};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

fn wide(s: &OsStr) -> Option<Vec<u16>> {
    let w: Vec<u16> = s.encode_wide().collect();
    (!w.contains(&0)).then(|| w.into_iter().chain(Some(0)).collect())
}

/// Starts `exe` (an absolute path) with `parameters` elevated, without waiting: the process handle (owned by the
/// caller); `Err(1223)` (`ERROR_CANCELLED`) when the UAC prompt was declined, `Err(other)` when it could not be
/// started.
pub(crate) fn start_elevated(exe: &Path, parameters: &str) -> Result<OwnedHandle, u32> {
    if !exe.is_absolute() {
        return Err(ERROR_INVALID_HANDLE);
    }
    let (Some(file), Some(params), Some(verb)) =
        (wide(exe.as_os_str()), wide(OsStr::new(parameters)), wide(OsStr::new("runas")))
    else {
        return Err(ERROR_INVALID_HANDLE);
    };
    let dir = exe.parent().and_then(|d| wide(d.as_os_str()));
    // ShellExecuteEx may use COM (shell extensions); this thread is the caller's worker thread.
    // SAFETY: plain call; balanced by CoUninitialize below when it succeeded (S_OK or S_FALSE).
    let com = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    // SAFETY: an all-zero SHELLEXECUTEINFOW is a valid "nothing set" value (null pointers and handles, zero flags).
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.lpDirectory = dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr());
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` and the strings it points to live across the call.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    let result = if ok == 0 {
        // SAFETY: plain call, right after the failing one (ERROR_CANCELLED: UAC declined).
        Err(unsafe { GetLastError() })
    } else if info.hProcess.is_null() {
        Err(ERROR_INVALID_HANDLE)
    } else {
        // SAFETY: SEE_MASK_NOCLOSEPROCESS hands this process handle to the caller, who now owns it.
        Ok(unsafe { OwnedHandle::from_raw_handle(info.hProcess) })
    };
    if com >= 0 {
        // SAFETY: balances the successful CoInitializeEx above on this thread.
        unsafe { CoUninitialize() };
    }
    result
}

/// Runs `exe` (an absolute path) with `parameters` elevated and returns its exit code; `Err(1223)`
/// (`ERROR_CANCELLED`) when the UAC prompt was declined, `Err(other)` when it could not be started.
pub(crate) fn run_elevated(exe: &Path, parameters: &str) -> Result<u32, u32> {
    let process = start_elevated(exe, parameters)?;
    let mut code = 0u32;
    // SAFETY: a valid process handle owned by `process` (closed when it drops).
    let waited = unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } == WAIT_OBJECT_0
        // SAFETY: as above; `code` is a plain out value.
        && unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } != 0;
    if waited { Ok(code) } else { Err(ERROR_INVALID_HANDLE) }
}

/// Opens an existing file of this user to an elevated program that only reads it ([`Protection::Shared`]:
/// `BUILTIN\Users`, which every interactive account is a member of, may read it; only this user and SYSTEM may change
/// it). For public inputs only (a signed installer, a CA certificate), which the elevated program checks itself.
/// Never through a reparse point. The caller then holds the file deny-write and checks it through that handle.
pub(crate) fn readable_by_the_elevated_step(path: &Path) -> io::Result<()> {
    let f = wfile::open(
        path,
        wfile::Open {
            read: false,
            write: true,
            append: false,
            disposition: wfile::Disposition::OpenExisting,
            protection: None,
            no_follow: true,
        },
    )?;
    wfile::set_protection(&f, Protection::Shared, false)
}

/// Opens a file of this user, through a handle with `WRITE_DAC`, to an elevated program that writes it
/// ([`Protection::AdminsReadWrite`]: the administrator the UAC prompt asked for may read and write it, never delete
/// it or change its DACL).
pub(crate) fn writable_by_the_elevated_step(file: &File) -> io::Result<()> {
    wfile::set_protection(file, Protection::AdminsReadWrite, false)
}
