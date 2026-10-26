//! The service's job object: every process the service starts (`openvpn.exe`) is in it and is killed when the
//! service ends, however it ends (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the job's only handle is the service's, so
//! it closes with the process). A VPN process must never outlive its service: nothing would own it any more.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Puts this process (and so every child it starts from now on) into a new kill-on-close job. The handle is kept
/// open on purpose until the process ends.
pub fn contain_self() -> io::Result<()> {
    // SAFETY: no security attributes (a handle that is not inherited) and no name: both may be null.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain data (integers); all zero is valid (no limits).
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `job` is the job just created; `info` is the class's structure, alive across the call, with its size.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } != 0
        // SAFETY: `job` is open; GetCurrentProcess is a pseudo handle that needs no closing.
        && unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } != 0;
    if !ok {
        let e = io::Error::last_os_error();
        // SAFETY: the job's handle, closed once (this process is not in it).
        unsafe { CloseHandle(job) };
        return Err(e);
    }
    // The handle is never closed: it lives as long as the process (leaked on purpose).
    Ok(())
}
