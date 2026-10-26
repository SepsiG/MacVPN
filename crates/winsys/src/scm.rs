//! A service's recovery settings (what the SCM does when the service fails), set through the SCM.
//!
//! Why not the MSI: Windows Installer's MsiServiceConfigFailureActions opens the service without SERVICE_START,
//! which ChangeServiceConfig2 requires for a restart action, so the install fails with error 1939 (access denied).
//! The service sets its own recovery instead (2b plan, Task 15, fix2).
//!
//! Also: another service's start type and state, and disabling and stopping one (OpenVPN's Interactive Service
//! after an OpenVPN install WinVPN made: 2b plan, Task 17, decision 4).

use crate::util::{check, wide};
use std::ffi::OsStr;
use std::io;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_NOT_ACTIVE};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfigW, QueryServiceStatus, SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_STOP, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW,
    SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS, SERVICE_STOP,
};

/// `dwStartType` of a disabled service (`SERVICE_DISABLED`).
pub const START_DISABLED: u32 = windows_sys::Win32::System::Services::SERVICE_DISABLED;
/// `dwCurrentState` of a stopped service (`SERVICE_STOPPED`).
pub const STATE_STOPPED: u32 = windows_sys::Win32::System::Services::SERVICE_STOPPED;

/// What the SCM does after one failure of the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Nothing.
    None,
    /// Start the service again after this many milliseconds.
    Restart { delay_ms: u32 },
}

/// The recovery settings: the n-th failure (counted since the last reset) takes the n-th action, every later one the
/// last action; the count goes back to 0 after `reset_period_secs` without a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery<'a> {
    pub reset_period_secs: u32,
    pub actions: &'a [FailureAction],
    /// Also when the service stops itself with a non-zero exit code, not only when its process dies.
    pub on_non_crash_failures: bool,
}

/// An SC_HANDLE, closed on drop.
struct ScHandle(SC_HANDLE);

impl ScHandle {
    fn new(h: SC_HANDLE) -> io::Result<Self> {
        if h.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(h)) }
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: a handle OpenSCManagerW/OpenServiceW returned, closed once, here.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Sets the recovery settings of the installed service `name` on this machine (no reboot message, no command).
/// Needs the right to change the service's configuration and to start it (LocalSystem and administrators have
/// both). Setting the same values again changes nothing.
pub fn set_recovery(name: &str, recovery: &Recovery<'_>) -> io::Result<()> {
    let name = wide(OsStr::new(name))?;
    let mut actions: Vec<SC_ACTION> = recovery
        .actions
        .iter()
        .map(|a| match *a {
            FailureAction::None => SC_ACTION { Type: SC_ACTION_NONE, Delay: 0 },
            FailureAction::Restart { delay_ms } => SC_ACTION { Type: SC_ACTION_RESTART, Delay: delay_ms },
        })
        .collect();
    let count = u32::try_from(actions.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: plain call; null machine and database name: this machine's active database.
    let scm = ScHandle::new(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) })?;
    // SAFETY: a valid SCM handle; `name` is NUL-terminated and alive across the call. SERVICE_START: a restart
    // action needs it (the right Windows Installer leaves out).
    let service = ScHandle::new(unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_CHANGE_CONFIG | SERVICE_START) })?;
    // "": no reboot message, no command (an empty string deletes either).
    let (mut reboot, mut command) = ([0u16], [0u16]);
    let info = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: recovery.reset_period_secs,
        lpRebootMsg: reboot.as_mut_ptr(),
        lpCommand: command.as_mut_ptr(),
        cActions: count,
        lpsaActions: if actions.is_empty() { std::ptr::null_mut() } else { actions.as_mut_ptr() },
    };
    // SAFETY: a valid service handle; `info` and everything it points to (the two empty strings, the actions) live
    // across the call, which only reads them.
    check(unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS, (&raw const info).cast()) })?;
    let flag =
        SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: recovery.on_non_crash_failures.into() };
    // SAFETY: a valid service handle; `flag` lives across the call.
    check(unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, (&raw const flag).cast()) })
}

/// What the SCM says about an installed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceState {
    /// `dwStartType` (`SERVICE_AUTO_START` 2, `SERVICE_DEMAND_START` 3, [`START_DISABLED`] 4, …).
    pub start_type: u32,
    /// `dwCurrentState` ([`STATE_STOPPED`] 1, `SERVICE_RUNNING` 4, …).
    pub current_state: u32,
}

impl ServiceState {
    pub fn is_disabled_and_stopped(&self) -> bool {
        self.start_type == START_DISABLED && self.current_state == STATE_STOPPED
    }
}

fn open_service(name: &str, access: u32) -> io::Result<(ScHandle, ScHandle)> {
    let name = wide(OsStr::new(name))?;
    // SAFETY: plain call; null machine and database name: this machine's active database.
    let scm = ScHandle::new(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) })?;
    // SAFETY: a valid SCM handle; `name` is NUL-terminated and alive across the call.
    let service = ScHandle::new(unsafe { OpenServiceW(scm.0, name.as_ptr(), access) })?;
    Ok((scm, service))
}

fn status(service: &ScHandle) -> io::Result<u32> {
    let mut st = SERVICE_STATUS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: a valid service handle with SERVICE_QUERY_STATUS; `st` is a plain out struct.
    check(unsafe { QueryServiceStatus(service.0, &mut st) })?;
    Ok(st.dwCurrentState)
}

fn start_type(service: &ScHandle) -> io::Result<u32> {
    let mut needed = 0u32;
    // SAFETY: a size query (null buffer, size 0); `needed` receives the size.
    let ok = unsafe { QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut needed) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(e);
        }
    }
    // u64 elements: aligned for QUERY_SERVICE_CONFIGW (pointers and u32s).
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(size_of::<QUERY_SERVICE_CONFIGW>().div_ceil(8))];
    let size = u32::try_from(buf.len() * 8).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let config = buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: `buf` holds `size` bytes, aligned for the struct; the SCM writes the struct and its strings there.
    check(unsafe { QueryServiceConfigW(service.0, config, size, &mut needed) })?;
    // SAFETY: the call succeeded, so the struct at the start of `buf` is initialized.
    Ok(unsafe { (*config).dwStartType })
}

/// The start type and state of the installed service `name` (any user may ask for most services).
pub fn query(name: &str) -> io::Result<ServiceState> {
    let (_scm, service) = open_service(name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    Ok(ServiceState { start_type: start_type(&service)?, current_state: status(&service)? })
}

/// Sets the installed service `name` to disabled, asks it to stop and waits up to `timeout` for it to have
/// stopped; then reads its start type and state back (the caller checks [`ServiceState::is_disabled_and_stopped`]).
/// Needs an administrator (or SYSTEM). A service that is not running is fine.
pub fn disable_and_stop(name: &str, timeout: Duration) -> io::Result<ServiceState> {
    let (_scm, service) =
        open_service(name, SERVICE_CHANGE_CONFIG | SERVICE_STOP | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    let no_change = SERVICE_NO_CHANGE;
    // SAFETY: a valid service handle with SERVICE_CHANGE_CONFIG; only the start type changes (SERVICE_NO_CHANGE
    // and null pointers leave everything else as it is).
    check(unsafe {
        ChangeServiceConfigW(
            service.0,
            no_change,
            START_DISABLED,
            no_change,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    })?;
    if status(&service)? != STATE_STOPPED {
        let mut st = SERVICE_STATUS {
            dwServiceType: 0,
            dwCurrentState: 0,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        // SAFETY: a valid service handle with SERVICE_STOP; `st` is a plain out struct.
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                return Err(e);
            }
        }
        let deadline = Instant::now() + timeout;
        while status(&service)? != STATE_STOPPED && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(ServiceState { start_type: start_type(&service)?, current_state: status(&service)? })
}
