//! `WinVPNService.exe service` under the SCM: service name `WinVPN` (the MSI's ServiceInstall), own process,
//! LocalSystem; accepts STOP, SHUTDOWN and SESSIONCHANGE. Start: the job, the data directory (degraded when it is
//! not in order), the install folder (`install_dir`: when others can change it, the service logs why and stops with
//! an error), the pipe (`Endpoint::Service`: owner SYSTEM, the production DACL; a name taken by someone else is
//! retried every 5 s), the recovery settings (`recovery`: restart after a failure; only logged when they cannot be
//! set). Stop: every connection down, the run directories removed.

use super::service_log::ServiceLog;
use super::{RealHost, data_dir, job, real_host, server, session};
use crate::windows::service::Service;
use crate::windows::{install_dir, recovery};
use macvpn_core::service_proto::PIPE_NAME;
use macvpn_winsys::pipe::{Endpoint, Listener};
use macvpn_winsys::scm::{self, FailureAction, Recovery};
use macvpn_winsys::sid::Sid;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::core::PWSTR;

/// `WTS_SESSION_LOGOFF` (winuser.h; in windows-sys only under `Win32_UI_WindowsAndMessaging`).
const WTS_SESSION_LOGOFF: u32 = 6;
/// The service's exit code when it cannot run at all (no job, not LocalSystem, an install folder others can change).
const FAILED: u32 = 1;

static STOP: AtomicBool = AtomicBool::new(false);
/// The SERVICE_STATUS_HANDLE (null until registered; never closed).
static STATUS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static SERVICE: OnceLock<Arc<Service<RealHost>>> = OnceLock::new();
static LOG: OnceLock<ServiceLog> = OnceLock::new();

fn service_name() -> Vec<u16> {
    recovery::SERVICE_NAME.encode_utf16().chain(Some(0)).collect()
}

/// Sets the service's recovery settings (every start: the same values again change nothing). Windows Installer
/// cannot set them (2b plan, Task 15, fix2). A failure is only logged: the service runs on without them.
fn set_recovery(log: &ServiceLog) {
    let actions = recovery::ACTIONS.map(|a| match a {
        Some(delay_ms) => FailureAction::Restart { delay_ms },
        None => FailureAction::None,
    });
    let settings = Recovery {
        reset_period_secs: recovery::RESET_PERIOD_SECS,
        actions: &actions,
        on_non_crash_failures: recovery::ON_NON_CRASH_FAILURES,
    };
    if let Err(e) = scm::set_recovery(recovery::SERVICE_NAME, &settings) {
        log.line(&format!("cannot set the recovery actions ({:?}, {:?})", e.kind(), e.raw_os_error()));
    }
}

/// Hands the process to the SCM; returns when the service has stopped (1: not started by the SCM).
pub fn run() -> i32 {
    let mut name = service_name();
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table (terminated by a null entry) and the name live until the dispatcher returns, which is after
    // the service has stopped.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 { 1 } else { 0 }
}

fn set_status(state: u32, exit_code: u32) {
    let handle = STATUS.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let pending = matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING);
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if pending { 30_000 } else { 0 },
    };
    // SAFETY: a handle RegisterServiceCtrlHandlerExW returned (never closed); `status` lives across the call.
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = service_name();
    // SAFETY: a NUL-terminated name alive across the call; the handler is a 'static function; no context.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::SeqCst);
    set_status(SERVICE_START_PENDING, 0);
    // Only as LocalSystem: the pipe's owner must be SYSTEM, the data directory SYSTEM's.
    if Sid::current_user().ok() != Some(Sid::local_system()) {
        set_status(SERVICE_STOPPED, FAILED);
        return;
    }
    // A VPN process must never outlive its service: no job, no service.
    if job::contain_self().is_err() {
        set_status(SERVICE_STOPPED, FAILED);
        return;
    }
    let data = data_dir::open_service().map(Arc::new);
    let log = match &data {
        Ok(d) => ServiceLog::open(d.root.join("service.log"), d.protection),
        Err(_) => ServiceLog::none(),
    };
    log.line("starting");
    // Only from an admin-only folder (P2-M2): a folder others can change would run their code as SYSTEM. The MSI
    // pins and locks the folder; this catches a copy run from anywhere else.
    let problem = match std::env::current_exe() {
        Ok(exe) => install_dir::problem(&exe, macvpn_winsys::acl_check::is_admin_only),
        Err(e) => Some(format!("refusing to start: the service's own path cannot be read ({:?})", e.kind())),
    };
    if let Some(problem) = problem {
        log.line(&problem);
        set_status(SERVICE_STOPPED, FAILED);
        return;
    }
    let _ = LOG.set(log.clone());
    set_recovery(&log);
    let host = real_host(data.clone(), &log, None);
    let service = Arc::new(Service::new(host));
    let _ = SERVICE.set(service.clone());
    // Running (STOP accepted) before the pipe: a name taken by a squatter must not keep the SCM waiting.
    set_status(SERVICE_RUNNING, 0);
    let listener = loop {
        if STOP.load(Ordering::SeqCst) {
            log.line("stopped before serving");
            set_status(SERVICE_STOPPED, 0);
            return;
        }
        match Listener::bind_endpoint(PIPE_NAME, Endpoint::Service) {
            Ok(l) => break l,
            Err(e) => {
                log.line(&format!("cannot serve the pipe ({:?}); retrying in 5 s", e.kind()));
                for _ in 0..25 {
                    if STOP.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    };
    log.line("serving");
    let server_log = log.clone();
    server::serve(listener, service.clone(), &STOP, move |l| server_log.line(l));
    service.shutdown();
    if let Ok(d) = &data {
        let left = d.sweep_runs();
        if left > 0 {
            log.line(&format!("{left} entries left in run"));
        }
    }
    log.line("stopped");
    set_status(SERVICE_STOPPED, 0);
}

unsafe extern "system" fn handler(control: u32, event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            set_status(SERVICE_STOP_PENDING, 0);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event == WTS_SESSION_LOGOFF
                && let Some(s) = SERVICE.get().cloned()
            {
                let log = LOG.get().cloned().unwrap_or_else(ServiceLog::none);
                // The handler must return at once: the sessions are looked at on a thread of their own.
                let _ = std::thread::Builder::new()
                    .name("winvpn-logoff".into())
                    .spawn(move || session::after_logoff(&s, &log));
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
