//! Logoff/shutdown (`WM_QUERYENDSESSION`; at a logoff `WM_ENDSESSION` runs the logoff observers: the RAS engine
//! hangs up WinVPN's connections), suspend and resume (`WM_POWERBROADCAST`; registered for Modern Standby
//! too, `RegisterSuspendResumeNotification`) and a theme switch (`WM_SETTINGCHANGE` "ImmersiveColorSet": the
//! appearance observers), through a hidden top-level window
//! (message-only windows get neither broadcast). The window belongs to the thread that creates it, which must pump
//! messages: the app's main thread (the terminate handler and the wake and sleep observers are installed there).

use crate::pure::texts;
use macvpn_platform_api::{AppLifecycle, TerminateReply};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::RegisterSuspendResumeNotification;
use windows_sys::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, ENDSESSION_LOGOFF, PBT_APMRESUMEAUTOMATIC,
    PBT_APMSUSPEND, RegisterClassExW, SendMessageW, WM_ENDSESSION, WM_POWERBROADCAST, WM_QUERYENDSESSION,
    WM_SETTINGCHANGE, WNDCLASSEXW, WS_EX_TOOLWINDOW,
};

type Handler = Box<dyn Fn() -> TerminateReply + Send + Sync>;
type Wake = Box<dyn Fn() + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();
static WAKE: Mutex<Vec<Wake>> = Mutex::new(Vec::new());
static SLEEP: Mutex<Vec<Wake>> = Mutex::new(Vec::new());
static LOGOFF: Mutex<Vec<Wake>> = Mutex::new(Vec::new());
static APPEARANCE: Mutex<Vec<Wake>> = Mutex::new(Vec::new());
static WINDOW: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
/// Serializes the window's creation.
static CREATING: Mutex<()> = Mutex::new(());
static BLOCKING: AtomicBool = AtomicBool::new(false);

/// The area a `WM_SETTINGCHANGE` names (its `lParam`) for a light/dark theme switch.
const COLOUR_SET: &str = "ImmersiveColorSet";

/// Whether `lparam` of a `WM_SETTINGCHANGE` names [`COLOUR_SET`]: a NUL-terminated UTF-16 string or null.
fn is_colour_set(lparam: LPARAM) -> bool {
    let p = lparam as *const u16;
    if p.is_null() {
        return false;
    }
    // One unit more than the name: a longer string never matches.
    let max = COLOUR_SET.len() + 1;
    let mut units = Vec::with_capacity(max);
    for i in 0..max {
        // SAFETY: Windows passes a NUL-terminated string (or null, handled above); the read stops at its NUL.
        let unit = unsafe { *p.add(i) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16(&units).is_ok_and(|s| s == COLOUR_SET)
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        // No handler: Windows may end the session (as without the window).
        WM_QUERYENDSESSION => match HANDLER.get().map_or(TerminateReply::Now, |h| h()) {
            TerminateReply::Now => 1,
            TerminateReply::Cancel => 0,
            TerminateReply::Later => {
                let reason: Vec<u16> = texts::closing().encode_utf16().chain(Some(0)).collect();
                // SAFETY: our window; a NUL-terminated reason. A failure only loses the text Windows shows.
                unsafe { ShutdownBlockReasonCreate(hwnd, reason.as_ptr()) };
                BLOCKING.store(true, Ordering::SeqCst);
                0
            }
        },
        // The session ends with a logoff (not a shutdown: Windows itself ends the RAS connections then).
        WM_ENDSESSION if wparam != 0 && (lparam as u32) & ENDSESSION_LOGOFF != 0 => {
            for f in LOGOFF.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                f();
            }
            0
        }
        WM_POWERBROADCAST if wparam == PBT_APMRESUMEAUTOMATIC as usize => {
            for f in WAKE.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                f();
            }
            1
        }
        WM_POWERBROADCAST if wparam == PBT_APMSUSPEND as usize => {
            for f in SLEEP.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                f();
            }
            1
        }
        // The light/dark theme changed (the taskbar's tint with it): the tray icon is drawn again.
        WM_SETTINGCHANGE if is_colour_set(lparam) => {
            for f in APPEARANCE.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                f();
            }
            0
        }
        // SAFETY: the default handling of every other message, with its own arguments.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// The hidden window, created once, on the calling thread.
fn ensure_window() -> bool {
    let _creating = CREATING.lock().unwrap_or_else(PoisonError::into_inner);
    if !WINDOW.load(Ordering::SeqCst).is_null() {
        return true;
    }
    let class: Vec<u16> = "WinVPNLifecycle\0".encode_utf16().collect();
    // SAFETY: a zeroed WNDCLASSEXW is valid (no icon, cursor, brush or menu); the class name outlives both calls
    // (RegisterClassExW copies it); the window is never shown (no WS_VISIBLE) and has no taskbar button
    // (WS_EX_TOOLWINDOW). A failed registration shows as a failed CreateWindowExW.
    let hwnd = unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return false;
    }
    // SAFETY: our window handle; the registration lives as long as the process (never unregistered: the window is
    // never destroyed). A failure only loses suspend/resume on Modern Standby machines (the network watch still
    // triggers auto-reconnect there).
    let _ = unsafe { RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE) };
    WINDOW.store(hwnd, Ordering::SeqCst);
    true
}

pub(crate) struct Lifecycle;

impl AppLifecycle for Lifecycle {
    /// Once per process; `false` if a handler is installed already or the window cannot be created.
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        HANDLER.set(handler).is_ok() && ensure_window()
    }

    /// After a `Later`: the block reason goes; `true` ends the process (the quit flow is done, as AppKit's
    /// terminate after `replyToApplicationShouldTerminate:YES`).
    fn reply_to_terminate(&self, terminate: bool) {
        let hwnd = WINDOW.load(Ordering::SeqCst);
        if BLOCKING.swap(false, Ordering::SeqCst) && !hwnd.is_null() {
            // SAFETY: our window.
            unsafe { ShutdownBlockReasonDestroy(hwnd) };
        }
        if terminate {
            std::process::exit(0);
        }
    }

    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>) {
        WAKE.lock().unwrap_or_else(PoisonError::into_inner).push(on_wake);
        ensure_window();
    }

    /// `PBT_APMSUSPEND` (also on Modern Standby: the window is registered for it).
    fn observe_sleep(&self, on_sleep: Box<dyn Fn() + Send + Sync>) {
        SLEEP.lock().unwrap_or_else(PoisonError::into_inner).push(on_sleep);
        ensure_window();
    }

    /// `WM_SETTINGCHANGE` "ImmersiveColorSet" (Settings → Personalization → Colors → "Choose your mode"), on the
    /// window's thread.
    fn observe_appearance(&self, on_change: Box<dyn Fn() + Send + Sync>) {
        APPEARANCE.lock().unwrap_or_else(PoisonError::into_inner).push(on_change);
        ensure_window();
    }
}

/// Runs `on_logoff` when this user's session ends with a logoff (`WM_ENDSESSION` with `ENDSESSION_LOGOFF`), on the
/// window's thread before the process ends. The window is the terminate handler's (made by the app at launch).
pub(crate) fn observe_logoff(on_logoff: Box<dyn Fn() + Send + Sync>) {
    LOGOFF.lock().unwrap_or_else(PoisonError::into_inner).push(on_logoff);
}

/// Tests: sends `msg` to the window as Windows would (from the window's thread: the procedure runs at once).
fn send_for_tests(msg: u32, wparam: usize) -> Option<isize> {
    send_with_lparam_for_tests(msg, wparam, 0)
}

fn send_with_lparam_for_tests(msg: u32, wparam: usize, lparam: isize) -> Option<isize> {
    let hwnd = WINDOW.load(Ordering::SeqCst);
    if hwnd.is_null() {
        return None;
    }
    // SAFETY: our window; a pointer in `lparam` (a setting change's string) outlives the synchronous send.
    Some(unsafe { SendMessageW(hwnd, msg, wparam, lparam) })
}

/// Tests: `WM_ENDSESSION` (the session ends) for a logoff (`ENDSESSION_LOGOFF`) or a shutdown (no flag).
pub(crate) fn end_session_for_tests(logoff: bool) -> Option<isize> {
    let lparam = if logoff { ENDSESSION_LOGOFF as isize } else { 0 };
    send_with_lparam_for_tests(WM_ENDSESSION, 1, lparam)
}

/// Tests: `WM_SETTINGCHANGE` naming `area` (`None`: a null `lParam`).
pub(crate) fn setting_change_for_tests(area: Option<&str>) -> Option<isize> {
    let text: Option<Vec<u16>> = area.map(|a| a.encode_utf16().chain(Some(0)).collect());
    // The string outlives the (synchronous) send.
    let lparam = text.as_ref().map_or(0, |t| t.as_ptr() as isize);
    send_with_lparam_for_tests(WM_SETTINGCHANGE, 0, lparam)
}

pub(crate) fn query_end_session_for_tests() -> Option<isize> {
    send_for_tests(WM_QUERYENDSESSION, 0)
}

pub(crate) fn resume_for_tests() -> Option<isize> {
    send_for_tests(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize)
}

pub(crate) fn suspend_for_tests() -> Option<isize> {
    send_for_tests(WM_POWERBROADCAST, PBT_APMSUSPEND as usize)
}
