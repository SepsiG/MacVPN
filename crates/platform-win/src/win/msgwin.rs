//! A message-only window on the main thread: jobs posted to it run later, from the event loop, on the main thread
//! (the file panels: their modal loop must not run inside a caller's lock, and their callbacks are not `Send`).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, GetWindowThreadProcessId, HWND_MESSAGE, IsWindow, PostMessageW, RegisterClassExW,
    WM_APP, WNDCLASSEXW,
};

const WM_RUN: u32 = WM_APP + 1;
static MAIN_THREAD: OnceLock<u32> = OnceLock::new();
/// The main thread's window (its address), for other threads: the clipboard's owner.
static MAIN_WINDOW: AtomicUsize = AtomicUsize::new(0);

type Job = Box<dyn FnOnce()>;

thread_local! {
    static JOBS: RefCell<VecDeque<Job>> = const { RefCell::new(VecDeque::new()) };
    static WINDOW: Cell<HWND> = const { Cell::new(std::ptr::null_mut()) };
}

/// Records the calling thread as the main thread (`WinPlatform::new`, from `main`). The first call wins.
pub(crate) fn remember_main_thread() {
    // SAFETY: plain call.
    let _ = MAIN_THREAD.set(unsafe { GetCurrentThreadId() });
}

pub(crate) fn on_main_thread() -> bool {
    // SAFETY: plain call.
    MAIN_THREAD.get().is_some_and(|&id| id == unsafe { GetCurrentThreadId() })
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_RUN {
        // The queue's borrow ends before the job runs (a job may post again, or pump messages in a modal loop).
        let job = JOBS.with(|j| j.borrow_mut().pop_front());
        if let Some(job) = job {
            job();
        }
        return 0;
    }
    // SAFETY: the default handling of every other message.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn window() -> Option<HWND> {
    let existing = WINDOW.with(Cell::get);
    if !existing.is_null() {
        return Some(existing);
    }
    let class: Vec<u16> = "WinVPNMessages\0".encode_utf16().collect();
    // SAFETY: a class with this module's instance and our window procedure (registering twice fails harmlessly);
    // a message-only window of that class. `class` outlives both calls.
    let hwnd = unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        CreateWindowExW(
            0,
            class.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return None;
    }
    WINDOW.with(|w| w.set(hwnd));
    if on_main_thread() {
        MAIN_WINDOW.store(hwnd as usize, Ordering::Release);
    }
    Some(hwnd)
}

/// Creates the main thread's window now (`WinPlatform::new`, on the main thread), so other threads can name it as
/// the clipboard's owner. Its handle, or `None` off the main thread.
pub(crate) fn ensure_main_window() -> Option<HWND> {
    if on_main_thread() { window() } else { None }
}

/// The main thread's window, from any thread: the documented owner for `OpenClipboard` (the main thread runs the
/// event loop, so the clipboard's messages to its owner are answered). Null when there is none (it was never made,
/// or its thread is gone: a test's thread): the clipboard is then opened without an owner.
pub(crate) fn main_window() -> HWND {
    let hwnd = MAIN_WINDOW.load(Ordering::Acquire) as HWND;
    if hwnd.is_null() {
        return hwnd;
    }
    // SAFETY: plain calls; a stale or reused handle only makes them fail (0) or name another thread.
    let (alive, thread) = unsafe { (IsWindow(hwnd) != 0, GetWindowThreadProcessId(hwnd, std::ptr::null_mut())) };
    if alive && MAIN_THREAD.get() == Some(&thread) { hwnd } else { std::ptr::null_mut() }
}

/// Runs `job` later on the main thread; `false` (and `job` dropped unrun) when not called on the main thread or the
/// window cannot be made or posted to.
pub(crate) fn post(job: Job) -> bool {
    if !on_main_thread() {
        return false;
    }
    let Some(hwnd) = window() else { return false };
    JOBS.with(|j| j.borrow_mut().push_back(job));
    // SAFETY: our own window, on its thread.
    if unsafe { PostMessageW(hwnd, WM_RUN, 0, 0) } == 0 {
        JOBS.with(|j| j.borrow_mut().pop_back());
        return false;
    }
    true
}
