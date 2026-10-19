//! The system VPN change watcher: `SCPreferences` commit / apply notifications on the system network preferences
//! (`/Library/Preferences/SystemConfiguration/preferences.plist`, where every `scutil --nc list` service lives).
//! Adding, renaming or deleting a VPN in System Settings (or installing a profile) commits that file, so the
//! callback fires; the app then reloads the list (debounced, through its status poller). The spike
//! (docs/superpowers/spikes/2026-10-19-live-system-list.md) chose this source; the app keeps the poll fallback
//! running as well.
//!
//! The watcher has its own thread with a `CFRunLoop`. The callback does nothing but call `on_change` (no listing on
//! the watcher thread); a panic in it is caught there. Stopping signals a private run loop source whose perform
//! function stops the run loop, so a stop that comes before the loop runs is not lost.
//!
//! Audit notes: the `SCPreferencesRef`, the run loop source and the retained run loop are owned (+1) and
//! released exactly once. The callback's `info` is a `Box<Callback>` leaked for the life of the thread and freed
//! on that thread after the preferences are unscheduled and their callback removed (no callback can run after
//! that). The stop source's `info` is null.
#![allow(unsafe_code)]

use crate::sc_ffi::{
    PREFERENCES_NOTIFICATION_APPLY, PREFERENCES_NOTIFICATION_COMMIT, SCPreferencesContext, SCPreferencesCreate,
    SCPreferencesRef, SCPreferencesScheduleWithRunLoop, SCPreferencesSetCallback, SCPreferencesUnscheduleFromRunLoop,
    last_error,
};
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFRetain};
use core_foundation_sys::runloop::{
    CFRunLoopAddSource, CFRunLoopGetCurrent, CFRunLoopRef, CFRunLoopRemoveSource, CFRunLoopRun, CFRunLoopSourceContext,
    CFRunLoopSourceCreate, CFRunLoopSourceInvalidate, CFRunLoopSourceRef, CFRunLoopSourceSignal, CFRunLoopStop,
    CFRunLoopWakeUp, kCFRunLoopDefaultMode,
};
use std::ffi::c_void;
use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;

type Callback = Box<dyn Fn() + Send + 'static>;

/// Calls `on_change` (on the watcher's own thread) when the system's network service setup changes.
pub struct SystemVpnWatcher {
    thread: Option<JoinHandle<()>>,
    control: Option<Control>,
}

/// The watcher thread's run loop and its stop source (both retained).
struct Control {
    run_loop: CFRunLoopRef,
    stop_source: CFRunLoopSourceRef,
    stopping: Arc<AtomicBool>,
}

// SAFETY: `CFRunLoopStop`, `CFRunLoopWakeUp` and `CFRunLoopSourceSignal` are documented as thread-safe; the
// pointers are retained until `Control` drops.
unsafe impl Send for Control {}

impl Control {
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        // SAFETY: both objects are retained by `self`; the calls are thread-safe.
        unsafe {
            CFRunLoopSourceSignal(self.stop_source);
            CFRunLoopWakeUp(self.run_loop);
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // SAFETY: the +1 references taken in `run`, released once.
        unsafe {
            CFRelease(self.stop_source.cast());
            CFRelease(self.run_loop.cast());
        }
    }
}

impl SystemVpnWatcher {
    /// Starts the watcher thread. Fails (no panic) when SystemConfiguration refuses the session or the callback.
    pub fn start(on_change: impl Fn() + Send + 'static) -> io::Result<SystemVpnWatcher> {
        let callback: Callback = Box::new(on_change);
        let (tx, rx) = mpsc::channel::<io::Result<Control>>();
        let thread = std::thread::Builder::new().name("macvpn-sc-watch".into()).spawn(move || run(callback, tx))?;
        match rx.recv() {
            Ok(Ok(control)) => Ok(SystemVpnWatcher { thread: Some(thread), control: Some(control) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("the system VPN watcher thread ended"))
            }
        }
    }

    /// Stops the run loop and joins the thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(control) = &self.control {
            control.stop();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.control = None;
    }
}

impl Drop for SystemVpnWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The preferences callback: only `on_change`, guarded against a panic.
extern "C" fn preferences_changed(_prefs: SCPreferencesRef, notification: u32, info: *mut c_void) {
    if info.is_null() || notification & (PREFERENCES_NOTIFICATION_COMMIT | PREFERENCES_NOTIFICATION_APPLY) == 0 {
        return;
    }
    // SAFETY: `info` is the `Box<Callback>` of this watcher thread, alive until the callback is removed.
    let callback = unsafe { &*(info as *const Callback) };
    notify(callback);
}

fn notify(callback: &Callback) {
    if catch_unwind(AssertUnwindSafe(callback)).is_err() {
        // Never `eprintln!` here: it panics if stderr is gone, and this runs under an `extern "C"` callback.
        let _ = writeln!(std::io::stderr(), "MacVPN: the system VPN change handler panicked");
    }
}

/// The stop source's perform function: stops the current (the watcher's) run loop.
extern "C" fn stop_perform(_info: *const c_void) {
    // SAFETY: called on the watcher thread by its own run loop.
    unsafe { CFRunLoopStop(CFRunLoopGetCurrent()) };
}

/// Releases what `run` created, in reverse order, whatever step failed.
struct Session {
    prefs: SCPreferencesRef,
    info: *mut c_void,
    callback_set: bool,
    run_loop: CFRunLoopRef,
    scheduled: bool,
    stop_source: CFRunLoopSourceRef,
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: each object is owned by this session (created or retained in `run`) and released once; the
        // callback is removed before its `info` is freed, on the only thread that runs it.
        unsafe {
            let mode = kCFRunLoopDefaultMode;
            if self.scheduled {
                SCPreferencesUnscheduleFromRunLoop(self.prefs, self.run_loop, mode);
            }
            if self.callback_set {
                SCPreferencesSetCallback(self.prefs, None, std::ptr::null_mut());
            }
            if !self.stop_source.is_null() {
                CFRunLoopRemoveSource(self.run_loop, self.stop_source, mode);
                CFRunLoopSourceInvalidate(self.stop_source);
                CFRelease(self.stop_source.cast());
            }
            if !self.prefs.is_null() {
                CFRelease(self.prefs);
            }
            if !self.info.is_null() {
                drop(Box::from_raw(self.info as *mut Callback));
            }
        }
    }
}

fn run(callback: Callback, ready: mpsc::Sender<io::Result<Control>>) {
    let fail = |what: &str| io::Error::other(format!("{what}: {}", last_error()));
    let name = CFString::new("MacVPN");
    // SAFETY: plain getter; the current thread's run loop lives as long as the thread.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    let mut session = Session {
        prefs: std::ptr::null(),
        info: Box::into_raw(Box::new(callback)).cast(),
        callback_set: false,
        run_loop,
        scheduled: false,
        stop_source: std::ptr::null_mut(),
    };
    // SAFETY: a valid name; null allocator and preferences ID (the default system preferences). +1 or null.
    session.prefs = unsafe { SCPreferencesCreate(std::ptr::null(), name.as_concrete_TypeRef(), std::ptr::null()) };
    if session.prefs.is_null() {
        let _ = ready.send(Err(fail("SCPreferencesCreate")));
        return;
    }
    let mut context = SCPreferencesContext {
        version: 0,
        info: session.info,
        retain: std::ptr::null(),
        release: std::ptr::null(),
        copy_description: std::ptr::null(),
    };
    // SAFETY: valid preferences; the context is copied by the call; `info` outlives the callback (see `Session`).
    if unsafe { SCPreferencesSetCallback(session.prefs, Some(preferences_changed), &mut context) } == 0 {
        let _ = ready.send(Err(fail("SCPreferencesSetCallback")));
        return;
    }
    session.callback_set = true;
    let mut source_context = CFRunLoopSourceContext {
        version: 0,
        info: std::ptr::null_mut(),
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: stop_perform,
    };
    // SAFETY: a version 0 context with only `perform`; the result is +1 or null.
    session.stop_source = unsafe { CFRunLoopSourceCreate(std::ptr::null(), 0, &mut source_context) };
    if session.stop_source.is_null() {
        let _ = ready.send(Err(io::Error::other("CFRunLoopSourceCreate failed")));
        return;
    }
    // SAFETY: valid run loop, source and mode.
    unsafe { CFRunLoopAddSource(run_loop, session.stop_source, kCFRunLoopDefaultMode) };
    // SAFETY: valid preferences, run loop and mode.
    if unsafe { SCPreferencesScheduleWithRunLoop(session.prefs, run_loop, kCFRunLoopDefaultMode) } == 0 {
        let _ = ready.send(Err(fail("SCPreferencesScheduleWithRunLoop")));
        return;
    }
    session.scheduled = true;
    let stopping = Arc::new(AtomicBool::new(false));
    // SAFETY: +1 references for the controlling side, released by `Control::drop`.
    let control = unsafe {
        CFRetain(run_loop.cast());
        CFRetain(session.stop_source.cast());
        Control { run_loop, stop_source: session.stop_source, stopping: stopping.clone() }
    };
    if ready.send(Ok(control)).is_err() {
        return;
    }
    while !stopping.load(Ordering::SeqCst) {
        // SAFETY: runs this thread's run loop until `stop_perform` stops it.
        unsafe { CFRunLoopRun() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn leaked(f: impl Fn() + Send + 'static) -> *mut c_void {
        Box::into_raw(Box::new(Box::new(f) as Callback)).cast()
    }

    fn free(info: *mut c_void) {
        // SAFETY: made by `leaked`.
        drop(unsafe { Box::from_raw(info as *mut Callback) });
    }

    #[test]
    fn the_callback_calls_on_change_for_commit_and_apply() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let info = leaked(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        preferences_changed(std::ptr::null(), PREFERENCES_NOTIFICATION_COMMIT, info);
        preferences_changed(std::ptr::null(), PREFERENCES_NOTIFICATION_APPLY, info);
        preferences_changed(std::ptr::null(), 0, info);
        preferences_changed(std::ptr::null(), PREFERENCES_NOTIFICATION_COMMIT, std::ptr::null_mut());
        free(info);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_panicking_handler_does_not_abort() {
        let info = leaked(|| panic!("handler failure"));
        preferences_changed(std::ptr::null(), PREFERENCES_NOTIFICATION_COMMIT, info);
        preferences_changed(std::ptr::null(), PREFERENCES_NOTIFICATION_APPLY, info);
        free(info);
    }
}
