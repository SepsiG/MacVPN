//! The network change watcher: `SCDynamicStore` notifications on `State:/Network/Global/IPv4` and
//! `State:/Network/Global/IPv6` (the primary interface, its router and service; they change when the Mac joins,
//! leaves or switches a network, and when DHCP or router advertisements change the default route). Registering
//! for the notifications only reads; nothing here changes the system's network setup.
//!
//! The structure is `sc_watch`'s: its own thread with a `CFRunLoop`; the callback does nothing but call
//! `on_change` (the probe runs elsewhere), a panic in it is caught there; stopping signals a private run loop
//! source whose perform function stops the run loop, so a stop that comes before the loop runs is not lost.
//!
//! Audit notes: the `SCDynamicStoreRef`, its run loop source, the stop source and the retained run loop are owned
//! (+1) and released exactly once. The callback's `info` is a `Box<Callback>` leaked for the life of the thread
//! and freed on that thread after the store's source is removed from the run loop and invalidated (the store
//! delivers its callback only through that source, on this thread, so no callback can run after that). The
//! context's `retain` / `release` are null: the store never frees `info`. The stop source's `info` is null.
#![allow(unsafe_code)]

use crate::sc_ffi::{
    SCDynamicStoreContext, SCDynamicStoreCreate, SCDynamicStoreCreateRunLoopSource, SCDynamicStoreRef,
    SCDynamicStoreSetNotificationKeys, last_error,
};
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
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

/// The dynamic store keys watched.
pub const WATCHED_KEYS: [&str; 2] = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"];

/// Calls `on_change` (on the watcher's own thread) when the primary network's addresses or routes change.
pub struct NetworkWatcher {
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

impl NetworkWatcher {
    /// Starts the watcher thread. Fails (no panic) when SystemConfiguration refuses the store or its keys.
    pub fn start(on_change: impl Fn() + Send + 'static) -> io::Result<NetworkWatcher> {
        let callback: Callback = Box::new(on_change);
        let (tx, rx) = mpsc::channel::<io::Result<Control>>();
        let thread = std::thread::Builder::new().name("macvpn-net-watch".into()).spawn(move || run(callback, tx))?;
        match rx.recv() {
            Ok(Ok(control)) => Ok(NetworkWatcher { thread: Some(thread), control: Some(control) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("the network change watcher thread ended"))
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

impl Drop for NetworkWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The store callback: only `on_change`, guarded against a panic.
extern "C" fn store_changed(_store: SCDynamicStoreRef, _changed: CFArrayRef, info: *mut c_void) {
    if info.is_null() {
        return;
    }
    // SAFETY: `info` is the `Box<Callback>` of this watcher thread, alive until the store's source is invalidated.
    let callback = unsafe { &*(info as *const Callback) };
    notify(callback);
}

fn notify(callback: &Callback) {
    if catch_unwind(AssertUnwindSafe(callback)).is_err() {
        // Never `eprintln!` here: it panics if stderr is gone, and this runs under an `extern "C"` callback.
        let _ = writeln!(std::io::stderr(), "MacVPN: the network change handler panicked");
    }
}

/// The stop source's perform function: stops the current (the watcher's) run loop.
extern "C" fn stop_perform(_info: *const c_void) {
    // SAFETY: called on the watcher thread by its own run loop.
    unsafe { CFRunLoopStop(CFRunLoopGetCurrent()) };
}

/// Releases what `run` created, in reverse order, whatever step failed.
struct Session {
    store: SCDynamicStoreRef,
    info: *mut c_void,
    run_loop: CFRunLoopRef,
    store_source: CFRunLoopSourceRef,
    stop_source: CFRunLoopSourceRef,
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: each object is owned by this session (created in `run`) and released once; the store's source
        // is removed and invalidated (no more callbacks) before its `info` is freed, on the only thread that runs
        // the callback.
        unsafe {
            let mode = kCFRunLoopDefaultMode;
            if !self.store_source.is_null() {
                CFRunLoopRemoveSource(self.run_loop, self.store_source, mode);
                CFRunLoopSourceInvalidate(self.store_source);
                CFRelease(self.store_source.cast());
            }
            if !self.stop_source.is_null() {
                CFRunLoopRemoveSource(self.run_loop, self.stop_source, mode);
                CFRunLoopSourceInvalidate(self.stop_source);
                CFRelease(self.stop_source.cast());
            }
            if !self.store.is_null() {
                CFRelease(self.store);
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
        store: std::ptr::null(),
        info: Box::into_raw(Box::new(callback)).cast(),
        run_loop,
        store_source: std::ptr::null_mut(),
        stop_source: std::ptr::null_mut(),
    };
    let mut context = SCDynamicStoreContext {
        version: 0,
        info: session.info,
        retain: std::ptr::null(),
        release: std::ptr::null(),
        copy_description: std::ptr::null(),
    };
    // SAFETY: a valid name; null allocator; the context is copied by the call and `info` outlives the callback
    // (see `Session`). +1 or null.
    session.store = unsafe {
        SCDynamicStoreCreate(std::ptr::null(), name.as_concrete_TypeRef(), Some(store_changed), &mut context)
    };
    if session.store.is_null() {
        let _ = ready.send(Err(fail("SCDynamicStoreCreate")));
        return;
    }
    let keys: Vec<CFString> = WATCHED_KEYS.iter().map(|k| CFString::new(k)).collect();
    let keys = CFArray::from_CFTypes(&keys);
    // SAFETY: a valid store and array (borrowed for the call: the store keeps its own copy); no patterns.
    if unsafe { SCDynamicStoreSetNotificationKeys(session.store, keys.as_concrete_TypeRef(), std::ptr::null()) } == 0 {
        let _ = ready.send(Err(fail("SCDynamicStoreSetNotificationKeys")));
        return;
    }
    // SAFETY: a valid store; the result is +1 or null.
    session.store_source = unsafe { SCDynamicStoreCreateRunLoopSource(std::ptr::null(), session.store, 0) };
    if session.store_source.is_null() {
        let _ = ready.send(Err(fail("SCDynamicStoreCreateRunLoopSource")));
        return;
    }
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
    // SAFETY: valid run loop, sources and mode.
    unsafe {
        CFRunLoopAddSource(run_loop, session.stop_source, kCFRunLoopDefaultMode);
        CFRunLoopAddSource(run_loop, session.store_source, kCFRunLoopDefaultMode);
    }
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
    fn the_callback_calls_on_change_and_ignores_a_null_info() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let info = leaked(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        store_changed(std::ptr::null(), std::ptr::null(), info);
        store_changed(std::ptr::null(), std::ptr::null(), info);
        store_changed(std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
        free(info);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_panicking_handler_does_not_abort() {
        let info = leaked(|| panic!("handler failure"));
        store_changed(std::ptr::null(), std::ptr::null(), info);
        free(info);
    }
}
