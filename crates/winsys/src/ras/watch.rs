//! A thread that calls back when a RAS connection appears or ends, or when a phonebook folder changes.
//!
//! It waits on (a) an auto-reset event registered with `RasConnectionNotificationW(INVALID_HANDLE_VALUE, …,
//! RASCN_Connection | RASCN_Disconnection)` — only a hint: Windows does not signal it for every failed dial or
//! hang-up, and never in a network logon —, (b) one `FindFirstChangeNotificationW` per folder (a file created,
//! renamed, deleted or written in it), and (c) its stop event. A folder that does not exist yet is watched through
//! its nearest existing ancestor (for subfolders appearing there) and taken over once it exists; a folder that is
//! deleted goes back to its ancestor. The callback is the caller's reload trigger: it debounces.

use super::{Error, Result};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::NetworkManagement::Rras::{RASCN_Connection, RASCN_Disconnection, RasConnectionNotificationW};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects};

/// `MAXIMUM_WAIT_OBJECTS` minus the stop and the RAS event.
const MAX_DIRS: usize = 62;

/// An event handle, closed once on drop.
struct Event(HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Event {}
// SAFETY: as above; `SetEvent` / waits are thread-safe.
unsafe impl Sync for Event {}

impl Event {
    fn new(manual_reset: bool) -> Result<Event> {
        // SAFETY: default security, not signalled, unnamed.
        let h = unsafe { CreateEventW(std::ptr::null(), i32::from(manual_reset), 0, std::ptr::null()) };
        if h.is_null() { Err(last_error("CreateEventW")) } else { Ok(Event(h)) }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: a handle CreateEventW returned, closed exactly once, here.
        unsafe { CloseHandle(self.0) };
    }
}

/// A change-notification handle, closed once on drop.
struct Change(HANDLE);

// SAFETY: as for `Event`.
unsafe impl Send for Change {}

impl Drop for Change {
    fn drop(&mut self) {
        // SAFETY: a handle FindFirstChangeNotificationW returned, closed exactly once, here.
        unsafe { FindCloseChangeNotification(self.0) };
    }
}

/// One wanted folder and what is watched for it.
struct Target {
    wanted: PathBuf,
    /// The folder itself, or its nearest existing ancestor.
    watched: PathBuf,
    exact: bool,
    change: Change,
}

impl Target {
    /// Watches what exists of `wanted` now. Resolved again after the handle is open: a folder that appeared in
    /// between would otherwise never be signalled (its parent's handle did not exist yet).
    fn arm(wanted: &Path) -> Result<Target> {
        for _ in 0..16 {
            let (watched, exact) = resolve(wanted)?;
            let filter: FILE_NOTIFY_CHANGE = if exact {
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                FILE_NOTIFY_CHANGE_DIR_NAME
            };
            let w = crate::util::wide_path(&watched).map_err(|e| Error::invalid(e.to_string()))?;
            // SAFETY: `w` is NUL-terminated and alive across the call; not the subtree.
            let h = unsafe { FindFirstChangeNotificationW(w.as_ptr(), 0, filter) };
            if h == INVALID_HANDLE_VALUE || h.is_null() {
                return Err(last_error("FindFirstChangeNotificationW"));
            }
            let change = Change(h);
            if resolve(wanted)? == (watched.clone(), exact) {
                return Ok(Target { wanted: wanted.to_path_buf(), watched, exact, change });
            }
        }
        Err(Error::invalid(format!("{} keeps changing", wanted.display())))
    }
}

/// The folder itself when it exists, else its nearest existing ancestor.
fn resolve(wanted: &Path) -> Result<(PathBuf, bool)> {
    if wanted.is_dir() {
        return Ok((wanted.to_path_buf(), true));
    }
    wanted
        .ancestors()
        .skip(1)
        .find(|a| a.is_dir())
        .map(|a| (a.to_path_buf(), false))
        .ok_or_else(|| Error::invalid(format!("no folder of {} exists", wanted.display())))
}

fn last_error(call: &'static str) -> Error {
    Error::Call { call, code: std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32 }
}

/// The running watcher; dropping it stops and joins the thread.
pub struct Watcher {
    stop: std::sync::Arc<Event>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    /// Starts watching the RAS connections and `dirs` (at most 62; plain absolute paths). `on_change` runs on the
    /// watcher's thread for every wake (a panic in it is caught).
    pub fn start(dirs: &[PathBuf], on_change: impl Fn() + Send + 'static) -> Result<Watcher> {
        if dirs.len() > MAX_DIRS {
            return Err(Error::invalid(format!("at most {MAX_DIRS} folders can be watched")));
        }
        for d in dirs {
            crate::util::plain_absolute(d).map_err(|e| Error::invalid(e.to_string()))?;
        }
        let stop = std::sync::Arc::new(Event::new(true)?);
        let ras = Event::new(false)?;
        // SAFETY: INVALID_HANDLE_VALUE: every connection; `ras.0` is a valid event (RAS duplicates it).
        let code =
            unsafe { RasConnectionNotificationW(INVALID_HANDLE_VALUE, ras.0, RASCN_Connection | RASCN_Disconnection) };
        super::rc("RasConnectionNotificationW", code)?;
        let mut targets = dirs.iter().map(|d| Target::arm(d)).collect::<Result<Vec<_>>>()?;
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("ras-watcher".into())
            .spawn(move || run(&thread_stop, &ras, &mut targets, &on_change))
            .map_err(|e| Error::invalid(format!("cannot start the watcher thread: {e}")))?;
        Ok(Watcher { stop, thread: Some(thread) })
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: the stop event lives until the thread is joined (shared through the Arc).
        unsafe { SetEvent(self.stop.0) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(stop: &Event, ras: &Event, targets: &mut [Target], on_change: &(impl Fn() + Send)) {
    let notify = || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(on_change));
    };
    loop {
        let mut handles: Vec<HANDLE> = vec![stop.0, ras.0];
        handles.extend(targets.iter().map(|t| t.change.0));
        // SAFETY: `handles` holds at most 64 valid handles, alive across the wait.
        let r = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, INFINITE) };
        if r == WAIT_FAILED {
            return;
        }
        let i = r.wrapping_sub(WAIT_OBJECT_0) as usize;
        match i {
            0 => return,
            1 => notify(),
            i if i < handles.len() => {
                let t = &mut targets[i - 2];
                let now = resolve(&t.wanted).ok();
                if now.as_ref() == Some(&(t.watched.clone(), t.exact)) {
                    // SAFETY: a valid change-notification handle owned by `t`.
                    if unsafe { FindNextChangeNotification(t.change.0) } == 0 {
                        return;
                    }
                    if t.exact {
                        notify();
                    }
                } else {
                    // The folder appeared (or went away): watch what exists now.
                    match Target::arm(&t.wanted) {
                        Ok(new) => *t = new,
                        Err(_) => return,
                    }
                    notify();
                }
            }
            _ => return,
        }
    }
}
