//! The clipboard through GTK 3 (the app is a GTK app; Wayland gives the clipboard only to a focused client, which
//! GTK handles). Main thread only: every call is moved there with `glib::MainContext::default().invoke` and waited
//! for. A secret goes out with the extra target `x-kde-passwordManagerHint` = `secret`, which clipboard managers that
//! honour it (KDE's Klipper, GNOME extensions that implement it) leave out of their history. The mark is a counter;
//! the secret is kept (zeroized when replaced) only to clear the clipboard if it still holds it.

use macvpn_platform_api::{ClipboardMark, PlatformError, SecretClipboard};
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

static GENERATION: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    /// The last secret written and its mark (on the main thread).
    static LAST: RefCell<Option<(isize, Zeroizing<String>)>> = const { RefCell::new(None) };
}

/// How long a caller waits for the main thread.
const MAIN_WAIT: Duration = Duration::from_secs(5);

/// Runs `f` on the GTK main thread and waits for it (at most [`MAIN_WAIT`]); `None` when it did not run in time.
fn on_main<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    on_context(&glib::MainContext::default(), MAIN_WAIT, f)
}

const PENDING: u8 = 0;
const RUNNING: u8 = 1;
const ABANDONED: u8 = 2;

/// Runs `f` on `context` and waits for it at most `wait`. A call that has not started by then is abandoned: the
/// queued closure later sees that and does nothing (a timed-out secret write never reaches the clipboard after the
/// caller was told it failed, so no secret stays there with no clear scheduled). One that already started is waited
/// for to its end (the GTK calls inside are short).
fn on_context<T: Send + 'static>(
    context: &glib::MainContext,
    wait: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    if context.is_owner() {
        return Some(f());
    }
    let state = Arc::new(AtomicU8::new(PENDING));
    let (tx, rx) = mpsc::channel();
    let queued = state.clone();
    context.invoke(move || {
        if queued.compare_exchange(PENDING, RUNNING, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let _ = tx.send(f());
        }
    });
    match rx.recv_timeout(wait) {
        Ok(v) => Some(v),
        Err(_) if state.compare_exchange(PENDING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst).is_ok() => None,
        // It started just in time: its result comes.
        Err(_) => rx.recv().ok(),
    }
}

fn clipboard() -> gtk::Clipboard {
    gtk::Clipboard::get(&gdk::SELECTION_CLIPBOARD)
}

fn busy() -> PlatformError {
    PlatformError::Failed("the clipboard is busy".into())
}

/// Plain text (`Shell::copy_text`).
pub fn write_plain(text: &str) -> Result<(), PlatformError> {
    let text = text.to_string();
    on_main(move || clipboard().set_text(&text)).ok_or_else(busy)
}

/// The secret clipboard of `LinPlatform`.
pub struct Clipboard;

impl SecretClipboard for Clipboard {
    fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError> {
        let secret = Zeroizing::new(text.to_string());
        on_main(move || {
            let targets = [
                gtk::TargetEntry::new("UTF8_STRING", gtk::TargetFlags::empty(), 0),
                gtk::TargetEntry::new("text/plain;charset=utf-8", gtk::TargetFlags::empty(), 0),
                gtk::TargetEntry::new("x-kde-passwordManagerHint", gtk::TargetFlags::empty(), 1),
            ];
            let for_get = secret.clone();
            let set = clipboard().set_with_data(&targets, move |_, data, info| {
                if info == 1 {
                    data.set(&data.target(), 8, b"secret");
                } else {
                    data.set_text(&for_get);
                }
            });
            if !set {
                return Err(PlatformError::Failed("the clipboard refused the text".into()));
            }
            let mark = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            LAST.with(|l| *l.borrow_mut() = Some((mark, secret)));
            Ok(ClipboardMark(mark))
        })
        .unwrap_or_else(|| Err(busy()))
    }

    fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool {
        on_main(move || {
            LAST.with(|l| {
                let mut last = l.borrow_mut();
                let Some((m, secret)) = last.as_ref() else { return false };
                if *m != mark.0 || clipboard().wait_for_text().as_deref() != Some(secret.as_str()) {
                    return false;
                }
                clipboard().set_text("");
                clipboard().clear();
                *last = None;
                true
            })
        })
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn a_call_that_times_out_never_runs_later() {
        let context = glib::MainContext::new();
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        let out = on_context(&context, Duration::from_millis(50), move || flag.store(true, Ordering::SeqCst));
        assert!(out.is_none(), "nobody runs the context: timed out");
        // The main loop gets to the queued call only now.
        let guard = context.acquire().expect("the context");
        while context.iteration(false) {}
        drop(guard);
        assert!(!ran.load(Ordering::SeqCst), "the abandoned call did nothing");
    }

    #[test]
    fn a_call_in_time_returns_its_value() {
        let context = glib::MainContext::new();
        let runner = context.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let t = std::thread::spawn(move || {
            let _g = runner.acquire().expect("the context");
            while !stop2.load(Ordering::SeqCst) {
                runner.iteration(false);
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        assert_eq!(on_context(&context, Duration::from_secs(5), || 7), Some(7));
        stop.store(true, Ordering::SeqCst);
        t.join().unwrap();
    }
}
