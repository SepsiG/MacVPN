//! Secrets the app puts on the pasteboard: the recovery key (create and new-key windows), a new team key (the
//! reveal) and a subscription string. They are written here, never by the web view, through
//! `macvpn_platform_mac::pasteboard` (concealed, transient, this Mac only), and cleared again after a while, at a
//! vault lock and at quit, but only while the pasteboard still holds that write (anything copied since is left
//! alone; the pasteboard is never read).
//!
//! Manual check (no automated test can see another app's view of the pasteboard): copy a team key with a
//! clipboard manager running (it must not list it), then Lock Now / Quit (the pasteboard is empty) and copy
//! something else before the minute is up (it stays).

use macvpn_platform_mac::pasteboard::{self, Written};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// How long a copied recovery key, team key or subscription string may stay on the pasteboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(60);

/// The pasteboard as this module uses it.
pub trait Board: Send + Sync {
    fn write_secret(&self, text: &str) -> Result<Written, String>;
    fn clear_if_unchanged(&self, written: Written) -> bool;
}

/// The general pasteboard.
pub struct General;

impl Board for General {
    fn write_secret(&self, text: &str) -> Result<Written, String> {
        pasteboard::write_secret(text)
    }

    fn clear_if_unchanged(&self, written: Written) -> bool {
        pasteboard::clear_if_unchanged(written)
    }
}

/// The last secret written (only the last one can still be on the pasteboard).
pub struct Secrets<B> {
    board: B,
    written: Mutex<Option<Written>>,
}

impl<B: Board> Secrets<B> {
    pub const fn new(board: B) -> Self {
        Secrets { board, written: Mutex::new(None) }
    }

    /// Puts `text` on the pasteboard; the write to clear later.
    pub fn copy(&self, text: &str) -> Result<Written, String> {
        let mut last = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        let written = self.board.write_secret(text)?;
        *last = Some(written);
        Ok(written)
    }

    /// Clears `written` if it is still the last secret and still on the pasteboard (the timer).
    pub fn expire(&self, written: Written) -> bool {
        let mut last = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        if *last != Some(written) {
            return false;
        }
        *last = None;
        self.board.clear_if_unchanged(written)
    }

    /// The vault was locked, or the app quits: the last secret goes if it is still on the pasteboard.
    pub fn clear(&self) -> bool {
        let last = self.written.lock().unwrap_or_else(PoisonError::into_inner).take();
        last.is_some_and(|written| self.board.clear_if_unchanged(written))
    }
}

static SECRETS: Secrets<General> = Secrets::new(General);

/// Puts a secret on the pasteboard and clears it after [`CLEAR_AFTER`] if it is still there.
pub fn copy_secret(text: &str) -> Result<(), String> {
    let written = SECRETS.copy(text)?;
    std::thread::Builder::new()
        .name("macvpn-clipboard".into())
        .spawn(move || {
            std::thread::sleep(CLEAR_AFTER);
            SECRETS.expire(written);
        })
        .map(drop)
        .map_err(|e| e.to_string())
}

/// At a vault lock and at quit: a copied secret still on the pasteboard goes.
pub fn clear_secret() {
    SECRETS.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pasteboard with a change count; `user_copies` stands for anything copied elsewhere.
    #[derive(Default)]
    struct Fake {
        count: Mutex<isize>,
        text: Mutex<Option<String>>,
    }

    impl Fake {
        fn user_copies(&self, text: &str) {
            *self.count.lock().unwrap() += 1;
            *self.text.lock().unwrap() = Some(text.into());
        }
        fn text(&self) -> Option<String> {
            self.text.lock().unwrap().clone()
        }
    }

    impl Board for Fake {
        fn write_secret(&self, text: &str) -> Result<Written, String> {
            self.user_copies(text);
            Ok(Written(*self.count.lock().unwrap()))
        }
        fn clear_if_unchanged(&self, written: Written) -> bool {
            let mut count = self.count.lock().unwrap();
            if *count != written.0 {
                return false;
            }
            *count += 1;
            *self.text.lock().unwrap() = None;
            true
        }
    }

    #[test]
    fn a_lock_or_the_quit_clears_a_secret_still_on_the_pasteboard() {
        let secrets = Secrets::new(Fake::default());
        secrets.copy("TEAM-KEY").unwrap();
        assert!(secrets.clear());
        assert_eq!(secrets.board.text(), None);
        assert!(!secrets.clear(), "nothing left to clear");
    }

    #[test]
    fn what_the_user_copied_since_is_left_alone() {
        let secrets = Secrets::new(Fake::default());
        let written = secrets.copy("macvpn-sub:…").unwrap();
        secrets.board.user_copies("a note");
        assert!(!secrets.clear());
        assert!(!secrets.expire(written));
        assert_eq!(secrets.board.text().as_deref(), Some("a note"));
    }

    #[test]
    fn the_timer_clears_only_the_last_secret() {
        let secrets = Secrets::new(Fake::default());
        let first = secrets.copy("RECOVERY-KEY").unwrap();
        let second = secrets.copy("TEAM-KEY").unwrap();
        assert!(!secrets.expire(first), "the first timer leaves the second secret");
        assert_eq!(secrets.board.text().as_deref(), Some("TEAM-KEY"));
        assert!(secrets.expire(second));
        assert_eq!(secrets.board.text(), None);
    }
}
