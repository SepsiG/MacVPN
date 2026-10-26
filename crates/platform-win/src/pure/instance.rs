//! The single-instance decision and what WinVPN says when it cannot claim the instance (review L3).

use macvpn_core::l10n::{self, AppLanguage};
use std::fmt;
use std::io;

/// The marker inside [`squatted`]'s error.
struct Squatted;

impl fmt::Display for Squatted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the single-instance lock belongs to another user")
    }
}

impl fmt::Debug for Squatted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Squatted {}

/// The lock is held by another user's process (it created the mutex first, or it cannot even be opened):
/// `PermissionDenied`. Not "WinVPN runs already": nothing is forwarded to it.
pub fn squatted() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, Squatted)
}

pub fn is_squatted(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Squatted>())
}

/// An existing mutex: `Ok` (WinVPN runs already for this user: forward to it) when its owner is this user,
/// [`squatted`] otherwise.
pub fn existing_mutex(owner_is_me: bool) -> io::Result<()> {
    if owner_is_me { Ok(()) } else { Err(squatted()) }
}

/// What the message box says when the claim fails (WinVPN then exits): the squatted lock, or any other failure (the
/// running WinVPN did not answer, the forwarding pipe is someone else's, a path the message cannot carry).
pub fn failure_message(e: &io::Error) -> String {
    failure_message_in(AppLanguage::current(), e)
}

pub fn failure_message_in(language: AppLanguage, e: &io::Error) -> String {
    if is_squatted(e) {
        l10n::tr_in(
            language,
            "WinVPN cannot start: a program of another user holds its single-instance lock in this session. Sign out and back in, or restart Windows.",
            &[],
        )
    } else {
        l10n::tr_in(
            language,
            "WinVPN cannot start: the WinVPN that is already running did not answer. Quit it from the notification area and start WinVPN again.",
            &[],
        )
    }
}
