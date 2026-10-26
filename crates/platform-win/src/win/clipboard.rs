//! The clipboard: plain text, and secrets kept out of clipboard history, cloud sync and clipboard monitors.
//!
//! Nothing here is logged; the UTF-16 copy of the text is zeroized, and so is a block the clipboard did not take.

use macvpn_platform_api::{ClipboardMark, PlatformError, SecretClipboard};
use std::time::Duration;
use windows_sys::Win32::Foundation::GlobalFree;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use zeroize::Zeroize;

/// The registered formats that keep a secret out of clipboard monitors, Windows' clipboard history and cloud sync.
pub(crate) const EXCLUDE_FROM_MONITORS: &str = "ExcludeClipboardContentFromMonitorProcessing";
pub(crate) const HISTORY: &str = "CanIncludeInClipboardHistory";
pub(crate) const CLOUD: &str = "CanUploadToCloudClipboard";

fn failed(what: &str) -> PlatformError {
    PlatformError::Failed(format!("clipboard: {what}"))
}

/// The clipboard is open while this lives (another app may hold it briefly: retried for about 100 ms). Its owner is
/// platform-win's hidden message window on the main thread (`OpenClipboard`'s documented form: with no window,
/// `EmptyClipboard` leaves the clipboard without an owner); without that window (tests), no owner.
struct Open;

impl Open {
    fn new() -> Result<Open, PlatformError> {
        let owner = super::msgwin::main_window();
        for _ in 0..10 {
            // SAFETY: `owner` is the main thread's live message window, or null (no owner, which is allowed).
            if unsafe { OpenClipboard(owner) } != 0 {
                return Ok(Open);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(failed("busy"))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: we opened it.
        unsafe { CloseClipboard() };
    }
}

/// Puts `bytes` on the open clipboard under `format`; the clipboard owns the memory on success (a block it did not
/// take is zeroized and freed).
fn set(_open: &Open, format: u32, bytes: &[u8]) -> Result<(), PlatformError> {
    // SAFETY: a movable block of `max(len, 1)` bytes, filled while locked, handed to the clipboard (or wiped and
    // freed).
    unsafe {
        let size = bytes.len().max(1);
        let mem = GlobalAlloc(GMEM_MOVEABLE, size);
        if mem.is_null() {
            return Err(failed("out of memory"));
        }
        let p = GlobalLock(mem).cast::<u8>();
        if p.is_null() {
            GlobalFree(mem);
            return Err(failed("lock"));
        }
        std::ptr::write_bytes(p, 0, size);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(mem);
        if SetClipboardData(format, mem).is_null() {
            let p = GlobalLock(mem).cast::<u8>();
            if !p.is_null() {
                std::ptr::write_bytes(p, 0, size);
                GlobalUnlock(mem);
            }
            GlobalFree(mem);
            return Err(failed("set"));
        }
    }
    Ok(())
}

fn registered(name: &str) -> Result<u32, PlatformError> {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: a NUL-terminated name.
    match unsafe { RegisterClipboardFormatW(wide.as_ptr()) } {
        0 => Err(failed("register format")),
        format => Ok(format),
    }
}

/// Writes `text`; a secret also gets the three exclusion formats (all or nothing: a secret whose exclusion cannot
/// be set is not left on the clipboard). Returns the clipboard's sequence number after the write: read after
/// `CloseClipboard`, which itself advances it (the system adds the synthesized text formats). If the clipboard may
/// have changed in between (another app copied), the number read while it was still open is returned instead: an
/// older number that never matches again, so nothing that is not ours is ever cleared.
pub(crate) fn write(text: &str, secret: bool) -> Result<u32, PlatformError> {
    let units = text.encode_utf16().count() + 1;
    // Exactly the capacity needed: no reallocation leaves a copy behind.
    let mut bytes: Vec<u8> = Vec::with_capacity(units * 2);
    bytes.extend(text.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes));
    let result = (|| {
        let open = Open::new()?;
        // SAFETY: the clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(failed("empty"));
        }
        if secret {
            let formats = (registered(EXCLUDE_FROM_MONITORS), registered(HISTORY), registered(CLOUD));
            let (Ok(monitors), Ok(history), Ok(cloud)) = formats else { return Err(failed("register format")) };
            set(&open, monitors, &[0])?;
            set(&open, history, &0u32.to_le_bytes())?;
            set(&open, cloud, &0u32.to_le_bytes())?;
        }
        if let Err(e) = set(&open, u32::from(CF_UNICODETEXT), &bytes) {
            // SAFETY: the clipboard is open; the exclusion formats alone are not left behind.
            unsafe { EmptyClipboard() };
            return Err(e);
        }
        Ok(sequence())
    })();
    bytes.zeroize();
    let while_open = result?;
    let after = sequence();
    let still_ours = !secret || has_format(EXCLUDE_FROM_MONITORS);
    Ok(if still_ours && sequence() == after { after } else { while_open })
}

pub(crate) fn sequence() -> u32 {
    // SAFETY: plain call.
    unsafe { GetClipboardSequenceNumber() }
}

/// Whether the clipboard currently offers the registered format `name`.
pub(crate) fn has_format(name: &str) -> bool {
    // SAFETY: plain call (no need to open the clipboard).
    registered(name).is_ok_and(|format| unsafe { IsClipboardFormatAvailable(format) } != 0)
}

pub(crate) struct Clipboard;

impl SecretClipboard for Clipboard {
    fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError> {
        write(text, true).map(|seq| ClipboardMark(seq as isize))
    }

    /// Empties the clipboard only if nothing was copied since `mark` (checked while the clipboard is open, so no
    /// other app can copy between the check and the clearing). A busy clipboard is left alone (`false`).
    fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool {
        let Ok(_open) = Open::new() else { return false };
        if sequence() as isize != mark.0 {
            return false;
        }
        // SAFETY: the clipboard is open.
        unsafe { EmptyClipboard() != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::DataExchange::GetClipboardOwner;

    /// After a write the clipboard's owner is the main thread's message window (review I3). This test's thread is
    /// the main thread of the unit test binary's platform-win: nothing else here records one.
    #[test]
    fn the_clipboard_is_owned_by_the_message_window() {
        crate::win::msgwin::remember_main_thread();
        let Some(window) = crate::win::msgwin::ensure_main_window() else {
            panic!("another thread was recorded as the main thread");
        };
        assert_eq!(crate::win::msgwin::main_window(), window);
        let mark = write("owner-check", false).unwrap();
        // SAFETY: plain call.
        assert_eq!(unsafe { GetClipboardOwner() }, window);
        assert!(Clipboard.clear_if_unchanged(ClipboardMark(mark as isize)));
    }
}
