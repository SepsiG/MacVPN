//! Secrets on the general pasteboard (a recovery key, a team key, a subscription string): written with
//! `NSPasteboard` for this Mac only (`NSPasteboardContentsCurrentHostOnly`, so Universal Clipboard does not send
//! it to the user's other devices) and marked `org.nspasteboard.ConcealedType` and
//! `org.nspasteboard.TransientType` (<http://nspasteboard.org>), so clipboard managers neither show nor keep it.
//!
//! The pasteboard is never read: a copied secret is recognised by the pasteboard's change count after the write
//! (anything copied later moves it on), so clearing it later shows no paste alert and leaves the user's own copy
//! alone. All of it goes through the safe `objc2` bindings (`NSPasteboard` may be used off the main thread).

use objc2_app_kit::{NSPasteboard, NSPasteboardContentsOptions};
use objc2_foundation::NSString;

/// The plain text type (`NSPasteboardTypeString`).
pub const STRING_TYPE: &str = "public.utf8-plain-text";
/// Clipboard managers do not show or record it.
pub const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
/// Clipboard managers do not record it (it is about to go).
pub const TRANSIENT_TYPE: &str = "org.nspasteboard.TransientType";

/// What a secret write left: the pasteboard's change count after it (platform-api's mark).
pub use macvpn_platform_api::ClipboardMark;

/// Whether the pasteboard still holds what was `written` (`current` is its change count now).
pub fn still_holds(written: ClipboardMark, current: isize) -> bool {
    written.0 == current
}

/// Puts `text` on the general pasteboard as a concealed, transient, this-Mac-only string.
pub fn write_secret(text: &str) -> Result<ClipboardMark, String> {
    write_secret_to(&NSPasteboard::generalPasteboard(), text)
}

/// Empties the general pasteboard if it still holds what was `written` (`true`: it did).
pub fn clear_if_unchanged(written: ClipboardMark) -> bool {
    clear_if_unchanged_on(&NSPasteboard::generalPasteboard(), written)
}

fn write_secret_to(board: &NSPasteboard, text: &str) -> Result<ClipboardMark, String> {
    board.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    let written = board.setString_forType(&NSString::from_str(text), &NSString::from_str(STRING_TYPE))
        && [CONCEALED_TYPE, TRANSIENT_TYPE]
            .iter()
            .all(|marker| board.setString_forType(&NSString::from_str(""), &NSString::from_str(marker)));
    if written {
        Ok(ClipboardMark(board.changeCount()))
    } else {
        board.clearContents();
        Err("the text could not be put on the clipboard".into())
    }
}

fn clear_if_unchanged_on(board: &NSPasteboard, written: ClipboardMark) -> bool {
    if still_holds(written, board.changeCount()) {
        board.clearContents();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A named private pasteboard for the tests (never the user's; one name, so the runs do not pile up).
    fn board() -> objc2::rc::Retained<NSPasteboard> {
        NSPasteboard::pasteboardWithName(&NSString::from_str("org.macvpn.tests.pasteboard"))
    }

    fn types(board: &NSPasteboard) -> Vec<String> {
        board.types().map(|t| t.iter().map(|s| s.to_string()).collect()).unwrap_or_default()
    }

    #[test]
    fn only_the_same_change_count_is_ours() {
        assert!(still_holds(ClipboardMark(7), 7));
        assert!(!still_holds(ClipboardMark(7), 8));
        assert!(!still_holds(ClipboardMark(7), 6));
    }

    /// The secret is a plain string marked concealed and transient; clearing it works only while it is unchanged.
    #[test]
    fn a_secret_is_concealed_and_cleared_only_while_unchanged() {
        let b = board();
        let written = write_secret_to(&b, "TEAM-ABCD").unwrap();
        let t = types(&b);
        for ty in [STRING_TYPE, CONCEALED_TYPE, TRANSIENT_TYPE] {
            assert!(t.iter().any(|x| x == ty), "{ty}: {t:?}");
        }
        assert_eq!(b.stringForType(&NSString::from_str(STRING_TYPE)).unwrap().to_string(), "TEAM-ABCD");
        assert!(clear_if_unchanged_on(&b, written));
        assert!(b.stringForType(&NSString::from_str(STRING_TYPE)).is_none());

        // Something else copied meanwhile is left alone.
        let written = write_secret_to(&b, "TEAM-ABCD").unwrap();
        b.clearContents();
        b.setString_forType(&NSString::from_str("the user's text"), &NSString::from_str(STRING_TYPE));
        assert!(!clear_if_unchanged_on(&b, written));
        assert_eq!(b.stringForType(&NSString::from_str(STRING_TYPE)).unwrap().to_string(), "the user's text");
    }
}
