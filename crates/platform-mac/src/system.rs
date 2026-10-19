//! The current user and the app's standard locations.

use std::path::{Path, PathBuf};

/// The user's home directory from the user database (`getpwuid`), not from `$HOME`: the value the core store
/// functions take (`~/Library/Application Support/MacVPN/…`).
pub fn home_directory() -> Option<PathBuf> {
    crate::sys::user_by_uid(crate::sys::getuid()).map(|u| u.home).filter(|h| h.is_absolute())
}

/// The user's login name (Foundation `NSUserName()`).
pub fn user_name() -> Option<String> {
    crate::sys::user_by_uid(crate::sys::getuid()).map(|u| u.name)
}

/// The bundled root layer: `<bundle>/Contents/Resources/root` if it holds `mvpn` (the app's `RootResources`).
pub fn bundled_root_directory(resources: &Path) -> Option<PathBuf> {
    let dir = resources.join("root");
    dir.join("mvpn").exists().then_some(dir)
}

/// The real user ID (`getuid`): the expected owner of the MFA bridge's UI state files.
pub fn user_id() -> u32 {
    crate::sys::getuid()
}

/// The bundle's `Contents/Info.plist` as Foundation's `infoDictionary` gives the update checker (strings and
/// numbers; other values skipped). Read only from a regular file, never through a symlink.
pub fn bundle_info(bundle: &Path) -> Option<macvpn_core::update::Info> {
    use macvpn_core::update::InfoValue;
    let path = bundle.join("Contents/Info.plist");
    if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file()) {
        return None;
    }
    let dict = plist::Value::from_file(&path).ok()?.into_dictionary()?;
    let mut info = macvpn_core::update::Info::new();
    for (key, value) in dict {
        let value = match value {
            plist::Value::String(s) => InfoValue::String(s),
            plist::Value::Boolean(b) => InfoValue::Boolean(b),
            plist::Value::Integer(i) => match i.as_signed() {
                Some(n) => InfoValue::Integer(n),
                None => continue,
            },
            plist::Value::Real(r) => InfoValue::Real(r),
            _ => continue,
        };
        info.insert(key, value);
    }
    Some(info)
}

/// The local date as `YYYY-MM-DD` (the backup's default file name); empty if the time cannot be converted.
pub fn local_date(unix: f64) -> String {
    match crate::sys::local_time(unix.floor() as i64) {
        Some((y, mo, d, ..)) => format!("{y:04}-{mo:02}-{d:02}"),
        None => String::new(),
    }
}

/// The local date and time as Swift's `Date().formatted(date: .numeric, time: .standard)` shows it in the two UI
/// languages: `10/18/2026, 2:03:05 PM` (English) and `2026. 10. 18. 14:03:05` (Hungarian).
pub fn local_date_time(unix: f64, language: macvpn_core::l10n::AppLanguage) -> String {
    let Some((y, mo, d, h, mi, s)) = crate::sys::local_time(unix.floor() as i64) else { return String::new() };
    match language {
        macvpn_core::l10n::AppLanguage::Hu => format!("{y}. {mo:02}. {d:02}. {h:02}:{mi:02}:{s:02}"),
        macvpn_core::l10n::AppLanguage::En => {
            let (h12, suffix) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            format!("{mo}/{d}/{y}, {h12}:{mi:02}:{s:02}\u{202f}{suffix}")
        }
    }
}
