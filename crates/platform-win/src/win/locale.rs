//! The user's UI languages and the locale-aware comparison of connection names (core's hooks).

use macvpn_core::{collation, l10n};
use std::cmp::Ordering;
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringEx, GetUserPreferredUILanguages, LINGUISTIC_IGNORECASE,
    MUI_LANGUAGE_NAME,
};

pub(crate) fn install() {
    l10n::AppLanguage::set_preferred_languages(preferred_languages());
    collation::set_localized_compare(Some(compare));
}

/// `GetUserPreferredUILanguages` as BCP 47 names (`hu-HU`, `en-US`), most preferred first.
fn preferred_languages() -> Vec<String> {
    let (mut count, mut len) = (0u32, 0u32);
    // SAFETY: a size query with a null buffer.
    if unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, std::ptr::null_mut(), &mut len) } == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` u16s as the size query asked.
    if unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, buf.as_mut_ptr(), &mut len) } == 0 {
        return Vec::new();
    }
    buf.truncate(len as usize);
    // A double-NUL-terminated list of NUL-terminated names.
    buf.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
}

/// Swift's `localizedCaseInsensitiveCompare` on Windows: the user's locale, case-insensitive.
fn compare(a: &str, b: &str) -> Ordering {
    let (wa, wb): (Vec<u16>, Vec<u16>) = (a.encode_utf16().collect(), b.encode_utf16().collect());
    let (Ok(la), Ok(lb)) = (i32::try_from(wa.len()), i32::try_from(wb.len())) else {
        return collation::default_compare(a, b);
    };
    // SAFETY: explicit lengths (no NUL termination needed); a null locale name is LOCALE_NAME_USER_DEFAULT.
    let r = unsafe {
        CompareStringEx(
            std::ptr::null(),
            LINGUISTIC_IGNORECASE,
            wa.as_ptr(),
            la,
            wb.as_ptr(),
            lb,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    match r {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_GREATER_THAN => Ordering::Greater,
        CSTR_EQUAL => Ordering::Equal,
        _ => collation::default_compare(a, b),
    }
}
