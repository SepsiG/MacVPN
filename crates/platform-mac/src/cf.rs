//! Core Foundation locale services for the core: the localized, case-insensitive comparison Swift's
//! `localizedCaseInsensitiveCompare` uses (so Hungarian names sort exactly as in the Swift app) and the user's
//! preferred languages (`Locale.preferredLanguages`).
//!
//! Audit notes: only owned `CFString` / `CFLocale` / `CFArray` objects cross the boundary; the returned objects
//! of the `Copy` functions are taken over with the create rule.
#![allow(unsafe_code)]

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFGetTypeID, CFRange};
use core_foundation_sys::locale::{CFLocaleCopyCurrent, CFLocaleCopyPreferredLanguages};
use core_foundation_sys::string::{
    CFStringCompareWithOptionsAndLocale, CFStringGetLength, kCFCompareCaseInsensitive, kCFCompareNonliteral,
};
use std::cmp::Ordering;

/// `a.localizedCaseInsensitiveCompare(b)`: `CFStringCompareWithOptionsAndLocale` with the case-insensitive option
/// and the current locale (what `NSString compare:options:range:locale:` calls).
pub fn localized_case_insensitive_compare(a: &str, b: &str) -> Ordering {
    let a = CFString::new(a);
    let b = CFString::new(b);
    // SAFETY: plain getter returning a +1 locale or null.
    let raw = unsafe { CFLocaleCopyCurrent() };
    // SAFETY: non-null +1 object (create rule), released when `locale` drops. Null: no locale (CF then compares
    // with the canonical, non-localized order instead of crashing).
    let locale = (!raw.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(raw.cast()) });
    // SAFETY: valid string; plain getter.
    let length = unsafe { CFStringGetLength(a.as_concrete_TypeRef()) };
    // SAFETY: two valid strings, the full range of the first, a valid locale or null; nothing is retained.
    let result = unsafe {
        CFStringCompareWithOptionsAndLocale(
            a.as_concrete_TypeRef(),
            b.as_concrete_TypeRef(),
            CFRange { location: 0, length },
            // NSString without `.literal` adds kCFCompareNonliteral (canonical equivalence).
            kCFCompareCaseInsensitive | kCFCompareNonliteral,
            locale.as_ref().map_or(std::ptr::null(), |l| l.as_CFTypeRef().cast()),
        )
    };
    // CFComparisonResult: -1 less, 0 equal, 1 greater.
    (result as i64).cmp(&0)
}

/// `Locale.preferredLanguages` (`CFLocaleCopyPreferredLanguages`), e.g. `["hu-HU", "en-US"]`.
pub fn preferred_languages() -> Vec<String> {
    // SAFETY: a +1 array (create rule), released when `array` drops.
    let raw = unsafe { CFLocaleCopyPreferredLanguages() };
    if raw.is_null() {
        return Vec::new();
    }
    // SAFETY: non-null +1 CFArray.
    let array: CFArray = unsafe { CFArray::wrap_under_create_rule(raw) };
    let mut out = Vec::new();
    for item in array.iter() {
        let p = *item;
        // SAFETY: the element is alive while `array` is; its type ID is checked before the cast.
        if !p.is_null() && unsafe { CFGetTypeID(p) } == CFString::type_id() {
            // SAFETY: a valid CFString (checked above), retained by the get rule.
            out.push(unsafe { CFString::wrap_under_get_rule(p.cast()) }.to_string());
        }
    }
    out
}
