//! `localizedCaseInsensitiveCompare` for connection names.
//!
//! Swift compares with the user's current locale (CFString + ICU collation). The core cannot call macOS APIs, so
//! the platform layer installs the real comparator with [`set_localized_compare`] (macOS:
//! `CFStringCompareWithOptionsAndLocale` with the current locale, exactly what Swift calls). Until then, and on
//! other platforms, [`default_compare`] approximates the ICU root order (en_US) used by Foundation: letters
//! compared without accents and case first, then with accents; punctuation and symbols before digits before
//! letters, in the ICU order.

use std::cmp::Ordering;
use std::sync::RwLock;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

type Compare = fn(&str, &str) -> Ordering;

static COMPARE: RwLock<Option<Compare>> = RwLock::new(None);

/// Installs the platform's locale-aware comparator.
pub fn set_localized_compare(compare: Option<Compare>) {
    if let Ok(mut c) = COMPARE.write() {
        *c = compare;
    }
}

/// Swift `a.localizedCaseInsensitiveCompare(b)`.
pub fn localized_case_insensitive_compare(a: &str, b: &str) -> Ordering {
    let installed = COMPARE.read().ok().and_then(|c| *c);
    match installed {
        Some(compare) => compare(a, b),
        None => default_compare(a, b),
    }
}

/// ICU root-like, case-insensitive comparison (primary, then secondary strength).
pub fn default_compare(a: &str, b: &str) -> Ordering {
    let (pa, sa) = keys(a);
    let (pb, sb) = keys(b);
    pa.cmp(&pb).then_with(|| sa.cmp(&sb))
}

/// ICU root order of the ASCII punctuation and symbols (all before digits and letters).
const PUNCTUATION: &str = "\t\n\u{b}\u{c}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$";

fn keys(s: &str) -> (Vec<u32>, Vec<u32>) {
    let mut primary = Vec::new();
    let mut secondary = Vec::new();
    for c in s.chars() {
        // Expansions: ß = ss (and its accent level is "different from ss").
        let base: Vec<char> =
            if c == 'ß' { vec!['s', 's'] } else { c.to_lowercase().collect::<String>().nfd().collect() };
        let mut accents = 0u32;
        for d in base {
            if is_combining_mark(d) {
                accents = accents * 31 + d as u32 % 31 + 1;
                continue;
            }
            let weight = if let Some(i) = PUNCTUATION.find(d) {
                1 + i as u32
            } else if d.is_ascii_digit() {
                0x100 + d as u32
            } else if d.is_alphabetic() {
                0x1_0000 + d as u32
            } else {
                0x80 + d as u32 % 0x80
            };
            primary.push(weight);
        }
        secondary.push(if c == 'ß' { 1 } else { accents });
    }
    (primary, secondary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approximates_icu_root() {
        let less = |a: &str, b: &str| assert_eq!(default_compare(a, b), Ordering::Less, "{a} < {b}");
        less("alpha", "éjszakai");
        less("éjszakai", "Ember");
        less("10", "9");
        less("9", "A");
        less("x y", "x_y");
        less("x_y", "x-y");
        less("x-y", "xy");
        less("Ö", "Office");
        less("arvizturo", "Árvíztűrő");
        less("ss", "ß");
        assert_eq!(default_compare("Office", "office"), Ordering::Equal);
    }
}
