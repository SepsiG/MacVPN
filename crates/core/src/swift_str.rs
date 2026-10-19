//! Swift `String` semantics where the ported code depends on them.
//!
//! A Swift `String` is a collection of `Character`s (extended grapheme clusters) compared by canonical
//! equivalence. So `"</\u{301}x".hasPrefix("</")` is false (the second Character is `/` + combining acute), and
//! `"\u{37E}x".hasPrefix(";")` is true (U+037E GREEK QUESTION MARK is canonically equivalent to `;`). The Swift
//! validators use `hasPrefix`, `firstIndex(of:)`, `split`, `contains` and `==` on raw config text, so the Rust port
//! does the same here instead of plain byte operations, to give the same result (and the same message) for every
//! input. `String.range(of:options: .regularExpression)` also matches whole Characters: see [`matches`].
//!
//! Byte-oriented Swift code (`utf8`, `unicodeScalars`, `trimmingCharacters(in:)`) stays byte-oriented in the port.

use regex::Regex;
use std::cmp::Ordering;
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::{GraphemeCursor, UnicodeSegmentation};

/// The Characters (extended grapheme clusters) of `s`.
pub fn characters(s: &str) -> Vec<&str> {
    s.graphemes(true).collect()
}

/// Swift `Character ==`: canonical equivalence.
pub fn char_eq(a: &str, b: &str) -> bool {
    a == b || a.nfd().eq(b.nfd())
}

/// Swift `String ==`: canonical equivalence of the whole strings.
pub fn eq(a: &str, b: &str) -> bool {
    a == b || a.nfd().eq(b.nfd())
}

/// Swift `String <`: lexicographic order of the NFC Unicode scalars.
pub fn cmp(a: &str, b: &str) -> Ordering {
    if a.is_ascii() && b.is_ascii() {
        return a.cmp(b);
    }
    a.nfc().cmp(b.nfc())
}

/// Swift `hasPrefix` (Character-wise).
pub fn has_prefix(s: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if s.is_ascii() && prefix.is_ascii() && !s.contains('\r') {
        return s.starts_with(prefix);
    }
    let sc = characters(s);
    let pc = characters(prefix);
    sc.len() >= pc.len() && sc.iter().zip(&pc).all(|(a, b)| char_eq(a, b))
}

/// Swift `hasSuffix` (Character-wise).
pub fn has_suffix(s: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    if s.is_ascii() && suffix.is_ascii() && !s.contains('\r') {
        return s.ends_with(suffix);
    }
    let sc = characters(s);
    let pc = characters(suffix);
    sc.len() >= pc.len() && sc[sc.len() - pc.len()..].iter().zip(&pc).all(|(a, b)| char_eq(a, b))
}

/// Swift `contains(_ other: String)` (Character-wise substring search).
pub fn contains(s: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if s.is_ascii() && needle.is_ascii() && !s.contains('\r') {
        return s.contains(needle);
    }
    let sc = characters(s);
    let nc = characters(needle);
    if nc.len() > sc.len() {
        return false;
    }
    (0..=sc.len() - nc.len()).any(|i| sc[i..i + nc.len()].iter().zip(&nc).all(|(a, b)| char_eq(a, b)))
}

/// Byte offset of the first Character equal to `ch` (Swift `firstIndex(of:)`).
pub fn first_index(s: &str, ch: &str) -> Option<usize> {
    s.grapheme_indices(true).find(|(_, g)| char_eq(g, ch)).map(|(i, _)| i)
}

/// Byte offset of the last Character equal to `ch` (Swift `lastIndex(of:)`).
pub fn last_index(s: &str, ch: &str) -> Option<usize> {
    s.grapheme_indices(true).rev().find(|(_, g)| char_eq(g, ch)).map(|(i, _)| i)
}

/// Byte length of the Character starting at `index`.
pub fn char_len_at(s: &str, index: usize) -> usize {
    s[index..].graphemes(true).next().map_or(0, str::len)
}

/// Swift `split(separator:maxSplits:omittingEmptySubsequences:)` with a Character separator.
pub fn split<'a>(s: &'a str, separator: &str, max_splits: usize, omitting_empty: bool) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut splits = 0;
    for (i, g) in s.grapheme_indices(true) {
        if splits >= max_splits {
            break;
        }
        if char_eq(g, separator) {
            if !(omitting_empty && i == start) {
                parts.push(&s[start..i]);
                splits += 1;
            }
            start = i + g.len();
        }
    }
    if !(omitting_empty && start == s.len()) {
        parts.push(&s[start..]);
    }
    parts
}

/// Swift `prefix(while:)` on Characters.
pub fn prefix_while(s: &str, mut pred: impl FnMut(&str) -> bool) -> &str {
    for (i, g) in s.grapheme_indices(true) {
        if !pred(g) {
            return &s[..i];
        }
    }
    s
}

/// Swift `s.range(of: pattern, options: .regularExpression) != nil` for the patterns MacVPN uses (ASCII literals and
/// classes, `\s`, `\S`, negated classes).
///
/// Foundation matches on whole Characters (grapheme clusters): an ASCII atom never matches a cluster of several
/// scalars, while `\S` or a negated class (`[^\s=]`) does, and a match cannot start or end inside a cluster
/// (`"ab\u{301}c"` does not match `^ab`). This is computed by matching a projection of `s` in which every
/// multi-scalar cluster is one placeholder scalar: U+2000 if its first scalar is whitespace (`\s`, like
/// `Character.isWhitespace`), otherwise U+E000. `\r\n` stays, and a match may not split it. (`(?i)` must be
/// written as `(?i-u)`: Foundation does not fold non-ASCII letters such as U+017F or U+212A into ASCII classes.)
pub fn matches(s: &str, re: &Regex) -> bool {
    let projected = character_projection(s);
    let p: &str = &projected;
    if !p.contains("\r\n") {
        return re.is_match(p);
    }
    let mut at = 0;
    while at <= p.len() {
        let Some(m) = re.find_at(p, at) else { return false };
        if is_boundary(p, m.start()) && is_boundary(p, m.end()) {
            return true;
        }
        let next = m.start() + p[m.start()..].chars().next().map_or(1, char::len_utf8);
        if next <= at {
            return false;
        }
        at = next;
    }
    false
}

/// Every multi-scalar grapheme cluster (except `\r\n`) replaced by one placeholder scalar; see [`matches`].
pub fn character_projection(s: &str) -> std::borrow::Cow<'_, str> {
    if s.is_ascii() {
        return s.into();
    }
    let mut out = String::with_capacity(s.len());
    for g in s.graphemes(true) {
        let mut chars = g.chars();
        let first = chars.next().unwrap_or(' ');
        if chars.next().is_none() || g == "\r\n" {
            out.push_str(g);
        } else if first.is_whitespace() {
            out.push('\u{2000}');
        } else {
            out.push('\u{E000}');
        }
    }
    out.into()
}

/// Whether `index` is an extended grapheme cluster boundary in `s`.
pub fn is_boundary(s: &str, index: usize) -> bool {
    if index == 0 || index == s.len() {
        return true;
    }
    let mut cursor = GraphemeCursor::new(index, s.len(), true);
    cursor.is_boundary(s, 0).unwrap_or(false)
}

/// Grapheme_Cluster_Break=Extend (e.g. U+0301, U+200C, but not U+200D or a SpacingMark such as U+0903). Under
/// GB11 an Extend run may sit between an emoji and a ZWJ, which tells it apart from SpacingMark and ZWJ. Matches
/// what Foundation keeps together with a preceding `\n` / `\r` when searching (checked over every scalar).
pub fn is_grapheme_extend(c: char) -> bool {
    c != '\u{200D}' && format!("\u{1F600}{c}\u{200D}\u{1F600}").graphemes(true).count() == 1
}

/// `String(data:encoding: .utf8)` / `String(contentsOf:encoding: .utf8)`: strict UTF-8, one leading BOM dropped.
pub fn string_from_utf8_data(bytes: Vec<u8>) -> Option<String> {
    let s = String::from_utf8(bytes).ok()?;
    Some(match s.strip_prefix('\u{FEFF}') {
        Some(rest) => rest.to_string(),
        None => s,
    })
}

/// Foundation `CharacterSet.whitespaces`: TAB, Zs and U+200B (checked over every scalar on macOS 27).
pub fn is_foundation_whitespace(c: char) -> bool {
    matches!(c, '\t' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200B}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

/// Foundation `CharacterSet.newlines`.
pub fn is_foundation_newline(c: char) -> bool {
    matches!(c, '\u{A}'..='\u{D}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Foundation `CharacterSet.whitespacesAndNewlines`.
pub fn is_foundation_whitespace_or_newline(c: char) -> bool {
    is_foundation_whitespace(c) || is_foundation_newline(c)
}

/// Only space and tab are trimmed (not Unicode whitespace); Swift `trimmingCharacters(in: " \t")`.
pub fn trim_space_tab(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Only A-Z -> a-z, without Unicode lowercasing.
pub fn ascii_lowercased(s: &str) -> String {
    s.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_semantics_match_swift() {
        assert!(!has_prefix("</\u{301}x", "</"));
        assert!(has_prefix("\u{37E}x", ";"));
        assert!(eq("\u{212A}", "K"));
        assert!(!contains("a..\u{301}b", ".."));
        assert!(!contains("a.\u{301}.b", ".."));
        assert!(!contains("file:\u{301}x", "file:"));
        assert!(contains("a\u{37E}b", ";"));
        assert!(!contains("e\u{301}", "e"));
        assert!(contains("cafe\u{301}", "caf\u{E9}"));
        assert!(!has_prefix("-\u{301}x", "-"));
        assert_eq!(split("a,\u{301}b,c", ",", usize::MAX, true).len(), 2);
        assert!(first_index("a=\u{301}b", "=").is_none());
        assert_eq!(prefix_while("remote \u{301}x y", |c| c != " " && c != "\t"), "remote \u{301}x");
        assert_eq!(prefix_while("ab\u{600} c", |c| c != " "), "ab\u{600} c");
        assert!(eq("\u{1100}\u{1161}", "\u{AC00}"));
        assert!(!contains("x\u{1F1ED}\u{1F1FA}y", "\u{1F1FA}"));
    }

    #[test]
    fn regex_matches_whole_characters() {
        let re = Regex::new("^connections[ \\t]*\\{").unwrap();
        assert!(!matches("connections {\u{301}", &re));
        assert!(matches("connections {", &re));
        let ab = Regex::new("^ab").unwrap();
        assert!(matches("abc\u{301}", &ab));
        assert!(!matches("ab\u{301}c", &ab));
        let crlf = Regex::new("^\\r\\n$").unwrap();
        assert!(matches("\r\n", &crlf));
        let a_cr = Regex::new("^a[\\r]").unwrap();
        assert!(!matches("a\r\nb", &a_cr));
    }

    #[test]
    fn split_keeps_empty_parts_when_asked() {
        assert_eq!(split("a,,b,", ",", usize::MAX, false), vec!["a", "", "b", ""]);
        assert_eq!(split("a,,b,", ",", usize::MAX, true), vec!["a", "b"]);
        assert_eq!(split("a#b#c", "#", 1, false), vec!["a", "b#c"]);
        assert_eq!(split("", "#", 1, false), vec![""]);
        assert_eq!(split("#", "#", 1, false), vec!["", ""]);
    }
}
