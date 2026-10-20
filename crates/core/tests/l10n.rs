//! The core text table and language selection (started as a port of the 0.x `LocalizationTests.swift` cases).

use macvpn_core::l10n::{self, AppLanguage, Arg, with_language};
use regex::Regex;

#[test]
fn resolve_picks_first_hungarian_or_english_else_english() {
    assert_eq!(AppLanguage::resolve(&["hu-HU", "en-US"]), AppLanguage::Hu);
    assert_eq!(AppLanguage::resolve(&["en-GB", "hu"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["de-DE", "hu-HU"]), AppLanguage::Hu);
    assert_eq!(AppLanguage::resolve(&["de-DE", "fr"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["hr-HR"]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve::<&str>(&[]), AppLanguage::En);
    assert_eq!(AppLanguage::resolve(&["HU_hu"]), AppLanguage::Hu);
}

#[test]
fn lang_argument_unknown_means_english() {
    assert_eq!(AppLanguage::from_argument("hu"), AppLanguage::Hu);
    assert_eq!(AppLanguage::from_argument("en"), AppLanguage::En);
    assert_eq!(AppLanguage::from_argument("de"), AppLanguage::En);
    assert_eq!(AppLanguage::from_argument(""), AppLanguage::En);
}

#[test]
fn explicit_language_parameter() {
    assert_eq!(l10n::tr_in(AppLanguage::En, "Missing remote directive", &[]), "Missing remote directive");
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "Missing remote directive", &[]), "Hiányzik a remote direktíva");
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "Line %ld: %@", &[Arg::Int(3), Arg::Str("x")]), "3. sor: x");
    assert_eq!(l10n::tr_in(AppLanguage::En, "Line %ld: %@", &[Arg::Int(3), Arg::Str("x")]), "Line 3: x");
    // A missing key falls back to the English text.
    assert_eq!(l10n::tr_in(AppLanguage::Hu, "No such key %@", &[Arg::Str("x")]), "No such key x");
}

#[test]
fn thread_override_wins_and_is_restored() {
    with_language(AppLanguage::Hu, || {
        assert_eq!(AppLanguage::current(), AppLanguage::Hu);
        with_language(AppLanguage::En, || assert_eq!(AppLanguage::current(), AppLanguage::En));
        assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    });
}

/// Format specifiers (`%@`, `%ld`, `%d`, also positional), as a sorted multiset.
fn specifiers(s: &str) -> Vec<String> {
    let re = Regex::new(r"%(?:[0-9]+\$)?(l{0,2}[dfu]|@)").unwrap();
    let mut v: Vec<String> = re.captures_iter(s).map(|c| c[1].to_string()).collect();
    v.sort();
    v
}

#[test]
fn core_table_has_both_languages_for_every_key() {
    assert!(!l10n::table().is_empty());
    for e in l10n::table() {
        let (key, hu) = (&e.key, &e.hu);
        assert!(!key.is_empty());
        assert!(!hu.trim_matches(' ').is_empty(), "empty Hungarian text: {key}");
        assert_eq!(specifiers(key), specifiers(hu), "different format specifiers: {key}");
    }
}

/// `strings.json` has no duplicate keys (a JSON parser keeps only the last one, silently) and every entry has a
/// known scope.
#[test]
fn table_has_unique_keys_and_known_scopes() {
    let entries = l10n::STRINGS_JSON.lines().filter(|l| l.starts_with("    \"") && l.ends_with('{')).count();
    assert_eq!(entries, l10n::table().len(), "a key appears twice in strings.json");
    for e in l10n::table() {
        assert!(
            ["core", "core-rust", "app", "mvpn", "platform"].contains(&e.scope.as_str()),
            "unknown scope {}: {}",
            e.scope,
            e.key
        );
    }
}

#[test]
fn positional_and_long_specifiers() {
    assert_eq!(l10n::tr_in(AppLanguage::En, "%2$@ and %1$@", &[Arg::Str("a"), Arg::Str("b")]), "b and a");
    assert_eq!(l10n::tr_in(AppLanguage::En, "%lld items, 100%%", &[Arg::Int(3)]), "3 items, 100%");
}

/// Every `tr("…")` key used in the Rust core sources has a Hungarian translation.
#[test]
fn every_core_call_site_has_a_translation() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let call = Regex::new(r#"\btr\(\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let mut found = 0;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for c in call.captures_iter(&source) {
                let key = c[1].replace("\\\"", "\"").replace("\\\\", "\\");
                found += 1;
                assert!(l10n::hungarian(&key).is_some(), "no Hungarian translation ({}): {key}", path.display());
            }
        }
    }
    assert!(found >= 50, "{found}");
}
