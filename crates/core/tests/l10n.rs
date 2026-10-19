//! Port of the `LocalizationTests.swift` cases that concern the core table and language selection.

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

/// The core part of `strings.json` equals the Swift `L10n.hungarian` table, verbatim and complete. (The Swift app
/// stays in `legacy/swift` until 1.0.0 ships as the reference; this test goes with it.)
#[test]
fn table_matches_the_swift_core_table() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let swift = std::fs::read_to_string(root.join("legacy/swift/Sources/MacVPNCore/L10n.swift")).unwrap();
    let body = &swift[swift.find("public static let hungarian").unwrap()..];
    let flat = body.replace('\n', " ");
    let unescape = |s: &str| s.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
    let pair = Regex::new(r#""((?:[^"\\]|\\.)*)":\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let mut swift_table = std::collections::HashMap::new();
    for c in pair.captures_iter(&flat) {
        swift_table.insert(unescape(&c[1]), unescape(&c[2]));
    }
    let core: Vec<_> = l10n::table().into_iter().filter(|e| e.scope == "core").collect();
    assert_eq!(core.len(), swift_table.len());
    for e in core {
        assert_eq!(swift_table.get(&e.key), Some(&e.hu), "{}", e.key);
    }
}

/// The `app` texts of the Rust UI that the Swift app did not have (from 1.1.0: the control API's pairing window and
/// Paired apps section, the live system VPN list, the credential prompt window).
const RUST_ONLY_APP_TEXTS: &[&str] = &[
    "Saved — type to replace",
    "Remove saved password",
    "Connecting…",
    "Disconnecting…",
    "Allow an App to Control VPNs?",
    "An app on this Mac asks to bring the connections you choose up and down. Allow it only if you started this app and you trust it.",
    "Name (self-reported)",
    "Executable",
    "Connections it may use",
    "There are no connections to allow.",
    "Deny",
    "Allow",
    "Paired apps",
    "Allow other apps to control VPNs",
    "Programs on this Mac that you pair can list the connections you allow, and bring them up and down. They never see configurations or passwords.",
    "Revoke",
    "Path changed",
    "This app was started from another location: %@. Revoke it and pair it again to use the new copy.",
    "Last used: %@",
    "Never used",
    "Paired: %@",
    "Allowed connections",
    "Held by %@",
    "No paired apps yet. An app asks for pairing while this is on.",
    "Activity",
    "No activity yet.",
    "Revoke %@?",
    "The app can no longer control VPNs, and its open sessions end now. Connections that only it brought up are disconnected.",
    "Could not change the allowed connections: %@",
    "Could not revoke %@: %@",
    // 1.1: the live system VPN list.
    "This VPN was removed from macOS",
    // 1.1: the credential prompt.
    "Credentials needed",
    "Stored in the macOS Keychain",
    "Not ready yet. Wait a moment, then click Connect again.",
    "MacVPN did not accept these values. Check them and try again.",
];

/// The app part of `strings.json` equals the String Catalog (`Localizable.xcstrings`): every key, translated.
/// (`legacy/swift`, removed after 1.0.0 together with this test.)
#[test]
fn table_matches_the_app_catalog() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("legacy/swift/Sources/MacVPN/Resources/Localizable.xcstrings")).unwrap(),
    )
    .unwrap();
    assert_eq!(catalog["sourceLanguage"], "en");
    let strings = catalog["strings"].as_object().unwrap();
    assert!(strings.len() > 100);
    let app: Vec<_> = l10n::table().into_iter().filter(|e| e.scope == "app").collect();
    // UI texts new in the Rust app (no Swift counterpart): listed here, so a Swift text cannot go missing unnoticed.
    let rust_only: Vec<_> = app.iter().filter(|e| RUST_ONLY_APP_TEXTS.contains(&e.key.as_str())).collect();
    assert_eq!(rust_only.len(), RUST_ONLY_APP_TEXTS.len(), "a Rust-only text is missing from the table");
    assert_eq!(app.len(), strings.len() + RUST_ONLY_APP_TEXTS.len());
    for e in app.into_iter().filter(|e| !RUST_ONLY_APP_TEXTS.contains(&e.key.as_str())) {
        let unit = &strings[&e.key]["localizations"]["hu"]["stringUnit"];
        assert_eq!(unit["state"], "translated", "{}", e.key);
        assert_eq!(unit["value"].as_str(), Some(e.hu.as_str()), "{}", e.key);
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
