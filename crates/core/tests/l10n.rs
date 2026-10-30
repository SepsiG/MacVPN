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

// Per-OS variants and the product name (platform-neutral refactor, Task 6).

use macvpn_core::TargetOs;
use macvpn_core::l10n::TextPlatform;

const WINDOWS: TextPlatform = TextPlatform { os: TargetOs::Windows, product: "WinVPN" };
const LINUX: TextPlatform = TextPlatform { os: TargetOs::Linux, product: "LinVPN" };

/// The macOS texts are byte-identical to 1.4.0 (the frozen baseline of Task 1), in both languages, and no 1.4.0
/// key is gone. Keys added since are new texts, not changed ones.
#[test]
fn macos_texts_equal_the_1_4_0_baseline() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/bundle-baseline/1.4.0/l10n-macos.json");
    let baseline: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(baseline.len() >= 1114, "{}", baseline.len());
    assert_eq!(l10n::text_platform(), TextPlatform::MACOS);
    for (key, texts) in &baseline {
        assert!(l10n::table().iter().any(|e| &e.key == key), "a 1.4.0 key is gone: {key}");
        for (language, name) in [(AppLanguage::En, "en"), (AppLanguage::Hu, "hu")] {
            let expected = texts[name].as_str().unwrap();
            assert_eq!(l10n::tr_for(TextPlatform::MACOS, language, key, &[]), expected, "{name}: {key}");
            assert_eq!(l10n::tr_in(language, key, &[]), expected, "{name}: {key}");
        }
    }
}

#[test]
fn text_platform_defaults_to_macos() {
    assert_eq!(TextPlatform::MACOS, TextPlatform { os: TargetOs::MacOs, product: "MacVPN" });
    assert_eq!(l10n::text_platform(), TextPlatform::MACOS);
}

#[test]
fn windows_variant_in_both_languages() {
    let key = "Enter the master password. Its key is then kept in the macOS Keychain, and MacVPN opens without asking.";
    assert_eq!(
        l10n::tr_for(WINDOWS, AppLanguage::En, key, &[]),
        "Enter the master password. Its key is then kept in the Windows Credential Manager, and WinVPN opens without asking."
    );
    assert_eq!(
        l10n::tr_for(WINDOWS, AppLanguage::Hu, key, &[]),
        "Add meg a mesterjelszót. A széf kulcsa ezután a Windows Hitelesítőadat-kezelőjében marad, és a WinVPN kérdés nélkül megnyílik."
    );
    assert_eq!(
        l10n::tr_for(LINUX, AppLanguage::En, key, &[]),
        "Enter the master password. Its key is then kept in your login keyring, and LinVPN opens without asking."
    );
    assert_eq!(
        l10n::tr_for(LINUX, AppLanguage::Hu, key, &[]),
        "Add meg a mesterjelszót. A széf kulcsa ezután a bejelentkezési kulcstartódban marad, és a LinVPN kérdés nélkül megnyílik."
    );
    // A variant with arguments.
    assert_eq!(
        l10n::tr_for(
            WINDOWS,
            AppLanguage::Hu,
            "Its %lld connections and folders are removed from this Mac, and paired apps lose access to them.",
            &[Arg::Int(3)]
        ),
        "A(z) 3 kapcsolata és a mappái törlődnek erről a számítógépről, és a párosított appok elveszítik hozzájuk a hozzáférést."
    );
}

/// G-9: "Remove WinVPN from This Account…" reuses the uninstaller's texts with WinVPN's wording.
#[test]
fn the_account_cleanup_texts_on_windows() {
    let title = "MacVPN has been uninstalled";
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::En, title, &[]), "WinVPN has been removed from this account");
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::Hu, title, &[]), "A WinVPN eltávolítva erről a fiókról");
    let next = "You can now drag the app to the Trash. The Homebrew packages were kept (brew uninstall openvpn wireguard-tools strongswan sstp-client).";
    assert_eq!(
        l10n::tr_for(WINDOWS, AppLanguage::En, next, &[]),
        "Now uninstall WinVPN in Settings → Apps → Installed apps (opened for you): the WinVPN Service and the program files go with it."
    );
    assert!(l10n::tr_for(WINDOWS, AppLanguage::Hu, next, &[]).starts_with("Most távolítsd el a WinVPN-t a Gépház"));
    let data = "~/Library/Application Support/MacVPN with the vault, and in the Keychain the vault key and the old MacVPN 1.1 items";
    assert_eq!(
        l10n::tr_for(WINDOWS, AppLanguage::En, data, &[]),
        r"AppData\Local\WinVPN with the vault, and in Credential Manager the vault key (local.winvpn.vault)"
    );
    assert_eq!(
        l10n::tr_for(WINDOWS, AppLanguage::Hu, data, &[]),
        r"AppData\Local\WinVPN a széffel, és a Hitelesítőadat-kezelőben a széf kulcsa (local.winvpn.vault)"
    );
    // macOS keeps its texts (the 1.4.0 baseline test pins them all).
    assert_eq!(l10n::tr_for(TextPlatform::MACOS, AppLanguage::En, title, &[]), title);
}

#[test]
fn product_name_replaced_without_a_variant() {
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::En, "Quit MacVPN", &[]), "Quit WinVPN");
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::En, "Disconnected in MacVPN", &[]), "Disconnected in WinVPN");
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::Hu, "Disconnected in MacVPN", &[]), "Bontva a WinVPN-ben");
    assert_eq!(
        l10n::tr_for(TextPlatform::MACOS, AppLanguage::Hu, "Disconnected in MacVPN", &[]),
        "Bontva a MacVPN-ben"
    );
    // Arguments are not rewritten, only the text.
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::En, "%@ not found", &[Arg::Str("MacVPN")]), "MacVPN not found");
    // A missing key is the base text too.
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::Hu, "No such MacVPN key", &[]), "No such WinVPN key");
}

#[test]
fn macos_only_texts_are_never_substituted() {
    let key =
        "Launch at login is available only when MacVPN runs from the Applications folder. Drag the app there first.";
    let entry = l10n::table().into_iter().find(|e| e.key == key).unwrap();
    assert_eq!(entry.only, vec![TargetOs::MacOs]);
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::En, key, &[]), key);
    assert_eq!(l10n::tr_for(WINDOWS, AppLanguage::Hu, key, &[]), entry.hu);
    for e in l10n::table() {
        if e.only == [TargetOs::MacOs] {
            for language in AppLanguage::ALL {
                assert_eq!(
                    l10n::tr_for(WINDOWS, language, &e.key, &[]),
                    l10n::tr_for(TextPlatform::MACOS, language, &e.key, &[]),
                    "{}",
                    e.key
                );
            }
        }
    }
}

/// Specifiers in their written order (kinds and positions), for the variants: a variant must take the same
/// arguments the same way as its base.
fn ordered_specifiers(s: &str) -> Vec<String> {
    let re = Regex::new(r"%([0-9]+\$)?(l{0,2}[dfu]|@)").unwrap();
    let mut v: Vec<String> = re.captures_iter(s).map(|c| c[0].to_string()).collect();
    if v.iter().any(|x| x.contains('$')) {
        v.sort();
    }
    v
}

#[test]
fn variants_keep_the_format_specifiers() {
    let mut variants = 0;
    for e in l10n::table() {
        for (os, (en, hu)) in &e.variants {
            variants += 1;
            assert_ne!(*os, TargetOs::MacOs, "a macOS variant: {}", e.key);
            assert!(!e.only.contains(os), "only and variants both name {os:?}: {}", e.key);
            assert!(!en.trim().is_empty() && !hu.trim().is_empty(), "empty variant: {}", e.key);
            assert_eq!(ordered_specifiers(en), ordered_specifiers(&e.key), "en variant: {}", e.key);
            assert_eq!(ordered_specifiers(hu), ordered_specifiers(&e.hu), "hu variant: {}", e.key);
            assert_eq!(specifiers(en), specifiers(hu), "variant: {}", e.key);
        }
    }
    assert!(variants >= 20, "{variants}");
}

#[test]
fn not_available_on_this_system_yet() {
    let key = "Not available on this system yet";
    let entry = l10n::table().into_iter().find(|e| e.key == key).unwrap();
    assert_eq!(entry.scope, "platform");
    assert_eq!(entry.hu, "Ezen a rendszeren még nem érhető el");
    assert!(entry.only.is_empty() && entry.variants.is_empty());
}
