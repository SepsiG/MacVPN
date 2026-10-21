//! CFPreferences round trips in a throwaway domain (never `local.macvpn`), and the bundle Info.plist reader.
#![cfg(target_os = "macos")]

use macvpn_core::date::Date;
use macvpn_core::update::{InfoValue, UpdateChecker};
use macvpn_platform_mac::preferences::CFPreferencesStore;
use macvpn_platform_mac::system::bundle_info;

#[test]
fn remove_all_empties_a_throwaway_domain() {
    let domain = format!("local.macvpn.rust-test.{}", uuid::Uuid::new_v4());
    let store = CFPreferencesStore::new(&domain);
    store.set_bool("autoCheckUpdates", false);
    store.set_string("noticedUpdateHelperRun", "run 1");
    store.remove_all();
    let again = CFPreferencesStore::new(&domain);
    assert_eq!(again.bool("autoCheckUpdates"), None);
    assert_eq!(again.string("noticedUpdateHelperRun"), None);
    again.remove_all();
}

#[test]
fn preferences_round_trip_in_a_throwaway_domain() {
    let domain = format!("local.macvpn.rust-test.{}", uuid::Uuid::new_v4());
    let store = CFPreferencesStore::new(&domain);
    assert_eq!(store.bool("autoCheckUpdates"), None);
    store.set_bool("autoCheckUpdates", false);
    store.set_bool("delayUpdates24h", true);
    let when = Date::from_time_interval_since_1970(1_800_000_123.5);
    store.set_date("lastUpdateCheck", when);
    store.set_string("noticedUpdateHelperRun", "run 1");
    let again = CFPreferencesStore::new(&domain);
    assert_eq!(again.bool("autoCheckUpdates"), Some(false));
    assert_eq!(again.bool("delayUpdates24h"), Some(true));
    assert_eq!(again.date("lastUpdateCheck"), Some(when));
    assert_eq!(again.string("noticedUpdateHelperRun").as_deref(), Some("run 1"));
    // Wrong types are not misread.
    assert_eq!(again.date("autoCheckUpdates"), None);
    assert_eq!(again.string("lastUpdateCheck"), None);
    // `defaults write … -string YES` style values still read as booleans (UserDefaults.bool semantics).
    again.set_string("autoCheckUpdates", "YES");
    assert_eq!(again.bool("autoCheckUpdates"), Some(true));
    for key in ["autoCheckUpdates", "delayUpdates24h", "lastUpdateCheck", "noticedUpdateHelperRun"] {
        again.remove(key);
        assert_eq!(again.string(key), None);
    }
    if let Some(home) = macvpn_platform_mac::system::home_directory() {
        let _ = std::fs::remove_file(home.join(format!("Library/Preferences/{domain}.plist")));
    }
}

#[test]
fn bundle_info_reads_the_update_source() {
    let dir = std::env::temp_dir().join(format!("macvpn-info-{}", uuid::Uuid::new_v4()));
    let bundle = dir.join("MacVPN.app");
    std::fs::create_dir_all(bundle.join("Contents")).unwrap();
    std::fs::write(
        bundle.join("Contents/Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>local.macvpn</string>
<key>MacVPNUpdateRepo</key><string>SepsiG/MacVPN</string>
<key>MacVPNUpdateRepoID</key><integer>1422472799</integer>
<key>LSUIElement</key><true/>
<key>CFBundleLocalizations</key><array><string>en</string></array>
</dict></plist>"#,
    )
    .unwrap();
    let info = bundle_info(&bundle).expect("info");
    assert_eq!(info.get("LSUIElement"), Some(&InfoValue::Boolean(true)));
    assert!(!info.contains_key("CFBundleLocalizations"));
    assert_eq!(UpdateChecker::source_from_info(Some(&info)), Some((1_422_472_799, "SepsiG/MacVPN".to_string())));
    assert_eq!(bundle_info(&dir.join("Missing.app")), None);
    std::fs::remove_dir_all(&dir).unwrap();
}
