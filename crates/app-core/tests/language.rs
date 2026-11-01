//! The Language setting: the preference, its resolution and the switch (the core's process-wide language: this
//! binary's tests take turns).

use macvpn_app_core::language::{LANGUAGE_KEY, LanguageSetting};
use macvpn_app_core::{ManagerSnapshot, ViewModel};
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_platform_api::{MemoryPreferences, PreferenceStore};
use std::sync::{Mutex, MutexGuard, PoisonError};

static TURN: Mutex<()> = Mutex::new(());

fn turn() -> MutexGuard<'static, ()> {
    let guard = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    AppLanguage::set_choice(None);
    guard
}

#[test]
fn the_preference_defaults_to_system_and_round_trips() {
    let _turn = turn();
    let prefs = MemoryPreferences::new();
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::System);
    assert_eq!(LanguageSetting::default(), LanguageSetting::System);
    LanguageSetting::Hungarian.store(&prefs);
    assert_eq!(prefs.string(LANGUAGE_KEY).as_deref(), Some("hu"));
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::Hungarian);
    LanguageSetting::English.store(&prefs);
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::English);
    LanguageSetting::System.store(&prefs);
    assert_eq!(prefs.string(LANGUAGE_KEY).as_deref(), Some("system"));
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::System);
    // An unknown stored value is System.
    prefs.set_string(LANGUAGE_KEY, "de");
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::System);
}

#[test]
fn parsing_is_strict() {
    for s in LanguageSetting::ALL {
        assert_eq!(LanguageSetting::parse(s.raw_value()), Some(s));
    }
    for bad in ["", "HU", "English", "hu-HU", "System"] {
        assert_eq!(LanguageSetting::parse(bad), None, "{bad}");
    }
}

#[test]
fn system_follows_the_os_and_an_explicit_choice_wins() {
    for system in AppLanguage::ALL {
        assert_eq!(LanguageSetting::System.resolve(system), system);
        assert_eq!(LanguageSetting::English.resolve(system), AppLanguage::En);
        assert_eq!(LanguageSetting::Hungarian.resolve(system), AppLanguage::Hu);
    }
}

#[test]
fn restored_at_launch_from_the_stored_preference() {
    let _turn = turn();
    AppLanguage::set_preferred_languages(vec!["en-US".into()]);
    let prefs = MemoryPreferences::new();
    // Nothing stored (a fresh install, the smoke sandbox): the system's language, exactly as before.
    assert_eq!(LanguageSetting::restore(&prefs), LanguageSetting::System);
    assert_eq!(AppLanguage::current(), AppLanguage::En);
    LanguageSetting::Hungarian.store(&prefs);
    assert_eq!(LanguageSetting::restore(&prefs), LanguageSetting::Hungarian);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    AppLanguage::set_choice(None);
}

#[test]
fn switching_changes_the_language_at_once_and_refreshes() {
    let _turn = turn();
    AppLanguage::set_preferred_languages(vec!["en-GB".into()]);
    let prefs = MemoryPreferences::new();
    LanguageSetting::restore(&prefs);

    let mut refreshed = None;
    assert!(LanguageSetting::Hungarian.switch(&prefs, |l| refreshed = Some(l)));
    assert_eq!(refreshed, Some(AppLanguage::Hu));
    assert_eq!(LanguageSetting::load(&prefs), LanguageSetting::Hungarian);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    assert_eq!(l10n::tr("Quit MacVPN", &[]), "Kilépés");
    // The view model built afterwards is in the new language.
    let vm =
        ViewModel::build(&ManagerSnapshot::default(), AppLanguage::current().raw_value(), |_| true, Vec::new(), true);
    assert_eq!(serde_json::to_value(&vm).unwrap()["language"], "hu");

    // The same language again: still refreshed (the setting's field changed), the language did not.
    let mut again = false;
    assert!(!LanguageSetting::Hungarian.switch(&prefs, |_| again = true));
    assert!(again);

    // English while the system is English: the language changes back; System then keeps English.
    assert!(LanguageSetting::English.switch(&prefs, |_| {}));
    assert_eq!(AppLanguage::current(), AppLanguage::En);
    assert!(!LanguageSetting::System.switch(&prefs, |_| {}));
    assert_eq!(AppLanguage::choice(), None);

    // System on a Hungarian system: Hungarian; English overrides it.
    AppLanguage::set_preferred_languages(vec!["hu-HU".into()]);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    assert!(LanguageSetting::English.switch(&prefs, |_| {}));
    assert_eq!(AppLanguage::current(), AppLanguage::En);
    AppLanguage::set_choice(None);
}

#[test]
fn the_view_model_field_is_absent_until_the_app_sets_it() {
    let mut vm = ViewModel::build(&ManagerSnapshot::default(), "en", |_| true, Vec::new(), true);
    let json = serde_json::to_value(&vm).unwrap();
    assert!(json.get("languageSetting").is_none());
    vm.language_setting = Some(LanguageSetting::Hungarian.raw_value());
    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json.get("languageSetting").and_then(|v| v.as_str()), Some("hu"));
}
