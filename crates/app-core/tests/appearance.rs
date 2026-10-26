//! The Appearance setting: the preference and the view-model field.

use macvpn_app_core::appearance::{APPEARANCE_KEY, Appearance};
use macvpn_app_core::{ManagerSnapshot, ViewModel};
use macvpn_platform_api::{MemoryPreferences, PreferenceStore};

#[test]
fn the_preference_round_trips_and_defaults_to_system() {
    let prefs = MemoryPreferences::new();
    assert_eq!(Appearance::load(&prefs), Appearance::System);
    Appearance::Dark.store(&prefs);
    assert_eq!(prefs.string(APPEARANCE_KEY).as_deref(), Some("dark"));
    assert_eq!(Appearance::load(&prefs), Appearance::Dark);
    Appearance::Light.store(&prefs);
    assert_eq!(Appearance::load(&prefs), Appearance::Light);
    prefs.set_string(APPEARANCE_KEY, "purple");
    assert_eq!(Appearance::load(&prefs), Appearance::System);
}

#[test]
fn parsing_is_strict() {
    assert_eq!(Appearance::parse("light"), Some(Appearance::Light));
    assert_eq!(Appearance::parse("dark"), Some(Appearance::Dark));
    assert_eq!(Appearance::parse("system"), Some(Appearance::System));
    assert_eq!(Appearance::parse("Dark"), None);
    assert_eq!(Appearance::parse(""), None);
    for a in [Appearance::System, Appearance::Light, Appearance::Dark] {
        assert_eq!(Appearance::parse(a.raw_value()), Some(a));
    }
}

#[test]
fn the_view_model_field_is_absent_until_the_app_sets_it() {
    let mut vm = ViewModel::build(&ManagerSnapshot::default(), "en", |_| true, Vec::new(), true);
    let json = serde_json::to_value(&vm).unwrap();
    assert!(json.get("appearance").is_none());
    vm.appearance = Some(Appearance::Light.raw_value());
    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json.get("appearance").and_then(|v| v.as_str()), Some("light"));
}
