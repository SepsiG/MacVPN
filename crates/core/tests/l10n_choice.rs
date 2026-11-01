//! The Language setting's layer of [`AppLanguage::current`] (process-wide state: its own test binary, one test).

use macvpn_core::l10n::{self, AppLanguage, with_language};

#[test]
fn the_choice_wins_over_the_system_and_loses_to_the_overrides() {
    // System (no choice): the preferred languages decide, as before.
    AppLanguage::set_preferred_languages(vec!["hu-HU".into(), "en-US".into()]);
    assert_eq!(AppLanguage::choice(), None);
    assert_eq!(AppLanguage::system(), AppLanguage::Hu);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    AppLanguage::set_preferred_languages(vec!["de-DE".into()]);
    assert_eq!(AppLanguage::current(), AppLanguage::En);

    // An explicit choice wins over the system, both ways; texts built afterwards follow it.
    AppLanguage::set_choice(Some(AppLanguage::Hu));
    assert_eq!(AppLanguage::choice(), Some(AppLanguage::Hu));
    assert_eq!(AppLanguage::system(), AppLanguage::En);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    assert_eq!(l10n::tr("Missing remote directive", &[]), "Hiányzik a remote direktíva");
    AppLanguage::set_preferred_languages(vec!["hu".into()]);
    AppLanguage::set_choice(Some(AppLanguage::En));
    assert_eq!(AppLanguage::current(), AppLanguage::En);
    assert_eq!(l10n::tr("Missing remote directive", &[]), "Missing remote directive");

    // A thread override (tests) and the process' `--lang` (the root helper) still win.
    with_language(AppLanguage::Hu, || assert_eq!(AppLanguage::current(), AppLanguage::Hu));
    AppLanguage::set_override(Some(AppLanguage::Hu));
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
    AppLanguage::set_override(None);
    assert_eq!(AppLanguage::current(), AppLanguage::En);

    // Back to System: the preferred languages again.
    AppLanguage::set_choice(None);
    assert_eq!(AppLanguage::current(), AppLanguage::Hu);
}
