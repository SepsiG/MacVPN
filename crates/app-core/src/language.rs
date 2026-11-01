//! The Language setting: follow the system's languages (the default, exactly the rule before the setting), or use
//! English or Hungarian for the whole app. The choice lives in the app's preferences and in the core's language
//! layer ([`AppLanguage::set_choice`]), which every text built afterwards reads: the windows (through the view
//! model's `language`), the tray, the app menu, notifications, native dialogs and the root helper's `--lang`.

use macvpn_core::l10n::AppLanguage;
use macvpn_platform_api::PreferenceStore;

/// The preference key: `system` / `en` / `hu` (anything else or missing = `system`).
pub const LANGUAGE_KEY: &str = "language";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LanguageSetting {
    #[default]
    System,
    English,
    Hungarian,
}

impl LanguageSetting {
    pub const ALL: [LanguageSetting; 3] =
        [LanguageSetting::System, LanguageSetting::English, LanguageSetting::Hungarian];

    /// The stored or UI value; strict (lower case only).
    pub fn parse(raw: &str) -> Option<LanguageSetting> {
        match raw {
            "system" => Some(LanguageSetting::System),
            "en" => Some(LanguageSetting::English),
            "hu" => Some(LanguageSetting::Hungarian),
            _ => None,
        }
    }

    pub fn raw_value(self) -> &'static str {
        match self {
            LanguageSetting::System => "system",
            LanguageSetting::English => "en",
            LanguageSetting::Hungarian => "hu",
        }
    }

    /// The fixed language of the setting; `None`: the system's.
    pub fn language(self) -> Option<AppLanguage> {
        match self {
            LanguageSetting::System => None,
            LanguageSetting::English => Some(AppLanguage::En),
            LanguageSetting::Hungarian => Some(AppLanguage::Hu),
        }
    }

    /// The language the setting gives with the system's language `system`.
    pub fn resolve(self, system: AppLanguage) -> AppLanguage {
        self.language().unwrap_or(system)
    }

    pub fn load(prefs: &dyn PreferenceStore) -> LanguageSetting {
        prefs.string(LANGUAGE_KEY).and_then(|s| LanguageSetting::parse(&s)).unwrap_or_default()
    }

    pub fn store(self, prefs: &dyn PreferenceStore) {
        prefs.set_string(LANGUAGE_KEY, self.raw_value());
    }

    /// Makes the setting the process' language (every text built afterwards).
    pub fn apply(self) {
        AppLanguage::set_choice(self.language());
    }

    /// At launch, before any window or tray text is built: the stored setting, applied.
    pub fn restore(prefs: &dyn PreferenceStore) -> LanguageSetting {
        let setting = LanguageSetting::load(prefs);
        setting.apply();
        setting
    }

    /// The user's switch: stored and applied at once. Then `refresh` runs with the new language (the app republishes
    /// its view model and re-labels what it built before); `true` when the language changed.
    pub fn switch(self, prefs: &dyn PreferenceStore, refresh: impl FnOnce(AppLanguage)) -> bool {
        let before = AppLanguage::current();
        self.store(prefs);
        self.apply();
        let now = AppLanguage::current();
        refresh(now);
        now != before
    }
}
