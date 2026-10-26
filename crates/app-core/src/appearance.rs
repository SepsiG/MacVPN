//! The Appearance setting: follow the system, or force light or dark for every window of the app.

use macvpn_platform_api::PreferenceStore;

/// The preference key: `system` / `light` / `dark` (anything else or missing = `system`).
pub const APPEARANCE_KEY: &str = "appearance";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Appearance {
    #[default]
    System,
    Light,
    Dark,
}

impl Appearance {
    /// The stored or UI value; strict (lower case only).
    pub fn parse(raw: &str) -> Option<Appearance> {
        match raw {
            "system" => Some(Appearance::System),
            "light" => Some(Appearance::Light),
            "dark" => Some(Appearance::Dark),
            _ => None,
        }
    }

    pub fn raw_value(self) -> &'static str {
        match self {
            Appearance::System => "system",
            Appearance::Light => "light",
            Appearance::Dark => "dark",
        }
    }

    pub fn load(prefs: &dyn PreferenceStore) -> Appearance {
        prefs.string(APPEARANCE_KEY).and_then(|s| Appearance::parse(&s)).unwrap_or_default()
    }

    pub fn store(self, prefs: &dyn PreferenceStore) {
        prefs.set_string(APPEARANCE_KEY, self.raw_value());
    }
}
