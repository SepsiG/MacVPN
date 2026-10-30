//! The user's preferred languages from the environment, in gettext's order: `LANGUAGE` (a colon list; ignored when
//! the locale is `C`/`POSIX`), then the first set of `LC_ALL`, `LC_MESSAGES`, `LANG`. `hu_HU.UTF-8@euro` becomes
//! `hu-HU` (the BCP 47 form `AppLanguage::resolve` reads).

fn tag(locale: &str) -> Option<String> {
    let base = locale.split(['.', '@']).next().unwrap_or("");
    if base.is_empty() || base == "C" || base == "POSIX" {
        return None;
    }
    Some(base.replace('_', "-"))
}

/// The preferred languages, most preferred first; empty when the locale is `C`/`POSIX` or unset.
pub fn preferred_languages(var: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let set = |k: &str| var(k).filter(|v| !v.is_empty());
    let locale = set("LC_ALL").or_else(|| set("LC_MESSAGES")).or_else(|| set("LANG"));
    let Some(primary) = locale.as_deref().and_then(tag) else {
        return Vec::new();
    };
    if let Some(list) = set("LANGUAGE") {
        let tags: Vec<String> = list.split(':').filter_map(tag).collect();
        if !tags.is_empty() {
            return tags;
        }
    }
    vec![primary]
}
