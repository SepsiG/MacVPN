//! UI languages and the EN/HU text table (port of `L10n.swift` and the app's `Localizable.xcstrings`).
//!
//! The key is the English text (also the `en` value). Both Swift tables are merged into one JSON source,
//! `crates/core/l10n/strings.json`, embedded here and loaded by the UI too; the texts are verbatim copies.
//!
//! The key is the macOS wording. An entry may carry per-OS texts (`variants.<os>`, both `en` and `hu`) and the OSes
//! whose code paths show it (`only`). On an OS whose product is not MacVPN, `MacVPN` in the resolved text becomes
//! the product name, except in texts that another OS's code paths show (`only` without this OS). On macOS the
//! output is exactly the 1.4.0 text.

use crate::TargetOs;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, RwLock};

/// The two UI languages. English is the source language and the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppLanguage {
    En,
    Hu,
}

const NO_OVERRIDE: u8 = 0;
static GLOBAL_OVERRIDE: AtomicU8 = AtomicU8::new(NO_OVERRIDE);
static PREFERRED: RwLock<Vec<String>> = RwLock::new(Vec::new());

thread_local! {
    static THREAD_OVERRIDE: Cell<Option<AppLanguage>> = const { Cell::new(None) };
}

impl AppLanguage {
    pub const ALL: [AppLanguage; 2] = [AppLanguage::En, AppLanguage::Hu];

    pub fn raw_value(self) -> &'static str {
        match self {
            AppLanguage::En => "en",
            AppLanguage::Hu => "hu",
        }
    }

    /// The first preferred language that is Hungarian or English; anything else (or nothing) means English.
    /// This mirrors how Foundation picks between the app's `en` and `hu` localizations.
    pub fn resolve<S: AsRef<str>>(preferred: &[S]) -> AppLanguage {
        for language in preferred {
            let code = language.as_ref().to_lowercase();
            if code == "hu" || crate::swift_str::has_prefix(&code, "hu-") || crate::swift_str::has_prefix(&code, "hu_")
            {
                return AppLanguage::Hu;
            }
            if code == "en" || crate::swift_str::has_prefix(&code, "en-") || crate::swift_str::has_prefix(&code, "en_")
            {
                return AppLanguage::En;
            }
        }
        AppLanguage::En
    }

    /// `--lang` value: `hu` gives Hungarian, anything else English.
    pub fn from_argument(argument: &str) -> AppLanguage {
        if argument == "hu" { AppLanguage::Hu } else { AppLanguage::En }
    }

    /// Fixed language for processes that get it on the command line (`--lang`) — Swift `AppLanguage.override`.
    pub fn set_override(language: Option<AppLanguage>) {
        let raw = match language {
            None => NO_OVERRIDE,
            Some(AppLanguage::En) => 1,
            Some(AppLanguage::Hu) => 2,
        };
        GLOBAL_OVERRIDE.store(raw, Ordering::SeqCst);
    }

    pub fn global_override() -> Option<AppLanguage> {
        match GLOBAL_OVERRIDE.load(Ordering::SeqCst) {
            1 => Some(AppLanguage::En),
            2 => Some(AppLanguage::Hu),
            _ => None,
        }
    }

    /// Per-thread override, taking precedence over the global one. Rust tests run in parallel threads, so they
    /// use this (or [`with_language`]) where the Swift tests set `AppLanguage.override`.
    pub fn set_thread_override(language: Option<AppLanguage>) {
        THREAD_OVERRIDE.with(|c| c.set(language));
    }

    /// The system's preferred languages (Swift `Locale.preferredLanguages`), supplied by the platform layer.
    pub fn set_preferred_languages(languages: Vec<String>) {
        if let Ok(mut p) = PREFERRED.write() {
            *p = languages;
        }
    }

    /// Thread override, else global override, else the preferred languages.
    pub fn current() -> AppLanguage {
        if let Some(l) = THREAD_OVERRIDE.with(Cell::get) {
            return l;
        }
        if let Some(l) = Self::global_override() {
            return l;
        }
        match PREFERRED.read() {
            Ok(p) => Self::resolve(&p),
            Err(_) => AppLanguage::En,
        }
    }
}

/// Runs `f` with the thread's language fixed to `language` (restoring the previous thread override afterwards).
pub fn with_language<T>(language: AppLanguage, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<AppLanguage>);
    impl Drop for Restore {
        fn drop(&mut self) {
            AppLanguage::set_thread_override(self.0);
        }
    }
    let _restore = Restore(THREAD_OVERRIDE.with(Cell::get));
    AppLanguage::set_thread_override(Some(language));
    f()
}

/// A `String(format:)` argument.
#[derive(Debug, Clone)]
pub enum Arg<'a> {
    Str(&'a str),
    Int(i64),
}

impl<'a> From<&'a str> for Arg<'a> {
    fn from(s: &'a str) -> Self {
        Arg::Str(s)
    }
}

impl<'a> From<&'a String> for Arg<'a> {
    fn from(s: &'a String) -> Self {
        Arg::Str(s)
    }
}

impl From<i64> for Arg<'_> {
    fn from(n: i64) -> Self {
        Arg::Int(n)
    }
}

impl From<usize> for Arg<'_> {
    fn from(n: usize) -> Self {
        Arg::Int(n as i64)
    }
}

impl From<i32> for Arg<'_> {
    fn from(n: i32) -> Self {
        Arg::Int(i64::from(n))
    }
}

/// The product name of the 1.4.0 texts (the keys), replaced by [`TextPlatform::product`] on other products.
const BASE_PRODUCT: &str = "MacVPN";

/// The OS and product the texts are worded for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextPlatform {
    pub os: TargetOs,
    pub product: &'static str,
}

impl TextPlatform {
    pub const MACOS: TextPlatform = TextPlatform { os: TargetOs::MacOs, product: BASE_PRODUCT };
}

static TEXT_PLATFORM: RwLock<TextPlatform> = RwLock::new(TextPlatform::MACOS);

/// Sets the OS and product of every later translation; the platform layer calls it once at launch. The default
/// is [`TextPlatform::MACOS`].
pub fn set_text_platform(platform: TextPlatform) {
    if let Ok(mut p) = TEXT_PLATFORM.write() {
        *p = platform;
    }
}

pub fn text_platform() -> TextPlatform {
    TEXT_PLATFORM.read().map(|p| *p).unwrap_or(TextPlatform::MACOS)
}

/// Translation in the current language ([`AppLanguage::current`]).
pub fn tr(key: &str, args: &[Arg<'_>]) -> String {
    tr_in(AppLanguage::current(), key, args)
}

/// Translation in an explicit language (Swift `L10n.tr(_:_:language:)`).
pub fn tr_in(language: AppLanguage, key: &str, args: &[Arg<'_>]) -> String {
    tr_for(text_platform(), language, key, args)
}

/// Translation for an explicit OS and product: the OS's variant if the entry has one, else the base text; then
/// the product name (see the module comment). A missing key is its own English text.
pub fn tr_for(platform: TextPlatform, language: AppLanguage, key: &str, args: &[Arg<'_>]) -> String {
    let entry = TABLE.get(key);
    let variant = entry.and_then(|e| e.variants.get(&platform.os));
    let format = match (language, variant) {
        (AppLanguage::En, Some((en, _))) => en.as_str(),
        (AppLanguage::Hu, Some((_, hu))) => hu.as_str(),
        (AppLanguage::En, None) => key,
        (AppLanguage::Hu, None) => entry.map_or(key, |e| e.hu.as_str()),
    };
    let foreign = entry.is_some_and(|e| !e.only.is_empty() && !e.only.contains(&platform.os));
    let renamed;
    let format = if platform.product != BASE_PRODUCT && !foreign && format.contains(BASE_PRODUCT) {
        renamed = format.replace(BASE_PRODUCT, platform.product);
        renamed.as_str()
    } else {
        format
    };
    if args.is_empty() { format.to_string() } else { format_string(format, args) }
}

/// The `String(format:)` subset the table uses: `%@`, `%d`, `%ld`, `%lld` (also positional, `%1$@`) and `%%`.
fn format_string(format: &str, args: &[Arg<'_>]) -> String {
    let mut out = String::with_capacity(format.len() + 16);
    let mut next = 0usize;
    let b = format.as_bytes();
    let mut i = 0;
    let mut literal_start = 0;
    while i < b.len() {
        if b[i] != b'%' {
            i += 1;
            continue;
        }
        out.push_str(&format[literal_start..i]);
        let mut j = i + 1;
        if b.get(j) == Some(&b'%') {
            out.push('%');
            i = j + 1;
            literal_start = i;
            continue;
        }
        // Optional position `n$`.
        let mut k = j;
        while k < b.len() && b[k].is_ascii_digit() {
            k += 1;
        }
        let mut position = None;
        if k > j && b.get(k) == Some(&b'$') {
            position = format[j..k].parse::<usize>().ok().map(|n| n.saturating_sub(1));
            j = k + 1;
        }
        while b.get(j) == Some(&b'l') {
            j += 1;
        }
        match b.get(j) {
            Some(b'@') | Some(b'd') | Some(b'u') => {
                let index = position.unwrap_or_else(|| {
                    next += 1;
                    next - 1
                });
                match args.get(index) {
                    Some(Arg::Str(s)) => out.push_str(s),
                    Some(Arg::Int(n)) => out.push_str(&n.to_string()),
                    None => {}
                }
                i = j + 1;
            }
            _ => {
                out.push('%');
                i += 1;
            }
        }
        literal_start = i;
    }
    out.push_str(&format[literal_start..]);
    out
}

/// One entry of the text table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub hu: String,
    /// `core` (core and root messages) or `app` (UI texts).
    pub scope: String,
    /// The OSes whose code paths show this text (empty: every OS).
    pub only: Vec<TargetOs>,
    /// The text on an OS whose wording differs from the key's: (English, Hungarian).
    pub variants: BTreeMap<TargetOs, (String, String)>,
}

impl Entry {
    /// Whether the code paths of `os` show this text (`only` is empty or names `os`).
    pub fn shown_on(&self, os: TargetOs) -> bool {
        self.only.is_empty() || self.only.contains(&os)
    }
}

fn target_os(name: &str, key: &str) -> TargetOs {
    TargetOs::parse(name).unwrap_or_else(|| panic!("l10n/strings.json: unknown OS {name:?} in {key:?}"))
}

fn text(value: &serde_json::Value, field: &str, key: &str) -> String {
    match value.get(field).and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => panic!("l10n/strings.json: variant without {field:?} in {key:?}"),
    }
}

/// The single EN/HU source (`crates/core/l10n/strings.json`), embedded. The UI loads the same file.
pub const STRINGS_JSON: &str = include_str!("../l10n/strings.json");

static TABLE: LazyLock<HashMap<String, Entry>> = LazyLock::new(|| {
    let value: serde_json::Value = serde_json::from_str(STRINGS_JSON).expect("valid l10n/strings.json");
    let mut table = HashMap::new();
    if let Some(strings) = value.get("strings").and_then(|s| s.as_object()) {
        for (key, entry) in strings {
            let hu = entry.get("hu").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let scope = entry.get("scope").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let only = entry
                .get("only")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().map(|os| target_os(os.as_str().unwrap_or_default(), key)).collect())
                .unwrap_or_default();
            let variants = entry
                .get("variants")
                .and_then(|v| v.as_object())
                .map(|o| {
                    o.iter().map(|(os, v)| (target_os(os, key), (text(v, "en", key), text(v, "hu", key)))).collect()
                })
                .unwrap_or_default();
            table.insert(key.clone(), Entry { key: key.clone(), hu, scope, only, variants });
        }
    }
    table
});

/// The Hungarian translation of `key`, if the table has one.
pub fn hungarian(key: &str) -> Option<&'static str> {
    TABLE.get(key).map(|e| e.hu.as_str())
}

/// All entries of the table (for coverage tests and the UI).
pub fn table() -> Vec<&'static Entry> {
    let mut v: Vec<&Entry> = TABLE.values().collect();
    v.sort_by(|a, b| a.key.cmp(&b.key));
    v
}
