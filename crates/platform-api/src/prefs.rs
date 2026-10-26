//! The app's persistent preferences.

use macvpn_core::date::Date;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Persistent preferences (the app's `UserDefaults`).
pub trait PreferenceStore: Send + Sync {
    fn bool(&self, key: &str) -> Option<bool>;
    fn set_bool(&self, key: &str, value: bool);
    fn date(&self, key: &str) -> Option<Date>;
    fn set_date(&self, key: &str, value: Date);
    fn string(&self, key: &str) -> Option<String>;
    fn set_string(&self, key: &str, value: &str);
    /// Every key of the app's domain (uninstall with the user data: the Swift `removePersistentDomain`).
    fn remove_all(&self);
}

/// An in-memory [`PreferenceStore`], gone at quit: tests, the development sandbox, runs without a bundle and
/// platforms that cannot store preferences yet. The one implementation every crate uses.
#[derive(Debug, Default)]
pub struct MemoryPreferences {
    values: Mutex<HashMap<String, PreferenceValue>>,
}

#[derive(Debug, Clone, PartialEq)]
enum PreferenceValue {
    Bool(bool),
    Date(Date),
    String(String),
}

impl MemoryPreferences {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &str) -> Option<PreferenceValue> {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).get(key).cloned()
    }

    fn put(&self, key: &str, value: PreferenceValue) {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).insert(key.to_string(), value);
    }
}

impl PreferenceStore for MemoryPreferences {
    fn bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            PreferenceValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn set_bool(&self, key: &str, value: bool) {
        self.put(key, PreferenceValue::Bool(value));
    }

    fn date(&self, key: &str) -> Option<Date> {
        match self.get(key)? {
            PreferenceValue::Date(d) => Some(d),
            _ => None,
        }
    }

    fn set_date(&self, key: &str, value: Date) {
        self.put(key, PreferenceValue::Date(value));
    }

    fn string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            PreferenceValue::String(s) => Some(s),
            _ => None,
        }
    }

    fn set_string(&self, key: &str, value: &str) {
        self.put(key, PreferenceValue::String(value.to_string()));
    }

    fn remove_all(&self) {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

/// The largest preference file [`FilePreferences`] reads (anything larger reads as empty).
const MAX_FILE: u64 = 1024 * 1024;

/// A [`PreferenceStore`] in one JSON file (WinVPN: `%LOCALAPPDATA%\WinVPN\preferences.json`), private (`fsx::Access::
/// Private`, written with `fsx::atomic_write`), read once and kept in memory. A missing or corrupt file reads as
/// empty and is replaced by the next write. Write errors are ignored like `CFPreferences`' (the value stays in
/// memory for this run). Format: `{"version":1,"values":{"key":{"bool":true}|{"string":"…"}|{"date":<seconds
/// since 1970>}}}`.
#[derive(Debug)]
pub struct FilePreferences {
    path: std::path::PathBuf,
    values: Mutex<Option<HashMap<String, PreferenceValue>>>,
}

impl FilePreferences {
    pub fn new(path: std::path::PathBuf) -> Self {
        FilePreferences { path, values: Mutex::new(None) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut HashMap<String, PreferenceValue>) -> T) -> T {
        let mut guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        let values = guard.get_or_insert_with(|| self.load());
        f(values)
    }

    fn load(&self) -> HashMap<String, PreferenceValue> {
        let Ok((mut file, meta)) = macvpn_core::fsx::open_regular(
            &self.path,
            macvpn_core::fsx::OpenFor::Read,
            macvpn_core::fsx::Follow::No,
            false,
        ) else {
            return HashMap::new();
        };
        if meta.len() > MAX_FILE {
            return HashMap::new();
        }
        // Bounded even if the file grows after the check.
        let mut data = Vec::new();
        if std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, MAX_FILE + 1), &mut data).is_err()
            || data.len() as u64 > MAX_FILE
        {
            return HashMap::new();
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) else { return HashMap::new() };
        let mut out = HashMap::new();
        if json.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return out;
        }
        for (key, value) in json.get("values").and_then(serde_json::Value::as_object).into_iter().flatten() {
            let parsed = if let Some(b) = value.get("bool").and_then(serde_json::Value::as_bool) {
                Some(PreferenceValue::Bool(b))
            } else if let Some(s) = value.get("string").and_then(serde_json::Value::as_str) {
                Some(PreferenceValue::String(s.to_string()))
            } else {
                value
                    .get("date")
                    .and_then(serde_json::Value::as_f64)
                    .map(|d| PreferenceValue::Date(Date::from_time_interval_since_1970(d)))
            };
            if let Some(v) = parsed {
                out.insert(key.clone(), v);
            }
        }
        out
    }

    fn save(&self, values: &HashMap<String, PreferenceValue>) {
        let mut map = serde_json::Map::new();
        let mut keys: Vec<&String> = values.keys().collect();
        keys.sort();
        for key in keys {
            let v = match &values[key] {
                PreferenceValue::Bool(b) => serde_json::json!({ "bool": b }),
                PreferenceValue::String(s) => serde_json::json!({ "string": s }),
                PreferenceValue::Date(d) => serde_json::json!({ "date": d.time_interval_since_1970() }),
            };
            map.insert(key.clone(), v);
        }
        let json = serde_json::json!({ "version": 1, "values": map });
        let Ok(bytes) = serde_json::to_vec_pretty(&json) else { return };
        if let Some(parent) = self.path.parent() {
            let _ = macvpn_core::fsx::create_missing_private_dirs(parent);
        }
        let _ = macvpn_core::fsx::atomic_write(&self.path, &bytes, macvpn_core::fsx::Access::Private);
    }

    fn put(&self, key: &str, value: PreferenceValue) {
        self.with(|values| {
            values.insert(key.to_string(), value);
            self.save(values);
        });
    }

    fn get(&self, key: &str) -> Option<PreferenceValue> {
        self.with(|values| values.get(key).cloned())
    }
}

impl PreferenceStore for FilePreferences {
    fn bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            PreferenceValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn set_bool(&self, key: &str, value: bool) {
        self.put(key, PreferenceValue::Bool(value));
    }

    fn date(&self, key: &str) -> Option<Date> {
        match self.get(key)? {
            PreferenceValue::Date(d) => Some(d),
            _ => None,
        }
    }

    fn set_date(&self, key: &str, value: Date) {
        self.put(key, PreferenceValue::Date(value));
    }

    fn string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            PreferenceValue::String(s) => Some(s),
            _ => None,
        }
    }

    fn set_string(&self, key: &str, value: &str) {
        self.put(key, PreferenceValue::String(value.to_string()));
    }

    fn remove_all(&self) {
        self.with(|values| {
            values.clear();
            self.save(values);
        });
    }
}
