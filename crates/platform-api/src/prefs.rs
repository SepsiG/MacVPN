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
