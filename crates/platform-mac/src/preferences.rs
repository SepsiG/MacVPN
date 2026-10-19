//! The app's `UserDefaults` through CFPreferences (domain `local.macvpn`, the current user, any host): the same
//! keys and value types the Swift app wrote (`autoCheckUpdates`, `delayUpdates24h`, `lastUpdateCheck`,
//! `noticedUpdateHelperRun`), so an updated app keeps the user's settings.
//!
//! Audit notes: `CFPreferencesCopyAppValue` returns a +1 object (create rule) or null; `CFPreferencesSetAppValue`
//! takes the key, an optional value and the application ID, all valid CF objects alive for the call and not
//! retained by us afterwards. Values are type-checked (`downcast`) before use.
#![allow(unsafe_code)]

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::date::CFDate;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::preferences::{
    CFPreferencesAppSynchronize, CFPreferencesCopyAppValue, CFPreferencesCopyKeyList, CFPreferencesSetAppValue,
    CFPreferencesSetMultiple, kCFPreferencesAnyHost, kCFPreferencesCurrentUser,
};
use macvpn_core::date::Date;

/// One preferences domain (an application ID).
pub struct CFPreferencesStore {
    app_id: CFString,
}

// SAFETY (Send/Sync): `CFString` is an immutable CF object; CFPreferences is thread-safe.
unsafe impl Send for CFPreferencesStore {}
// SAFETY: as above.
unsafe impl Sync for CFPreferencesStore {}

impl CFPreferencesStore {
    /// The app's domain (its bundle identifier).
    pub const APP_ID: &'static str = "local.macvpn";

    pub fn new(app_id: &str) -> Self {
        CFPreferencesStore { app_id: CFString::new(app_id) }
    }

    pub fn app() -> Self {
        Self::new(Self::APP_ID)
    }

    fn copy(&self, key: &str) -> Option<CFType> {
        let key = CFString::new(key);
        // SAFETY: two valid CFStrings; the result is +1 or null.
        let raw = unsafe { CFPreferencesCopyAppValue(key.as_concrete_TypeRef(), self.app_id.as_concrete_TypeRef()) };
        // SAFETY: non-null +1 object, released when the wrapper drops.
        (!raw.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(raw) })
    }

    fn set(&self, key: &str, value: Option<&CFType>) {
        let key = CFString::new(key);
        let value = value.map_or(std::ptr::null(), |v| v.as_CFTypeRef());
        // SAFETY: valid key and application ID; the value is a valid CF object or null (removes the key).
        unsafe {
            CFPreferencesSetAppValue(key.as_concrete_TypeRef(), value, self.app_id.as_concrete_TypeRef());
            CFPreferencesAppSynchronize(self.app_id.as_concrete_TypeRef());
        }
    }

    /// `UserDefaults.bool(forKey:)` semantics for a stored value: a boolean, a number (non-zero), or the strings
    /// `YES` / `true` / a non-zero integer. `None`: missing (the caller's registered default applies).
    pub fn bool(&self, key: &str) -> Option<bool> {
        let value = self.copy(key)?;
        if let Some(b) = value.downcast::<CFBoolean>() {
            return Some(b.into());
        }
        if let Some(n) = value.downcast::<CFNumber>() {
            return n.to_f64().map(|f| f != 0.0);
        }
        if let Some(s) = value.downcast::<CFString>() {
            let s = s.to_string().trim().to_lowercase();
            return Some(s == "yes" || s == "true" || s.parse::<i64>().is_ok_and(|n| n != 0));
        }
        None
    }

    pub fn set_bool(&self, key: &str, value: bool) {
        let b = if value { CFBoolean::true_value() } else { CFBoolean::false_value() };
        self.set(key, Some(&b.as_CFType()));
    }

    /// A stored `Date` (`CFDate`).
    pub fn date(&self, key: &str) -> Option<Date> {
        let date = self.copy(key)?.downcast::<CFDate>()?;
        Some(Date::from_time_interval_since_reference_date(date.abs_time()))
    }

    pub fn set_date(&self, key: &str, value: Date) {
        let date = CFDate::new(value.time_interval_since_reference_date());
        self.set(key, Some(&date.as_CFType()));
    }

    pub fn string(&self, key: &str) -> Option<String> {
        Some(self.copy(key)?.downcast::<CFString>()?.to_string())
    }

    pub fn set_string(&self, key: &str, value: &str) {
        self.set(key, Some(&CFString::new(value).as_CFType()));
    }

    pub fn remove(&self, key: &str) {
        self.set(key, None);
    }

    /// Every key of the domain for the current user (the Swift `removePersistentDomain(forName:)`).
    pub fn remove_all(&self) {
        // SAFETY: a valid application ID and the CF user / host constants; the result is +1 or null.
        let keys = unsafe {
            CFPreferencesCopyKeyList(
                self.app_id.as_concrete_TypeRef(),
                kCFPreferencesCurrentUser,
                kCFPreferencesAnyHost,
            )
        };
        if keys.is_null() {
            return;
        }
        // SAFETY: a non-null +1 CFArray, released when the wrapper drops.
        let keys: CFArray<CFType> = unsafe { CFArray::wrap_under_create_rule(keys) };
        // SAFETY: no values to set (null), the keys to remove, the same domain, user and host as read.
        unsafe {
            CFPreferencesSetMultiple(
                std::ptr::null(),
                keys.as_concrete_TypeRef(),
                self.app_id.as_concrete_TypeRef(),
                kCFPreferencesCurrentUser,
                kCFPreferencesAnyHost,
            );
            CFPreferencesAppSynchronize(self.app_id.as_concrete_TypeRef());
        }
    }
}
