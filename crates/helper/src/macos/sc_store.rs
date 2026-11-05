//! The SystemConfiguration dynamic store the DNS manager writes (root layer 15): `SCDynamicStoreCopyValue`,
//! `SCDynamicStoreCopyKeyList` and `SCDynamicStoreSetMultiple` (one batch per change, so configd's IPMonitor
//! recomputes the resolver configuration once). The dynamic store is volatile: nothing written here survives a
//! reboot. Thin wrappers only; the DNS logic is in `dns` / `dns_plan`.
//!
//! Audit notes (as `sc_prefs`): the `SCDynamicStoreRef` and every value or key list returned by a `Create` / `Copy`
//! function is owned (+1) and wrapped under the create rule, so it is released exactly once when its wrapper drops.
//! Array elements and dictionary keys and values are wrapped under the get rule while their container is alive. No
//! callback is registered (`SCDynamicStoreCreate` gets no callout and no context), no pointer is kept past a call,
//! and every argument is a live, correctly typed Core Foundation object. Reading converts strictly: only strings,
//! integers, booleans, arrays and dictionaries (nested at most [`MAX_DEPTH`] deep) are represented; anything else
//! (data, dates, reals) is dropped from its container.
#![allow(unsafe_code)]

use crate::macos::dns_store::{Dict, Op, Value};
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{Boolean, CFAllocatorRef, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::number::{CFNumberIsFloatType, CFNumberRef};
use core_foundation_sys::string::CFStringRef;
use std::ffi::{CStr, c_char, c_int, c_void};

/// Values nested deeper than this are dropped (a DNS dictionary is two levels deep).
pub const MAX_DEPTH: usize = 8;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callout: *const c_void,
        context: *const c_void,
    ) -> CFTypeRef;
    fn SCDynamicStoreCopyValue(store: CFTypeRef, key: CFStringRef) -> CFTypeRef;
    fn SCDynamicStoreCopyKeyList(store: CFTypeRef, pattern: CFStringRef) -> CFArrayRef;
    fn SCDynamicStoreSetMultiple(
        store: CFTypeRef,
        keys_to_set: CFDictionaryRef,
        keys_to_remove: CFArrayRef,
        keys_to_notify: CFArrayRef,
    ) -> Boolean;
}

/// `"<SCErrorString> (<code>)"` of the last SystemConfiguration error, after `what`.
fn error(what: &str) -> String {
    // SAFETY: plain getters; SCErrorString returns a static C string (or null).
    let code = unsafe { SCError() };
    // SAFETY: as above.
    let p = unsafe { SCErrorString(code) };
    let text = if p.is_null() {
        String::new()
    } else {
        // SAFETY: non-null, NUL-terminated, static.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    };
    format!("{what}: {text} ({code})")
}

/// A +1 object (or null) wrapped under the create rule.
fn owned(raw: CFTypeRef) -> Option<CFType> {
    // SAFETY: `raw` is non-null and owned (+1) by the caller (create / copy rule); the wrapper releases it once.
    (!raw.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(raw) })
}

/// An `SCDynamicStoreRef` session (no notifications).
pub struct Session(CFType);

/// A session named `name` (configd shows it in its session list).
pub fn open(name: &str) -> Result<Session, String> {
    let name = CFString::new(name);
    // SAFETY: a valid CFString; default allocator; no callout and no context (no notification is requested).
    let raw = unsafe {
        SCDynamicStoreCreate(std::ptr::null(), name.as_concrete_TypeRef(), std::ptr::null(), std::ptr::null())
    };
    owned(raw).map(Session).ok_or_else(|| error("SCDynamicStoreCreate"))
}

impl Session {
    fn r(&self) -> CFTypeRef {
        self.0.as_CFTypeRef()
    }

    /// `SCDynamicStoreCopyValue`: the value of `key`, `None` when absent or not representable.
    pub fn get(&self, key: &str) -> Option<Value> {
        let key = CFString::new(key);
        // SAFETY: a live store and a valid CFString; the result is +1 (copy rule) or null.
        let v = owned(unsafe { SCDynamicStoreCopyValue(self.r(), key.as_concrete_TypeRef()) })?;
        from_cf(&v, 0)
    }

    /// `SCDynamicStoreCopyKeyList`: the keys matching the regular expression `pattern`.
    pub fn keys(&self, pattern: &str) -> Result<Vec<String>, String> {
        let pattern = CFString::new(pattern);
        // SAFETY: a live store and a valid CFString; the result is +1 (copy rule) or null.
        let raw = unsafe { SCDynamicStoreCopyKeyList(self.r(), pattern.as_concrete_TypeRef()) };
        if raw.is_null() {
            return Err(error("SCDynamicStoreCopyKeyList"));
        }
        // SAFETY: a +1 CFArray, released once by the wrapper.
        let arr: CFArray = unsafe { CFArray::wrap_under_create_rule(raw) };
        Ok(arr
            .get_all_values()
            .into_iter()
            // SAFETY: the elements are live CF objects owned by the array, retained by each wrapper.
            .filter_map(|p| unsafe { CFType::wrap_under_get_rule(p) }.downcast::<CFString>().map(|s| s.to_string()))
            .collect())
    }

    /// `SCDynamicStoreSetMultiple`: every set and remove of `ops` in one call.
    pub fn apply(&self, ops: &[Op]) -> Result<(), String> {
        let mut set: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
        let mut remove: Vec<CFString> = Vec::new();
        for op in ops {
            match op {
                Op::Set(k, d) => set.set(CFString::new(k), dict_to_cf(d).as_CFType()),
                Op::Remove(k) => remove.push(CFString::new(k)),
            }
        }
        let remove = CFArray::from_CFTypes(&remove);
        // SAFETY: a live store, a live dictionary and a live array, only borrowed for the call; no notify keys.
        let ok = unsafe {
            SCDynamicStoreSetMultiple(
                self.r(),
                set.as_concrete_TypeRef(),
                remove.as_concrete_TypeRef(),
                std::ptr::null(),
            )
        };
        if ok == 0 { Err(error("SCDynamicStoreSetMultiple")) } else { Ok(()) }
    }
}

/// A value as a Core Foundation property list.
pub fn to_cf(v: &Value) -> CFType {
    match v {
        Value::Str(s) => CFString::new(s).as_CFType(),
        Value::Int(i) => CFNumber::from(*i).as_CFType(),
        Value::Bool(b) => CFBoolean::from(*b).as_CFType(),
        Value::Array(a) => {
            let items: Vec<CFType> = a.iter().map(to_cf).collect();
            CFArray::from_CFTypes(&items).as_CFType()
        }
        Value::Dict(d) => dict_to_cf(d).as_CFType(),
    }
}

fn dict_to_cf(d: &Dict) -> CFDictionary<CFString, CFType> {
    let pairs: Vec<(CFString, CFType)> = d.iter().map(|(k, v)| (CFString::new(k), to_cf(v))).collect();
    CFDictionary::from_CFType_pairs(&pairs)
}

/// A Core Foundation property list as a value; `None` for anything not represented (see the module notes).
pub fn from_cf(v: &CFType, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    if let Some(s) = v.downcast::<CFString>() {
        return Some(Value::Str(s.to_string()));
    }
    if let Some(b) = v.downcast::<CFBoolean>() {
        return Some(Value::Bool(b.into()));
    }
    if let Some(n) = v.downcast::<CFNumber>() {
        let raw: CFNumberRef = n.as_concrete_TypeRef();
        // SAFETY: a live CFNumber.
        if unsafe { CFNumberIsFloatType(raw) } != 0 {
            return None;
        }
        return n.to_i64().map(Value::Int);
    }
    if let Some(a) = v.downcast::<CFArray>() {
        let items = a
            .get_all_values()
            .into_iter()
            // SAFETY: the elements are live CF objects owned by the array, retained by each wrapper.
            .filter_map(|p| from_cf(&unsafe { CFType::wrap_under_get_rule(p) }, depth + 1))
            .collect();
        return Some(Value::Array(items));
    }
    if let Some(d) = v.downcast::<CFDictionary>() {
        let (keys, values) = d.get_keys_and_values();
        let mut out = Dict::new();
        for (k, val) in keys.into_iter().zip(values) {
            // SAFETY: the keys and values are live CF objects owned by the dictionary, retained by each wrapper.
            let (k, val) = unsafe { (CFType::wrap_under_get_rule(k), CFType::wrap_under_get_rule(val)) };
            if let (Some(k), Some(val)) = (k.downcast::<CFString>(), from_cf(&val, depth + 1)) {
                out.insert(k.to_string(), val);
            }
        }
        return Some(Value::Dict(out));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_cf_round_trip() {
        let mut inner = Dict::new();
        inner.insert("ServerAddresses".into(), Value::Array(vec![Value::Str("10.8.0.1".into())]));
        inner.insert("SearchOrder".into(), Value::Int(100));
        inner.insert("Flag".into(), Value::Bool(true));
        inner.insert("Nested".into(), Value::Dict(Dict::from([("x".to_string(), Value::Int(-1))])));
        let v = Value::Dict(inner);
        assert_eq!(from_cf(&to_cf(&v), 0), Some(v));
        // Reals and too-deep values are not represented.
        assert_eq!(from_cf(&CFNumber::from(1.5f64).as_CFType(), 0), None);
        let mut deep = Value::Int(1);
        for _ in 0..=MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        let Some(Value::Array(a)) = from_cf(&to_cf(&deep), 0) else { panic!("an array") };
        assert_eq!(a.len(), 1);
        let mut v = &a[0];
        let mut levels = 1;
        while let Value::Array(x) = v {
            if x.is_empty() {
                break;
            }
            v = &x[0];
            levels += 1;
        }
        assert!(levels <= MAX_DEPTH + 1, "the innermost levels are dropped");
    }

    /// Read-only: the live store's primary service and its DNS. Writing to the real store is tested only live.
    #[test]
    #[ignore = "reads the live dynamic store: cargo test -p macvpn-helper sc_store -- --ignored"]
    fn reads_this_macs_primary_dns() {
        let s = open("mvpn-test").expect("a session");
        let global = s.get("State:/Network/Global/IPv4");
        let primary = global.as_ref().and_then(Value::as_dict).and_then(|d| d.get("PrimaryService")).cloned();
        if let Some(Value::Str(sid)) = primary {
            let dns = s.get(&format!("State:/Network/Service/{sid}/DNS"));
            assert!(dns.is_none() || dns.as_ref().and_then(Value::as_dict).is_some());
        }
        let keys = s.keys("^State:/Network/Service/[^/]+/DNS$").expect("a key list");
        assert!(keys.iter().all(|k| k.starts_with("State:/Network/Service/")));
    }
}
