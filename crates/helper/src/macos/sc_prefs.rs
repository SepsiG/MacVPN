//! The SystemConfiguration preferences the DNS manager changes (root layer 14): what `networksetup
//! -setdnsservers` / `-setsearchdomains` / `-getdnsservers` / `-getsearchdomains` do internally, without a process
//! per call. Thin wrappers only; the DNS logic is in `dns_sc`.
//!
//! Audit notes: every `SCPreferencesRef`, `SCNetworkSetRef`, `SCNetworkServiceRef`, `SCNetworkProtocolRef` and
//! array returned by a `Create` / `Copy` function is owned (+1) and wrapped under the create rule, so it is released
//! exactly once when its wrapper drops. `SCNetworkServiceGetName` and `SCNetworkProtocolGetConfiguration` follow the
//! get rule: their result is retained (wrapped under the get rule) before use. Array elements are wrapped under the
//! get rule while the array is alive. No callback is registered, no pointer is kept past a call, and every
//! argument is a live, correctly typed Core Foundation object. A locked `Prefs` is unlocked when it drops.
#![allow(unsafe_code)]

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{Boolean, CFAllocatorRef, CFGetTypeID, CFTypeRef};
use core_foundation_sys::dictionary::{CFDictionaryGetTypeID, CFDictionaryRef};
use core_foundation_sys::string::CFStringRef;
use std::cell::Cell;
use std::ffi::{CStr, c_char, c_int};
use std::path::Path;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static kSCNetworkProtocolTypeDNS: CFStringRef;
    static kSCPropNetDNSServerAddresses: CFStringRef;
    static kSCPropNetDNSSearchDomains: CFStringRef;
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
    fn SCPreferencesCreate(allocator: CFAllocatorRef, name: CFStringRef, prefs_id: CFStringRef) -> CFTypeRef;
    fn SCPreferencesLock(prefs: CFTypeRef, wait: Boolean) -> Boolean;
    fn SCPreferencesUnlock(prefs: CFTypeRef) -> Boolean;
    fn SCPreferencesCommitChanges(prefs: CFTypeRef) -> Boolean;
    fn SCPreferencesApplyChanges(prefs: CFTypeRef) -> Boolean;
    fn SCNetworkSetCopyCurrent(prefs: CFTypeRef) -> CFTypeRef;
    fn SCNetworkSetCopyServices(set: CFTypeRef) -> CFArrayRef;
    fn SCNetworkServiceGetName(service: CFTypeRef) -> CFStringRef;
    fn SCNetworkServiceGetEnabled(service: CFTypeRef) -> Boolean;
    fn SCNetworkServiceCopyProtocol(service: CFTypeRef, protocol_type: CFStringRef) -> CFTypeRef;
    fn SCNetworkProtocolGetEnabled(protocol: CFTypeRef) -> Boolean;
    fn SCNetworkProtocolGetConfiguration(protocol: CFTypeRef) -> CFDictionaryRef;
    fn SCNetworkProtocolSetConfiguration(protocol: CFTypeRef, config: CFDictionaryRef) -> Boolean;
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

/// `ServerAddresses` (`kSCPropNetDNSServerAddresses`).
pub fn key_servers() -> CFString {
    // SAFETY: a constant CFString of the framework, retained by the wrapper.
    unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) }
}

/// `SearchDomains` (`kSCPropNetDNSSearchDomains`).
pub fn key_domains() -> CFString {
    // SAFETY: as above.
    unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchDomains) }
}

/// An `SCPreferencesRef` session.
pub struct Prefs {
    raw: CFType,
    locked: Cell<bool>,
}

/// A session on the system's preferences (`prefs_id` `None`) or on a private preferences file (the tests).
pub fn open(name: &str, prefs_id: Option<&Path>) -> Result<Prefs, String> {
    let name = CFString::new(name);
    let id = prefs_id.map(|p| CFString::new(&p.to_string_lossy()));
    let id_ref = id.as_ref().map_or(std::ptr::null(), |s| s.as_concrete_TypeRef());
    // SAFETY: valid CFStrings (or null for the default preferences); default allocator.
    let raw = unsafe { SCPreferencesCreate(std::ptr::null(), name.as_concrete_TypeRef(), id_ref) };
    let raw = owned(raw).ok_or_else(|| error("SCPreferencesCreate"))?;
    Ok(Prefs { raw, locked: Cell::new(false) })
}

impl Prefs {
    fn r(&self) -> CFTypeRef {
        self.raw.as_CFTypeRef()
    }

    /// `SCPreferencesLock(prefs, true)`: waits for another writer.
    pub fn lock(&self) -> Result<(), String> {
        // SAFETY: a live SCPreferencesRef.
        if unsafe { SCPreferencesLock(self.r(), 1) } == 0 {
            return Err(error("SCPreferencesLock"));
        }
        self.locked.set(true);
        Ok(())
    }

    pub fn commit(&self) -> Result<(), String> {
        // SAFETY: a live SCPreferencesRef.
        if unsafe { SCPreferencesCommitChanges(self.r()) } == 0 {
            return Err(error("SCPreferencesCommitChanges"));
        }
        Ok(())
    }

    pub fn apply(&self) -> Result<(), String> {
        // SAFETY: a live SCPreferencesRef.
        if unsafe { SCPreferencesApplyChanges(self.r()) } == 0 {
            return Err(error("SCPreferencesApplyChanges"));
        }
        Ok(())
    }

    pub fn unlock(&self) {
        if self.locked.replace(false) {
            // SAFETY: a live SCPreferencesRef this session locked.
            unsafe { SCPreferencesUnlock(self.r()) };
        }
    }

    /// The services of the current set (what `networksetup -listallnetworkservices` lists).
    pub fn current_services(&self) -> Result<Vec<Service>, String> {
        // SAFETY: a live SCPreferencesRef; the result is +1 (copy rule).
        let set =
            owned(unsafe { SCNetworkSetCopyCurrent(self.r()) }).ok_or_else(|| error("SCNetworkSetCopyCurrent"))?;
        // SAFETY: a live SCNetworkSetRef; the result is +1 (copy rule).
        let raw = unsafe { SCNetworkSetCopyServices(set.as_CFTypeRef()) };
        if raw.is_null() {
            return Err(error("SCNetworkSetCopyServices"));
        }
        // SAFETY: a +1 CFArray, released once by the wrapper.
        let arr: CFArray = unsafe { CFArray::wrap_under_create_rule(raw) };
        // SAFETY: the elements are SCNetworkServiceRefs owned by the live array; each is retained by its wrapper.
        Ok(arr.get_all_values().into_iter().map(|p| Service(unsafe { CFType::wrap_under_get_rule(p) })).collect())
    }
}

impl Drop for Prefs {
    fn drop(&mut self) {
        self.unlock();
    }
}

/// An `SCNetworkServiceRef`.
pub struct Service(CFType);

impl Service {
    /// `SCNetworkServiceGetName`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: a live SCNetworkServiceRef; the result follows the get rule (or is null).
        let raw = unsafe { SCNetworkServiceGetName(self.0.as_CFTypeRef()) };
        // SAFETY: a non-null CFString, retained by the wrapper.
        (!raw.is_null()).then(|| unsafe { CFString::wrap_under_get_rule(raw) }.to_string())
    }

    pub fn enabled(&self) -> bool {
        // SAFETY: a live SCNetworkServiceRef.
        unsafe { SCNetworkServiceGetEnabled(self.0.as_CFTypeRef()) != 0 }
    }

    /// The service's DNS protocol entity; `None` if it has none.
    pub fn dns(&self) -> Option<Protocol> {
        // SAFETY: a live SCNetworkServiceRef and the framework's constant; the result is +1 (copy rule) or null.
        owned(unsafe { SCNetworkServiceCopyProtocol(self.0.as_CFTypeRef(), kSCNetworkProtocolTypeDNS) }).map(Protocol)
    }
}

/// An `SCNetworkProtocolRef`.
pub struct Protocol(CFType);

impl Protocol {
    pub fn enabled(&self) -> bool {
        // SAFETY: a live SCNetworkProtocolRef.
        unsafe { SCNetworkProtocolGetEnabled(self.0.as_CFTypeRef()) != 0 }
    }

    /// The configuration dictionary; `Ok(None)`: none set; `Err`: not a dictionary.
    pub fn configuration(&self) -> Result<Option<CFDictionary<CFString, CFType>>, ()> {
        // SAFETY: a live SCNetworkProtocolRef; the result follows the get rule (or is null).
        let raw = unsafe { SCNetworkProtocolGetConfiguration(self.0.as_CFTypeRef()) };
        if raw.is_null() {
            return Ok(None);
        }
        // SAFETY: a live CF object (type check only).
        if unsafe { CFGetTypeID(raw.cast()) != CFDictionaryGetTypeID() } {
            return Err(());
        }
        // SAFETY: a live CFDictionary, retained by the wrapper; its keys and values are only read as CFTypes and
        // checked before any further use (`string_list`).
        Ok(Some(unsafe { CFDictionary::wrap_under_get_rule(raw) }))
    }

    pub fn set_configuration(&self, config: &CFDictionary<CFString, CFType>) -> Result<(), String> {
        // SAFETY: a live SCNetworkProtocolRef and a live dictionary, only borrowed for the call.
        if unsafe { SCNetworkProtocolSetConfiguration(self.0.as_CFTypeRef(), config.as_concrete_TypeRef()) } == 0 {
            return Err(error("SCNetworkProtocolSetConfiguration"));
        }
        Ok(())
    }
}

/// A CFArray of CFStrings as strings; `None` if `v` is not an array or holds anything but strings.
pub fn string_list(v: &CFType) -> Option<Vec<String>> {
    let arr = v.downcast::<CFArray>()?;
    arr.get_all_values()
        .into_iter()
        // SAFETY: the elements are live CF objects owned by the array, retained by each wrapper.
        .map(|p| unsafe { CFType::wrap_under_get_rule(p) }.downcast::<CFString>().map(|s| s.to_string()))
        .collect()
}

/// A CFArray of CFStrings.
pub fn cf_strings(v: &[String]) -> CFType {
    let items: Vec<CFString> = v.iter().map(|s| CFString::new(s)).collect();
    CFArray::from_CFTypes(&items).as_CFType()
}
