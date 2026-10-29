//! In-process `SCNetworkConnection` start/stop (the `SystemConfigurationDriver` of `NativeVPN.swift`).
//! `system-configuration-sys` has no `SCNetworkConnection` bindings, so the five functions are declared here.
//!
//! The `SCPreferences` notification functions of the system VPN watcher (`sc_watch`) and the `SCDynamicStore`
//! functions of the network change watcher (`net_watch`) are declared here too.
//!
//! The live traffic reads a connected service's `SCNetworkConnectionCopyStatistics` and
//! `SCNetworkConnectionCopyExtendedStatus` (user-level, as the user) and copies them out as a
//! [`crate::native_vpn::Plist`]; the dictionaries are owned (+1) and released when their wrapper drops.
//!
//! Audit notes: the connection object returned by `SCNetworkConnectionCreateWithServiceID` is owned (+1) and
//! released when the wrapper drops; no callout or context is registered (both null), so nothing calls back into
//! Rust. The options dictionary is built from owned Core Foundation objects and only borrowed for the call.
#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{Boolean, CFAllocatorRef, CFIndex, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::runloop::{CFRunLoopRef, CFRunLoopSourceRef};
use core_foundation_sys::string::CFStringRef;
use macvpn_core::native::NativeStartOptions;
use std::ffi::{CStr, c_char, c_int, c_void};

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCNetworkConnectionCreateWithServiceID(
        allocator: CFAllocatorRef,
        service_id: CFStringRef,
        callout: *const c_void,
        context: *mut c_void,
    ) -> CFTypeRef;
    fn SCNetworkConnectionStart(connection: CFTypeRef, user_options: CFDictionaryRef, linger: Boolean) -> Boolean;
    fn SCNetworkConnectionStop(connection: CFTypeRef, force_disconnect: Boolean) -> Boolean;
    fn SCNetworkConnectionCopyStatistics(connection: CFTypeRef) -> CFDictionaryRef;
    fn SCNetworkConnectionCopyExtendedStatus(connection: CFTypeRef) -> CFDictionaryRef;
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
    pub(crate) fn SCPreferencesCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        prefs_id: CFStringRef,
    ) -> SCPreferencesRef;
    pub(crate) fn SCPreferencesSetCallback(
        prefs: SCPreferencesRef,
        callout: Option<SCPreferencesCallBack>,
        context: *mut SCPreferencesContext,
    ) -> Boolean;
    pub(crate) fn SCPreferencesScheduleWithRunLoop(
        prefs: SCPreferencesRef,
        run_loop: CFRunLoopRef,
        mode: CFStringRef,
    ) -> Boolean;
    pub(crate) fn SCPreferencesUnscheduleFromRunLoop(
        prefs: SCPreferencesRef,
        run_loop: CFRunLoopRef,
        mode: CFStringRef,
    ) -> Boolean;
    pub(crate) fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callout: Option<SCDynamicStoreCallBack>,
        context: *mut SCDynamicStoreContext,
    ) -> SCDynamicStoreRef;
    pub(crate) fn SCDynamicStoreSetNotificationKeys(
        store: SCDynamicStoreRef,
        keys: CFArrayRef,
        patterns: CFArrayRef,
    ) -> Boolean;
    pub(crate) fn SCDynamicStoreCreateRunLoopSource(
        allocator: CFAllocatorRef,
        store: SCDynamicStoreRef,
        order: CFIndex,
    ) -> CFRunLoopSourceRef;
}

/// An `SCPreferencesRef` (a CF object: released with `CFRelease`).
pub(crate) type SCPreferencesRef = CFTypeRef;

/// `kSCPreferencesNotificationCommit`: new preferences were saved.
pub(crate) const PREFERENCES_NOTIFICATION_COMMIT: u32 = 1 << 0;
/// `kSCPreferencesNotificationApply`: the saved preferences are applied to the running system.
pub(crate) const PREFERENCES_NOTIFICATION_APPLY: u32 = 1 << 1;

/// `SCPreferencesCallBack(prefs, notificationType, info)`.
pub(crate) type SCPreferencesCallBack = extern "C" fn(prefs: SCPreferencesRef, notification: u32, info: *mut c_void);

/// `SCPreferencesContext` (version 0); `retain` / `release` / `copyDescription` are not used (null).
#[repr(C)]
pub(crate) struct SCPreferencesContext {
    pub version: CFIndex,
    pub info: *mut c_void,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copy_description: *const c_void,
}

/// An `SCDynamicStoreRef` (a CF object: released with `CFRelease`).
pub(crate) type SCDynamicStoreRef = CFTypeRef;

/// `SCDynamicStoreCallBack(store, changedKeys, info)`.
pub(crate) type SCDynamicStoreCallBack =
    extern "C" fn(store: SCDynamicStoreRef, changed: CFArrayRef, info: *mut c_void);

/// `SCDynamicStoreContext` (version 0); `retain` / `release` / `copyDescription` are not used (null).
#[repr(C)]
pub(crate) struct SCDynamicStoreContext {
    pub version: CFIndex,
    pub info: *mut c_void,
    pub retain: *const c_void,
    pub release: *const c_void,
    pub copy_description: *const c_void,
}

/// `"<SCErrorString> (<code>)"` of the last SystemConfiguration error.
pub fn last_error() -> String {
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
    format!("{text} ({code})")
}

/// An owned `SCNetworkConnectionRef`.
struct Connection(CFType);

fn connection(service_id: &str) -> Option<Connection> {
    let id = CFString::new(service_id);
    // SAFETY: a valid service ID string; null allocator (default), no callout and no context.
    let raw = unsafe {
        SCNetworkConnectionCreateWithServiceID(
            std::ptr::null(),
            id.as_concrete_TypeRef(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() {
        return None;
    }
    // SAFETY: a +1 object (create rule), released on drop.
    Some(Connection(unsafe { CFType::wrap_under_create_rule(raw) }))
}

fn options_dictionary(options: &NativeStartOptions) -> CFDictionary<CFString, CFType> {
    let pairs: Vec<(CFString, CFType)> = options
        .iter()
        .map(|(entity, properties)| {
            let inner: Vec<(CFString, CFString)> =
                properties.iter().map(|(k, v)| (CFString::new(k), CFString::new(v))).collect();
            (CFString::new(entity), CFDictionary::from_CFType_pairs(&inner).as_CFType())
        })
        .collect();
    CFDictionary::from_CFType_pairs(&pairs)
}

pub enum Failure {
    Open(String),
    Start(String),
    Stop(String),
}

pub fn start(service_id: &str, options: Option<&NativeStartOptions>, linger: bool) -> Result<(), Failure> {
    let conn = connection(service_id).ok_or_else(|| Failure::Open(last_error()))?;
    let dictionary = options.map(options_dictionary);
    let options_ref: CFDictionaryRef = dictionary.as_ref().map_or(std::ptr::null(), |d| d.as_concrete_TypeRef());
    // SAFETY: a valid connection; a valid dictionary or null; the call does not keep the dictionary past it
    // beyond its own retain.
    let ok = unsafe { SCNetworkConnectionStart(conn.0.as_CFTypeRef(), options_ref, Boolean::from(linger)) };
    if ok == 0 { Err(Failure::Start(last_error())) } else { Ok(()) }
}

pub fn stop(service_id: &str) -> Result<(), Failure> {
    let conn = connection(service_id).ok_or_else(|| Failure::Open(last_error()))?;
    // SAFETY: a valid connection.
    let ok = unsafe { SCNetworkConnectionStop(conn.0.as_CFTypeRef(), 1) };
    if ok == 0 { Err(Failure::Stop(last_error())) } else { Ok(()) }
}

/// How deep a copied dictionary is followed.
const PLIST_DEPTH: usize = 4;
/// The most entries copied per dictionary or array.
const PLIST_ITEMS: usize = 64;

/// A Core Foundation value copied out: dictionaries with string keys, arrays, integers and strings (the rest is
/// `Other`).
fn plist_of(value: &CFType, depth: usize) -> crate::native_vpn::Plist {
    use crate::native_vpn::Plist;
    use core_foundation::array::CFArray;
    use core_foundation::number::CFNumber;
    if let Some(n) = value.downcast::<CFNumber>() {
        return n.to_i64().map_or(Plist::Other, Plist::Num);
    }
    if let Some(s) = value.downcast::<CFString>() {
        return Plist::Str(s.to_string());
    }
    if depth == 0 {
        return Plist::Other;
    }
    if let Some(d) = value.downcast::<CFDictionary>() {
        let (keys, values) = d.get_keys_and_values();
        let mut out = Vec::new();
        for (k, v) in keys.into_iter().zip(values).take(PLIST_ITEMS) {
            if k.is_null() || v.is_null() {
                continue;
            }
            // SAFETY: the dictionary (alive here) holds both; a get-rule wrapper retains them for this scope.
            let (k, v) = unsafe { (CFType::wrap_under_get_rule(k), CFType::wrap_under_get_rule(v)) };
            if let Some(k) = k.downcast::<CFString>() {
                out.push((k.to_string(), plist_of(&v, depth - 1)));
            }
        }
        return Plist::Dict(out);
    }
    if let Some(a) = value.downcast::<CFArray>() {
        let items = a.get_all_values();
        let mut out = Vec::new();
        for item in items.into_iter().take(PLIST_ITEMS).filter(|i| !i.is_null()) {
            // SAFETY: as above, the array holds the value.
            let item = unsafe { CFType::wrap_under_get_rule(item) };
            out.push(plist_of(&item, depth - 1));
        }
        return Plist::Array(out);
    }
    Plist::Other
}

fn copied(
    service_id: &str,
    copy: unsafe extern "C" fn(CFTypeRef) -> CFDictionaryRef,
) -> Option<crate::native_vpn::Plist> {
    let conn = connection(service_id)?;
    // SAFETY: a valid connection; the call returns a +1 dictionary or null.
    let raw = unsafe { copy(conn.0.as_CFTypeRef()) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: a +1 object (copy rule), released on drop.
    let d = unsafe { CFType::wrap_under_create_rule(raw.cast()) };
    Some(plist_of(&d, PLIST_DEPTH))
}

/// `SCNetworkConnectionCopyStatistics` of the service (`None`: not available, e.g. not connected).
pub fn statistics(service_id: &str) -> Option<crate::native_vpn::Plist> {
    copied(service_id, SCNetworkConnectionCopyStatistics)
}

/// `SCNetworkConnectionCopyExtendedStatus` of the service.
pub fn extended_status(service_id: &str) -> Option<crate::native_vpn::Plist> {
    copied(service_id, SCNetworkConnectionCopyExtendedStatus)
}
