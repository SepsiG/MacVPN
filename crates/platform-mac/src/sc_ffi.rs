//! In-process `SCNetworkConnection` start/stop (the `SystemConfigurationDriver` of `NativeVPN.swift`).
//! `system-configuration-sys` has no `SCNetworkConnection` bindings, so the five functions are declared here.
//!
//! Audit notes: the connection object returned by `SCNetworkConnectionCreateWithServiceID` is owned (+1) and
//! released when the wrapper drops; no callout or context is registered (both null), so nothing calls back into
//! Rust. The options dictionary is built from owned Core Foundation objects and only borrowed for the call.
#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{Boolean, CFAllocatorRef, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
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
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
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
