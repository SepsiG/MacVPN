//! The raw Keychain calls behind [`crate::secrets::SystemKeychain`] (the `SystemKeychain` class of
//! `SecretStore.swift`): `SecItemCopyMatching` / `SecItemUpdate` / `SecItemAdd` / `SecItemDelete` on generic
//! passwords. Errors other than "not found" are logged to the unified log (subsystem `local.macvpn`, category
//! `keychain`) with their status code only, never with an account's value.
//!
//! Audit notes: every dictionary is built from owned Core Foundation objects (`core-foundation` keeps the
//! retain counts); the only raw pointers are the `CFTypeRef` out-parameters of `SecItemCopyMatching`, taken over
//! with the create rule (we own the returned object) after checking their type ID.
#![allow(unsafe_code)]

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFGetTypeID, CFTypeRef, OSStatus};
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitAll, kSecReturnAttributes, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate};
use std::sync::LazyLock;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    // Not in `security-framework-sys`; both are `CFStringRef` constants of Security.framework.
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
}

static LOG: LazyLock<oslog::OsLog> = LazyLock::new(|| oslog::OsLog::new("local.macvpn", "keychain"));

fn log_error(message: &str) {
    LOG.with_level(oslog::Level::Error, message);
}

/// A constant `CFStringRef` as an owned `CFString`.
fn key(k: CFStringRef) -> CFString {
    // SAFETY: `k` is one of Security.framework's immortal constant strings; get-rule retains it.
    unsafe { CFString::wrap_under_get_rule(k) }
}

fn query(service: &str, account: Option<&str>) -> Vec<(CFString, CFType)> {
    let mut q = vec![
        (key(unsafe_const(&raw const kSecClass)), key(unsafe_const(&raw const kSecClassGenericPassword)).as_CFType()),
        (key(unsafe_const(&raw const kSecAttrService)), CFString::new(service).as_CFType()),
    ];
    if let Some(account) = account {
        q.push((key(unsafe_const(&raw const kSecAttrAccount)), CFString::new(account).as_CFType()));
    }
    q
}

/// Reads an extern constant.
fn unsafe_const(p: *const CFStringRef) -> CFStringRef {
    // SAFETY: `p` points to an extern `static` of the linked Security framework, initialised at load time.
    unsafe { *p }
}

fn dictionary(pairs: &[(CFString, CFType)]) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(pairs)
}

/// `SecItemCopyMatching` returning the owned result object.
fn copy_matching(q: &CFDictionary<CFString, CFType>) -> (OSStatus, Option<CFType>) {
    let mut result: CFTypeRef = std::ptr::null();
    // SAFETY: a valid dictionary and a valid out-pointer for the duration of the call.
    let status = unsafe { SecItemCopyMatching(q.as_concrete_TypeRef(), &mut result) };
    if status != errSecSuccess || result.is_null() {
        return (status, None);
    }
    // SAFETY: on success the result is a +1 object owned by the caller (create rule).
    (status, Some(unsafe { CFType::wrap_under_create_rule(result) }))
}

pub fn read(service: &str, account: &str) -> Option<Vec<u8>> {
    let mut q = query(service, Some(account));
    q.push((key(unsafe_const(&raw const kSecReturnData)), CFBoolean::true_value().as_CFType()));
    q.push((key(unsafe_const(&raw const kSecMatchLimit)), key(unsafe_const(&raw const kSecMatchLimitOne)).as_CFType()));
    let (status, item) = copy_matching(&dictionary(&q));
    let data = item.and_then(|item| item.downcast::<CFData>());
    if data.is_none() && status != errSecItemNotFound && status != errSecSuccess {
        log_error(&format!("SecItemCopyMatching error: {status}"));
    }
    data.map(|d| d.bytes().to_vec())
}

pub fn write(data: &[u8], service: &str, account: &str) -> bool {
    let q = query(service, Some(account));
    let update = dictionary(&[(key(unsafe_const(&raw const kSecValueData)), CFData::from_buffer(data).as_CFType())]);
    // SAFETY: two valid dictionaries for the duration of the call.
    let update_status = unsafe { SecItemUpdate(dictionary(&q).as_concrete_TypeRef(), update.as_concrete_TypeRef()) };
    if update_status == errSecSuccess {
        return true;
    }
    if update_status != errSecItemNotFound {
        log_error(&format!("SecItemUpdate error: {update_status}"));
        return false;
    }
    let field = account.rsplit('.').next().unwrap_or("");
    let mut add = q;
    add.push((key(unsafe_const(&raw const kSecValueData)), CFData::from_buffer(data).as_CFType()));
    add.push((key(unsafe_const(&raw const kSecAttrLabel)), CFString::new(&format!("MacVPN: {field}")).as_CFType()));
    add.push((
        key(unsafe_const(&raw const kSecAttrAccessible)),
        key(unsafe_const(&raw const kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)).as_CFType(),
    ));
    // SAFETY: a valid dictionary; a null result pointer is allowed (we do not want the added item back).
    let add_status = unsafe { SecItemAdd(dictionary(&add).as_concrete_TypeRef(), std::ptr::null_mut()) };
    if add_status != errSecSuccess {
        log_error(&format!("SecItemAdd error: {add_status}"));
    }
    add_status == errSecSuccess
}

/// On the old (file-based) keychain one call sometimes deletes only one item, so it is repeated (bounded).
pub fn delete(service: &str, account: &str) {
    let q = dictionary(&query(service, Some(account)));
    for _ in 0..100 {
        // SAFETY: a valid dictionary for the duration of the call.
        let status = unsafe { SecItemDelete(q.as_concrete_TypeRef()) };
        if status == errSecItemNotFound {
            return;
        }
        if status != errSecSuccess {
            log_error(&format!("SecItemDelete error: {status}"));
            return;
        }
    }
}

pub fn accounts(service: &str) -> Vec<String> {
    let mut q = query(service, None);
    q.push((key(unsafe_const(&raw const kSecReturnAttributes)), CFBoolean::true_value().as_CFType()));
    q.push((key(unsafe_const(&raw const kSecMatchLimit)), key(unsafe_const(&raw const kSecMatchLimitAll)).as_CFType()));
    let (status, items) = copy_matching(&dictionary(&q));
    let Some(list) = items.and_then(|i| i.downcast::<CFArray>()) else {
        if status != errSecItemNotFound && status != errSecSuccess {
            log_error(&format!("SecItemCopyMatching (list) error: {status}"));
        }
        return Vec::new();
    };
    let account_key = key(unsafe_const(&raw const kSecAttrAccount));
    let mut out = Vec::new();
    for item in list.iter() {
        let p = *item;
        // SAFETY: the element is alive while `list` is; its type ID is checked before the cast.
        if p.is_null() || unsafe { CFGetTypeID(p) } != CFDictionary::<CFString, CFType>::type_id() {
            continue;
        }
        // SAFETY: a valid CFDictionary (checked above), retained by the get rule.
        let attributes: CFDictionary = unsafe { CFDictionary::wrap_under_get_rule(p.cast()) };
        let Some(value) = attributes.find(account_key.as_concrete_TypeRef().cast()) else { continue };
        let value = *value;
        // SAFETY: `value` is borrowed from `attributes` (alive here); the type ID is checked before the cast.
        if !value.is_null() && unsafe { CFGetTypeID(value) } == CFString::type_id() {
            // SAFETY: a valid CFString (checked above); get-rule retains it for the owned wrapper.
            out.push(unsafe { CFString::wrap_under_get_rule(value.cast()) }.to_string());
        }
    }
    out
}
