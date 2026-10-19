//! The raw Keychain calls behind [`crate::secrets::SystemKeychain`] (the `SystemKeychain` class of
//! `SecretStore.swift`): `SecItemCopyMatching` / `SecItemUpdate` / `SecItemAdd` / `SecItemDelete` on generic
//! passwords. Errors other than "not found" are logged to the unified log (subsystem `local.macvpn`, category
//! `keychain`) with their status code only, never with an account's value.
//!
//! The vault's DEK item ([`crate::vault_keys::KeychainKeyStore`]) uses the `item_*` functions below: they report
//! the `OSStatus` instead of hiding it, read without UI first, and address exactly one keychain: the user's default
//! keychain, or (only in the isolated integration test) an explicit keychain file. A write deletes every matching
//! item in the search list first and then adds a fresh one, so the item and its ACL are always created by the app
//! (no squatting by an item planted in another keychain, security review M2).
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
use security_framework_sys::access_control::{
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
use security_framework_sys::base::{SecKeychainRef, errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitAll, kSecMatchSearchList, kSecReturnAttributes, kSecReturnData, kSecUseAuthenticationUI,
    kSecUseKeychain, kSecValueData,
};
use security_framework_sys::keychain::{SecKeychainCopyDefault, SecKeychainOpen};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::LazyLock;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    // Not in `security-framework-sys`; all are `CFStringRef` constants of Security.framework.
    static kSecMatchLimitOne: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
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

/// The item's data: `Ok(None)` when there is no item, `Err(status)` for any other failure (a denied or cancelled
/// prompt included).
pub fn read_checked(service: &str, account: &str) -> Result<Option<Vec<u8>>, OSStatus> {
    let mut q = query(service, Some(account));
    q.push((key(unsafe_const(&raw const kSecReturnData)), CFBoolean::true_value().as_CFType()));
    q.push((key(unsafe_const(&raw const kSecMatchLimit)), key(unsafe_const(&raw const kSecMatchLimitOne)).as_CFType()));
    let (status, item) = copy_matching(&dictionary(&q));
    match item.and_then(|item| item.downcast::<CFData>()) {
        Some(data) if status == errSecSuccess => Ok(Some(data.bytes().to_vec())),
        _ if status == errSecItemNotFound || status == errSecSuccess => Ok(None),
        _ => {
            log_error(&format!("SecItemCopyMatching error: {status}"));
            Err(status)
        }
    }
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

// --- The vault's DEK item ---------------------------------------------------------------------------------------

/// Which keychain an item operation addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The user's default keychain (`SecKeychainCopyDefault`, normally the login keychain).
    Default,
    /// One explicitly addressed keychain file, for the isolated integration test. It is opened for each call
    /// (`SecKeychainOpen`), so no Core Foundation object is kept across threads. Built only with `test-support`.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    Keychain(PathBuf),
}

/// `errSecParam`.
const ERR_SEC_PARAM: OSStatus = -50;

/// The keychain reference for `target` (owned; get-rule semantics are not involved).
fn resolve(target: &Target) -> Result<CFType, OSStatus> {
    let mut keychain: SecKeychainRef = std::ptr::null_mut();
    let status = match target {
        // SAFETY: a valid out-pointer for the duration of the call.
        Target::Default => unsafe { SecKeychainCopyDefault(&mut keychain) },
        Target::Keychain(path) => {
            let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ERR_SEC_PARAM)?;
            // SAFETY: a valid NUL-terminated path and a valid out-pointer for the duration of the call.
            unsafe { SecKeychainOpen(c.as_ptr(), &mut keychain) }
        }
    };
    if status != errSecSuccess || keychain.is_null() {
        return Err(if status == errSecSuccess { ERR_SEC_PARAM } else { status });
    }
    // SAFETY: on success the keychain reference is +1 and owned by the caller (create rule).
    Ok(unsafe { CFType::wrap_under_create_rule(keychain as CFTypeRef) })
}

fn search_list(keychain: &CFType) -> (CFString, CFType) {
    let list = CFArray::from_CFTypes(std::slice::from_ref(keychain));
    (key(unsafe_const(&raw const kSecMatchSearchList)), list.as_CFType())
}

/// Whether a read may show the macOS access prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ui {
    /// `kSecUseAuthenticationUIFail`: fail with `errSecInteractionNotAllowed` / `errSecAuthFailed` instead.
    Fail,
    Allow,
}

/// The `SecItemCopyMatching` query for the item's data, limited to the one target keychain.
pub fn item_read_query(
    service: &str,
    account: &str,
    ui: Ui,
    target: &Target,
) -> Result<CFDictionary<CFString, CFType>, OSStatus> {
    let mut q = query(service, Some(account));
    q.push(search_list(&resolve(target)?));
    q.push((key(unsafe_const(&raw const kSecReturnData)), CFBoolean::true_value().as_CFType()));
    q.push((key(unsafe_const(&raw const kSecMatchLimit)), key(unsafe_const(&raw const kSecMatchLimitOne)).as_CFType()));
    if ui == Ui::Fail {
        q.push((
            key(unsafe_const(&raw const kSecUseAuthenticationUI)),
            key(unsafe_const(&raw const kSecUseAuthenticationUIFail)).as_CFType(),
        ));
    }
    Ok(dictionary(&q))
}

/// The `SecItemAdd` attributes: generic password, service, account, label, the data,
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (spike report B.3; the file-based login keychain does not keep
/// it, but it documents the intent) and `kSecUseKeychain` = the target keychain. Never
/// `kSecUseDataProtectionKeychain`.
pub fn item_add_query(
    service: &str,
    account: &str,
    label: &str,
    data: &[u8],
    target: &Target,
) -> Result<CFDictionary<CFString, CFType>, OSStatus> {
    let mut q = query(service, Some(account));
    q.push((key(unsafe_const(&raw const kSecUseKeychain)), resolve(target)?));
    q.push((key(unsafe_const(&raw const kSecValueData)), CFData::from_buffer(data).as_CFType()));
    q.push((key(unsafe_const(&raw const kSecAttrLabel)), CFString::new(label).as_CFType()));
    q.push((
        key(unsafe_const(&raw const kSecAttrAccessible)),
        key(unsafe_const(&raw const kSecAttrAccessibleWhenUnlockedThisDeviceOnly)).as_CFType(),
    ));
    Ok(dictionary(&q))
}

/// The `SecItemDelete` query: for the default target every matching item in the user's search list (so an item
/// planted in another keychain goes too); for an explicit keychain only that keychain.
pub fn item_delete_query(
    service: &str,
    account: &str,
    target: &Target,
) -> Result<CFDictionary<CFString, CFType>, OSStatus> {
    let mut q = query(service, Some(account));
    if let Target::Keychain(_) = target {
        q.push(search_list(&resolve(target)?));
    }
    Ok(dictionary(&q))
}

/// Whether the item exists in the target keychain: attributes only (no data, so no ACL check) and
/// `kSecUseAuthenticationUIFail`, so it never shows a prompt.
pub fn item_exists(service: &str, account: &str, target: &Target) -> Result<bool, OSStatus> {
    let mut q = query(service, Some(account));
    q.push(search_list(&resolve(target)?));
    q.push((key(unsafe_const(&raw const kSecReturnAttributes)), CFBoolean::true_value().as_CFType()));
    q.push((key(unsafe_const(&raw const kSecMatchLimit)), key(unsafe_const(&raw const kSecMatchLimitOne)).as_CFType()));
    q.push((
        key(unsafe_const(&raw const kSecUseAuthenticationUI)),
        key(unsafe_const(&raw const kSecUseAuthenticationUIFail)).as_CFType(),
    ));
    match copy_matching(&dictionary(&q)) {
        (status, Some(_)) if status == errSecSuccess => Ok(true),
        (status, _) if status == errSecItemNotFound || status == errSecSuccess => Ok(false),
        (status, _) => Err(status),
    }
}

/// The item's data from the target keychain; `Err(status)` for anything but success (`errSecItemNotFound`
/// included).
pub fn item_read(service: &str, account: &str, ui: Ui, target: &Target) -> Result<Vec<u8>, OSStatus> {
    let (status, item) = copy_matching(&item_read_query(service, account, ui, target)?);
    match item.and_then(|item| item.downcast::<CFData>()) {
        Some(data) if status == errSecSuccess => Ok(data.bytes().to_vec()),
        _ => {
            if status != errSecItemNotFound {
                log_error(&format!("SecItemCopyMatching (vault) error: {status}"));
            }
            Err(if status == errSecSuccess { errSecItemNotFound } else { status })
        }
    }
}

/// Deletes every matching item ([`item_delete`]) and adds a fresh one to the target keychain, so the item and its
/// ACL are always created by this app.
pub fn item_write(service: &str, account: &str, label: &str, data: &[u8], target: &Target) -> Result<(), OSStatus> {
    item_delete(service, account, target)?;
    let add = item_add_query(service, account, label, data, target)?;
    // SAFETY: a valid dictionary; a null result pointer is allowed (we do not want the added item back).
    let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status != errSecSuccess {
        log_error(&format!("SecItemAdd (vault) error: {status}"));
        return Err(status);
    }
    Ok(())
}

/// Removes the item (repeated, bounded, like [`delete`]); a missing item is success.
pub fn item_delete(service: &str, account: &str, target: &Target) -> Result<(), OSStatus> {
    let q = item_delete_query(service, account, target)?;
    for _ in 0..100 {
        // SAFETY: a valid dictionary for the duration of the call.
        let status = unsafe { SecItemDelete(q.as_concrete_TypeRef()) };
        if status == errSecItemNotFound {
            return Ok(());
        }
        if status != errSecSuccess {
            log_error(&format!("SecItemDelete (vault) error: {status}"));
            return Err(status);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every query here addresses a keychain file that does not exist (SecKeychainOpen only makes a reference), so
    // building them touches no real keychain.
    fn nowhere() -> Target {
        Target::Keychain(std::env::temp_dir().join(format!("macvpn-no-such-{}.keychain-db", uuid::Uuid::new_v4())))
    }

    fn string_at(d: &CFDictionary<CFString, CFType>, k: CFStringRef) -> Option<String> {
        d.find(key(k)).and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string())
    }

    fn has(d: &CFDictionary<CFString, CFType>, k: CFStringRef) -> bool {
        d.find(key(k)).is_some()
    }

    fn constant(k: CFStringRef) -> String {
        key(k).to_string()
    }

    #[test]
    fn add_query_has_class_service_account_label_accessibility_and_the_keychain() {
        let d = item_add_query("local.macvpn.vault", "dek", "MacVPN vault key", &[1, 2], &nowhere()).unwrap();
        assert_eq!(
            string_at(&d, unsafe_const(&raw const kSecClass)),
            Some(constant(unsafe_const(&raw const kSecClassGenericPassword)))
        );
        assert_eq!(string_at(&d, unsafe_const(&raw const kSecAttrService)).as_deref(), Some("local.macvpn.vault"));
        assert_eq!(string_at(&d, unsafe_const(&raw const kSecAttrAccount)).as_deref(), Some("dek"));
        assert_eq!(string_at(&d, unsafe_const(&raw const kSecAttrLabel)).as_deref(), Some("MacVPN vault key"));
        assert_eq!(
            string_at(&d, unsafe_const(&raw const kSecAttrAccessible)),
            Some(constant(unsafe_const(&raw const kSecAttrAccessibleWhenUnlockedThisDeviceOnly)))
        );
        let data = d.find(key(unsafe_const(&raw const kSecValueData))).and_then(|v| v.downcast::<CFData>());
        assert_eq!(data.map(|d| d.bytes().to_vec()), Some(vec![1, 2]));
        // Always added to one explicit keychain; never the data-protection keychain.
        assert!(has(&d, unsafe_const(&raw const kSecUseKeychain)));
        assert_eq!(d.len(), 7);
    }

    #[test]
    fn read_query_is_limited_to_one_keychain_and_fails_instead_of_prompting_only_when_asked() {
        let silent = item_read_query("s", "a", Ui::Fail, &nowhere()).unwrap();
        assert_eq!(
            string_at(&silent, unsafe_const(&raw const kSecUseAuthenticationUI)),
            Some(constant(unsafe_const(&raw const kSecUseAuthenticationUIFail)))
        );
        assert_eq!(
            string_at(&silent, unsafe_const(&raw const kSecMatchLimit)),
            Some(constant(unsafe_const(&raw const kSecMatchLimitOne)))
        );
        assert_eq!(string_at(&silent, unsafe_const(&raw const kSecAttrService)).as_deref(), Some("s"));
        assert_eq!(string_at(&silent, unsafe_const(&raw const kSecAttrAccount)).as_deref(), Some("a"));
        let list = silent.find(key(unsafe_const(&raw const kSecMatchSearchList))).and_then(|v| v.downcast::<CFArray>());
        assert_eq!(list.map(|l| l.len()), Some(1), "exactly one keychain is searched");
        let prompting = item_read_query("s", "a", Ui::Allow, &nowhere()).unwrap();
        assert!(!has(&prompting, unsafe_const(&raw const kSecUseAuthenticationUI)));
        assert!(has(&prompting, unsafe_const(&raw const kSecMatchSearchList)));
    }

    #[test]
    fn delete_query_covers_the_whole_search_list_for_the_default_target() {
        let all = item_delete_query("s", "a", &Target::Default).unwrap();
        assert!(!has(&all, unsafe_const(&raw const kSecMatchSearchList)));
        assert!(!has(&all, unsafe_const(&raw const kSecMatchLimit)));
        assert_eq!(string_at(&all, unsafe_const(&raw const kSecAttrService)).as_deref(), Some("s"));
        let one = item_delete_query("s", "a", &nowhere()).unwrap();
        assert!(has(&one, unsafe_const(&raw const kSecMatchSearchList)));
    }
}
