//! Local NRPT rules (Windows' Name Resolution Policy Table) in the registry, written as OpenVPN's interactive
//! service (`openvpnserv`) writes them for `--dns`: one subkey per rule under [`POLICY_PATH`] in
//! `HKEY_LOCAL_MACHINE`, then [`apply`] makes the DNS client re-read the policy and drop its cache. Writing needs
//! an administrator (or LocalSystem). Every path here is relative to `HKEY_LOCAL_MACHINE` (64-bit view).

use crate::dll::Library;
use crate::scm;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR};
// DELETE is a standard access right; windows-sys files it under FileSystem.
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD,
    REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
    RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::core::BOOL;

/// Where the DNS client keeps the local NRPT rules (under `HKEY_LOCAL_MACHINE`).
pub const POLICY_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// `ConfigOptions`: the rule names its own DNS servers (`GenericDNSServers`).
const CONFIG_GENERIC_DNS_SERVERS: u32 = 8;
/// `Version` of the rule format.
const RULE_VERSION: u32 = 2;
/// `Comment` of every rule written here.
const COMMENT: &str = "WinVPN";
/// A registry key name has at most 255 characters.
const MAX_KEY_NAME: usize = 256;
/// The enumeration stops after this many subkeys (far more than any machine has rules).
const MAX_RULES: u32 = 100_000;

/// A registry key this module opened, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key this module opened or created, closed once, here.
        unsafe { RegCloseKey(self.0) };
    }
}

fn result(rc: WIN32_ERROR) -> io::Result<()> {
    if rc == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(rc as i32)) }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_string())
}

/// UTF-16 without a terminator; an interior NUL is refused.
fn units(s: &str) -> io::Result<Vec<u16>> {
    let w: Vec<u16> = s.encode_utf16().collect();
    if w.contains(&0) { Err(invalid("a NUL character in a registry name or value")) } else { Ok(w) }
}

/// A NUL-terminated UTF-16 string (`REG_SZ`, key and value names).
fn sz(s: &str) -> io::Result<Vec<u16>> {
    let mut w = units(s)?;
    w.push(0);
    Ok(w)
}

/// A `REG_MULTI_SZ` buffer: each string NUL-terminated, the list ended by one more NUL. An empty list or an empty
/// string (which would end the list early) is refused.
fn multi_sz(items: &[String]) -> io::Result<Vec<u16>> {
    if items.is_empty() || items.iter().any(String::is_empty) {
        return Err(invalid("a REG_MULTI_SZ needs at least one string and no empty one"));
    }
    let mut w = Vec::new();
    for item in items {
        w.extend(sz(item)?);
    }
    w.push(0);
    Ok(w)
}

/// `base\name` for a single subkey name (no separator, not empty).
fn subkey(base: &str, name: &str) -> io::Result<String> {
    if name.is_empty() || name.contains('\\') || name.len() >= MAX_KEY_NAME {
        return Err(invalid("a registry subkey name must be one non-empty component"));
    }
    Ok(format!(r"{base}\{name}"))
}

/// Opens `path`; `Ok(None)` when it does not exist.
fn open(path: &str, access: REG_SAM_FLAGS) -> io::Result<Option<Key>> {
    let path = sz(path)?;
    let mut raw: HKEY = std::ptr::null_mut();
    // SAFETY: a predefined root, a NUL-terminated subkey name alive across the call, a valid out pointer.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut raw) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    result(rc)?;
    Ok(Some(Key(raw)))
}

fn set(key: &Key, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> io::Result<()> {
    let name = sz(name)?;
    let len = u32::try_from(data.len()).map_err(|_| invalid("a registry value too long"))?;
    // SAFETY: an open key with KEY_SET_VALUE; `name` is NUL-terminated and `data` valid for `len` bytes, both alive
    // across the call, which only reads them.
    result(unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, kind, data.as_ptr(), len) })
}

fn set_wide(key: &Key, name: &str, kind: REG_VALUE_TYPE, data: &[u16]) -> io::Result<()> {
    let bytes: Vec<u8> = data.iter().flat_map(|u| u.to_le_bytes()).collect();
    set(key, name, kind, &bytes)
}

/// Writes one rule as OpenVPN's interactive service does: `Name` (REG_MULTI_SZ), `GenericDNSServers` (REG_SZ,
/// `;`-joined), `ConfigOptions` (DWORD 8), `Version` (DWORD 2), `IPSECCARestriction` (REG_SZ ""), `Comment` (REG_SZ
/// "WinVPN"). The key `base\key` is created if needed; an existing rule's values are overwritten. `names` (`.` for
/// every name, `.suffix` for a domain) and `servers` (IP literals) must not be empty.
pub fn write_rule(base: &str, key: &str, names: &[String], servers: &[String]) -> io::Result<()> {
    if servers.is_empty() || servers.iter().any(|s| s.is_empty() || s.contains(';')) {
        return Err(invalid("an NRPT rule needs DNS servers"));
    }
    let name_data = multi_sz(names)?;
    let server_data = sz(&servers.join(";"))?;
    let path = sz(&subkey(base, key)?)?;
    let mut raw: HKEY = std::ptr::null_mut();
    // SAFETY: a predefined root; `path` is NUL-terminated and alive across the call; no class, default security,
    // a valid out pointer, no disposition wanted.
    result(unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut raw,
            std::ptr::null_mut(),
        )
    })?;
    let rule = Key(raw);
    set_wide(&rule, "Name", REG_MULTI_SZ, &name_data)?;
    set_wide(&rule, "GenericDNSServers", REG_SZ, &server_data)?;
    set(&rule, "ConfigOptions", REG_DWORD, &CONFIG_GENERIC_DNS_SERVERS.to_le_bytes())?;
    set(&rule, "Version", REG_DWORD, &RULE_VERSION.to_le_bytes())?;
    set_wide(&rule, "IPSECCARestriction", REG_SZ, &sz("")?)?;
    set_wide(&rule, "Comment", REG_SZ, &sz(COMMENT)?)
}

/// The key names under `base` (for the reconcile); none when `base` does not exist. A name that is not Unicode is
/// skipped.
pub fn rule_keys(base: &str) -> io::Result<Vec<String>> {
    let Some(key) = open(base, KEY_ENUMERATE_SUB_KEYS)? else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for index in 0..MAX_RULES {
        let mut name = [0u16; MAX_KEY_NAME];
        let mut len = name.len() as u32;
        // SAFETY: an open key with KEY_ENUMERATE_SUB_KEYS; `name` is valid for `len` UTF-16 units; the optional
        // out pointers are null.
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        result(rc)?;
        let units = &name[..(len as usize).min(name.len())];
        if let Ok(sub) = OsString::from_wide(units).into_string() {
            out.push(sub);
        }
    }
    Ok(out)
}

/// Deletes every rule under `base` whose key starts with `prefix` (with its values); returns how many went. An
/// empty prefix is refused (it would take other programs' rules too); a missing `base` deletes nothing.
pub fn delete_rules(base: &str, prefix: &str) -> io::Result<usize> {
    if prefix.is_empty() {
        return Err(invalid("an NRPT rule prefix must not be empty"));
    }
    let Some(key) = open(base, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE)? else { return Ok(0) };
    let mut deleted = 0;
    // Listed first: deleting while enumerating would shift the indexes.
    for name in rule_keys(base)?.into_iter().filter(|k| k.starts_with(prefix)) {
        let wide = sz(&name)?;
        // SAFETY: an open key with DELETE, KEY_ENUMERATE_SUB_KEYS and KEY_QUERY_VALUE (what RegDeleteTreeW needs);
        // `wide` is NUL-terminated and alive across the call.
        match unsafe { RegDeleteTreeW(key.0, wide.as_ptr()) } {
            ERROR_SUCCESS => deleted += 1,
            // Gone in the meantime.
            ERROR_FILE_NOT_FOUND => {}
            rc => return Err(io::Error::from_raw_os_error(rc as i32)),
        }
    }
    Ok(deleted)
}

/// Makes the DNS client re-read the policy and drop its cache: `SERVICE_CONTROL_PARAMCHANGE` to `Dnscache` (as
/// openvpnserv's `ApplyDnsSettings`), then `DnsFlushResolverCache` (dnsapi.dll, loaded from System32 through
/// [`Library::system32`], since windows-sys does not export it). Both are tried; the first error is returned, for
/// the caller to log: the rules are in place either way.
pub fn apply() -> io::Result<()> {
    let changed = scm::param_change("Dnscache");
    let flushed = flush_cache();
    changed.and(flushed)
}

fn flush_cache() -> io::Result<()> {
    let lib = Library::system32("dnsapi.dll")?;
    let f = lib.symbol(c"DnsFlushResolverCache")?;
    type DnsFlushResolverCache = unsafe extern "system" fn() -> BOOL;
    // SAFETY: the export DnsFlushResolverCache takes no arguments and returns a BOOL; `lib` outlives the call.
    let f: DnsFlushResolverCache = unsafe { std::mem::transmute::<*const std::ffi::c_void, DnsFlushResolverCache>(f) };
    // SAFETY: no arguments; the function only talks to the DNS client service.
    if unsafe { f() } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_name_list_is_a_double_nul_terminated_utf16_buffer() {
        let w = multi_sz(&s(&[".", ".lab.test"])).unwrap();
        let expected: Vec<u16> = ".\0.lab.test\0\0".encode_utf16().collect();
        assert_eq!(w, expected);
    }

    #[test]
    fn an_empty_list_an_empty_name_or_a_nul_is_refused() {
        assert!(multi_sz(&[]).is_err());
        assert!(multi_sz(&s(&[".a", ""])).is_err());
        assert!(multi_sz(&s(&[".a\0b"])).is_err());
    }

    #[test]
    fn a_rule_key_is_one_component() {
        assert_eq!(subkey("A", "WinVPN-x-0").unwrap(), r"A\WinVPN-x-0");
        assert!(subkey("A", r"x\y").is_err());
        assert!(subkey("A", "").is_err());
    }

    #[test]
    fn rules_without_servers_and_deletes_without_a_prefix_are_refused() {
        assert!(write_rule(r"SOFTWARE\WinVPN-never", "k", &s(&["."]), &[]).is_err());
        assert!(delete_rules(r"SOFTWARE\WinVPN-never", "").is_err());
    }
}
