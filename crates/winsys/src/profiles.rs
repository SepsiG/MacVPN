//! The user profiles of this machine as Windows records them: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
//! ProfileList`, each subkey's name and its `ProfileImagePath` (a `REG_EXPAND_SZ`, expanded in the caller's
//! environment, e.g. `%SystemDrive%\Users\alice`). Read only (the 64-bit view); readable by every user.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
    RegOpenKeyExW,
};

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// A registry key name has at most 255 characters.
const MAX_KEY_NAME: usize = 256;
/// More subkeys than any machine has profiles: the enumeration stops there.
const MAX_PROFILES: u32 = 10_000;
/// A profile path longer than this (UTF-16 units) is skipped.
const MAX_PATH_UNITS: u32 = 32_768;

/// One subkey of `ProfileList`: its name (normally a SID string; Windows also leaves `<SID>.bak` keys) and the
/// profile folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub key: String,
    pub dir: PathBuf,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key this module opened, closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Every profile with a readable `ProfileImagePath` (a subkey without one, or with a name or path that is not
/// Unicode, is skipped). `Err` only when the list itself cannot be opened or enumerated.
pub fn list() -> io::Result<Vec<Profile>> {
    let path = wide(PROFILE_LIST);
    let mut raw: HKEY = std::ptr::null_mut();
    // SAFETY: a predefined root, a NUL-terminated subkey name alive across the call, a valid out pointer.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut raw) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let key = Key(raw);
    let mut out = Vec::new();
    for index in 0..MAX_PROFILES {
        let mut name = [0u16; MAX_KEY_NAME];
        let mut len = name.len() as u32;
        // SAFETY: an open key; `name` is valid for `len` UTF-16 units; the optional out pointers are null.
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
            return Ok(out);
        }
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let units = &name[..(len as usize).min(name.len())];
        let Ok(sub) = OsString::from_wide(units).into_string() else { continue };
        if let Some(dir) = image_path(&key, units) {
            out.push(Profile { key: sub, dir });
        }
    }
    Ok(out)
}

/// `ProfileImagePath` of the subkey `sub` (UTF-16, no NUL) of `key`, expanded; `None` when missing, empty, not
/// a string, not Unicode or longer than [`MAX_PATH_UNITS`].
fn image_path(key: &Key, sub: &[u16]) -> Option<PathBuf> {
    let sub: Vec<u16> = sub.iter().copied().chain(Some(0)).collect();
    let value = wide("ProfileImagePath");
    // RRF_RT_REG_SZ without RRF_NOEXPAND: a REG_EXPAND_SZ value is expanded and returned as REG_SZ.
    let flags = RRF_RT_REG_SZ;
    let mut buf: Vec<u16> = vec![0; 260];
    loop {
        let mut bytes = (buf.len() * 2) as u32;
        // SAFETY: an open key, NUL-terminated subkey and value names alive across the call, `buf` valid for
        // `bytes` bytes, `bytes` a valid in/out pointer, no type out pointer.
        let rc = unsafe {
            RegGetValueW(
                key.0,
                sub.as_ptr(),
                value.as_ptr(),
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc == ERROR_MORE_DATA && (buf.len() as u32) < MAX_PATH_UNITS {
            let wanted = (bytes as usize).div_ceil(2).max(buf.len() * 2);
            buf = vec![0; wanted.min(MAX_PATH_UNITS as usize)];
            continue;
        }
        if rc != ERROR_SUCCESS {
            return None;
        }
        let units = &buf[..((bytes as usize) / 2).min(buf.len())];
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        let text = OsString::from_wide(&units[..end]).into_string().ok().filter(|s| !s.is_empty())?;
        return Some(PathBuf::from(text));
    }
}
