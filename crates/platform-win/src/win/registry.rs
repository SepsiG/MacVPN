//! The few `HKEY_CURRENT_USER` values WinVPN reads and writes, and the `HKEY_LOCAL_MACHINE` values of the OpenVPN
//! install (OpenVPN's `exe_path`, WinVPN's marker; 64-bit view).

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_BINARY, REG_DWORD, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegDeleteKeyValueW, RegDeleteKeyW, RegGetValueW, RegSetKeyValueW,
};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn os_error(err: u32) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

/// The value's data, if it exists and has the type `flags` asks for (`RRF_RT_*`).
fn read(subkey: &str, value: &str, flags: u32) -> Option<Vec<u8>> {
    read_in(HKEY_CURRENT_USER, subkey, value, flags)
}

fn read_in(root: HKEY, subkey: &str, value: &str, flags: u32) -> Option<Vec<u8>> {
    let (k, v) = (wide(subkey), wide(value));
    let mut len = 0u32;
    // SAFETY: a size query (null data pointer); NUL-terminated names.
    let err = unsafe {
        RegGetValueW(root, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut len)
    };
    if err != 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` holds `len` bytes, as `len` says.
    let err = unsafe {
        RegGetValueW(root, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
    };
    if err != 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

/// A `REG_DWORD` (the taskbar's light or dark theme).
pub(crate) fn read_dword(subkey: &str, value: &str) -> Option<u32> {
    read(subkey, value, RRF_RT_REG_DWORD).and_then(|b| Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?)))
}

/// A `REG_SZ` (up to its first NUL).
pub(crate) fn read_string(subkey: &str, value: &str) -> Option<String> {
    utf16_string(&read(subkey, value, RRF_RT_REG_SZ)?)
}

/// A machine `REG_SZ` (64-bit view; any user may read `HKLM\SOFTWARE`).
pub(crate) fn read_machine_string(subkey: &str, value: &str) -> Option<String> {
    utf16_string(&read_in(HKEY_LOCAL_MACHINE, subkey, value, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY)?)
}

/// A machine `REG_DWORD` (64-bit view).
pub(crate) fn read_machine_dword(subkey: &str, value: &str) -> Option<u32> {
    let b = read_in(HKEY_LOCAL_MACHINE, subkey, value, RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY)?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

/// Writes a machine `REG_DWORD`, creating the key if needed (an administrator only). WinVPN is a 64-bit process
/// (x64 or ARM64), so this is the 64-bit view.
pub(crate) fn write_machine_dword(subkey: &str, value: &str, data: u32) -> io::Result<()> {
    let (k, v) = (wide(subkey), wide(value));
    let bytes = data.to_le_bytes();
    // SAFETY: NUL-terminated names; `bytes` holds the 4 bytes of a REG_DWORD.
    let err =
        unsafe { RegSetKeyValueW(HKEY_LOCAL_MACHINE, k.as_ptr(), v.as_ptr(), REG_DWORD, bytes.as_ptr().cast(), 4) };
    if err == 0 { Ok(()) } else { Err(os_error(err)) }
}

fn utf16_string(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
    Some(String::from_utf16_lossy(units.split(|&c| c == 0).next().unwrap_or_default()))
}

pub(crate) fn read_binary(subkey: &str, value: &str) -> Option<Vec<u8>> {
    read(subkey, value, RRF_RT_REG_BINARY)
}

/// Creates the key if needed.
pub(crate) fn write_string(subkey: &str, value: &str, data: &str) -> io::Result<()> {
    let (k, v, d) = (wide(subkey), wide(value), wide(data));
    let size = u32::try_from(d.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: NUL-terminated strings; the size includes the terminating NUL, as REG_SZ requires.
    let err = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), REG_SZ, d.as_ptr().cast(), size) };
    if err == 0 { Ok(()) } else { Err(os_error(err)) }
}

/// Creates the key if needed.
pub(crate) fn write_binary(subkey: &str, value: &str, data: &[u8]) -> io::Result<()> {
    let (k, v) = (wide(subkey), wide(value));
    let size = u32::try_from(data.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `data` is valid for `size` bytes; NUL-terminated names.
    let err =
        unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), REG_BINARY, data.as_ptr().cast(), size) };
    if err == 0 { Ok(()) } else { Err(os_error(err)) }
}

/// A missing value (or key) is not an error.
pub(crate) fn delete_value(subkey: &str, value: &str) -> io::Result<()> {
    let (k, v) = (wide(subkey), wide(value));
    // SAFETY: NUL-terminated strings.
    let err = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr()) };
    if err == 0 || err == ERROR_FILE_NOT_FOUND { Ok(()) } else { Err(os_error(err)) }
}

/// `registry_round_trip_for_tests` (lib.rs): its own random key, removed at the end.
pub(crate) fn round_trip_for_tests() -> bool {
    let mut id = [0u8; 16];
    if macvpn_winsys::random::fill(&mut id).is_err() {
        return false;
    }
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let key = format!("Software\\WinVPN-test-{hex}");
    let ok = (|| {
        write_string(&key, "x", "C:\\Program Files\\WinVPN\\WinVPN.exe").ok()?;
        (read_string(&key, "x")? == "C:\\Program Files\\WinVPN\\WinVPN.exe").then_some(())?;
        // The wrong type is not read.
        read_binary(&key, "x").is_none().then_some(())?;
        write_binary(&key, "x", &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).ok()?;
        (read_binary(&key, "x")? == [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).then_some(())?;
        delete_value(&key, "x").ok()?;
        read_binary(&key, "x").is_none().then_some(())?;
        // A missing value is not an error.
        delete_value(&key, "x").ok()
    })()
    .is_some();
    let k = wide(&key);
    // SAFETY: a NUL-terminated name; deletes only this test's (empty) key.
    let removed = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, k.as_ptr()) } == 0;
    ok && removed
}
