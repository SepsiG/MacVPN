//! A file's version from its version resource (`VS_FIXEDFILEINFO`), as Explorer's "File version" shows it.
//!
//! One exception, by Windows itself: in a process without a Windows 10 compatibility manifest, Windows' own files
//! report 6.2 instead of 10.0 (an application compatibility shim; the build number stays the real one). Files of
//! other vendors (OpenVPN's) are read as they are.

use crate::util::{check, plain_absolute, wide_path};
use std::io;
use std::path::Path;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_VER_GET_NEUTRAL, GetFileVersionInfoExW, GetFileVersionInfoSizeExW, VS_FIXEDFILEINFO, VerQueryValueW,
};

/// `VS_FIXEDFILEINFO::dwSignature`.
const FIXED_SIGNATURE: u32 = 0xFEEF_04BD;

/// The file version `(major, minor, build, revision)` of the file at `path` (a plain absolute path: the version
/// API loads the file as a data module, and a bare name would be searched for). The language-neutral resource of
/// the file itself is read (`FILE_VER_GET_NEUTRAL`), not a MUI satellite's. A file without a version resource, or
/// one whose fixed part is missing or malformed, is an error.
pub fn file_version(path: &Path) -> io::Result<(u16, u16, u16, u16)> {
    plain_absolute(path)?;
    let name = wide_path(path)?;
    let mut ignored = 0u32;
    // SAFETY: `name` is NUL-terminated; `ignored` is a valid out pointer.
    let size = unsafe { GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, name.as_ptr(), &mut ignored) };
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    // u32 elements: the block is read as 32-bit fields below.
    let mut block = vec![0u32; (size as usize).div_ceil(4)];
    let cap = u32::try_from(block.len() * 4).map_err(io::Error::other)?;
    // SAFETY: `block` is valid for writes of `cap` bytes (at least `size`); `name` is NUL-terminated.
    check(unsafe { GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, name.as_ptr(), 0, cap, block.as_mut_ptr().cast()) })?;
    let root: Vec<u16> = "\\\0".encode_utf16().collect();
    let mut value: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: `block` holds the version resource the call above wrote and lives across this call; `root` is
    // NUL-terminated; valid out pointers. The returned pointer points into `block`.
    check(unsafe { VerQueryValueW(block.as_ptr().cast(), root.as_ptr(), &mut value, &mut len) })?;
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "no valid fixed version information");
    let start = block.as_ptr() as usize;
    let end = start + block.len() * 4;
    let at = value as usize;
    if value.is_null()
        || (len as usize) < size_of::<VS_FIXEDFILEINFO>()
        || at < start
        || at.checked_add(size_of::<VS_FIXEDFILEINFO>()).is_none_or(|e| e > end)
    {
        return Err(malformed());
    }
    // SAFETY: the structure's bytes lie within `block` (checked above), which is alive; plain data, read unaligned.
    let fixed = unsafe { std::ptr::read_unaligned(value as *const VS_FIXEDFILEINFO) };
    if fixed.dwSignature != FIXED_SIGNATURE {
        return Err(malformed());
    }
    let (ms, ls) = (fixed.dwFileVersionMS, fixed.dwFileVersionLS);
    Ok(((ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16))
}
