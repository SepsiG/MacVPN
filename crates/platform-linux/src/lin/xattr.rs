//! `getxattr(path, "user.xdg.origin.url")` (the size only; the value is never read).

use crate::pure::mark::XattrRead;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn origin(path: &Path) -> XattrRead {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else { return XattrRead::Error(libc::EINVAL) };
    // SAFETY: two NUL-terminated strings that live for the call; a null buffer with size 0 asks for the size only.
    let n = unsafe { libc::getxattr(c.as_ptr(), c"user.xdg.origin.url".as_ptr(), std::ptr::null_mut(), 0) };
    if n >= 0 {
        return XattrRead::Present;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA) => XattrRead::Absent,
        Some(libc::ENOTSUP) => XattrRead::NotSupported,
        Some(libc::ENOENT) => XattrRead::NoFile,
        Some(e) => XattrRead::Error(e),
        None => XattrRead::Error(0),
    }
}
