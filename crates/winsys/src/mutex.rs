//! Named mutexes with a private DACL (WinVPN's single-instance lock).

use crate::security::{Ace, Acl, Descriptor};
use crate::sid::Sid;
use std::io;
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::System::Threading::{CreateMutexW, MUTEX_ALL_ACCESS};

/// A named mutex this process holds a handle to.
pub struct NamedMutex {
    /// Closed on drop: the name lives while any process holds a handle.
    pub handle: OwnedHandle,
    /// `None`: this call created it. `Some(owner)`: it existed already, with this owner (read from its descriptor).
    pub existing_owner: Option<Sid>,
}

/// Creates (or opens) the mutex `name` (`Local\…`, not initially owned). A new mutex gets a protected DACL for this
/// user and SYSTEM and this user as its owner, so no other user can open it. An existing one is opened and its owner
/// read: a mutex another user created first (a squatter) shows that user as the owner, or cannot be opened at all
/// (`PermissionDenied`, `ERROR_ACCESS_DENIED`).
pub fn create_private(name: &str) -> io::Result<NamedMutex> {
    let (user, system) = (Sid::current_user()?, Sid::local_system());
    let acl = Acl::new(&[Ace::Allow(&user, MUTEX_ALL_ACCESS), Ace::Allow(&system, MUTEX_ALL_ACCESS)], 0)?;
    let d = Descriptor::new(user, acl)?;
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    if wide[..wide.len() - 1].contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: `wide` is NUL-terminated; the attributes point into `d`, alive across the call.
    let h = unsafe { CreateMutexW(d.attributes(), 0, wide.as_ptr()) };
    // SAFETY: plain call, right after CreateMutexW (which sets ERROR_ALREADY_EXISTS on success for an existing one).
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle CreateMutexW just returned; nobody else owns it.
    let handle = unsafe { OwnedHandle::from_raw_handle(h) };
    let existing_owner = if already { Some(crate::file::kernel_object_owner(handle.as_handle())?) } else { None };
    Ok(NamedMutex { handle, existing_owner })
}
