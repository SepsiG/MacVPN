//! The pre-shared key of an L2TP entry in the user's RAS credential store (`RasSetCredentialsW` /
//! `RasGetCredentialsW` with `RASCM_PreSharedKey`): `RASDIALPARAMSW` has no PSK field, so Windows takes it only
//! from there. Works in a network logon (SSH) too. The `RASCREDENTIALSW` that carries a key is wiped after every
//! call; the key never reaches the phonebook file.

use super::entry::entry_name;
use super::{Error, Phonebook, Result, fill, rc, wipe};
use windows_sys::Win32::NetworkManagement::Rras::{
    RASCM_PreSharedKey, RASCREDENTIALSW, RasGetCredentialsW, RasSetCredentialsW,
};

/// `ERROR_FILE_NOT_FOUND` and `E_FAIL`: what `RasGetCredentialsW` answers for an entry without a stored PSK (the
/// spike saw both).
const NO_CREDENTIALS: [u32; 2] = [2, 0x8000_4005];

/// A `RASCREDENTIALSW` on the heap, wiped on drop (it may hold a key).
struct Credentials(Box<RASCREDENTIALSW>);

impl Credentials {
    fn new(mask: u32) -> Credentials {
        let mut c = Box::<RASCREDENTIALSW>::default();
        c.dwSize = std::mem::size_of::<RASCREDENTIALSW>() as u32;
        c.dwMask = mask;
        Credentials(c)
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        let p: *mut RASCREDENTIALSW = &mut *self.0;
        // SAFETY: `p` points to the whole boxed structure, valid for writes of its size.
        unsafe { wipe(p.cast(), std::mem::size_of::<RASCREDENTIALSW>()) };
    }
}

/// Stores `psk` as the pre-shared key of the entry `name` (replacing an earlier one). Private phonebooks only.
pub fn set_psk(book: &Phonebook, name: &str, psk: &str) -> Result<()> {
    book.private_path()?;
    if psk.is_empty() {
        return Err(Error::invalid("the pre-shared key is empty"));
    }
    let wname = entry_name(name)?;
    let mut c = Credentials::new(RASCM_PreSharedKey);
    let field = c.0.szPassword.as_mut_ptr();
    // SAFETY: `fill` writes at most the field's 257 units.
    unsafe { fill(field, 257, psk, "the pre-shared key")? };
    // SAFETY: the strings are NUL-terminated and alive across the call; `c` is a complete RASCREDENTIALSW with
    // `dwSize` set; FALSE: store, not clear.
    rc("RasSetCredentialsW", unsafe { RasSetCredentialsW(book.as_pcwstr(), wname.as_ptr(), &*c.0, 0) })
}

/// Removes the stored pre-shared key of the entry `name` (`fClearCredentials`). Call it before deleting the entry.
/// Private phonebooks only.
pub fn clear_psk(book: &Phonebook, name: &str) -> Result<()> {
    book.private_path()?;
    let wname = entry_name(name)?;
    let c = Credentials::new(RASCM_PreSharedKey);
    // SAFETY: as in `set_psk`; TRUE: clear the credentials the mask names.
    rc("RasSetCredentialsW", unsafe { RasSetCredentialsW(book.as_pcwstr(), wname.as_ptr(), &*c.0, 1) })
}

/// Whether a pre-shared key is stored for the entry `name` (the returned mask only: Windows hands back a
/// placeholder, never the key; the buffer is wiped at once). Private phonebooks only.
pub fn has_psk(book: &Phonebook, name: &str) -> Result<bool> {
    book.private_path()?;
    let wname = entry_name(name)?;
    let mut c = Credentials::new(RASCM_PreSharedKey);
    // SAFETY: the strings are NUL-terminated and alive across the call; `c` is a writable RASCREDENTIALSW with
    // `dwSize` and the mask set.
    let code = unsafe { RasGetCredentialsW(book.as_pcwstr(), wname.as_ptr(), &mut *c.0) };
    let mask = c.0.dwMask;
    drop(c);
    match code {
        0 => Ok(mask & RASCM_PreSharedKey != 0),
        code if NO_CREDENTIALS.contains(&code) => Ok(false),
        code => Err(Error::Call { call: "RasGetCredentialsW", code }),
    }
}
