//! The Remote Access Service (RAS, `rasapi32.dll`): VPN phonebook entries, dialling and hanging up, the RAS
//! credential store's pre-shared key, the IKEv2 policy keys of a phonebook section, and a watcher for RAS
//! connections and phonebook folders.
//!
//! Generic: it knows nothing of the caller's entry names or texts. The flag values each [`Strategy`] / [`Auth`]
//! writes are the ones Microsoft's own `Add-VpnConnection` writes for the same choices, pinned by the reference
//! sections in `tests/fixtures/ras` (WinVPN 2c plan, Task 2: `docs/superpowers/spikes/2026-10-25-winvpn-ras.md`).
//!
//! Facts the callers rely on (the spike's findings):
//! - A private phonebook (any `.pbk` path in a folder the caller owns) works for writing, reading and dialling. Its
//!   file is created by the first [`Phonebook::write`] (the folder must exist) and **deleted by Windows with its
//!   last entry**: "no file" means "no entries".
//! - `RASCONNW.szPhonebook` is the path exactly as the dialler passed it (letter case included): compare it
//!   without regard to letter case.
//! - Dialling, the connection status, the connection list and hanging up work only in an interactive logon
//!   session. In a network logon (SSH) `RasGetConnectStatusW` and `RasHangUpW` answer 668 for the process' own
//!   dial and the connection is released only when the process ends.
//! - Dial callbacks of an earlier dial can arrive after a later dial started: each [`dial`] gets its own callback,
//!   and events of another connection handle are never delivered to it.

mod creds;
mod dial;
mod entry;
mod ini;
mod watch;

pub use creds::{clear_psk, has_psk, set_psk};
pub use dial::{
    Conn, Dial, DialEvent, DialParams, Handle, Saved, Status, connections, dial, dial_dlg, dial_saved, error_text,
    hang_up, ipv4, saved_credentials, status,
};
pub use entry::{Auth, Entry, EntryName, Phonebook, Strategy, system_entries, validate_name};
pub use ini::{
    AuthTransform, CipherTransform, DhGroup, Encryption, Integrity, IpsecPolicy, PfsGroup, custom_policy,
    set_custom_policy,
};
pub use watch::Watcher;

use std::fmt;

/// `ERROR_INVALID_HANDLE`: what `RasGetConnectStatusW` answers once a connection handle is released.
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// `ERROR_NO_CONNECTION` (668): `RasHangUpW` / `RasGetConnectStatusW` for a connection that is gone (or, over SSH,
/// for one the process cannot see).
pub const ERROR_NO_CONNECTION: u32 = 668;
/// `ERROR_ALREADY_EXISTS` (183): `RasValidateEntryNameW` for an entry that exists.
pub const ERROR_ALREADY_EXISTS: u32 = 183;
/// `ERROR_CANNOT_FIND_PHONEBOOK_ENTRY` (623).
pub const ERROR_CANNOT_FIND_PHONEBOOK_ENTRY: u32 = 623;

/// A RAS call failed, a value was refused before any call, or a wait timed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The named call returned this code (a RAS, Win32 or HRESULT code; [`error_text`] describes it).
    Call { call: &'static str, code: u32 },
    /// A value the RAS structures cannot hold, or a combination the entry kind does not allow (nothing was
    /// called).
    Invalid(String),
    /// [`Dial::hang_up_and_wait`] / [`hang_up`]: the handle was not released in time.
    Timeout,
}

impl Error {
    /// The Windows code of a failed call.
    pub fn code(&self) -> Option<u32> {
        match self {
            Error::Call { code, .. } => Some(*code),
            Error::Invalid(_) | Error::Timeout => None,
        }
    }

    pub(crate) fn invalid(text: impl Into<String>) -> Error {
        Error::Invalid(text.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Call { call, code } if *code > 0xFFFF => write!(f, "{call} failed: 0x{code:08X}"),
            Error::Call { call, code } => write!(f, "{call} failed: {code}"),
            Error::Invalid(text) => f.write_str(text),
            Error::Timeout => f.write_str("the RAS connection was not released in time"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        match e {
            Error::Call { code, .. } => std::io::Error::from_raw_os_error(code as i32),
            Error::Invalid(text) => std::io::Error::new(std::io::ErrorKind::InvalidInput, text),
            Error::Timeout => std::io::Error::from(std::io::ErrorKind::TimedOut),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// `Ok` for 0, else the call's code.
pub(crate) fn rc(call: &'static str, code: u32) -> Result<()> {
    if code == 0 { Ok(()) } else { Err(Error::Call { call, code }) }
}

/// Copies `s` into the fixed UTF-16 field at `dst` (`cap` units, NUL included) without an intermediate
/// allocation (the field may receive a secret). Refused (nothing truncated): a NUL in `s`, or `s` too long.
///
/// # Safety
/// `dst` must be valid for writes of `cap` `u16` values; it need not be aligned.
pub(crate) unsafe fn fill(dst: *mut u16, cap: usize, s: &str, what: &str) -> Result<()> {
    let len = s.encode_utf16().count();
    if len >= cap {
        return Err(Error::invalid(format!("{what} is longer than {} UTF-16 units", cap - 1)));
    }
    if s.contains('\0') {
        return Err(Error::invalid(format!("{what} contains a NUL character")));
    }
    for (i, unit) in s.encode_utf16().chain(std::iter::once(0)).enumerate() {
        // SAFETY: i <= len < cap: inside the field the caller vouches for; unaligned writes are allowed.
        unsafe { dst.add(i).write_unaligned(unit) };
    }
    Ok(())
}

/// The text of a fixed UTF-16 field up to its first NUL (lossy).
pub(crate) fn field_text(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Overwrites `len` bytes at `p` with zeros in a way the optimiser keeps (the memory held a secret).
///
/// # Safety
/// `p` must be valid for writes of `len` bytes.
pub(crate) unsafe fn wipe(p: *mut u8, len: usize) {
    for i in 0..len {
        // SAFETY: inside the range the caller vouches for.
        unsafe { p.add(i).write_volatile(0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// A GUID in RFC 4122 byte order (`uuid::Uuid::from_bytes` reads it as the same UUID Windows prints).
pub(crate) fn guid_bytes(g: &windows_sys::core::GUID) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1.to_be_bytes());
    b[4..6].copy_from_slice(&g.data2.to_be_bytes());
    b[6..8].copy_from_slice(&g.data3.to_be_bytes());
    b[8..].copy_from_slice(&g.data4);
    b
}
