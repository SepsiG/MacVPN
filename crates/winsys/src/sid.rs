//! Security identifiers.

use crate::util::{LocalBox, check, wide};
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetTokenInformation, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
    WinBuiltinUsersSid, WinCreatorOwnerRightsSid, WinInteractiveSid, WinLocalSystemSid, WinNetworkSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A SID as owned bytes. Built only from SIDs the system produced or checked, so it is always valid: at least 8
/// bytes, and exactly `8 + 4 * sub-authority count` long.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// The user this process runs as (the process token's `TokenUser`), read once.
    pub fn current_user() -> io::Result<Sid> {
        static USER: OnceLock<Sid> = OnceLock::new();
        if let Some(sid) = USER.get() {
            return Ok(sid.clone());
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; `token` is a valid out pointer.
        check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
        // SAFETY: OpenProcessToken succeeded, so `token` is a new handle that nobody else owns; it is closed on drop.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let sid = Sid::of_token(token.as_handle())?;
        Ok(USER.get_or_init(|| sid).clone())
    }

    /// The user of an access token opened with `TOKEN_QUERY`.
    pub fn of_token(token: BorrowedHandle<'_>) -> io::Result<Sid> {
        let token = token.as_raw_handle();
        let mut len = 0u32;
        // SAFETY: a size query: a null buffer of length 0 is allowed; `len` is a valid out pointer. The call fails
        // (ERROR_INSUFFICIENT_BUFFER) and sets `len`, which is checked below.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if (len as usize) < size_of::<TOKEN_USER>() {
            return Err(io::Error::last_os_error());
        }
        // u64 elements: the buffer is aligned for TOKEN_USER (pointer alignment).
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let cap = u32::try_from(buf.len() * 8).map_err(io::Error::other)?;
        let mut written = 0u32;
        // SAFETY: the buffer is valid for writes of `cap` bytes, at least `len` as the size query asked.
        check(unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), cap, &mut written) })?;
        if (written as usize) < size_of::<TOKEN_USER>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a short TOKEN_USER"));
        }
        // SAFETY: the system wrote a TOKEN_USER at the start of the aligned buffer; its SID points into the buffer,
        // which lives until `from_psid` has copied it.
        unsafe {
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            Sid::from_psid(user.User.Sid)
        }
    }

    /// Copies a SID.
    ///
    /// # Safety
    /// `psid` is null or points to memory that holds a SID (as the system wrote it) for the duration of the call.
    pub(crate) unsafe fn from_psid(psid: PSID) -> io::Result<Sid> {
        if psid.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no SID"));
        }
        // SAFETY: by the caller's contract `psid` points to a SID; IsValidSid checks the revision and the
        // sub-authority count before GetLengthSid computes the length from that count.
        unsafe {
            if IsValidSid(psid) == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "not a valid SID"));
            }
            let len = GetLengthSid(psid) as usize;
            Sid::from_bytes(std::slice::from_raw_parts(psid as *const u8, len))
        }
    }

    /// A SID from its binary form, checked: revision 1, at most 15 sub-authorities, exactly the length they need.
    pub(crate) fn from_bytes(b: &[u8]) -> io::Result<Sid> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "not a valid SID");
        if b.len() < 8 || b[0] != 1 || b[1] > 15 || b.len() != 8 + 4 * usize::from(b[1]) {
            return Err(invalid());
        }
        Ok(Sid(b.to_vec()))
    }

    /// A SID from its string form (`S-1-5-…`) or an SDDL alias (`SY`, `BA`, `LA`, …), as the system reads SDDL:
    /// `ConvertStringSidToSidW`. An alias of a machine-relative account (`LA`, `LG`) resolves on this machine.
    pub fn parse(s: &str) -> io::Result<Sid> {
        let w = wide(OsStr::new(s))?;
        let mut psid: PSID = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated UTF-16 that lives across the call; `psid` is a valid out pointer.
        check(unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut psid) })?;
        // The call allocated the SID with LocalAlloc: freed when `_owned` drops, after the copy.
        let _owned = LocalBox(psid);
        // SAFETY: the call succeeded, so `psid` points to a SID the system wrote, alive until `_owned` drops.
        unsafe { Sid::from_psid(psid) }
    }

    /// `NT AUTHORITY\SYSTEM` (S-1-5-18).
    pub fn local_system() -> Sid {
        well_known(WinLocalSystemSid)
    }

    /// `NT AUTHORITY\NETWORK` (S-1-5-2): every logon over the network.
    pub fn network() -> Sid {
        well_known(WinNetworkSid)
    }

    /// `OWNER RIGHTS` (S-1-3-4): an ACE for it replaces the owner's implicit `READ_CONTROL | WRITE_DAC`.
    pub fn owner_rights() -> Sid {
        well_known(WinCreatorOwnerRightsSid)
    }

    /// `BUILTIN\Users` (S-1-5-32-545).
    pub fn builtin_users() -> Sid {
        well_known(WinBuiltinUsersSid)
    }

    /// `NT AUTHORITY\INTERACTIVE` (S-1-5-4): every logon at the console or over Remote Desktop (not a network logon).
    pub fn interactive() -> Sid {
        well_known(WinInteractiveSid)
    }

    /// `BUILTIN\Administrators` (S-1-5-32-544).
    pub fn builtin_administrators() -> Sid {
        well_known(WinBuiltinAdministratorsSid)
    }

    /// For the security APIs, which take a non-const pointer but do not write through it.
    pub(crate) fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.0.len()
    }
}

/// Whether this process runs with an elevated token (an administrator's full token: "Run as administrator", an
/// administrator without UAC, a CI runner). `false` when the token cannot be read.
pub fn this_process_is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    // SAFETY: OpenProcessToken succeeded, so `token` is a new handle that nobody else owns; it is closed on drop.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `elevation` is a writable TOKEN_ELEVATION of the given size; the token is open with TOKEN_QUERY.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    } != 0;
    ok && elevation.TokenIsElevated != 0
}

fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Sid {
    let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is valid for writes of `len` bytes, room for any SID (SECURITY_MAX_SID_SIZE); these kinds need
    // no domain SID.
    let ok = unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
    assert!(ok != 0, "CreateWellKnownSid({kind}) cannot fail for a domain-less SID");
    buf.truncate(len as usize);
    Sid::from_bytes(&buf).expect("CreateWellKnownSid writes a valid SID")
}

/// The standard string form (`S-1-5-21-…`), computed from the bytes (MS-DTYP 2.4.2.1): revision, the 48-bit
/// identifier authority (in hex as `0x…` when it does not fit 32 bits), then each sub-authority.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let authority = b[2..8].iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
        if authority >> 32 == 0 {
            write!(f, "S-{}-{authority}", b[0])?;
        } else {
            write!(f, "S-{}-0x{authority:012X}", b[0])?;
        }
        for sub in b[8..].as_chunks::<4>().0 {
            write!(f, "-{}", u32::from_le_bytes(*sub))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
