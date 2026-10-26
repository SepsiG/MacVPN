//! The vault key in Credential Manager: one generic credential, DPAPI-protected for this user, never roaming.

use macvpn_core::vault::{KeyStore, KeyStoreError};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, GetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

/// The production credential: target `local.winvpn.vault`, user name `dek` (storage identifiers: literals).
pub(crate) const VAULT_TARGET: &str = "local.winvpn.vault";
pub(crate) const VAULT_USER: &str = "dek";
/// Credential Manager's limit for a generic credential's blob (CRED_MAX_CREDENTIAL_BLOB_SIZE).
const MAX_BLOB: usize = 5 * 512;

pub(crate) struct CredentialKeyStore {
    target: Vec<u16>,
    user: Vec<u16>,
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// The error of a failed call (status codes only, never key material).
fn failure(code: u32) -> KeyStoreError {
    if code == ERROR_NO_SUCH_LOGON_SESSION {
        KeyStoreError::Unavailable(format!("no logon session ({code})"))
    } else {
        KeyStoreError::Io(format!("Credential Manager error {code}"))
    }
}

/// The credential CredReadW returned: its blob is wiped before CredFree.
struct Read(*mut CREDENTIALW);

impl Read {
    /// The blob (empty when the credential has none), alive as long as `self`.
    fn blob(&self) -> &[u8] {
        // SAFETY: `self.0` came from a successful CredReadW and stays valid until `drop`; the blob pointer and size
        // describe the system's buffer.
        unsafe {
            let c = &*self.0;
            if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize)
            }
        }
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful CredReadW and is freed exactly once; the blob pointer and size
        // are the system's, writable (CredReadW allocates one buffer for the struct and its data).
        unsafe {
            let c = &*self.0;
            if !c.CredentialBlob.is_null() {
                std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize).zeroize();
            }
            CredFree(self.0.cast());
        }
    }
}

impl CredentialKeyStore {
    pub(crate) fn new(target: &str, user: &str) -> Self {
        CredentialKeyStore { target: wide(target), user: wide(user) }
    }

    fn read(&self) -> Result<Option<Read>, KeyStoreError> {
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is NUL-terminated; `cred` is a valid out pointer.
        if unsafe { CredReadW(self.target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
            // SAFETY: plain call.
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND { Ok(None) } else { Err(failure(code)) };
        }
        if cred.is_null() {
            return Err(KeyStoreError::Io("Credential Manager returned no credential".into()));
        }
        Ok(Some(Read(cred)))
    }
}

impl KeyStore for CredentialKeyStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let Some(read) = self.read()? else { return Ok(None) };
        let blob = read.blob();
        if blob.is_empty() {
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(blob.to_vec())))
    }

    fn exists(&self) -> Result<bool, KeyStoreError> {
        Ok(self.read()?.is_some())
    }

    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        if key.is_empty() || key.len() > MAX_BLOB {
            return Err(KeyStoreError::Io("invalid key length".into()));
        }
        let mut blob = Zeroizing::new(key.to_vec());
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: self.target.as_ptr().cast_mut(),
            UserName: self.user.as_ptr().cast_mut(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: every pointer in `cred` outlives the call; CredWriteW copies the blob.
        if unsafe { CredWriteW(&cred, 0) } == 0 {
            // SAFETY: plain call.
            return Err(failure(unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        // SAFETY: `target` is NUL-terminated.
        if unsafe { CredDeleteW(self.target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: plain call.
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(failure(code));
            }
        }
        Ok(())
    }
}
