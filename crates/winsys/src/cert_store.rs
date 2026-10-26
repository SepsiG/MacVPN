//! The certificate stores of the computer and of the user: does a system store (e.g. `Root`, the Trusted Root
//! Certification Authorities) hold the certificate with this SHA-1 thumbprint, and with which enhanced key usage
//! property; adding a certificate with its enhanced key usage property already set, and removing one.
//!
//! The only writer in WinVPN is the elevated **Trust This CA in Windows…** step (`WinVPN.exe
//! --winvpn-trust-ca-step`, M-1 of the 2.0.0 security review): it adds the CA to the computer's `Root` store with
//! the property `CERT_ENHKEY_USAGE_PROP_ID` = server and client authentication, so Windows trusts it for TLS (SSTP,
//! IKEv2, any HTTPS) but not for code signing, time stamping or anything else. The property is set on the
//! certificate before it enters the store ([`add_with_usage`]), read back from the store, and the certificate is
//! removed again when the store does not hold exactly that property.

use crate::util::wide;
use std::ffi::OsStr;
use std::io;
use windows_sys::Win32::Foundation::CRYPT_E_EXISTS;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_ENHKEY_USAGE_PROP_ID, CERT_FIND_SHA1_HASH, CERT_STORE_ADD_NEW, CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, CertCloseStore,
    CertCreateCertificateContext, CertDeleteCertificateFromStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGetCertificateContextProperty, CertOpenStore, CertSetCertificateContextProperty,
    HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

/// Whose system store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// The computer's (`HKLM`): readable by everyone, writable by administrators.
    LocalMachine,
    /// The signed-in user's (`HKCU`).
    CurrentUser,
}

/// A certificate in a store, as [`presence`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    Absent,
    /// `usage`: the DER `ExtKeyUsageSyntax` of its `CERT_ENHKEY_USAGE_PROP_ID` property (`None`: no property, so
    /// every usage the certificate itself allows).
    Present {
        usage: Option<Vec<u8>>,
    },
}

/// What [`add_with_usage`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// Added, and the store holds it with exactly the usage property asked for.
    New,
    /// The store held the certificate already: left as it was (its properties untouched).
    AlreadyThere,
}

const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

/// An open system store, closed on drop.
struct Store(HCERTSTORE);

impl Store {
    fn open(location: Location, name: &str, writable: bool) -> io::Result<Store> {
        let wname = wide(OsStr::new(name))?;
        let place = match location {
            Location::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            Location::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        };
        let flags = place | CERT_STORE_OPEN_EXISTING_FLAG | if writable { 0 } else { CERT_STORE_READONLY_FLAG };
        // SAFETY: `wname` is NUL-terminated and outlives the call; the system provider takes the store name as
        // `pvPara`; no legacy provider handle (0).
        let handle = unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, wname.as_ptr().cast()) };
        if handle.is_null() { Err(io::Error::last_os_error()) } else { Ok(Store(handle)) }
    }

    /// The certificate with this SHA-1 thumbprint (a context the caller frees), or `None`.
    fn find(&self, sha1: &[u8; 20]) -> Option<Context> {
        let blob = CRYPT_INTEGER_BLOB { cbData: sha1.len() as u32, pbData: sha1.as_ptr().cast_mut() };
        // SAFETY: an open store; `blob` points at 20 bytes that live across the call (only read); no previous
        // context.
        let found = unsafe {
            CertFindCertificateInStore(
                self.0,
                ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                (&raw const blob).cast(),
                std::ptr::null(),
            )
        };
        (!found.is_null()).then_some(Context(found))
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store opened in `open`, closed once (no flags: every context is freed by its own guard).
        unsafe { CertCloseStore(self.0, 0) };
    }
}

/// A certificate context, freed on drop.
struct Context(*const CERT_CONTEXT);

impl Context {
    /// The enhanced key usage property's bytes; `None` when it is not set.
    fn usage(&self) -> io::Result<Option<Vec<u8>>> {
        let mut len = 0u32;
        // SAFETY: a valid context; a size query (null buffer).
        let ok = unsafe {
            CertGetCertificateContextProperty(self.0, CERT_ENHKEY_USAGE_PROP_ID, std::ptr::null_mut(), &mut len)
        };
        if ok == 0 {
            // CRYPT_E_NOT_FOUND: no such property.
            return Ok(None);
        }
        let mut data = vec![0u8; len as usize];
        // SAFETY: `data` is writable for `len` bytes, the size the query returned; the call updates `len`.
        let ok = unsafe {
            CertGetCertificateContextProperty(self.0, CERT_ENHKEY_USAGE_PROP_ID, data.as_mut_ptr().cast(), &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        data.truncate(len as usize);
        Ok(Some(data))
    }

    fn set_usage(&self, usage_der: &[u8]) -> io::Result<()> {
        let blob = CRYPT_INTEGER_BLOB { cbData: usage_der.len() as u32, pbData: usage_der.as_ptr().cast_mut() };
        // SAFETY: a valid context; `blob` points at `usage_der`, which lives across the call (copied, only read).
        let ok = unsafe {
            CertSetCertificateContextProperty(self.0, CERT_ENHKEY_USAGE_PROP_ID, 0, (&raw const blob).cast())
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Deletes the certificate from its store (which frees the context, also on failure).
    fn delete(self) -> io::Result<()> {
        let ctx = self.0;
        std::mem::forget(self);
        // SAFETY: a context of an open store, owned here; the call frees it whatever it answers.
        if unsafe { CertDeleteCertificateFromStore(ctx) } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: a context this guard owns, freed once.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

/// Whether the local machine's system store `store` (e.g. `Root`) holds a certificate whose SHA-1 thumbprint is
/// `sha1`. The store is opened read-only and must exist. The logical store includes its physical parts (for
/// `Root`: the local machine's, Group Policy's and the enterprise's), which is what Windows trusts.
pub fn local_machine_contains(store: &str, sha1: &[u8; 20]) -> io::Result<bool> {
    Ok(Store::open(Location::LocalMachine, store, false)?.find(sha1).is_some())
}

/// The certificate with SHA-1 thumbprint `sha1` in the system store `store` of `location` (opened read-only; it
/// must exist), and its enhanced key usage property.
pub fn presence(location: Location, store: &str, sha1: &[u8; 20]) -> io::Result<Presence> {
    match Store::open(location, store, false)?.find(sha1) {
        None => Ok(Presence::Absent),
        Some(cert) => Ok(Presence::Present { usage: cert.usage()? }),
    }
}

/// Adds the certificate `der` to the system store `store` of `location` with the enhanced key usage property
/// `usage_der` (a DER `ExtKeyUsageSyntax`), never without it: the property is set on the certificate before it is
/// added (`CertAddCertificateContextToStore` copies a context's properties), read back from the store, and when it
/// is not exactly `usage_der` the certificate is removed again and an error of kind `InvalidData` returned (any
/// other error: nothing was added, or it could not be removed). A certificate the store already holds is left as it
/// is ([`Added::AlreadyThere`]).
pub fn add_with_usage(location: Location, store: &str, der: &[u8], usage_der: &[u8]) -> io::Result<Added> {
    // SAFETY: `der` is readable for its length; the call copies it into a new context (owned by the guard).
    let created = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as u32) };
    if created.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cert = Context(created);
    cert.set_usage(usage_der)?;
    let store = Store::open(location, store, true)?;
    let mut stored: *mut CERT_CONTEXT = std::ptr::null_mut();
    // SAFETY: an open store and a valid context; `stored` receives the store's own context (owned by the guard).
    if unsafe { CertAddCertificateContextToStore(store.0, cert.0, CERT_STORE_ADD_NEW, &mut stored) } == 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(CRYPT_E_EXISTS) { Ok(Added::AlreadyThere) } else { Err(e) };
    }
    let stored = Context(stored);
    let restricted = |c: &Context| c.usage().is_ok_and(|u| u.as_deref() == Some(usage_der));
    if restricted(&stored) || (stored.set_usage(usage_der).is_ok() && restricted(&stored)) {
        return Ok(Added::New);
    }
    match stored.delete() {
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the store did not keep the usage property; the certificate was removed again",
        )),
        Err(e) => Err(io::Error::other(format!(
            "the store did not keep the usage property, and the certificate could not be removed again: {e}"
        ))),
    }
}

/// Removes the certificate with SHA-1 thumbprint `sha1` from the system store `store` of `location`; `false` when
/// the store does not hold it.
pub fn remove(location: Location, store: &str, sha1: &[u8; 20]) -> io::Result<bool> {
    let store = Store::open(location, store, true)?;
    match store.find(sha1) {
        None => Ok(false),
        Some(cert) => cert.delete().map(|()| true),
    }
}
