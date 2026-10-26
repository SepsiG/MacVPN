//! Authenticode: is a file signed, unmodified, by a certificate that chains to a trusted root, and by whom.
//!
//! The policy, as the WinVPN Service needs it before it runs `openvpn.exe` or trusts a downloaded MSI:
//! - `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` (the Authenticode policy provider): the file's hash
//!   must match its signature, the signer certificate must be valid for code signing and chain to a root in the
//!   machine's trusted roots, and must have been valid when the file was signed (a timestamp) or now. An explicitly
//!   distrusted certificate (the `Disallowed` store) is refused.
//! - **Embedded signatures only** (`WTD_CHOICE_FILE`): a file signed only through a catalog in `CatRoot` (most of
//!   Windows' own binaries) has no embedded signature and is refused. The signers WinVPN pins (OpenVPN, WireGuard
//!   LLC) sign their files themselves.
//! - **Revocation is not checked** (`WTD_REVOKE_NONE`, plus `WTD_CACHE_ONLY_URL_RETRIEVAL` so no part of the check
//!   touches the network): the service runs this before every OpenVPN start, possibly before any network is up and
//!   with no VPN yet; an online check would make a connection wait for (or depend on) a CRL server, and Authenticode
//!   treats "revocation server offline" as a failure. What a revoked-but-otherwise-valid certificate could sign is
//!   bounded by the other pins: the signer's name and its issuing CA's key (the caller compares both), an
//!   admin-only path (only an administrator can place the file), and for bundled files a SHA-256 pin.
//! - The signer is the primary signature's leaf certificate; its simple display name (`CertGetNameStringW` with
//!   `CERT_NAME_SIMPLE_DISPLAY_TYPE`: the subject's CN) is returned for the caller to compare with its pin.
//! - **The signer's chain** as `WinVerifyTrust` built it (`CRYPT_PROVIDER_SGNR.pasCertChain`: the signer first, up
//!   to the root) is returned as each certificate's SPKI SHA-256 (the SHA-256 of its DER `SubjectPublicKeyInfo`,
//!   as `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256` prints it). [`Signer::is_pinned`] asks
//!   for the pinned name *and* a pinned CA key above the signer (M-1 of the 2.0.0 security review): any root in the
//!   machine's store, an operator CA that **Trust This CA in Windows…** or a TLS-inspection product added among
//!   them, can issue a certificate named `WireGuard LLC`, but not one under the publisher's real CA.
//!
//! Anything that cannot be completed (no signature, a hash mismatch, an untrusted chain, no signer certificate, no
//! name) is an error: fail closed.

use crate::util::{plain_absolute, wide_path};
use std::io;
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW, CryptEncodeObject, CryptHashCertificate2,
    X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};

/// The signer of a file whose embedded Authenticode signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// The signer certificate's simple display name (its CN), e.g. `OpenVPN Inc.`.
    pub subject: String,
    /// The SPKI SHA-256 (64 lower-case hex digits) of each certificate of the signer's chain: the signer's own
    /// first, then its issuing CA, up to the root.
    pub chain_spki_sha256: Vec<String>,
}

impl Signer {
    /// Whether the signer is `name` and a CA above it in its chain (not the signer's own certificate) has one of
    /// the keys `ca_spki_sha256` (lower-case hex, as the pin files list them).
    pub fn is_pinned(&self, name: &str, ca_spki_sha256: &[&str]) -> bool {
        self.subject == name && self.chain_spki_sha256.iter().skip(1).any(|h| ca_spki_sha256.contains(&h.as_str()))
    }
}

/// Verifies the embedded Authenticode signature of the file at `path` (a plain absolute path) and returns its
/// signer. See the module documentation for the policy.
pub fn verify_signature(path: &Path) -> io::Result<Signer> {
    plain_absolute(path)?;
    let wpath = wide_path(path)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wpath.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data`, `file` and the NUL-terminated path they point to live across this call and the close below
    // (no UI is shown: `WTD_UI_NONE`). The call fills `hWVTStateData`, which the close below releases.
    let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, (&raw mut data).cast()) };
    let signer = if status == 0 {
        // SAFETY: the verify succeeded and its state stays open until the close below.
        unsafe { signer_of(&data) }
    } else {
        Err(io::Error::from_raw_os_error(status))
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: releases the state the verify call opened (required after a failed verify too); the same live `data`.
    // Its result carries no information.
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, (&raw mut data).cast()) };
    signer
}

/// The simple display name of the primary signer's leaf certificate and its chain's keys.
///
/// # Safety
/// `data.hWVTStateData` is the state of a successful `WTD_STATEACTION_VERIFY` that is still open (not yet closed)
/// for the whole call.
unsafe fn signer_of(data: &WINTRUST_DATA) -> io::Result<Signer> {
    let fail = || io::Error::new(io::ErrorKind::InvalidData, "the signature names no signer certificate");
    // SAFETY: by the contract the state is open; the provider data, the signer and its certificate chain are owned
    // by that state and stay valid until it is closed (after this function). Every pointer is checked for null and
    // the chain's length before it is read.
    unsafe {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return Err(fail());
        }
        let signer = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if signer.is_null() || (*signer).dwError != 0 || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null()
        {
            return Err(fail());
        }
        let chain = std::slice::from_raw_parts((*signer).pasCertChain, (*signer).csCertChain as usize);
        let mut chain_spki_sha256 = Vec::with_capacity(chain.len());
        for element in chain {
            if element.pCert.is_null() {
                return Err(fail());
            }
            chain_spki_sha256.push(spki_sha256(element.pCert).ok_or_else(fail)?);
        }
        // The chain's first element is the signer's own certificate.
        let subject = simple_name(chain[0].pCert).ok_or_else(fail)?;
        Ok(Signer { subject, chain_spki_sha256 })
    }
}

/// The SHA-256 of the certificate's DER `SubjectPublicKeyInfo`, as lower-case hex; `None` when it cannot be encoded
/// or hashed.
///
/// # Safety
/// `cert` is a valid certificate context for the whole call.
unsafe fn spki_sha256(cert: *const CERT_CONTEXT) -> Option<String> {
    // SAFETY: by the contract the context and its `pCertInfo` are valid; checked for null.
    let info = unsafe { (*cert).pCertInfo };
    if info.is_null() {
        return None;
    }
    // SAFETY: `info` is valid (above); the key info lives as long as the context.
    let spki = unsafe { &raw const (*info).SubjectPublicKeyInfo };
    let mut len = 0u32;
    // SAFETY: a size query (null output buffer); `spki` is a valid CERT_PUBLIC_KEY_INFO for X509_PUBLIC_KEY_INFO.
    if unsafe {
        CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki.cast(), std::ptr::null_mut(), &mut len)
    } == 0
        || len == 0
    {
        return None;
    }
    let mut der = vec![0u8; len as usize];
    // SAFETY: `der` is valid for writes of `len` bytes, the size the query returned; the call updates `len`.
    if unsafe { CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki.cast(), der.as_mut_ptr(), &mut len) }
        == 0
    {
        return None;
    }
    der.truncate(len as usize);
    let mut hash = [0u8; 32];
    let mut hash_len = hash.len() as u32;
    let algorithm: Vec<u16> = "SHA256".encode_utf16().chain(Some(0)).collect();
    // SAFETY: `algorithm` is a NUL-terminated CNG algorithm name; `der` is readable for its length; `hash` is
    // writable for `hash_len` bytes; no reserved pointer.
    let ok = unsafe {
        CryptHashCertificate2(
            algorithm.as_ptr(),
            0,
            std::ptr::null(),
            der.as_ptr(),
            der.len() as u32,
            hash.as_mut_ptr(),
            &mut hash_len,
        )
    };
    (ok != 0 && hash_len == 32).then(|| hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// The certificate's simple display name; `None` when it has none.
///
/// # Safety
/// `cert` is a valid certificate context for the whole call.
unsafe fn simple_name(cert: *const CERT_CONTEXT) -> Option<String> {
    // SAFETY: by the contract; a size query (null buffer, length 0) returns the length including the NUL.
    let len = unsafe {
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), std::ptr::null_mut(), 0)
    };
    if len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: by the contract; `buf` is valid for writes of `len` UTF-16 units, the size the query returned.
    let n =
        unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), len) };
    // The same certificate gives the same length; anything else (a truncated name) is refused.
    if n != len {
        return None;
    }
    buf.truncate(n as usize - 1);
    if buf.contains(&0) {
        return None;
    }
    String::from_utf16(&buf).ok()
}
