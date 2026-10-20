//! The password-sealed container shared by the full backup (`.macvpnbackup`) and the admin key file
//! (`.macvpnadminkey`, catalog plan Task 14), and the reader both use for a file the user picked. All integers big-endian: a 64-byte header followed by the ciphertext.
//!
//! ```text
//! magic        8  per file type
//! format       2
//! kdf          1  1 = Argon2id
//! reserved     1  0
//! m_kib        4
//! t            4
//! p            4
//! salt        16
//! nonce       24
//! ciphertext   …  XChaCha20-Poly1305(key = Argon2id(password, salt, params), nonce, plaintext,
//!                 AAD = the 64 header bytes), the 16-byte tag last
//! ```
//!
//! The key derivation is the vault's own ([`derive_kek`], with its floor), under a lower ceiling ([`MAX_KDF`]),
//! checked before the KDF runs. Opening fails with one generic [`SealedError::CannotOpen`] for a wrong password,
//! any damaged byte, a truncated file, an unknown KDF or impossible parameters. Only a newer `format` is told apart
//! (checked first, since an unknown format cannot be authenticated).

use super::entropy::Entropy;
use super::keys::{KdfParams, derive_kek};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const TAG_LEN: usize = 16;
/// The KDF ceiling of a sealed header (below the vault's own): 256 MiB, 64 passes, 4 lanes.
pub(crate) const MAX_KDF: KdfParams = KdfParams { m_kib: 256 * 1024, t: 64, p: 4 };

const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Why a container could not be sealed or opened. No variant carries the password or the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealedError {
    /// A wrong password or a damaged, truncated or foreign file: deliberately one error for all of them.
    CannotOpen,
    /// A container `format` above the one this build reads.
    NewerVersion(u16),
    /// Over the caller's size cap.
    TooLarge,
    /// Sealing failed (randomness, parameters above the ceiling).
    Io(String),
}

fn within_ceiling(kdf: KdfParams) -> bool {
    kdf.m_kib <= MAX_KDF.m_kib && kdf.t <= MAX_KDF.t && kdf.p <= MAX_KDF.p
}

fn header(
    magic: &[u8; 8],
    format: u16,
    kdf: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(magic);
    h[8..10].copy_from_slice(&format.to_be_bytes());
    h[10] = KDF_ARGON2ID;
    h[11] = 0;
    h[12..16].copy_from_slice(&kdf.m_kib.to_be_bytes());
    h[16..20].copy_from_slice(&kdf.t.to_be_bytes());
    h[20..24].copy_from_slice(&kdf.p.to_be_bytes());
    h[24..40].copy_from_slice(salt);
    h[40..HEADER_LEN].copy_from_slice(nonce);
    h
}

/// Seals `plaintext`. `kdf` is raised to at least [`KdfParams::DEFAULT`] (never lowered) and must stay within
/// [`MAX_KDF`]; salt and nonce come fresh from `e`. The plaintext is copied straight into the output buffer and
/// encrypted there, so no other copy is made. Runs the KDF: call it off the main thread.
pub(crate) fn seal_with_password(
    magic: &[u8; 8],
    format: u16,
    plaintext: &[u8],
    password: &str,
    kdf: KdfParams,
    e: &dyn Entropy,
) -> Result<Vec<u8>, SealedError> {
    let kdf = kdf.strengthened();
    if !within_ceiling(kdf) {
        return Err(SealedError::Io("the key derivation parameters are above the ceiling".into()));
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    e.fill(&mut salt).map_err(|e| SealedError::Io(e.to_string()))?;
    e.fill(&mut nonce).map_err(|e| SealedError::Io(e.to_string()))?;
    let header = header(magic, format, kdf, &salt, &nonce);
    let key = derive_kek(password.as_bytes(), &salt, kdf).map_err(|e| SealedError::Io(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SealedError::Io("invalid key".into()))?;
    // Wiped if anything fails before the plaintext in it has been encrypted.
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN));
    out.extend_from_slice(&header);
    out.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &header, (&mut out[HEADER_LEN..]).into())
        .map_err(|_| SealedError::Io("encryption failed".into()))?;
    out.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *out))
}

/// Opens a sealed container of type `magic` (see the module docs for the errors); `max_len` caps the whole file.
/// Runs the KDF (up to [`MAX_KDF`], seconds): call it off the main thread.
pub(crate) fn open_with_password(
    bytes: &[u8],
    magic: &[u8; 8],
    format: u16,
    password: &str,
    max_len: usize,
) -> Result<Zeroizing<Vec<u8>>, SealedError> {
    if bytes.len() > max_len {
        return Err(SealedError::TooLarge);
    }
    if bytes.len() < HEADER_LEN + TAG_LEN || &bytes[..8] != magic {
        return Err(SealedError::CannotOpen);
    }
    let found = u16::from_be_bytes([bytes[8], bytes[9]]);
    if found > format {
        return Err(SealedError::NewerVersion(found));
    }
    if found != format || bytes[10] != KDF_ARGON2ID || bytes[11] != 0 {
        return Err(SealedError::CannotOpen);
    }
    let word = |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let kdf = KdfParams { m_kib: word(12), t: word(16), p: word(20) };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[24..40]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[40..HEADER_LEN]);
    let (header, rest) = bytes.split_at(HEADER_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    // Above the ceiling: refused before the KDF runs. Below the vault's floor: refused by `derive_kek`.
    if !within_ceiling(kdf) {
        return Err(SealedError::CannotOpen);
    }
    let key = derive_kek(password.as_bytes(), &salt, kdf).map_err(|_| SealedError::CannotOpen)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| SealedError::CannotOpen)?;
    let tag = Tag::try_from(tag).map_err(|_| SealedError::CannotOpen)?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&XNonce::from(nonce), header, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| SealedError::CannotOpen)?;
    Ok(plaintext)
}

/// Why [`read_sealed_file`] read nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadError {
    TooLarge,
    /// Missing, a symlink, not a regular file, unreadable.
    CannotRead,
}

/// Reads a sealed file a user picked: never follows a symlink (`O_NOFOLLOW`), never blocks on a FIFO
/// (`O_NONBLOCK`), only a regular file, and at most `cap` bytes (read through `take`, so a file that grows while it
/// is read cannot exhaust memory).
pub(crate) fn read_sealed_file(path: &Path, cap: usize) -> Result<Vec<u8>, ReadError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ReadError::CannotRead)?;
    let meta = file.metadata().map_err(|_| ReadError::CannotRead)?;
    if !meta.file_type().is_file() {
        return Err(ReadError::CannotRead);
    }
    if meta.len() > cap as u64 {
        return Err(ReadError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes).map_err(|_| ReadError::CannotRead)?;
    if bytes.len() > cap {
        return Err(ReadError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::vault::FixedEntropy;

    const MAGIC: &[u8; 8] = b"MVPNTEST";

    #[test]
    fn round_trip_and_the_generic_error() {
        let e = FixedEntropy::new(1);
        let kdf = KdfParams::insecure_for_tests();
        let sealed = seal_with_password(MAGIC, 1, b"plain text", "password", kdf, &e).unwrap();
        assert_eq!(sealed.len(), HEADER_LEN + 10 + TAG_LEN);
        assert!(!sealed.windows(10).any(|w| w == b"plain text"));
        assert_eq!(&open_with_password(&sealed, MAGIC, 1, "password", 1024).unwrap()[..], b"plain text");
        assert_eq!(open_with_password(&sealed, MAGIC, 1, "wrong", 1024), Err(SealedError::CannotOpen));
        assert_eq!(open_with_password(&sealed, b"MVPNOTHR", 1, "password", 1024), Err(SealedError::CannotOpen));
        assert_eq!(open_with_password(&sealed, MAGIC, 1, "password", 10), Err(SealedError::TooLarge));
        let mut newer = sealed.clone();
        newer[9] = 2;
        assert_eq!(open_with_password(&newer, MAGIC, 1, "password", 1024), Err(SealedError::NewerVersion(2)));
    }
}
