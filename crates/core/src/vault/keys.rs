//! The key hierarchy (spec 2.2): the random database key (DEK) wrapped twice in `vault.keys`.
//!
//! - password slot: `KEK_pw = Argon2id(master password, salt₁)`, `XChaCha20-Poly1305(KEK_pw, nonce, DEK,
//!   aad = "macvpn-vault-v1|pw")`
//! - recovery slot: the same with the decoded recovery key and `aad = "macvpn-vault-v1|rc"`
//!
//! Every wrap takes a fresh salt and nonce. An unwrap failure is always [`KeyError::Wrong`], whatever part (the
//! secret, the salt, the nonce, the ciphertext or the slot's AAD) was wrong, so the error tells nothing about which.

use super::entropy::Entropy;
use super::recovery::RecoveryKey;
use crate::fsx::{self, Follow, OpenFor};
use crate::l10n::{Arg, tr};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use serde_json::{Value, json};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

pub const KEYS_FILE: &str = "vault.keys";
pub const AAD_PASSWORD: &[u8] = b"macvpn-vault-v1|pw";
pub const AAD_RECOVERY: &[u8] = b"macvpn-vault-v1|rc";
/// The master password's minimum length, in characters (grapheme clusters).
pub const MIN_PASSWORD_CHARS: usize = 10;

const FILE_VERSION: u32 = 1;
const DEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = DEK_LEN + TAG_LEN;
/// `vault.keys` is a few hundred bytes; anything much larger is not ours.
const MAX_FILE_LEN: u64 = 64 * 1024;
/// The floor for parameters read from the file or passed to `create` (security review M1: a tampered file must not
/// downgrade the KDF): 64 MiB and 3 passes, the spec's original cost. New wraps use at least
/// [`KdfParams::DEFAULT`] anyway ([`KdfParams::strengthened`]).
const MIN_M_KIB: u32 = 65536;
const MIN_T: u32 = 3;
/// The ceiling (a tampered file must not make the KDF allocate or spin without limit): 1 GiB, 256 passes, 16 lanes.
const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_T: u32 = 256;
const MAX_P: u32 = 16;

/// Argon2id cost parameters, stored in `vault.keys` so they can be raised later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 32 passes, 1 lane: about 0.66 s on an M5 (spike report, part C). The spec's `t = 3` took 60 ms.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 65536, t: 32, p: 1 };

    /// Tiny parameters that keep tests fast, accepted below the floor only with the `test-support` feature (which
    /// only this crate's own tests enable). **Never** for a real vault.
    #[cfg(feature = "test-support")]
    pub const fn insecure_for_tests() -> KdfParams {
        KdfParams { m_kib: 64, t: 1, p: 1 }
    }

    /// Within the floor and the ceiling (or, in test builds, exactly the test parameters).
    fn is_allowed(self) -> bool {
        #[cfg(feature = "test-support")]
        if self == Self::insecure_for_tests() {
            return true;
        }
        (MIN_M_KIB..=MAX_M_KIB).contains(&self.m_kib)
            && (MIN_T..=MAX_T).contains(&self.t)
            && (1..=MAX_P).contains(&self.p)
    }

    /// The parameters for a new wrap: each one at least [`KdfParams::DEFAULT`]'s, never lowered. (In test builds
    /// the test parameters stay as they are.)
    pub fn strengthened(self) -> KdfParams {
        #[cfg(feature = "test-support")]
        if self == Self::insecure_for_tests() {
            return self;
        }
        KdfParams {
            m_kib: self.m_kib.max(Self::DEFAULT.m_kib),
            t: self.t.max(Self::DEFAULT.t),
            p: self.p.max(Self::DEFAULT.p),
        }
    }

    fn argon2_params(self) -> Option<Params> {
        if !self.is_allowed() {
            return None;
        }
        Params::new(self.m_kib, self.t, self.p, Some(DEK_LEN)).ok()
    }
}

/// The database key. No `Clone`, a redacted `Debug`, wiped on drop.
pub struct Dek(Zeroizing<[u8; DEK_LEN]>);

impl Dek {
    /// 32 fresh random bytes.
    pub fn generate(e: &dyn Entropy) -> io::Result<Dek> {
        let mut key = Zeroizing::new([0u8; DEK_LEN]);
        e.fill(&mut key[..])?;
        Ok(Dek(key))
    }

    /// A DEK read back from the OS key store; `None` unless exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Dek> {
        if bytes.len() != DEK_LEN {
            return None;
        }
        let mut key = Zeroizing::new([0u8; DEK_LEN]);
        key.copy_from_slice(bytes);
        Some(Dek(key))
    }

    pub fn as_bytes(&self) -> &[u8; DEK_LEN] {
        &self.0
    }

    /// Lower-case hex, for SQLCipher's raw-key pragma (`x'…'`).
    pub fn hex(&self) -> Zeroizing<String> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = Zeroizing::new(String::with_capacity(DEK_LEN * 2));
        for b in self.0.iter() {
            s.push(char::from(DIGITS[usize::from(b >> 4)]));
            s.push(char::from(DIGITS[usize::from(b & 0x0F)]));
        }
        s
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(..)")
    }
}

/// One wrapped copy of the DEK, with its own KDF parameters (so each slot can be raised on its own).
#[derive(Clone, PartialEq, Eq)]
pub struct Slot {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext (32 bytes) followed by the Poly1305 tag (16 bytes).
    pub wrapped: Vec<u8>,
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Slot(..)")
    }
}

/// The contents of `vault.keys`.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyFile {
    pub version: u32,
    pub password: Slot,
    pub recovery: Slot,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile").field("version", &self.version).finish_non_exhaustive()
    }
}

/// Why `vault.keys` could not be used. `Wrong` never says which part was wrong.
#[derive(Debug)]
pub enum KeyError {
    /// Wrong password or recovery key, or a slot that does not authenticate.
    Wrong,
    /// Not a valid `vault.keys` (malformed JSON, bad lengths, impossible KDF parameters).
    Corrupt,
    /// Written by a newer MacVPN.
    UnsupportedVersion(u32),
    Io(io::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Wrong => f.write_str("wrong password or recovery key"),
            KeyError::Corrupt => f.write_str("the vault key file is damaged"),
            KeyError::UnsupportedVersion(v) => write!(f, "unsupported vault key file version {v}"),
            KeyError::Io(e) => write!(f, "vault key file: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// `Argon2id(secret, salt, kdf)` → a 32-byte KEK. `Corrupt` for parameters Argon2 (or our bounds) refuse.
pub fn derive_kek(secret: &[u8], salt: &[u8; SALT_LEN], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let params = kdf.argon2_params().ok_or(KeyError::Corrupt)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, &mut kek[..])
        .map_err(|_| KeyError::Corrupt)?;
    Ok(kek)
}

/// The master password rules: at least [`MIN_PASSWORD_CHARS`] characters (grapheme clusters). The error is the
/// localized message for the UI.
pub fn check_password_rules(password: &str) -> Result<(), String> {
    if password.graphemes(true).count() < MIN_PASSWORD_CHARS {
        return Err(tr("The master password must be at least %d characters long", &[Arg::from(MIN_PASSWORD_CHARS)]));
    }
    Ok(())
}

fn wrap(dek: &Dek, secret: &[u8], aad: &[u8], kdf: KdfParams, e: &dyn Entropy) -> io::Result<Slot> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    e.fill(&mut salt)?;
    e.fill(&mut nonce)?;
    let kek = derive_kek(secret, &salt, kdf).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // From the slice: no un-wiped stack copy of the KEK (the cipher wipes its own key schedule on drop).
    let cipher = XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| io::Error::other("invalid key length"))?;
    let mut buffer = Zeroizing::new(*dek.as_bytes());
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), aad, (&mut buffer[..]).into())
        .map_err(|_| io::Error::other("encryption failed"))?;
    let mut wrapped = Vec::with_capacity(WRAPPED_LEN);
    wrapped.extend_from_slice(&buffer[..]);
    wrapped.extend_from_slice(&tag);
    Ok(Slot { kdf, salt, nonce, wrapped })
}

fn unwrap(slot: &Slot, secret: &[u8], aad: &[u8]) -> Result<Dek, KeyError> {
    if slot.wrapped.len() != WRAPPED_LEN {
        return Err(KeyError::Wrong);
    }
    let kek = derive_kek(secret, &slot.salt, slot.kdf).map_err(|_| KeyError::Wrong)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&kek[..]).map_err(|_| KeyError::Wrong)?;
    let mut buffer = Zeroizing::new([0u8; DEK_LEN]);
    buffer.copy_from_slice(&slot.wrapped[..DEK_LEN]);
    let tag = Tag::try_from(&slot.wrapped[DEK_LEN..]).map_err(|_| KeyError::Wrong)?;
    cipher
        .decrypt_inout_detached(&XNonce::from(slot.nonce), aad, (&mut buffer[..]).into(), &tag)
        .map_err(|_| KeyError::Wrong)?;
    Ok(Dek(buffer))
}

impl KeyFile {
    /// Wraps `dek` into a new password slot and a new recovery slot, with `kdf` raised to at least the default.
    /// Parameters below the floor are refused (`InvalidInput`).
    pub fn create(
        dek: &Dek,
        password: &str,
        recovery: &RecoveryKey,
        kdf: KdfParams,
        e: &dyn Entropy,
    ) -> io::Result<KeyFile> {
        if !kdf.is_allowed() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "KDF parameters below the floor"));
        }
        let kdf = kdf.strengthened();
        let password = wrap(dek, password.as_bytes(), AAD_PASSWORD, kdf, e)?;
        let recovery = wrap(dek, &recovery.secret_bytes()[..], AAD_RECOVERY, kdf, e)?;
        Ok(KeyFile { version: FILE_VERSION, password, recovery })
    }

    pub fn unlock_password(&self, password: &str) -> Result<Dek, KeyError> {
        unwrap(&self.password, password.as_bytes(), AAD_PASSWORD)
    }

    pub fn unlock_recovery(&self, key: &RecoveryKey) -> Result<Dek, KeyError> {
        unwrap(&self.recovery, &key.secret_bytes()[..], AAD_RECOVERY)
    }

    /// Rewraps the password slot only (changing the master password; the database is not re-encrypted). The new
    /// slot's parameters are the old ones raised to at least the default.
    pub fn set_password(&mut self, dek: &Dek, new_password: &str, e: &dyn Entropy) -> io::Result<()> {
        let kdf = self.password.kdf.strengthened();
        self.password = wrap(dek, new_password.as_bytes(), AAD_PASSWORD, kdf, e)?;
        Ok(())
    }

    /// Rewraps the recovery slot only; the old recovery key stops working. Parameters as in `set_password`.
    pub fn set_recovery(&mut self, dek: &Dek, key: &RecoveryKey, e: &dyn Entropy) -> io::Result<()> {
        let kdf = self.recovery.kdf.strengthened();
        self.recovery = wrap(dek, &key.secret_bytes()[..], AAD_RECOVERY, kdf, e)?;
        Ok(())
    }

    /// Reads `<dir>/vault.keys`: a regular file (opened without following a symlink, never blocking on a FIFO)
    /// owned by the directory's owner.
    pub fn load(dir: &Path) -> Result<KeyFile, KeyError> {
        // Not a regular file: refused below with the owner check's error, after the directory's owner is read.
        let opened = match fsx::open_regular(&dir.join(KEYS_FILE), OpenFor::Read, Follow::No, false) {
            Ok(opened) => Some(opened),
            Err(e) if fsx::is_not_regular_file(&e) => None,
            Err(e) => return Err(KeyError::Io(e)),
        };
        let dir_owner = fsx::owner(&fs::metadata(dir).map_err(KeyError::Io)?).map_err(KeyError::Io)?;
        let file = match opened {
            Some((file, meta)) if fsx::owner(&meta).map_err(KeyError::Io)? == dir_owner => file,
            _ => {
                return Err(KeyError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "vault.keys must be a regular file of the vault directory's owner",
                )));
            }
        };
        let mut data = Vec::new();
        file.take(MAX_FILE_LEN + 1).read_to_end(&mut data).map_err(KeyError::Io)?;
        if data.len() as u64 > MAX_FILE_LEN {
            return Err(KeyError::Corrupt);
        }
        let json: Value = serde_json::from_slice(&data).map_err(|_| KeyError::Corrupt)?;
        let version = json.get("version").and_then(Value::as_u64).ok_or(KeyError::Corrupt)?;
        let version = u32::try_from(version).map_err(|_| KeyError::UnsupportedVersion(u32::MAX))?;
        if version > FILE_VERSION {
            return Err(KeyError::UnsupportedVersion(version));
        }
        if version != FILE_VERSION {
            return Err(KeyError::Corrupt);
        }
        Ok(KeyFile {
            version,
            password: parse_slot(json.get("password"))?,
            recovery: parse_slot(json.get("recovery"))?,
        })
    }

    /// Writes `<dir>/vault.keys` (JSON, base64 fields) atomically with mode 0600.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let slot = |s: &Slot| {
            json!({
                "kdf": { "m_kib": s.kdf.m_kib, "t": s.kdf.t, "p": s.kdf.p },
                "salt": BASE64.encode(s.salt),
                "nonce": BASE64.encode(s.nonce),
                "wrapped": BASE64.encode(&s.wrapped),
            })
        };
        let value = json!({
            "version": self.version,
            "password": slot(&self.password),
            "recovery": slot(&self.recovery),
        });
        let mut data = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
        data.push(b'\n');
        crate::store::write_private(&data, &dir.join(KEYS_FILE))
    }
}

fn parse_slot(value: Option<&Value>) -> Result<Slot, KeyError> {
    let value = value.ok_or(KeyError::Corrupt)?;
    let kdf = value.get("kdf").ok_or(KeyError::Corrupt)?;
    let number = |key: &str| -> Result<u32, KeyError> {
        kdf.get(key).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or(KeyError::Corrupt)
    };
    let kdf = KdfParams { m_kib: number("m_kib")?, t: number("t")?, p: number("p")? };
    kdf.argon2_params().ok_or(KeyError::Corrupt)?;
    let field = |key: &str| -> Result<Vec<u8>, KeyError> {
        let text = value.get(key).and_then(Value::as_str).ok_or(KeyError::Corrupt)?;
        BASE64.decode(text).map_err(|_| KeyError::Corrupt)
    };
    let salt = field("salt")?.try_into().map_err(|_| KeyError::Corrupt)?;
    let nonce = field("nonce")?.try_into().map_err(|_| KeyError::Corrupt)?;
    let wrapped = field("wrapped")?;
    if wrapped.len() != WRAPPED_LEN {
        return Err(KeyError::Corrupt);
    }
    Ok(Slot { kdf, salt, nonce, wrapped })
}
