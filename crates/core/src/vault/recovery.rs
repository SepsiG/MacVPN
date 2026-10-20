//! The recovery key (spec 2.2): 120 random bits shown as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` in Crockford base32
//! (24 symbols, alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, big-endian bit order). The secret fed to Argon2id is
//! the decoded 15 bytes ([`RecoveryKey::secret_bytes`]), not the text.

use super::crockford::{self, CrockfordError};
use super::entropy::Entropy;
use std::fmt;
use std::io;
use zeroize::Zeroizing;

/// 120 bits.
const BYTES: usize = 15;
const SYMBOLS: usize = 24;
const GROUP: usize = 4;
const GROUPS: usize = SYMBOLS / GROUP;

/// Why a typed recovery key was not accepted. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryKeyError {
    /// Not exactly 24 symbols (separators and spaces aside).
    WrongLength,
    /// A character outside the Crockford alphabet (also `U`).
    InvalidCharacter,
}

/// A recovery key in its canonical form. No `Clone`, a redacted `Debug`, and the text is wiped on drop.
pub struct RecoveryKey(Zeroizing<String>);

impl RecoveryKey {
    /// 15 fresh random bytes.
    pub fn generate(e: &dyn Entropy) -> io::Result<RecoveryKey> {
        let mut bytes = Zeroizing::new([0u8; BYTES]);
        e.fill(&mut bytes[..])?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Case-insensitive; `O` reads as `0`, `I` and `L` as `1`; `-` and white space are ignored.
    pub fn parse(input: &str) -> Result<RecoveryKey, RecoveryKeyError> {
        let values = crockford::normalize(input)
            .map_err(|CrockfordError::InvalidCharacter| RecoveryKeyError::InvalidCharacter)?;
        if values.len() != SYMBOLS {
            return Err(RecoveryKeyError::WrongLength);
        }
        // 24 × 5 = 120 = 15 × 8 bits: nothing is left over, so every 24-symbol text decodes.
        let bytes = crockford::decode(&values).ok_or(RecoveryKeyError::InvalidCharacter)?;
        let mut key = Zeroizing::new([0u8; BYTES]);
        key.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&key))
    }

    /// The canonical text, `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Group `index` (0..6), for the "retype one group" check. An index past the end gives `""`.
    pub fn group(&self, index: usize) -> &str {
        if index >= GROUPS {
            return "";
        }
        let start = index * (GROUP + 1);
        &self.0[start..start + GROUP]
    }

    /// The decoded 120 bits: the secret behind the recovery slot.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; BYTES]> {
        let mut out = Zeroizing::new([0u8; BYTES]);
        // The stored text is canonical, so it always decodes to exactly 15 bytes.
        if let Ok(values) = crockford::normalize(&self.0)
            && let Some(bytes) = crockford::decode(&values)
            && bytes.len() == BYTES
        {
            out.copy_from_slice(&bytes);
        }
        out
    }

    fn from_bytes(bytes: &[u8; BYTES]) -> RecoveryKey {
        RecoveryKey(crockford::grouped(&crockford::encode(bytes, SYMBOLS), GROUP))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}
