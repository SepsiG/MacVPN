//! The recovery key (spec 2.2): 120 random bits shown as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` in Crockford base32
//! (24 symbols, alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, big-endian bit order). The secret fed to Argon2id is
//! the decoded 15 bytes ([`RecoveryKey::secret_bytes`]), not the text.

use super::entropy::Entropy;
use std::fmt;
use std::io;
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
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
        let mut values = Zeroizing::new([0u8; SYMBOLS]);
        let mut count = 0usize;
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let value = symbol_value(c).ok_or(RecoveryKeyError::InvalidCharacter)?;
            if count < SYMBOLS {
                values[count] = value;
            }
            count += 1;
        }
        if count != SYMBOLS {
            return Err(RecoveryKeyError::WrongLength);
        }
        let bytes = decode(&values);
        Ok(Self::from_bytes(&bytes))
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
        let mut values = Zeroizing::new([0u8; SYMBOLS]);
        for (slot, c) in values.iter_mut().zip(self.0.chars().filter(|c| *c != '-')) {
            *slot = symbol_value(c).unwrap_or(0);
        }
        decode(&values)
    }

    fn from_bytes(bytes: &[u8; BYTES]) -> RecoveryKey {
        let mut text = Zeroizing::new(String::with_capacity(SYMBOLS + GROUPS - 1));
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        let mut emitted = 0usize;
        let mut push = |text: &mut String, v: u32| {
            if emitted > 0 && emitted.is_multiple_of(GROUP) {
                text.push('-');
            }
            text.push(char::from(ALPHABET[v as usize]));
            emitted += 1;
        };
        for &b in bytes {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                push(&mut text, (acc >> bits) & 0x1F);
            }
            acc &= (1 << bits) - 1;
        }
        RecoveryKey(text)
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

/// 24 five-bit symbol values → 15 bytes, big-endian (24 × 5 = 120 = 15 × 8 bits, so nothing is left over).
fn decode(values: &[u8; SYMBOLS]) -> Zeroizing<[u8; BYTES]> {
    let mut bytes = Zeroizing::new([0u8; BYTES]);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = 0usize;
    for &v in values {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes[out] = (acc >> bits) as u8;
            out += 1;
            acc &= (1 << bits) - 1;
        }
    }
    bytes
}

fn symbol_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    if !c.is_ascii() {
        return None;
    }
    ALPHABET.iter().position(|&a| a == c as u8).map(|p| p as u8)
}
