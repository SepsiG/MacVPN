//! The catalog keys (spec 3 and 7, plan Task 2).
//!
//! - **Team key:** 256 random bits that seal the payload. Shared out of band as text: `TEAM-` and 14 groups of 4
//!   Crockford symbols (the recovery key's alphabet and parse rules), 13 groups (52 symbols, the last 4 bits zero)
//!   for the key and one check group (the first 20 bits of `SHA-256("macvpn-team-key-v1\n" ‖ key)`), so a mistyped
//!   key ([`TeamKeyError::Typo`]) is told apart from a wrong one without any decryption.
//! - **Admin key:** an Ed25519 signing key, made from 32 [`Entropy`] bytes (no `rand`), wiped on drop.
//! - **Publisher key:** its public half; travels in full in the catalog header. Small-order keys are refused
//!   (`ed25519-dalek`'s `VerifyingKey::from_bytes` accepts them, spike C.3).
//! - **Fingerprint:** the first 16 bytes of `SHA-256("macvpn-catalog-key-v1\n" ‖ public key)`, shown as 8 groups of
//!   4 upper-case hex digits; what users compare and pin.

use crate::vault::Entropy;
use crate::vault::crockford::{self, CrockfordError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io;
use zeroize::Zeroizing;

pub const TEAM_KEY_PREFIX: &str = "TEAM-";
pub const KEY_FINGERPRINT_DOMAIN: &[u8] = b"macvpn-catalog-key-v1\n";
const TEAM_KEY_CHECK_DOMAIN: &[u8] = b"macvpn-team-key-v1\n";

const TEAM_KEY_BYTES: usize = 32;
/// 256 bits in 5-bit symbols: 52 (the last 4 bits are padding).
const KEY_SYMBOLS: usize = 52;
const CHECK_SYMBOLS: usize = 4;
const TEXT_SYMBOLS: usize = KEY_SYMBOLS + CHECK_SYMBOLS;
const GROUP: usize = 4;
const GROUPS: usize = TEXT_SYMBOLS / GROUP;
const FINGERPRINT_BYTES: usize = 16;

/// Why typed team-key text was not accepted. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamKeyError {
    /// Not exactly 56 symbols (prefix, separators and white space aside).
    WrongLength,
    /// A character outside the Crockford alphabet, or a last key symbol whose padding bits are not zero.
    InvalidCharacter,
    /// The check group does not match: a typo.
    Typo,
}

impl fmt::Display for TeamKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TeamKeyError::WrongLength => "a team key has 14 groups of 4 characters",
            TeamKeyError::InvalidCharacter => "the team key contains an invalid character",
            TeamKeyError::Typo => "the team key contains a typo",
        })
    }
}

impl std::error::Error for TeamKeyError {}

/// 256 random bits. No `Clone`, a redacted `Debug`, wiped on drop.
pub struct TeamKey(Zeroizing<[u8; TEAM_KEY_BYTES]>);

impl TeamKey {
    /// 32 fresh random bytes.
    pub fn generate(e: &dyn Entropy) -> io::Result<TeamKey> {
        let mut key = Zeroizing::new([0u8; TEAM_KEY_BYTES]);
        e.fill(&mut key[..])?;
        Ok(TeamKey(key))
    }

    /// Accepts the text as [`TeamKey::to_text`] writes it and the forgiving forms: lower case, an optional `TEAM`
    /// prefix (with or without `-`), `-` and white space anywhere, `O` for `0`, `I`/`L` for `1`.
    pub fn parse(input: &str) -> Result<TeamKey, TeamKeyError> {
        let values =
            crockford::normalize(input).map_err(|CrockfordError::InvalidCharacter| TeamKeyError::InvalidCharacter)?;
        // The prefix letters are themselves symbols: drop them only when they make the text one group too long,
        // so a key whose first group happens to read `TEAM` still parses bare.
        let values = match values.len() {
            n if n == TEXT_SYMBOLS + GROUP && values[..GROUP] == prefix_values()[..] => &values[GROUP..],
            n if n == TEXT_SYMBOLS => &values[..],
            _ => return Err(TeamKeyError::WrongLength),
        };
        let bytes = crockford::decode(&values[..KEY_SYMBOLS]).ok_or(TeamKeyError::InvalidCharacter)?;
        let key = TeamKey::from_bytes(&bytes).ok_or(TeamKeyError::WrongLength)?;
        let expected = crockford::normalize(&key.check_group()).map_err(|_| TeamKeyError::Typo)?;
        if values[KEY_SYMBOLS..] != expected[..] {
            return Err(TeamKeyError::Typo);
        }
        Ok(key)
    }

    /// `TEAM-XXXX-…`: 13 groups of key symbols and the check group.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut symbols = Zeroizing::new(String::with_capacity(TEXT_SYMBOLS));
        symbols.push_str(&crockford::encode(&self.0[..], KEY_SYMBOLS));
        symbols.push_str(&self.check_group());
        let grouped = crockford::grouped(&symbols, GROUP);
        let mut text = Zeroizing::new(String::with_capacity(TEAM_KEY_PREFIX.len() + grouped.len()));
        text.push_str(TEAM_KEY_PREFIX);
        text.push_str(&grouped);
        text
    }

    /// Group `index` (0..14, the last one is the check group), for the "retype one group" confirmation. An index
    /// past the end gives `""`.
    pub fn group(&self, index: usize) -> Zeroizing<String> {
        if index >= GROUPS {
            return Zeroizing::new(String::new());
        }
        let text = self.to_text();
        let start = TEAM_KEY_PREFIX.len() + index * (GROUP + 1);
        Zeroizing::new(text[start..start + GROUP].to_string())
    }

    pub fn as_bytes(&self) -> &[u8; TEAM_KEY_BYTES] {
        &self.0
    }

    /// A key read back from the vault; `None` unless exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<TeamKey> {
        if bytes.len() != TEAM_KEY_BYTES {
            return None;
        }
        let mut key = Zeroizing::new([0u8; TEAM_KEY_BYTES]);
        key.copy_from_slice(bytes);
        Some(TeamKey(key))
    }

    /// The first 20 bits of `SHA-256(TEAM_KEY_CHECK_DOMAIN ‖ key)` as 4 symbols.
    fn check_group(&self) -> Zeroizing<String> {
        let mut h = Sha256::new();
        h.update(TEAM_KEY_CHECK_DOMAIN);
        h.update(&self.0[..]);
        let digest = h.finalize();
        crockford::encode(&digest[..3], CHECK_SYMBOLS)
    }
}

/// The symbol values of `TEAM`.
fn prefix_values() -> [u8; GROUP] {
    let mut out = [0u8; GROUP];
    for (slot, c) in out.iter_mut().zip(TEAM_KEY_PREFIX.chars()) {
        *slot = crockford::symbol_value(c).unwrap_or(u8::MAX);
    }
    out
}

impl fmt::Debug for TeamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TeamKey(..)")
    }
}

/// An Ed25519 signing key (the admin key). No `Clone`, a `Debug` that shows only the fingerprint, wiped on drop
/// (`SigningKey` is `ZeroizeOnDrop`).
pub struct AdminKey(SigningKey);

impl AdminKey {
    /// From 32 fresh random bytes.
    pub fn generate(e: &dyn Entropy) -> io::Result<AdminKey> {
        let mut seed = Zeroizing::new([0u8; 32]);
        e.fill(&mut seed[..])?;
        Ok(AdminKey(SigningKey::from_bytes(&seed)))
    }

    /// From its 32-byte seed (the vault, a backup, an admin key file); `None` for any other length.
    pub fn from_seed(seed: &[u8]) -> Option<AdminKey> {
        if seed.len() != 32 {
            return None;
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(seed);
        Some(AdminKey(SigningKey::from_bytes(&bytes)))
    }

    /// The seed, for storing the key.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> PublisherKey {
        PublisherKey(self.0.verifying_key().to_bytes())
    }

    /// An Ed25519 signature (deterministic) over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdminKey({})", self.public().fingerprint().to_text())
    }
}

/// A publisher's Ed25519 public key: a valid point that is not of small order.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublisherKey([u8; 32]);

impl PublisherKey {
    /// `None` unless 32 bytes that decode to a curve point of large order.
    pub fn from_bytes(bytes: &[u8]) -> Option<PublisherKey> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&bytes).ok()?;
        (!key.is_weak()).then_some(PublisherKey(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let mut h = Sha256::new();
        h.update(KEY_FINGERPRINT_DOMAIN);
        h.update(self.0);
        let digest = h.finalize();
        let mut out = [0u8; FINGERPRINT_BYTES];
        out.copy_from_slice(&digest[..FINGERPRINT_BYTES]);
        Fingerprint(out)
    }

    /// `verify_strict` (refuses non-canonical signatures and small-order components).
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else { return false };
        key.verify_strict(message, &Signature::from_bytes(signature)).is_ok()
    }
}

impl fmt::Debug for PublisherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublisherKey({})", self.fingerprint().to_text())
    }
}

/// Why a typed fingerprint was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// Not exactly 32 hex digits (separators and white space aside).
    WrongLength,
    /// A character that is not a hex digit, `-` or white space.
    InvalidCharacter,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FingerprintError::WrongLength => "a fingerprint has 8 groups of 4 hex digits",
            FingerprintError::InvalidCharacter => "the fingerprint contains an invalid character",
        })
    }
}

impl std::error::Error for FingerprintError {}

/// The first 16 bytes of `SHA-256(KEY_FINGERPRINT_DOMAIN ‖ public key)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_BYTES]);

impl Fingerprint {
    /// Case-insensitive, `-` and white space ignored, exactly 32 hex digits.
    pub fn parse(input: &str) -> Result<Fingerprint, FingerprintError> {
        let mut out = [0u8; FINGERPRINT_BYTES];
        let mut count = 0usize;
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            let digit = c.to_digit(16).ok_or(FingerprintError::InvalidCharacter)? as u8;
            if count < FINGERPRINT_BYTES * 2 {
                out[count / 2] |= if count.is_multiple_of(2) { digit << 4 } else { digit };
            }
            count += 1;
        }
        if count != FINGERPRINT_BYTES * 2 {
            return Err(FingerprintError::WrongLength);
        }
        Ok(Fingerprint(out))
    }

    /// `ABCD-1234-…`: 8 groups of 4 upper-case hex digits.
    pub fn to_text(&self) -> String {
        let digits: String = self.0.iter().map(|b| format!("{b:02X}")).collect();
        crockford::grouped(&digits, GROUP).to_string()
    }

    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.0
    }

    /// From 16 stored bytes; `None` for any other length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Fingerprint> {
        bytes.try_into().ok().map(Fingerprint)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_text())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}
