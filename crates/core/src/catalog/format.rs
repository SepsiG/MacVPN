//! The catalog file, `<name>.macvpncatalog` (spec 3, plan Task 4). Container version 1, integers big-endian:
//!
//! ```text
//! magic         8   b"MVPNCAT1"
//! header_len    4   1 ..= MAX_HEADER_BYTES
//! header        …   UTF-8 JSON, header_len bytes
//! sealed        …   XChaCha20-Poly1305(team key, header.nonce, payload JSON,
//!                   AAD = AAD_DOMAIN ‖ magic ‖ header_len ‖ header), the 16-byte tag last
//! signature    64   Ed25519 over SIGNATURE_DOMAIN ‖ magic ‖ header_len ‖ header ‖ sealed
//! ```
//!
//! The header JSON (strict: a duplicate or unknown key is [`CatalogError::BadHeader`]):
//! `{ "format": 1, "catalog_id", "name", "version", "created", "publisher_key": base64, "publisher_key_id":
//! fingerprint text, "successor_key": base64|null, "kdf": "none", "enc": "xchacha20poly1305", "nonce": base64 }`.
//!
//! [`open_catalog`] runs the spec's order of checks exactly, each only after the previous one passed: framing,
//! header, trust and signature, catalog id, version, decryption, payload validation. Because the signature is
//! checked before decryption, [`CatalogError::WrongTeamKey`] can only mean a wrong or rotated team key. No error
//! message shows a value from the file except the two version numbers of a rollback (which are signed);
//! [`CatalogError::NewerFormat`] keeps the unauthenticated format number for the code only and never displays it.
//!
//! The successor key (spec 7, spike decision C): a header field covered by the catalog signature, so the current
//! key signs the announcement. A catalog signed by the announced successor opens with `signed_by_successor`; the
//! service re-pins to it once such a catalog is applied (Task 11).

use super::keys::{AdminKey, Fingerprint, PublisherKey, TeamKey};
use super::payload::{
    CatalogFindings, CatalogPayload, InvalidCatalog, decode_unchecked, encode_payload, validate_payload,
};
use crate::date::Date;
use crate::models::{parse_uuid, uuid_string};
use crate::vault::wiped_json::parse_strict;
use crate::vault::{Entropy, validate_credential_name};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"MVPNCAT1";
/// The container format this build writes and reads.
pub const FORMAT: u32 = 1;
pub const SIGNATURE_DOMAIN: &[u8] = b"macvpn-catalog-v1\n";
pub const AAD_DOMAIN: &[u8] = b"macvpn-catalog-v1|payload\n";
pub const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const EXTENSION: &str = "macvpncatalog";

const KDF_NONE: &str = "none";
const ENC: &str = "xchacha20poly1305";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;
const PREFIX_LEN: usize = 8 + 4;
/// Magic, length, a 1-byte header, the tag and the signature.
const MIN_LEN: usize = PREFIX_LEN + 1 + TAG_LEN + SIGNATURE_LEN;
const HEADER_KEYS: [&str; 11] = [
    "format",
    "catalog_id",
    "name",
    "version",
    "created",
    "publisher_key",
    "publisher_key_id",
    "successor_key",
    "kdf",
    "enc",
    "nonce",
];

/// The catalog header, as read from a file (validated, see [`peek_header`]).
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogHeader {
    pub format: u32,
    pub catalog_id: Uuid,
    pub name: String,
    /// Monotonic, at least 1.
    pub version: u64,
    pub created: Date,
    pub publisher_key: PublisherKey,
    pub publisher_key_id: Fingerprint,
    pub successor_key: Option<PublisherKey>,
    /// Always `"none"`: the team key is a key, not a password.
    pub kdf: String,
    /// Always `"xchacha20poly1305"`.
    pub enc: String,
    pub nonce: [u8; NONCE_LEN],
}

/// What the publisher sets for a new catalog version; the publisher key comes from the admin key, the rest
/// (`format`, `kdf`, `enc`, a fresh nonce) from [`seal_catalog`].
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogHeaderInput {
    pub catalog_id: Uuid,
    pub name: String,
    pub version: u64,
    pub created: Date,
    pub successor_key: Option<PublisherKey>,
}

/// What a subscription trusts: the pinned fingerprint, the full key once a first catalog was verified, and an
/// announced successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trust {
    pub pinned: Fingerprint,
    pub publisher_key: Option<PublisherKey>,
    pub successor: Option<PublisherKey>,
}

/// One open: the trust, the expected catalog id (`None` for a first download), the last applied version (the
/// rollback floor) and the team key.
pub struct OpenRequest<'a> {
    pub trust: &'a Trust,
    pub catalog_id: Option<Uuid>,
    pub applied_version: Option<u64>,
    pub team_key: &'a TeamKey,
}

/// A catalog that passed every check.
#[derive(Debug)]
pub struct OpenedCatalog {
    pub header: CatalogHeader,
    pub payload: CatalogPayload,
    /// The risky directives each subscriber must acknowledge.
    pub findings: CatalogFindings,
    /// Signed by `trust.successor`, not the pinned key.
    pub signed_by_successor: bool,
    /// SHA-256 of the whole file (the file source's change check).
    pub content_hash: [u8; 32],
}

/// Why a catalog cannot be used (or written). Distinct for every failure, but no message shows a value from the
/// file except the two (signed) version numbers of [`CatalogError::Rollback`]; the number in
/// [`CatalogError::NewerFormat`] is unauthenticated and is never displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    /// The magic is not `MVPNCAT1`.
    NotACatalog,
    /// Shorter than the framing needs, or a header length out of range.
    Truncated,
    /// Over [`MAX_CATALOG_BYTES`].
    TooLarge,
    /// A container format (or payload version) above the one this build reads.
    NewerFormat(u32),
    /// The header is not valid (JSON, keys, values).
    BadHeader,
    /// Signed by a key that is neither the pinned one nor the announced successor.
    UnknownPublisher,
    /// The signature does not verify: the file was changed.
    BadSignature,
    /// Another catalog than the subscription's.
    WrongCatalog,
    /// The version already applied (ignored silently).
    SameVersion,
    /// An older version than the one applied.
    Rollback { applied: u64, offered: u64 },
    /// The payload does not decrypt (after a good signature: a wrong or rotated team key).
    WrongTeamKey,
    /// The decrypted payload is refused.
    Invalid(InvalidCatalog),
    /// The source cannot be reached (a missing share, a host down); carries the file or host name.
    Unavailable(String),
    /// Reading or writing failed; a message without secrets.
    Io(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::NotACatalog => f.write_str("the file is not a MacVPN team catalog"),
            CatalogError::Truncated => f.write_str("the team catalog file is incomplete"),
            CatalogError::TooLarge => f.write_str("the team catalog file is too large"),
            // The number comes from the unauthenticated header (or a payload whose signature verified, but still a
            // value from the file): never shown.
            CatalogError::NewerFormat(_) => f.write_str("the team catalog was made by a newer MacVPN"),
            CatalogError::BadHeader => f.write_str("the team catalog file is damaged"),
            CatalogError::UnknownPublisher => {
                f.write_str("the team catalog was signed by another publisher than the one you trust")
            }
            CatalogError::BadSignature => f.write_str("the team catalog's signature is not valid: it was changed"),
            CatalogError::WrongCatalog => f.write_str("the file is another team catalog"),
            CatalogError::SameVersion => f.write_str("the team catalog has not changed"),
            CatalogError::Rollback { applied, offered } => write!(
                f,
                "the team catalog offers version {offered}, older than the applied version {applied}: refused"
            ),
            CatalogError::WrongTeamKey => {
                f.write_str("the team key does not open this catalog (it is wrong or was rotated)")
            }
            CatalogError::Invalid(e) => e.fmt(f),
            CatalogError::Unavailable(source) => write!(f, "the team catalog source is unavailable: {source}"),
            CatalogError::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CatalogError {}

impl From<InvalidCatalog> for CatalogError {
    fn from(e: InvalidCatalog) -> CatalogError {
        match e {
            InvalidCatalog::NewerVersion(v) => CatalogError::NewerFormat(v),
            other => CatalogError::Invalid(other),
        }
    }
}

/// The fieldless form stored in a subscription's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogErrorKind {
    NotACatalog,
    Truncated,
    TooLarge,
    NewerFormat,
    BadHeader,
    UnknownPublisher,
    BadSignature,
    WrongCatalog,
    WrongTeamKey,
    Invalid,
    Io,
}

impl CatalogErrorKind {
    /// The stable storage name.
    pub fn as_str(self) -> &'static str {
        match self {
            CatalogErrorKind::NotACatalog => "not_a_catalog",
            CatalogErrorKind::Truncated => "truncated",
            CatalogErrorKind::TooLarge => "too_large",
            CatalogErrorKind::NewerFormat => "newer_format",
            CatalogErrorKind::BadHeader => "bad_header",
            CatalogErrorKind::UnknownPublisher => "unknown_publisher",
            CatalogErrorKind::BadSignature => "bad_signature",
            CatalogErrorKind::WrongCatalog => "wrong_catalog",
            CatalogErrorKind::WrongTeamKey => "wrong_team_key",
            CatalogErrorKind::Invalid => "invalid",
            CatalogErrorKind::Io => "io",
        }
    }

    pub fn parse(s: &str) -> Option<CatalogErrorKind> {
        use CatalogErrorKind as K;
        [
            K::NotACatalog,
            K::Truncated,
            K::TooLarge,
            K::NewerFormat,
            K::BadHeader,
            K::UnknownPublisher,
            K::BadSignature,
            K::WrongCatalog,
            K::WrongTeamKey,
            K::Invalid,
            K::Io,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }
}

impl CatalogError {
    /// The status kind of a failure. `None` for the outcomes that have their own subscription status:
    /// [`CatalogError::SameVersion`] (not modified), [`CatalogError::Rollback`] (rollback refused) and
    /// [`CatalogError::Unavailable`].
    pub fn kind(&self) -> Option<CatalogErrorKind> {
        use CatalogErrorKind as K;
        Some(match self {
            CatalogError::NotACatalog => K::NotACatalog,
            CatalogError::Truncated => K::Truncated,
            CatalogError::TooLarge => K::TooLarge,
            CatalogError::NewerFormat(_) => K::NewerFormat,
            CatalogError::BadHeader => K::BadHeader,
            CatalogError::UnknownPublisher => K::UnknownPublisher,
            CatalogError::BadSignature => K::BadSignature,
            CatalogError::WrongCatalog => K::WrongCatalog,
            CatalogError::WrongTeamKey => K::WrongTeamKey,
            CatalogError::Invalid(_) => K::Invalid,
            CatalogError::Io(_) => K::Io,
            CatalogError::SameVersion | CatalogError::Rollback { .. } | CatalogError::Unavailable(_) => return None,
        })
    }
}

// MARK: - framing and header

/// The parts of a framed file: the header bytes, the sealed payload (with its tag), the signed bytes and the
/// signature.
struct Framed<'a> {
    header: &'a [u8],
    sealed: &'a [u8],
    signed: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
}

fn frame(bytes: &[u8]) -> Result<Framed<'_>, CatalogError> {
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(CatalogError::TooLarge);
    }
    let prefix = bytes.len().min(MAGIC.len());
    if bytes[..prefix] != MAGIC[..prefix] {
        return Err(CatalogError::NotACatalog);
    }
    if bytes.len() < MIN_LEN {
        return Err(CatalogError::Truncated);
    }
    let header_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if header_len == 0
        || header_len > MAX_HEADER_BYTES
        || PREFIX_LEN + header_len + TAG_LEN + SIGNATURE_LEN > bytes.len()
    {
        return Err(CatalogError::Truncated);
    }
    let (signed, signature) = bytes.split_at(bytes.len() - SIGNATURE_LEN);
    let signature: [u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| CatalogError::Truncated)?;
    Ok(Framed {
        header: &signed[PREFIX_LEN..PREFIX_LEN + header_len],
        sealed: &signed[PREFIX_LEN + header_len..],
        signed,
        signature,
    })
}

fn b64_bytes<const N: usize>(v: &Value) -> Option<[u8; N]> {
    let text = v.as_str()?;
    let bytes = BASE64.decode(text).ok()?;
    bytes.try_into().ok()
}

fn publisher_key_of(v: &Value) -> Option<PublisherKey> {
    PublisherKey::from_bytes(&b64_bytes::<32>(v)?)
}

/// The catalog name rule: `validate_credential_name`'s (1 to 64 characters, no control characters), in stored
/// form.
fn valid_name(name: &str) -> bool {
    validate_credential_name(name).is_ok_and(|cleaned| cleaned == name)
}

fn parse_header(bytes: &[u8]) -> Result<CatalogHeader, CatalogError> {
    // The format first, from a plain parse: a newer header may have other keys.
    let plain: Value = serde_json::from_slice(bytes).map_err(|_| CatalogError::BadHeader)?;
    let format = plain.get("format").and_then(Value::as_u64).ok_or(CatalogError::BadHeader)?;
    if format > u64::from(FORMAT) {
        return Err(CatalogError::NewerFormat(u32::try_from(format).unwrap_or(u32::MAX)));
    }
    let tree = parse_strict(bytes).ok_or(CatalogError::BadHeader)?;
    decode_header(&tree.0).ok_or(CatalogError::BadHeader)
}

fn decode_header(v: &Value) -> Option<CatalogHeader> {
    let m = v.as_object()?;
    if m.len() != HEADER_KEYS.len() || !HEADER_KEYS.iter().all(|k| m.contains_key(*k)) {
        return None;
    }
    let format = u32::try_from(m["format"].as_u64()?).ok()?;
    let name = m["name"].as_str()?.to_string();
    let version = m["version"].as_u64()?;
    let publisher_key = publisher_key_of(&m["publisher_key"])?;
    let publisher_key_id = Fingerprint::parse(m["publisher_key_id"].as_str()?).ok()?;
    let successor_key = match &m["successor_key"] {
        Value::Null => None,
        other => Some(publisher_key_of(other)?),
    };
    let kdf = m["kdf"].as_str()?.to_string();
    let enc = m["enc"].as_str()?.to_string();
    let ok = format == FORMAT
        && valid_name(&name)
        && version >= 1
        && kdf == KDF_NONE
        && enc == ENC
        && publisher_key_id == publisher_key.fingerprint()
        && successor_key != Some(publisher_key);
    ok.then_some(())?;
    Some(CatalogHeader {
        format,
        catalog_id: parse_uuid(m["catalog_id"].as_str()?)?,
        name,
        version,
        created: Date::parse_iso8601(m["created"].as_str()?)?,
        publisher_key,
        publisher_key_id,
        successor_key,
        kdf,
        enc,
        nonce: b64_bytes::<NONCE_LEN>(&m["nonce"])?,
    })
}

fn encode_header(h: &CatalogHeader) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("format".into(), Value::from(h.format));
    m.insert("catalog_id".into(), Value::String(uuid_string(&h.catalog_id)));
    m.insert("name".into(), Value::String(h.name.clone()));
    m.insert("version".into(), Value::from(h.version));
    m.insert("created".into(), Value::String(h.created.iso8601()));
    m.insert("publisher_key".into(), Value::String(BASE64.encode(h.publisher_key.as_bytes())));
    m.insert("publisher_key_id".into(), Value::String(h.publisher_key_id.to_text()));
    m.insert(
        "successor_key".into(),
        h.successor_key.map_or(Value::Null, |k| Value::String(BASE64.encode(k.as_bytes()))),
    );
    m.insert("kdf".into(), Value::String(h.kdf.clone()));
    m.insert("enc".into(), Value::String(h.enc.clone()));
    m.insert("nonce".into(), Value::String(BASE64.encode(h.nonce)));
    // A map of strings and numbers always serializes.
    serde_json::to_vec(&Value::Object(m)).unwrap_or_default()
}

/// `AAD_DOMAIN ‖ magic ‖ header_len ‖ header`.
fn aad(header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + PREFIX_LEN + header.len());
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(header);
    out
}

fn signature_message(signed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_DOMAIN.len() + signed.len());
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.extend_from_slice(signed);
    out
}

/// A header read without any check of its signature ([`peek_header`]): anyone can write any value into it.
///
/// It offers only the catalog's name, for display ("Acme VPN, not verified yet"). Never prefill, compare or store
/// its fingerprint, key or catalog id: the trust decision is the fingerprint the user typed (spec 5), checked by
/// [`open_catalog`].
#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedHeader(CatalogHeader);

impl UnverifiedHeader {
    /// The catalog's name as the (unauthenticated) header claims it, for display only.
    pub fn display_name(&self) -> &str {
        &self.0.name
    }
}

/// The framing and the header only, without any trust (for display before subscribing, never for applying).
pub fn peek_header(bytes: &[u8]) -> Result<UnverifiedHeader, CatalogError> {
    parse_header(frame(bytes)?.header).map(UnverifiedHeader)
}

// MARK: - open

/// Opens a catalog with the checks in the spec's order (see the module docs).
pub fn open_catalog(bytes: &[u8], req: &OpenRequest) -> Result<OpenedCatalog, CatalogError> {
    // 1. Framing.
    let framed = frame(bytes)?;
    // 2. Header.
    let header = parse_header(framed.header)?;
    // 3. Trust, then the signature.
    let trust = req.trust;
    let pinned = header.publisher_key_id == trust.pinned
        && trust.publisher_key.is_none_or(|known| known == header.publisher_key);
    let signed_by_successor = !pinned && trust.successor == Some(header.publisher_key);
    if !pinned && !signed_by_successor {
        return Err(CatalogError::UnknownPublisher);
    }
    if !header.publisher_key.verify(&signature_message(framed.signed), &framed.signature) {
        return Err(CatalogError::BadSignature);
    }
    // 4. The catalog id.
    if req.catalog_id.is_some_and(|id| id != header.catalog_id) {
        return Err(CatalogError::WrongCatalog);
    }
    // 5. The version.
    if let Some(applied) = req.applied_version {
        if header.version == applied {
            return Err(CatalogError::SameVersion);
        }
        if header.version < applied {
            return Err(CatalogError::Rollback { applied, offered: header.version });
        }
    }
    // 6. Decryption.
    let cipher =
        XChaCha20Poly1305::new_from_slice(&req.team_key.as_bytes()[..]).map_err(|_| CatalogError::WrongTeamKey)?;
    let (ciphertext, tag) = framed.sealed.split_at(framed.sealed.len() - TAG_LEN);
    let tag = Tag::try_from(tag).map_err(|_| CatalogError::WrongTeamKey)?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&XNonce::from(header.nonce), &aad(framed.header), (&mut plaintext[..]).into(), &tag)
        .map_err(|_| CatalogError::WrongTeamKey)?;
    // 7. The payload.
    let payload = decode_unchecked(&plaintext)?;
    let findings = validate_payload(&payload)?;
    Ok(OpenedCatalog { header, payload, findings, signed_by_successor, content_hash: Sha256::digest(bytes).into() })
}

// MARK: - seal

/// Writes a catalog: validates the payload (a catalog no subscriber could apply is never written) and the header,
/// seals the payload with the team key under a fresh nonce, and signs everything with the admin key.
pub fn seal_catalog(
    input: CatalogHeaderInput,
    payload: &CatalogPayload,
    team_key: &TeamKey,
    admin: &AdminKey,
    e: &dyn Entropy,
) -> Result<Vec<u8>, CatalogError> {
    let plaintext = encode_payload(payload)?;
    let publisher_key = admin.public();
    if !valid_name(&input.name) || input.version == 0 || input.successor_key == Some(publisher_key) {
        return Err(CatalogError::BadHeader);
    }
    let mut nonce = [0u8; NONCE_LEN];
    e.fill(&mut nonce).map_err(|e| CatalogError::Io(e.to_string()))?;
    let header = CatalogHeader {
        format: FORMAT,
        catalog_id: input.catalog_id,
        name: input.name,
        version: input.version,
        created: input.created,
        publisher_key,
        publisher_key_id: publisher_key.fingerprint(),
        successor_key: input.successor_key,
        kdf: KDF_NONE.into(),
        enc: ENC.into(),
        nonce,
    };
    let header_bytes = encode_header(&header);
    if header_bytes.is_empty() || header_bytes.len() > MAX_HEADER_BYTES {
        return Err(CatalogError::BadHeader);
    }
    let total = PREFIX_LEN + header_bytes.len() + plaintext.len() + TAG_LEN + SIGNATURE_LEN;
    if total > MAX_CATALOG_BYTES {
        return Err(CatalogError::TooLarge);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&team_key.as_bytes()[..])
        .map_err(|_| CatalogError::Io("invalid team key".into()))?;
    // The plaintext is copied straight into the output and encrypted there; wiped if anything fails before that.
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_bytes);
    let start = out.len();
    out.extend_from_slice(&plaintext);
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &aad(&header_bytes), (&mut out[start..]).into())
        .map_err(|_| CatalogError::Io("encryption failed".into()))?;
    out.extend_from_slice(&tag);
    let signature = admin.sign(&signature_message(&out));
    out.extend_from_slice(&signature);
    Ok(std::mem::take(&mut *out))
}
