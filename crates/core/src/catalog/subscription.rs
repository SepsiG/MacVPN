//! The subscription string (spec 5, plan Task 5): one line that carries the source, the team key and the
//! publisher fingerprint, `macvpn-sub:` followed by base64url (no padding) of
//!
//! ```text
//! {"v":1,"source":{"https":"…"}|{"file":"…"},"teamKey":"TEAM-…","fingerprint":"XXXX-…",
//!  "catalogId":"<uuid>"?,"minVersion":n?}
//! ```
//!
//! The two optional keys (review L6) bind the first download: `catalogId` is the expected catalog id and
//! `minVersion` the lowest version accepted (the initial rollback floor), so a stale or foreign file on the same
//! source is refused before anything is stored.
//!
//! It is a secret (it holds the team key): the decoded bytes, the JSON tree and the formatted string are wiped,
//! and its `Debug` shows only the source and the fingerprint. The bearer token of an HTTPS source is **not** part
//! of it (a token is often per user; see the plan's resolved points). Only outer white space is trimmed: a string
//! broken across lines by a mail client is refused rather than guessed at.

use super::keys::{Fingerprint, FingerprintError, TeamKey, TeamKeyError};
use super::source::{CatalogSource, HttpsUrl, SourceError, parse_file_source};
use crate::models::{parse_uuid, uuid_string};
use crate::vault::wiped_json::{WipedValue, parse_strict, to_wiped_vec};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const SUBSCRIPTION_PREFIX: &str = "macvpn-sub:";
pub const MAX_SUBSCRIPTION_CHARS: usize = 4096;
const VERSION: u64 = 1;

/// Everything a subscriber needs to add a catalog, except an optional bearer token.
pub struct SubscriptionString {
    pub source: CatalogSource,
    pub team_key: TeamKey,
    pub fingerprint: Fingerprint,
    /// The catalog the first download must be (`catalogId`).
    pub catalog_id: Option<Uuid>,
    /// The lowest version the first download may have (`minVersion`, at least 1).
    pub min_version: Option<u64>,
}

impl fmt::Debug for SubscriptionString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionString")
            .field("source", &self.source)
            .field("fingerprint", &self.fingerprint)
            .field("catalog_id", &self.catalog_id)
            .field("min_version", &self.min_version)
            .finish_non_exhaustive()
    }
}

/// Why a pasted subscription string was refused. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionError {
    /// Does not start with `macvpn-sub:`.
    NotASubscription,
    /// Over [`MAX_SUBSCRIPTION_CHARS`].
    TooLong,
    /// Bad base64url, bad JSON, a duplicate, unknown or missing key.
    Malformed,
    /// Made by a newer MacVPN.
    NewerVersion(u32),
    Source(SourceError),
    TeamKey(TeamKeyError),
    Fingerprint(FingerprintError),
}

impl fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubscriptionError::NotASubscription => f.write_str("this is not a MacVPN subscription string"),
            SubscriptionError::TooLong => f.write_str("the subscription string is too long"),
            SubscriptionError::Malformed => f.write_str("the subscription string is damaged"),
            SubscriptionError::NewerVersion(v) => {
                write!(f, "the subscription string was made by a newer MacVPN (version {v})")
            }
            SubscriptionError::Source(e) => e.fmt(f),
            SubscriptionError::TeamKey(e) => e.fmt(f),
            SubscriptionError::Fingerprint(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// Parses a pasted subscription string (outer white space trimmed, nothing else).
pub fn parse_subscription(input: &str) -> Result<SubscriptionString, SubscriptionError> {
    let input = input.trim();
    if input.chars().count() > MAX_SUBSCRIPTION_CHARS {
        return Err(SubscriptionError::TooLong);
    }
    let body = input.strip_prefix(SUBSCRIPTION_PREFIX).ok_or(SubscriptionError::NotASubscription)?;
    let mut bytes = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(body.len())]);
    let n = URL_SAFE_NO_PAD.decode_slice(body, &mut bytes[..]).map_err(|_| SubscriptionError::Malformed)?;
    let tree = parse_strict(&bytes[..n]).ok_or(SubscriptionError::Malformed)?;
    let root = tree.0.as_object().ok_or(SubscriptionError::Malformed)?;
    let version = root.get("v").and_then(Value::as_u64).ok_or(SubscriptionError::Malformed)?;
    if version > VERSION {
        return Err(SubscriptionError::NewerVersion(u32::try_from(version).unwrap_or(u32::MAX)));
    }
    let keys = ["v", "source", "teamKey", "fingerprint"];
    let optional = ["catalogId", "minVersion"];
    if version != VERSION
        || !keys.iter().all(|k| root.contains_key(*k))
        || !root.keys().all(|k| keys.contains(&k.as_str()) || optional.contains(&k.as_str()))
    {
        return Err(SubscriptionError::Malformed);
    }
    let catalog_id = match root.get("catalogId") {
        None => None,
        Some(v) => {
            let text = v.as_str().ok_or(SubscriptionError::Malformed)?;
            Some(parse_uuid(text).filter(|id| uuid_string(id) == text).ok_or(SubscriptionError::Malformed)?)
        }
    };
    let min_version = match root.get("minVersion") {
        None => None,
        Some(v) => Some(v.as_u64().filter(|n| *n >= 1).ok_or(SubscriptionError::Malformed)?),
    };
    let source = root["source"].as_object().ok_or(SubscriptionError::Malformed)?;
    let source = match source.iter().next() {
        Some((kind, value)) if source.len() == 1 => {
            let text = value.as_str().ok_or(SubscriptionError::Malformed)?;
            match kind.as_str() {
                "https" => CatalogSource::Https(HttpsUrl::parse(text).map_err(SubscriptionError::Source)?),
                "file" => CatalogSource::File(parse_file_source(text).map_err(SubscriptionError::Source)?),
                _ => return Err(SubscriptionError::Malformed),
            }
        }
        _ => return Err(SubscriptionError::Malformed),
    };
    let team_key = root["teamKey"].as_str().ok_or(SubscriptionError::Malformed)?;
    let team_key = TeamKey::parse(team_key).map_err(SubscriptionError::TeamKey)?;
    let fingerprint = root["fingerprint"].as_str().ok_or(SubscriptionError::Malformed)?;
    let fingerprint = Fingerprint::parse(fingerprint).map_err(SubscriptionError::Fingerprint)?;
    Ok(SubscriptionString { source, team_key, fingerprint, catalog_id, min_version })
}

/// The one-line string, in a wiped buffer.
pub fn format_subscription(s: &SubscriptionString) -> Zeroizing<String> {
    let mut source = Map::new();
    match &s.source {
        CatalogSource::Https(url) => source.insert("https".into(), Value::String(url.as_str().into())),
        CatalogSource::File(path) => source.insert("file".into(), Value::String(path.to_string_lossy().into_owned())),
    };
    let mut root = Map::new();
    root.insert("v".into(), Value::from(VERSION));
    root.insert("source".into(), Value::Object(source));
    root.insert("teamKey".into(), Value::String(s.team_key.to_text().to_string()));
    root.insert("fingerprint".into(), Value::String(s.fingerprint.to_text()));
    if let Some(id) = &s.catalog_id {
        root.insert("catalogId".into(), Value::String(uuid_string(id)));
    }
    if let Some(n) = s.min_version {
        root.insert("minVersion".into(), Value::from(n));
    }
    let tree = WipedValue(Value::Object(root));
    // A map of strings and a number always serializes.
    let json = to_wiped_vec(&tree.0).unwrap_or_default();
    let mut out = Zeroizing::new(String::with_capacity(
        SUBSCRIPTION_PREFIX.len() + base64::encoded_len(json.len(), false).unwrap_or(0),
    ));
    out.push_str(SUBSCRIPTION_PREFIX);
    URL_SAFE_NO_PAD.encode_string(&json[..], &mut out);
    out
}
