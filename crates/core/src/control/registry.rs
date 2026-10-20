//! The paired clients: `<application support>/control-clients.json` (0600, atomic write).
//!
//! A client is identified by its token, which only the client keeps (in its Keychain); MacVPN stores the token's
//! SHA-256 and the executable path the client was paired from. `hello` succeeds only if both match. The pairing
//! rate limit (3 rejections in 10 minutes block pairing for 10 minutes) is kept in memory only.
//!
//! Tokens are secrets: never log one, and never put one in a `Debug` output.
//!
//! [`Registry::load`] is fallible on purpose. A missing or corrupt file is recoverable (an empty registry; the
//! corrupt file is kept as `.bad`), but a file that exists and cannot be read (permissions, a directory in its
//! place, an I/O error) is returned as an error: an empty registry in that case would be saved over the real
//! one at the next change and silently unpair every client.

use super::protocol::ErrorCode;
use crate::date::Date;
use crate::models::{parse_uuid, uuid_string};
use crate::store::{ensure_private_parent, write_private};
use crate::swift_json;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const FILE_NAME: &str = "control-clients.json";
/// This many rejected pairings ...
pub const REJECTION_LIMIT: usize = 3;
/// ... inside this many seconds block pairing for this many seconds after the newest one.
pub const REJECTION_WINDOW: f64 = 600.0;

/// A fresh token from 32 bytes of entropy (the platform layer's `getentropy`): base64url without padding, 43
/// characters.
pub fn new_token(entropy: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(entropy)
}

/// The SHA-256 of a token: the one hashing path for both storing and checking.
fn digest(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(token.as_bytes()));
    out
}

/// The lower-case hex SHA-256 of a token, as stored.
pub fn token_sha256(token: &str) -> String {
    digest(token).iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares two hashes without an early exit: every byte is always looked at.
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// 64 lower-case hex digits to bytes.
fn decode_hash(hex: &str) -> Option<[u8; 32]> {
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, &[hi, lo]) in b.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (digit(hi)? << 4) | digit(lo)?;
    }
    Some(out)
}

/// `PartialEq` is for tests and bookkeeping only: it compares the token hash with an ordinary (early-exit)
/// comparison. Authentication goes through [`Registry::authenticate`] alone.
#[derive(Clone, PartialEq)]
pub struct PairedClient {
    pub id: Uuid,
    /// Self-reported by the client at pairing (sanitized).
    pub name: String,
    /// Lower-case hex SHA-256 of the token.
    pub token_sha256: String,
    /// The pinned executable path (`proc_pidpath` at pairing).
    pub executable: String,
    /// The connection keys (`ConnectionItem::id()`) the client may use.
    pub allowed: Vec<String>,
    pub created: Date,
    pub last_used: Option<Date>,
}

impl PairedClient {
    /// A new pairing; only the token's hash is kept.
    pub fn new(id: Uuid, name: String, token: &str, executable: String, allowed: Vec<String>, created: Date) -> Self {
        PairedClient { id, name, token_sha256: token_sha256(token), executable, allowed, created, last_used: None }
    }

    fn from_json(value: &Value) -> Option<PairedClient> {
        let obj = value.as_object()?;
        let string = |key: &str| obj.get(key).and_then(Value::as_str).map(str::to_string);
        let date = |v: &Value| v.as_str().and_then(Date::parse_iso8601);
        let token_sha256 = string("tokenSha256")?;
        decode_hash(&token_sha256)?;
        let allowed = obj
            .get("allowed")?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?;
        let last_used = match obj.get("lastUsed") {
            None => None,
            Some(v) => Some(date(v)?),
        };
        Some(PairedClient {
            id: parse_uuid(&string("id")?)?,
            name: string("name")?,
            token_sha256,
            executable: string("executable")?,
            allowed,
            created: date(obj.get("created")?)?,
            last_used,
        })
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(uuid_string(&self.id)));
        m.insert("name".into(), Value::String(self.name.clone()));
        m.insert("tokenSha256".into(), Value::String(self.token_sha256.clone()));
        m.insert("executable".into(), Value::String(self.executable.clone()));
        m.insert("allowed".into(), Value::Array(self.allowed.iter().cloned().map(Value::String).collect()));
        m.insert("created".into(), Value::String(self.created.iso8601()));
        if let Some(last_used) = self.last_used {
            m.insert("lastUsed".into(), Value::String(last_used.iso8601()));
        }
        Value::Object(m)
    }
}

/// Without the token hash.
impl std::fmt::Debug for PairedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedClient")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("executable", &self.executable)
            .field("allowed", &self.allowed)
            .field("created", &self.created)
            .field("last_used", &self.last_used)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    clients: Vec<PairedClient>,
    /// The newest `REJECTION_LIMIT` rejected pairings, oldest first. Not persisted.
    rejections: Vec<Date>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// `<dir>/control-clients.json`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    /// A missing file is an empty registry. So is a corrupt one, which is first renamed to
    /// `control-clients.json.bad` (replacing an older one) so the next save does not destroy it silently. Any
    /// other read error is returned: the caller must not save over a file it could not read.
    pub fn load(dir: &Path) -> io::Result<Registry> {
        let path = Self::path(dir);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Registry::new()),
            Err(e) => return Err(e),
        };
        match Self::decode(&data) {
            Some(clients) => Ok(Registry { clients, rejections: Vec::new() }),
            None => {
                fs::rename(&path, dir.join(format!("{FILE_NAME}.bad")))?;
                Ok(Registry::new())
            }
        }
    }

    /// `{"clients":[…]}`; any malformed entry or a repeated id makes the whole file invalid.
    fn decode(data: &[u8]) -> Option<Vec<PairedClient>> {
        let value = swift_json::parse(data).ok()?;
        Self::from_client_values(value.as_object()?.get("clients")?.as_array()?).map(|r| r.clients)
    }

    /// 0600, atomic; the directory is created 0700 if missing.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let path = Self::path(dir);
        ensure_private_parent(&path)?;
        let mut m = Map::new();
        m.insert("clients".into(), Value::Array(self.client_values()));
        let json = swift_json::to_pretty_sorted(&Value::Object(m)).map_err(io::Error::other)?;
        write_private(json.as_bytes(), &path)
    }

    /// The clients as the JSON objects of the file's `clients` array (the vault keeps one row per client).
    pub fn client_values(&self) -> Vec<Value> {
        self.clients.iter().map(PairedClient::to_json).collect()
    }

    /// A registry from the JSON objects of [`Self::client_values`]. `None`: an entry is malformed or an id
    /// repeats (the caller must not save over the source then).
    pub fn from_client_values(values: &[Value]) -> Option<Registry> {
        let mut clients: Vec<PairedClient> = Vec::new();
        for v in values {
            let client = PairedClient::from_json(v)?;
            if clients.iter().any(|c| c.id == client.id) {
                return None;
            }
            clients.push(client);
        }
        Some(Registry { clients, rejections: Vec::new() })
    }

    pub fn clients(&self) -> &[PairedClient] {
        &self.clients
    }

    pub fn get(&self, id: Uuid) -> Option<&PairedClient> {
        self.clients.iter().find(|c| c.id == id)
    }

    /// The client whose token hash matches (compared in constant time against every client) and whose pinned
    /// executable path equals `executable` exactly. Anything else is the generic `Unauthorized`.
    pub fn authenticate(&self, token: &str, executable: &str) -> Result<&PairedClient, ErrorCode> {
        let presented = digest(token);
        let mut found = None;
        for (i, client) in self.clients.iter().enumerate() {
            let matched = decode_hash(&client.token_sha256).is_some_and(|stored| constant_time_eq(&presented, &stored));
            if matched && found.is_none() {
                found = Some(i);
            }
        }
        match found.map(|i| &self.clients[i]) {
            Some(client) if client.executable == executable => Ok(client),
            _ => Err(ErrorCode::Unauthorized),
        }
    }

    /// The client whose token hash matches, whatever executable presents it (compared in constant time against
    /// every client, as [`Self::authenticate`]). Only for the "path changed" note of the Paired apps list after a
    /// failed `hello`: never a way in, and the client still gets the generic `Unauthorized`.
    pub fn identify(&self, token: &str) -> Option<Uuid> {
        let presented = digest(token);
        let mut found = None;
        for client in &self.clients {
            let matched = decode_hash(&client.token_sha256).is_some_and(|stored| constant_time_eq(&presented, &stored));
            if matched && found.is_none() {
                found = Some(client.id);
            }
        }
        found
    }

    /// Adds a pairing; one with the same id is replaced.
    pub fn add(&mut self, client: PairedClient) {
        match self.clients.iter_mut().find(|c| c.id == client.id) {
            Some(existing) => *existing = client,
            None => self.clients.push(client),
        }
    }

    /// `false`: no such client.
    pub fn revoke(&mut self, id: Uuid) -> bool {
        let before = self.clients.len();
        self.clients.retain(|c| c.id != id);
        self.clients.len() != before
    }

    /// `false`: no such client.
    pub fn set_allowed(&mut self, id: Uuid, allowed: Vec<String>) -> bool {
        self.client_mut(id).map(|c| c.allowed = allowed).is_some()
    }

    /// Removes `keys` from every client's allowlist (connections that no longer exist, such as removed team catalog
    /// connections, whose deterministic ids would come back with a re-subscribe). `true`: something changed.
    pub fn forget_keys(&mut self, keys: &[String]) -> bool {
        let mut changed = false;
        for client in &mut self.clients {
            let before = client.allowed.len();
            client.allowed.retain(|k| !keys.contains(k));
            changed |= client.allowed.len() != before;
        }
        changed
    }

    /// Records a successful `hello`. `false`: no such client.
    pub fn touch(&mut self, id: Uuid, now: Date) -> bool {
        self.client_mut(id).map(|c| c.last_used = Some(now)).is_some()
    }

    fn client_mut(&mut self, id: Uuid) -> Option<&mut PairedClient> {
        self.clients.iter_mut().find(|c| c.id == id)
    }

    /// Exact key match against the client's allowlist.
    pub fn is_allowed(client: &PairedClient, key: &str) -> bool {
        client.allowed.iter().any(|k| k == key)
    }

    /// A pairing the user denied or let time out.
    pub fn record_rejection(&mut self, now: Date) {
        self.rejections.push(now);
        if self.rejections.len() > REJECTION_LIMIT {
            self.rejections.remove(0);
        }
    }

    /// The last 3 rejections fall inside 10 minutes and the newest is less than 10 minutes old. A clock that went
    /// back by up to 10 minutes keeps it blocked; one that went back further unblocks (it would otherwise block
    /// for as long as the jump).
    pub fn pairing_blocked(&self, now: Date) -> bool {
        match (self.rejections.first(), self.rejections.last()) {
            (Some(&oldest), Some(&newest)) if self.rejections.len() >= REJECTION_LIMIT => {
                let since_newest = now.time_interval_since(newest);
                newest.time_interval_since(oldest) < REJECTION_WINDOW
                    && (-REJECTION_WINDOW..REJECTION_WINDOW).contains(&since_newest)
            }
            _ => false,
        }
    }
}
