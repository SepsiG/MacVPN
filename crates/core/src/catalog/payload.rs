//! The catalog payload (spec 2 and 3, plan Task 3): the connections, their folder tree, the credential slots and
//! the optional team secrets, as the JSON that the team key seals.
//!
//! **JSON**, built and parsed like the backup payload: the serialized text lives in a `Zeroizing` buffer of
//! exactly the right size, the `serde_json::Value` trees are wiped, and the configs and secret values are base64
//! inside the JSON. Parsing is strict: a duplicate key at any depth, an unknown key, a value of the wrong type, an
//! unknown OTP separator or a UUID that is not in its canonical upper-case text (ids, references and the
//! `sharedSecrets` keys) is [`InvalidCatalog::Malformed`]; two spellings of one shared-secret id are
//! [`InvalidCatalog::Duplicate`].
//!
//! ```text
//! { "version": 1,
//!   "folders": [ { "id", "parentId": uuid|null, "name", "color": name|null, "position" } ],
//!   "connections": [ { "id", "name", "kind", "folderId": uuid|null, "color": name|null, "config": base64,
//!                      "native": null | { "server", "account", "groupName", "sendAllTraffic" },
//!                      "otp": { "enabled", "separator" }, "slot": uuid|null,
//!                      "secretRefs": { "psk"|"keypass": uuid } } ],
//!   "credentialSlots": [ { "id", "name" } ],
//!   "sharedSecrets": { uuid: base64 } }
//! ```
//!
//! **Validation** ([`validate_payload`]): a catalog is untrusted input, like a backup. Every rule the editors and
//! the repositories apply is applied here, the configs go through the same validators as an import, and the whole
//! payload is refused on the first problem. Errors carry ids, never values. Risky OpenVPN directives are not an
//! error: they are returned in [`CatalogFindings`] and each subscriber acknowledges them, never the catalog.

use crate::exporter;
use crate::mfa;
use crate::models::{NativeSettings, OTPSeparator, OTPSetting, SecretField, VPNKind, parse_uuid, uuid_string};
use crate::validators::{self, OpenVPNValidator, RiskyFinding, SSTPConfig};
use crate::vault::wiped_json::{WipedValue, parse_strict, to_wiped_vec};
use crate::vault::{FolderColor, FolderNode, FolderTree, validate_credential_name, validate_folder_name};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The payload schema this build writes and reads.
pub const PAYLOAD_VERSION: u32 = 1;
pub const MAX_CATALOG_CONNECTIONS: usize = 2000;
pub const MAX_CATALOG_FOLDERS: usize = 1000;
pub const MAX_CREDENTIAL_SLOTS: usize = 200;
pub const MAX_SHARED_SECRETS: usize = 2000;
/// The editor's and the root layer's config limit.
pub const MAX_CATALOG_CONFIG_BYTES: usize = 1_048_576;
/// The longest connection name, in characters (the editors have no name rule of their own, so the catalog
/// defines it).
pub const MAX_CONNECTION_NAME_CHARACTERS: usize = 128;
/// The longest shared secret (the backup's and the editors' secret limit).
pub const MAX_SHARED_SECRET_BYTES: usize = 64 * 1024;
/// The longest native server address or Cisco group name (the native editor's field limit).
const MAX_NATIVE_FIELD_BYTES: usize = 64 * 1024;

/// A folder of the catalog's tree (placed under the catalog's root folder on the subscriber).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFolder {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub name: String,
    pub color: Option<FolderColor>,
    pub position: i64,
}

/// A named placeholder each subscriber fills with their own username and password (spec 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSlot {
    pub id: Uuid,
    pub name: String,
}

/// One published connection. The config is a secret-bearing value: wiped on drop, never in `Debug`.
#[derive(Clone, PartialEq)]
pub struct CatalogConnection {
    pub id: Uuid,
    pub name: String,
    pub kind: VPNKind,
    pub folder: Option<Uuid>,
    pub color: Option<FolderColor>,
    /// Empty for L2TP/Cisco.
    pub config: Zeroizing<String>,
    /// L2TP/Cisco only; `account` always empty (it is per user).
    pub native: Option<NativeSettings>,
    pub otp: OTPSetting,
    pub slot: Option<Uuid>,
    /// Only [`SecretField::Psk`] and [`SecretField::KeyPassword`], each naming a shared secret.
    pub secret_refs: BTreeMap<SecretField, Uuid>,
}

impl fmt::Debug for CatalogConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogConnection")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("folder", &self.folder)
            .field("color", &self.color)
            .field("config_bytes", &self.config.len())
            .field("native", &self.native.as_ref().map(|n| (&n.server, &n.group_name, n.send_all_traffic)))
            .field("otp", &self.otp)
            .field("slot", &self.slot)
            .field("secret_refs", &self.secret_refs)
            .finish()
    }
}

/// The decrypted contents of a catalog.
#[derive(Clone, PartialEq)]
pub struct CatalogPayload {
    pub version: u32,
    pub folders: Vec<CatalogFolder>,
    pub connections: Vec<CatalogConnection>,
    pub credential_slots: Vec<CredentialSlot>,
    pub shared_secrets: BTreeMap<Uuid, Zeroizing<String>>,
}

impl fmt::Debug for CatalogPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogPayload")
            .field("version", &self.version)
            .field("folders", &self.folders)
            .field("connections", &self.connections)
            .field("credential_slots", &self.credential_slots)
            .field("shared_secrets", &self.shared_secrets.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A collection of the payload, for [`InvalidCatalog::TooMany`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogCollection {
    Connections,
    Folders,
    CredentialSlots,
    SharedSecrets,
}

/// Why a payload is refused. Carries ids and kinds only, never a value from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCatalog {
    /// More entries than the collection's cap.
    TooMany(CatalogCollection),
    /// Two connections, folders or slots with the same id.
    Duplicate,
    /// A folder name `validate_folder_name` refuses, or not in its stored form.
    FolderName,
    /// The folders are not a tree (a cycle, an unknown parent).
    FolderTree,
    /// A connection in a folder the catalog does not have.
    UnknownFolder,
    /// A connection name that is empty, too long, has a control character or is not in its stored form.
    ConnectionName,
    /// A connection naming a slot the catalog does not have.
    UnknownSlot,
    /// A secret reference naming a shared secret the catalog does not have.
    UnknownSecret,
    /// A secret reference for a field other than the PSK and the key password.
    SecretField,
    /// A shared secret with a control character or over [`MAX_SHARED_SECRET_BYTES`].
    Secret,
    /// A slot name `validate_credential_name` refuses, or not in its stored form.
    SlotName,
    /// A config over [`MAX_CATALOG_CONFIG_BYTES`].
    ConfigTooLarge,
    /// The config has a blocking validator issue (or a NUL); the UI resolves the name from the payload.
    Config { connection: Uuid },
    /// A config with inline credentials: an OpenVPN `<auth-user-pass>` or `<http-proxy-user-pass>` block, or a
    /// strongSwan `secrets { … }` section. A catalog never carries a user's password, and a team PSK travels only
    /// as a shared secret (`secretRefs`).
    InlineCredentials { connection: Uuid },
    /// Native settings missing on L2TP/Cisco, present elsewhere, with an account name, without a server (or a
    /// Cisco group name), or with a config.
    NativeSettings { connection: Uuid },
    /// Not the payload JSON: invalid JSON, a duplicate or unknown key, a wrong type, bad base64.
    Malformed,
    /// A payload `version` above [`PAYLOAD_VERSION`] (only from [`decode_payload`]; the file format reports it as
    /// a newer format).
    NewerVersion(u32),
}

impl fmt::Display for InvalidCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            InvalidCatalog::TooMany(_) => "too many entries",
            InvalidCatalog::Duplicate => "a duplicate entry",
            InvalidCatalog::FolderName => "an invalid folder name",
            InvalidCatalog::FolderTree => "folders that are not a tree",
            InvalidCatalog::UnknownFolder => "a connection in an unknown folder",
            InvalidCatalog::ConnectionName => "an invalid connection name",
            InvalidCatalog::UnknownSlot => "an unknown credential slot",
            InvalidCatalog::UnknownSecret => "an unknown shared secret",
            InvalidCatalog::SecretField => "a shared secret for a field that cannot be shared",
            InvalidCatalog::Secret => "an invalid shared secret",
            InvalidCatalog::SlotName => "an invalid credential slot name",
            InvalidCatalog::ConfigTooLarge => "a configuration that is too large",
            InvalidCatalog::Config { .. } => "a configuration that does not pass validation",
            InvalidCatalog::InlineCredentials { .. } => "a configuration with an inline user name and password",
            InvalidCatalog::NativeSettings { .. } => "invalid L2TP or Cisco IPsec settings",
            InvalidCatalog::Malformed => "damaged contents",
            InvalidCatalog::NewerVersion(_) => "contents made by a newer MacVPN",
        };
        write!(f, "the team catalog cannot be used: it has {what}")
    }
}

impl std::error::Error for InvalidCatalog {}

/// What a valid payload asks of each subscriber: the risky OpenVPN directives per connection (only connections
/// that have any).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatalogFindings {
    pub risky: BTreeMap<Uuid, Vec<RiskyFinding>>,
}

/// A per-user value found in a connection that is about to be published (the publish review warns about it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PersonalField {
    /// SSTP: a `user=` value in the config.
    SstpUser,
    /// L2TP/Cisco: an account name.
    NativeAccount,
    /// WireGuard: a `PrivateKey` value.
    WireGuardPrivateKey,
    /// OpenVPN: an inline `<key>` or `<pkcs12>` block.
    OpenVpnInlineKey,
}

/// The per-user values in `c`, in [`PersonalField`] order.
pub fn personal_fields(c: &CatalogConnection) -> Vec<PersonalField> {
    let mut out = Vec::new();
    match c.kind {
        VPNKind::Sstp => {
            if !SSTPConfig::parse(&c.config).user.is_empty() {
                out.push(PersonalField::SstpUser);
            }
        }
        VPNKind::L2tp | VPNKind::Cisco => {
            if c.native.as_ref().is_some_and(|n| !n.account.is_empty()) {
                out.push(PersonalField::NativeAccount);
            }
        }
        VPNKind::Wireguard => {
            if exporter::secret_material(&c.config, c.kind).iter().any(|k| k == "PrivateKey") {
                out.push(PersonalField::WireGuardPrivateKey);
            }
        }
        VPNKind::Openvpn => {
            if exporter::secret_material(&c.config, c.kind).iter().any(|k| k == "<key>" || k == "<pkcs12>") {
                out.push(PersonalField::OpenVpnInlineKey);
            }
        }
        VPNKind::Strongswan => {}
    }
    out
}

// MARK: - validation

/// A name the validator accepts **and** in the form it stores.
fn stored_form<E>(name: &str, validator: impl FnOnce(&str) -> Result<String, E>) -> bool {
    validator(name).is_ok_and(|cleaned| cleaned == name)
}

fn cap(n: usize, max: usize, collection: CatalogCollection) -> Result<(), InvalidCatalog> {
    if n > max {
        return Err(InvalidCatalog::TooMany(collection));
    }
    Ok(())
}

fn valid_native_field(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NATIVE_FIELD_BYTES && !mfa::has_control(s)
}

/// The rules of the module docs, in order; the first problem refuses the whole payload.
pub fn validate_payload(p: &CatalogPayload) -> Result<CatalogFindings, InvalidCatalog> {
    use InvalidCatalog as I;
    if p.version > PAYLOAD_VERSION {
        return Err(I::NewerVersion(p.version));
    }
    if p.version == 0 {
        return Err(I::Malformed);
    }
    cap(p.connections.len(), MAX_CATALOG_CONNECTIONS, CatalogCollection::Connections)?;
    cap(p.folders.len(), MAX_CATALOG_FOLDERS, CatalogCollection::Folders)?;
    cap(p.credential_slots.len(), MAX_CREDENTIAL_SLOTS, CatalogCollection::CredentialSlots)?;
    cap(p.shared_secrets.len(), MAX_SHARED_SECRETS, CatalogCollection::SharedSecrets)?;

    let mut folder_ids = HashSet::new();
    for f in &p.folders {
        if !folder_ids.insert(f.id) {
            return Err(I::Duplicate);
        }
    }
    let mut connection_ids = HashSet::new();
    for c in &p.connections {
        if !connection_ids.insert(c.id) {
            return Err(I::Duplicate);
        }
    }
    let mut slot_ids = HashSet::new();
    for s in &p.credential_slots {
        if !slot_ids.insert(s.id) {
            return Err(I::Duplicate);
        }
    }

    for f in &p.folders {
        if !stored_form(&f.name, validate_folder_name) {
            return Err(I::FolderName);
        }
    }
    let nodes = p
        .folders
        .iter()
        .map(|f| FolderNode {
            id: f.id,
            parent: f.parent,
            name: f.name.clone(),
            color: f.color,
            position: f.position,
            collapsed: false,
        })
        .collect();
    FolderTree::new(nodes).map_err(|_| I::FolderTree)?;

    for s in &p.credential_slots {
        if !stored_form(&s.name, validate_credential_name) {
            return Err(I::SlotName);
        }
    }
    for value in p.shared_secrets.values() {
        if value.len() > MAX_SHARED_SECRET_BYTES || mfa::has_control(value) {
            return Err(I::Secret);
        }
    }

    let mut findings = CatalogFindings::default();
    for c in &p.connections {
        check_connection_name(c)?;
        if c.folder.is_some_and(|f| !folder_ids.contains(&f)) {
            return Err(I::UnknownFolder);
        }
        if c.slot.is_some_and(|s| !slot_ids.contains(&s)) {
            return Err(I::UnknownSlot);
        }
        for (field, secret) in &c.secret_refs {
            if !matches!(field, SecretField::Psk | SecretField::KeyPassword) {
                return Err(I::SecretField);
            }
            if !p.shared_secrets.contains_key(secret) {
                return Err(I::UnknownSecret);
            }
        }
        let risky = validate_connection(c)?;
        if !risky.is_empty() {
            findings.risky.insert(c.id, risky);
        }
    }
    Ok(findings)
}

fn check_connection_name(c: &CatalogConnection) -> Result<(), InvalidCatalog> {
    if !stored_form(&c.name, |n| mfa::clean_name(n, MAX_CONNECTION_NAME_CHARACTERS).ok_or(())) {
        return Err(InvalidCatalog::ConnectionName);
    }
    Ok(())
}

/// The rules of one connection on its own (name, config, native settings), for the publish review: what
/// [`validate_payload`] would refuse it for, apart from its references.
pub(crate) fn check_connection(c: &CatalogConnection) -> Result<(), InvalidCatalog> {
    check_connection_name(c)?;
    validate_connection(c).map(drop)
}

/// The config and native rules of one connection; the risky findings of an OpenVPN config.
fn validate_connection(c: &CatalogConnection) -> Result<Vec<RiskyFinding>, InvalidCatalog> {
    let connection = c.id;
    if c.config.len() > MAX_CATALOG_CONFIG_BYTES {
        return Err(InvalidCatalog::ConfigTooLarge);
    }
    if c.kind.is_native() {
        let Some(native) = &c.native else { return Err(InvalidCatalog::NativeSettings { connection }) };
        let group_ok = match c.kind {
            VPNKind::Cisco => valid_native_field(&native.group_name),
            _ => native.group_name.is_empty(),
        };
        if !c.config.is_empty() || !native.account.is_empty() || !valid_native_field(&native.server) || !group_ok {
            return Err(InvalidCatalog::NativeSettings { connection });
        }
        return Ok(Vec::new());
    }
    if c.native.is_some() {
        return Err(InvalidCatalog::NativeSettings { connection });
    }
    if c.config.contains('\0') {
        return Err(InvalidCatalog::Config { connection });
    }
    if c.kind == VPNKind::Strongswan && !exporter::secret_material(&c.config, c.kind).is_empty() {
        return Err(InvalidCatalog::InlineCredentials { connection });
    }
    if c.kind == VPNKind::Openvpn {
        if exporter::secret_material(&c.config, c.kind)
            .iter()
            .any(|b| b == "<auth-user-pass>" || b == "<http-proxy-user-pass>")
        {
            return Err(InvalidCatalog::InlineCredentials { connection });
        }
        let result = OpenVPNValidator.validate_full(&c.config, &HashSet::new());
        if !result.issues.is_empty() {
            return Err(InvalidCatalog::Config { connection });
        }
        return Ok(result.risky);
    }
    match validators::validator(c.kind) {
        Some(v) if v.validate(&c.config).is_empty() => Ok(Vec::new()),
        _ => Err(InvalidCatalog::Config { connection }),
    }
}

// MARK: - JSON

fn b64(value: &str) -> Value {
    Value::String(BASE64.encode(value.as_bytes()))
}

fn uuid_value(id: &Uuid) -> Value {
    Value::String(uuid_string(id))
}

fn opt<T>(value: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, f)
}

fn color_value(c: FolderColor) -> Value {
    Value::String(c.as_str().into())
}

/// [`validate_payload`], then the JSON in a right-sized wiped buffer.
pub fn encode_payload(p: &CatalogPayload) -> Result<Zeroizing<Vec<u8>>, InvalidCatalog> {
    validate_payload(p)?;
    let mut root = Map::new();
    root.insert("version".into(), Value::from(p.version));
    let folders = p
        .folders
        .iter()
        .map(|f| {
            let mut m = Map::new();
            m.insert("id".into(), uuid_value(&f.id));
            m.insert("parentId".into(), opt(f.parent.as_ref(), uuid_value));
            m.insert("name".into(), Value::String(f.name.clone()));
            m.insert("color".into(), opt(f.color, color_value));
            m.insert("position".into(), Value::from(f.position));
            Value::Object(m)
        })
        .collect();
    root.insert("folders".into(), Value::Array(folders));
    let connections = p
        .connections
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("id".into(), uuid_value(&c.id));
            m.insert("name".into(), Value::String(c.name.clone()));
            m.insert("kind".into(), Value::String(c.kind.raw_value().into()));
            m.insert("folderId".into(), opt(c.folder.as_ref(), uuid_value));
            m.insert("color".into(), opt(c.color, color_value));
            m.insert("config".into(), b64(&c.config));
            m.insert(
                "native".into(),
                opt(c.native.as_ref(), |n| {
                    let mut m = Map::new();
                    m.insert("server".into(), Value::String(n.server.clone()));
                    m.insert("account".into(), Value::String(n.account.clone()));
                    m.insert("groupName".into(), Value::String(n.group_name.clone()));
                    m.insert("sendAllTraffic".into(), Value::Bool(n.send_all_traffic));
                    Value::Object(m)
                }),
            );
            m.insert("otp".into(), c.otp.to_json());
            m.insert("slot".into(), opt(c.slot.as_ref(), uuid_value));
            m.insert(
                "secretRefs".into(),
                Value::Object(
                    c.secret_refs.iter().map(|(field, id)| (field.raw_value().to_string(), uuid_value(id))).collect(),
                ),
            );
            Value::Object(m)
        })
        .collect();
    root.insert("connections".into(), Value::Array(connections));
    let slots = p
        .credential_slots
        .iter()
        .map(|s| {
            let mut m = Map::new();
            m.insert("id".into(), uuid_value(&s.id));
            m.insert("name".into(), Value::String(s.name.clone()));
            Value::Object(m)
        })
        .collect();
    root.insert("credentialSlots".into(), Value::Array(slots));
    root.insert(
        "sharedSecrets".into(),
        Value::Object(p.shared_secrets.iter().map(|(id, value)| (uuid_string(id), b64(value))).collect()),
    );
    let tree = WipedValue(Value::Object(root));
    to_wiped_vec(&tree.0).map_err(|_| InvalidCatalog::Malformed)
}

/// Parses (strictly, see the module docs) and validates the decrypted payload.
pub fn decode_payload(plaintext: &[u8]) -> Result<CatalogPayload, InvalidCatalog> {
    let payload = decode_unchecked(plaintext)?;
    validate_payload(&payload)?;
    Ok(payload)
}

/// [`decode_payload`] without [`validate_payload`], for callers that validate once themselves (the file format,
/// which needs the findings).
pub(crate) fn decode_unchecked(plaintext: &[u8]) -> Result<CatalogPayload, InvalidCatalog> {
    let tree = parse_strict(plaintext).ok_or(InvalidCatalog::Malformed)?;
    let root = tree.0.as_object().ok_or(InvalidCatalog::Malformed)?;
    // The version first, so a newer payload is told apart from a damaged one.
    let version = root.get("version").and_then(Value::as_u64).ok_or(InvalidCatalog::Malformed)?;
    if version > u64::from(PAYLOAD_VERSION) {
        return Err(InvalidCatalog::NewerVersion(u32::try_from(version).unwrap_or(u32::MAX)));
    }
    // Two spellings of one shared-secret id would collapse into one map entry: a duplicate, not a choice.
    if let Some(secrets) = root.get("sharedSecrets").and_then(Value::as_object) {
        let mut seen = HashSet::new();
        for id in secrets.keys() {
            if let Some(id) = parse_uuid(id)
                && !seen.insert(id)
            {
                return Err(InvalidCatalog::Duplicate);
            }
        }
    }
    decode_root(root).ok_or(InvalidCatalog::Malformed)
}

/// Only these keys, all of them (`optional` ones may be absent).
fn exact_keys(m: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Option<()> {
    let known = |k: &str| required.contains(&k) || optional.contains(&k);
    (m.keys().all(|k| known(k)) && required.iter().all(|k| m.contains_key(*k))).then_some(())
}

/// A UUID in its canonical (upper-case) text only, so one id has exactly one spelling in a catalog.
fn canonical_uuid(s: &str) -> Option<Uuid> {
    parse_uuid(s).filter(|id| uuid_string(id) == s)
}

fn uuid_of(v: &Value) -> Option<Uuid> {
    v.as_str().and_then(canonical_uuid)
}

/// `null` is `Some(None)`; a present value `f` refuses is `None`.
fn nullable<T>(v: &Value, f: impl FnOnce(&Value) -> Option<T>) -> Option<Option<T>> {
    match v {
        Value::Null => Some(None),
        x => f(x).map(Some),
    }
}

/// A colour this build does not know (a newer palette) reads as no colour, as in the database and the backup.
fn color_of(v: &Value) -> Option<Option<FolderColor>> {
    nullable(v, |x| x.as_str().map(FolderColor::parse)).map(Option::flatten)
}

fn string_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

/// Base64 text into a wiped string.
fn secret_of(v: &Value) -> Option<Zeroizing<String>> {
    let text = v.as_str()?;
    let mut buffer = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(text.len())]);
    let n = BASE64.decode_slice(text, &mut buffer[..]).ok()?;
    std::str::from_utf8(&buffer[..n]).ok().map(|s| Zeroizing::new(s.to_owned()))
}

fn decode_root(root: &Map<String, Value>) -> Option<CatalogPayload> {
    exact_keys(root, &["version", "folders", "connections", "credentialSlots", "sharedSecrets"], &[])?;
    let version = u32::try_from(root.get("version")?.as_u64()?).ok()?;
    if version == 0 {
        return None;
    }
    let mut folders = Vec::new();
    for f in root.get("folders")?.as_array()? {
        let f = f.as_object()?;
        exact_keys(f, &["id", "parentId", "name", "color", "position"], &[])?;
        folders.push(CatalogFolder {
            id: uuid_of(&f["id"])?,
            parent: nullable(&f["parentId"], uuid_of)?,
            name: string_of(&f["name"])?,
            color: color_of(&f["color"])?,
            position: f["position"].as_i64()?,
        });
    }
    let mut connections = Vec::new();
    for c in root.get("connections")?.as_array()? {
        let c = c.as_object()?;
        exact_keys(
            c,
            &["id", "name", "kind", "folderId", "color", "config", "native", "otp", "slot", "secretRefs"],
            &[],
        )?;
        let mut secret_refs = BTreeMap::new();
        for (field, id) in c["secretRefs"].as_object()? {
            secret_refs.insert(SecretField::from_raw_value(field)?, uuid_of(id)?);
        }
        let otp = c["otp"].as_object()?;
        exact_keys(otp, &["enabled", "separator"], &[])?;
        connections.push(CatalogConnection {
            id: uuid_of(&c["id"])?,
            name: string_of(&c["name"])?,
            kind: VPNKind::from_raw_value(c["kind"].as_str()?)?,
            folder: nullable(&c["folderId"], uuid_of)?,
            color: color_of(&c["color"])?,
            config: secret_of(&c["config"])?,
            native: nullable(&c["native"], native_of)?,
            otp: OTPSetting::new(otp["enabled"].as_bool()?, OTPSeparator::from_raw_value(otp["separator"].as_str()?)?),
            slot: nullable(&c["slot"], uuid_of)?,
            secret_refs,
        });
    }
    let mut credential_slots = Vec::new();
    for s in root.get("credentialSlots")?.as_array()? {
        let s = s.as_object()?;
        exact_keys(s, &["id", "name"], &[])?;
        credential_slots.push(CredentialSlot { id: uuid_of(&s["id"])?, name: string_of(&s["name"])? });
    }
    let mut shared_secrets = BTreeMap::new();
    for (id, value) in root.get("sharedSecrets")?.as_object()? {
        shared_secrets.insert(canonical_uuid(id)?, secret_of(value)?);
    }
    Some(CatalogPayload { version, folders, connections, credential_slots, shared_secrets })
}

fn native_of(v: &Value) -> Option<NativeSettings> {
    let n = v.as_object()?;
    exact_keys(n, &["server", "account", "groupName", "sendAllTraffic"], &[])?;
    Some(NativeSettings {
        server: string_of(&n["server"])?,
        account: string_of(&n["account"])?,
        group_name: string_of(&n["groupName"])?,
        send_all_traffic: n["sendAllTraffic"].as_bool()?,
    })
}
