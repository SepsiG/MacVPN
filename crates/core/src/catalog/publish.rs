//! The publish builder (spec 7 steps 1–3, plan Task 14): turns the administrator's selection into a catalog
//! payload. Pure apart from reading the vault; the app layer (`app-core::catalog_publish`) seals, signs, writes the
//! file and stores the publication.
//!
//! - **Selection:** a selected folder brings its whole subtree; a selected connection whose folder is not selected
//!   lands at the catalog root; a sub-folder selected without its parent becomes a top-level catalog folder. Item
//!   ids are the publisher's own folder and connection UUIDs, so they are stable across publishes. System VPNs and
//!   rows of a catalog the publisher subscribes to cannot be selected ([`BuildError::NotSelectable`]); a selected
//!   item that no longer exists is dropped.
//! - **Team secrets:** only a stored PSK or key password of a selected connection is offered, and none is included
//!   unless ticked. A published secret keeps its id across publishes (`PublicationRecord::secret_ids`).
//! - **Credential slots:** the shared credential linked to a selected connection is offered with its id and name,
//!   never its user name or password. An unticked slot leaves its connections without one.
//! - **Refusals:** every connection the payload validation would refuse (inline user names and passwords,
//!   blocking validator issues, an invalid name) is listed; any refusal blocks the build. A native account is
//!   always stripped (it is per user) and listed in `personal`.
//! - **Inline key material** ([`InlineSecret`]: a WireGuard private or preshared key, an OpenVPN client key,
//!   `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`) is published as is, so each one needs an explicit
//!   tick in [`PublishSelection::inline_secrets`] ([`BuildError::Unacknowledged`]).
//! - **SSTP user:** with a ticked credential slot the config's `user=` is published as
//!   [`super::selection::SSTP_SLOT_USER`] (the subscriber's slot user goes in at connect); without one the user
//!   name is published only with an explicit tick ([`InlineSecret::SstpUser`]).
//! - **Item hashes:** a SHA-256 per published item over what the catalog carries for it (name, kind, folder,
//!   colour, config, native settings, OTP setting, slot, included secrets), for the "published in catalog X (vN)"
//!   badge ([`changed_since_publish`]). They are stored in the encrypted vault only.
//!
//! Nothing here logs, and no error carries a config or a secret.

use super::payload::{
    CatalogConnection, CatalogFolder, CatalogPayload, CredentialSlot, InvalidCatalog, PAYLOAD_VERSION, PersonalField,
    check_connection, personal_fields, validate_payload,
};
use super::selection::{InlineSecret, PublishSelection, SSTP_SLOT_USER};
use crate::models::{SecretField, VPNKind, parse_uuid, uuid_string};
use crate::validators::SSTPConfig;
use crate::vault::{
    Entropy, PublicationRecord, StoredConnection, Vault, VaultError, validate_credential_name, validate_folder_name,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use uuid::{Builder, Uuid};
use zeroize::Zeroizing;

const ITEM_HASH_DOMAIN: &[u8] = b"macvpn-publish-item-v1\n";
/// The only fields a catalog can share.
const SHAREABLE: [SecretField; 2] = [SecretField::Psk, SecretField::KeyPassword];

/// What the publish wizard shows before writing (steps 1–3 and the review).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublishPreview {
    /// (folders, connections, credential slots, team secrets) as the selection would publish them now.
    pub payload_counts: (usize, usize, usize, usize),
    /// Per-user values found in the selected connections, for the review (a native account is always stripped).
    pub personal: Vec<(Uuid, PersonalField)>,
    /// Inline key material each needing a tick.
    pub inline_secrets: Vec<(Uuid, InlineSecret)>,
    /// Stored PSKs and key passwords that can be ticked.
    pub available_secrets: Vec<(Uuid, SecretField)>,
    /// (credential id, credential name, selected connections linked to it), sorted by name.
    pub available_slots: Vec<(Uuid, String, usize)>,
    /// Connections that cannot be published, and why.
    pub refused: Vec<(Uuid, InvalidCatalog)>,
    /// The publications (their names) whose last version announced a successor key that the next version would no
    /// longer announce (the backup key was deleted or replaced): subscribers then cannot follow a later switch to
    /// it. Filled by the app's publisher, which knows the admin keys.
    pub successor_dropped_in: Vec<String>,
}

/// Why a payload could not be built. No variant carries a value from a config or a secret.
#[derive(Debug)]
pub enum BuildError {
    /// Nothing to publish.
    Empty,
    /// A system VPN, or a folder or connection of a team catalog this Mac subscribes to.
    NotSelectable(Uuid),
    /// Connections the payload validation refuses.
    Refused(Vec<(Uuid, InvalidCatalog)>),
    /// Inline key material that was not ticked.
    Unacknowledged(Vec<(Uuid, InlineSecret)>),
    /// The whole payload is refused (a cap, a name).
    Invalid(InvalidCatalog),
    Vault(VaultError),
    /// Randomness failed.
    Io(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Empty => f.write_str("nothing is selected"),
            BuildError::NotSelectable(_) => f.write_str("a selected item cannot be published"),
            BuildError::Refused(list) => write!(f, "{} connections cannot be published", list.len()),
            BuildError::Unacknowledged(list) => write!(f, "{} inline keys are not confirmed", list.len()),
            BuildError::Invalid(e) => e.fmt(f),
            BuildError::Vault(e) => e.fmt(f),
            BuildError::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<VaultError> for BuildError {
    fn from(e: VaultError) -> Self {
        BuildError::Vault(e)
    }
}

/// A payload ready to seal, with what the publication record keeps of it.
#[derive(Debug)]
pub struct BuiltPayload {
    pub payload: CatalogPayload,
    pub secret_ids: BTreeMap<(Uuid, SecretField), Uuid>,
    pub item_hashes: BTreeMap<Uuid, String>,
}

/// A catalog name in its stored form (the credential-name and folder-name rules, as the vault and the header
/// require); `None` if it is not valid.
pub fn clean_catalog_name(name: &str) -> Option<String> {
    let cleaned = validate_credential_name(name).ok()?;
    (validate_folder_name(&cleaned).ok()? == cleaned).then_some(cleaned)
}

/// A random (v4) UUID from 16 bytes of `e`.
pub fn random_uuid(e: &dyn Entropy) -> std::io::Result<Uuid> {
    let mut bytes = [0u8; 16];
    e.fill(&mut bytes)?;
    Ok(Builder::from_random_bytes(bytes).into_uuid())
}

// MARK: - the draft

/// One selected connection as it would be published, before slots and secrets are attached.
struct DraftConnection {
    c: CatalogConnection,
    /// The linked shared credential (id, name).
    credential: Option<(Uuid, String)>,
    /// Stored, non-empty PSK and key password.
    secrets: BTreeMap<SecretField, Zeroizing<String>>,
    personal: Vec<PersonalField>,
    inline: Vec<InlineSecret>,
    refused: Option<InvalidCatalog>,
}

struct Draft {
    folders: Vec<CatalogFolder>,
    /// Sorted by id.
    connections: Vec<DraftConnection>,
}

fn owned(vault: &Vault, id: Uuid) -> Result<bool, VaultError> {
    Ok(vault.catalog_owner(&uuid_string(&id))?.is_some())
}

fn draft(vault: &Vault, sel: &PublishSelection) -> Result<Draft, BuildError> {
    let tree = vault.folder_tree()?;
    let mut included = BTreeSet::new();
    for &folder in &sel.folders {
        if owned(vault, folder)? {
            return Err(BuildError::NotSelectable(folder));
        }
        if !tree.contains(folder) {
            continue;
        }
        included.insert(folder);
        for below in tree.descendants(folder) {
            if !owned(vault, below)? {
                included.insert(below);
            }
        }
    }
    let system: HashSet<Uuid> = vault.system_items()?.into_iter().filter_map(|s| parse_uuid(&s.service_id)).collect();
    for &id in &sel.connections {
        if system.contains(&id) || owned(vault, id)? {
            return Err(BuildError::NotSelectable(id));
        }
    }
    let folders = included
        .iter()
        .filter_map(|id| tree.get(*id))
        .map(|node| CatalogFolder {
            id: node.id,
            parent: node.parent.filter(|p| included.contains(p)),
            name: node.name.clone(),
            color: node.color,
            position: node.position,
        })
        .collect();
    let mut stored: Vec<StoredConnection> = vault
        .connections()?
        .into_iter()
        .filter(|s| sel.connections.contains(&s.connection.id) || s.folder_id.is_some_and(|f| included.contains(&f)))
        .collect();
    stored.sort_by_key(|s| s.connection.id);
    let mut connections = Vec::with_capacity(stored.len());
    for s in stored {
        if owned(vault, s.connection.id)? {
            continue;
        }
        connections.push(draft_connection(vault, s, &included)?);
    }
    Ok(Draft { folders, connections })
}

fn draft_connection(
    vault: &Vault,
    s: StoredConnection,
    included: &BTreeSet<Uuid>,
) -> Result<DraftConnection, BuildError> {
    let id = s.connection.id;
    let key = uuid_string(&id);
    let kind = s.connection.kind;
    let config = if kind.is_native() { Zeroizing::new(String::new()) } else { vault.config(&id)? };
    let has_account = s.connection.native.as_ref().is_some_and(|n| !n.account.is_empty());
    // The account is per user: never published.
    let native = if kind.is_native() {
        s.connection.native.clone().map(|mut n| {
            n.account.clear();
            n
        })
    } else {
        None
    };
    let c = CatalogConnection {
        id,
        name: s.connection.name.clone(),
        kind,
        folder: s.folder_id.filter(|f| included.contains(f)),
        color: s.color,
        config,
        native,
        otp: s.connection.otp,
        slot: None,
        secret_refs: BTreeMap::new(),
    };
    let mut personal = personal_fields(&c);
    if has_account {
        personal.push(PersonalField::NativeAccount);
        personal.sort();
    }
    let inline = InlineSecret::of(kind, &c.config);
    let refused = check_connection(&c).err();
    let credential = match vault.credential_of(&key)? {
        Some(cid) => vault.credential(cid)?.map(|cr| (cid, cr.name)),
        None => None,
    };
    let mut secrets = BTreeMap::new();
    for field in SHAREABLE {
        if let Some(value) = vault.secret(&key, field)?.filter(|v| !v.is_empty()) {
            secrets.insert(field, value);
        }
    }
    Ok(DraftConnection { c, credential, secrets, personal, inline, refused })
}

/// Whether the connection's credential is published as a ticked slot.
fn slot_ticked(dc: &DraftConnection, sel: &PublishSelection) -> bool {
    dc.credential.as_ref().is_some_and(|(cid, _)| sel.slots.contains(cid))
}

/// The inline values of a connection that need an explicit tick: an SSTP `user=` does not when a slot is ticked
/// (it is replaced then).
fn needs_tick<'a>(dc: &'a DraftConnection, sel: &PublishSelection) -> impl Iterator<Item = InlineSecret> + 'a {
    let slot = slot_ticked(dc, sel);
    dc.inline.iter().copied().filter(move |s| !(slot && *s == InlineSecret::SstpUser))
}

/// Attaches the ticked slots and secrets; `secret_id` names each included secret.
fn finish(
    d: Draft,
    sel: &PublishSelection,
    mut secret_id: impl FnMut(Uuid, SecretField) -> Result<Uuid, BuildError>,
) -> Result<BuiltPayload, BuildError> {
    let mut slots: BTreeMap<Uuid, String> = BTreeMap::new();
    let mut shared_secrets = BTreeMap::new();
    let mut secret_ids = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    let mut connections = Vec::with_capacity(d.connections.len());
    for mut dc in d.connections {
        let id = dc.c.id;
        if let Some((cid, name)) = dc.credential.as_ref().filter(|(cid, _)| sel.slots.contains(cid)) {
            dc.c.slot = Some(*cid);
            slots.insert(*cid, name.clone());
            if dc.c.kind == VPNKind::Sstp {
                // The publisher's user name stays here: the subscriber's slot user goes in at connect.
                let mut parsed = SSTPConfig::parse(&dc.c.config);
                if !parsed.user.is_empty() {
                    parsed.user = SSTP_SLOT_USER.to_string();
                    dc.c.config = Zeroizing::new(parsed.serialized());
                }
            }
        }
        let mut included = BTreeMap::new();
        for (field, value) in dc.secrets {
            if !sel.secrets.contains(&(id, field)) {
                continue;
            }
            let sid = secret_id(id, field)?;
            dc.c.secret_refs.insert(field, sid);
            secret_ids.insert((id, field), sid);
            included.insert(field, value.clone());
            shared_secrets.insert(sid, value);
        }
        let slot_name = dc.c.slot.and_then(|s| slots.get(&s)).map(String::as_str);
        hashes.insert(id, connection_hash(&dc.c, slot_name, &included));
        connections.push(dc.c);
    }
    for f in &d.folders {
        hashes.insert(f.id, folder_hash(f));
    }
    let payload = CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: d.folders,
        connections,
        credential_slots: slots.into_iter().map(|(id, name)| CredentialSlot { id, name }).collect(),
        shared_secrets,
    };
    Ok(BuiltPayload { payload, secret_ids, item_hashes: hashes })
}

// MARK: - the hashes

/// Length-prefixed fields into a domain-separated SHA-256.
struct ItemHasher(Sha256);

impl ItemHasher {
    fn new(kind: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(ITEM_HASH_DOMAIN);
        h.update(kind);
        ItemHasher(h)
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
        self
    }

    fn opt_uuid(&mut self, id: Option<Uuid>) -> &mut Self {
        self.field(id.map(|i| uuid_string(&i)).unwrap_or_default().as_bytes())
    }

    fn finish(self) -> String {
        self.0.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn folder_hash(f: &CatalogFolder) -> String {
    let mut h = ItemHasher::new(b"folder\n");
    h.opt_uuid(f.parent)
        .field(f.name.as_bytes())
        .field(f.color.map(|c| c.as_str()).unwrap_or_default().as_bytes())
        .field(&f.position.to_be_bytes());
    h.finish()
}

fn connection_hash(
    c: &CatalogConnection,
    slot_name: Option<&str>,
    secrets: &BTreeMap<SecretField, Zeroizing<String>>,
) -> String {
    let mut h = ItemHasher::new(b"connection\n");
    h.field(c.name.as_bytes())
        .field(c.kind.raw_value().as_bytes())
        .opt_uuid(c.folder)
        .field(c.color.map(|x| x.as_str()).unwrap_or_default().as_bytes())
        .field(c.config.as_bytes());
    match &c.native {
        None => {
            h.field(b"");
        }
        Some(n) => {
            h.field(b"native")
                .field(n.server.as_bytes())
                .field(n.group_name.as_bytes())
                .field(&[n.send_all_traffic as u8]);
        }
    }
    h.field(c.otp.to_json().to_string().as_bytes()).opt_uuid(c.slot).field(slot_name.unwrap_or_default().as_bytes());
    for (field, value) in secrets {
        let id = c.secret_refs.get(field).copied();
        h.field(field.raw_value().as_bytes()).opt_uuid(id).field(&Sha256::digest(value.as_bytes()));
    }
    h.finish()
}

// MARK: - the API

/// Steps 1–3 and the review of the wizard for `sel`.
pub fn preview(vault: &Vault, sel: &PublishSelection) -> Result<PublishPreview, BuildError> {
    let d = draft(vault, sel)?;
    let mut out = PublishPreview::default();
    let mut slots: BTreeMap<Uuid, (String, usize)> = BTreeMap::new();
    let mut ticked_slots = BTreeSet::new();
    let mut ticked_secrets = 0;
    for dc in &d.connections {
        let id = dc.c.id;
        out.personal.extend(dc.personal.iter().map(|p| (id, *p)));
        out.inline_secrets.extend(needs_tick(dc, sel).map(|s| (id, s)));
        for field in dc.secrets.keys() {
            out.available_secrets.push((id, *field));
            if sel.secrets.contains(&(id, *field)) {
                ticked_secrets += 1;
            }
        }
        if let Some((cid, name)) = &dc.credential {
            slots.entry(*cid).or_insert_with(|| (name.clone(), 0)).1 += 1;
            if sel.slots.contains(cid) {
                ticked_slots.insert(*cid);
            }
        }
        if let Some(e) = dc.refused {
            out.refused.push((id, e));
        }
    }
    out.available_slots = slots.into_iter().map(|(id, (name, n))| (id, name, n)).collect();
    out.available_slots.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    out.payload_counts = (d.folders.len(), d.connections.len(), ticked_slots.len(), ticked_secrets);
    Ok(out)
}

/// The payload of `sel` (see the module docs); `prior` (the publication's last record) keeps the secret ids, new
/// ones come from `e`.
pub fn build_payload(
    vault: &Vault,
    sel: &PublishSelection,
    prior: Option<&PublicationRecord>,
    e: &dyn Entropy,
) -> Result<BuiltPayload, BuildError> {
    let d = draft(vault, sel)?;
    if d.connections.is_empty() && d.folders.is_empty() {
        return Err(BuildError::Empty);
    }
    let refused: Vec<(Uuid, InvalidCatalog)> =
        d.connections.iter().filter_map(|dc| dc.refused.map(|e| (dc.c.id, e))).collect();
    if !refused.is_empty() {
        return Err(BuildError::Refused(refused));
    }
    let unacknowledged: Vec<(Uuid, InlineSecret)> = d
        .connections
        .iter()
        .flat_map(|dc| needs_tick(dc, sel).map(move |s| (dc.c.id, s)))
        .filter(|pair| !sel.inline_secrets.contains(pair))
        .collect();
    if !unacknowledged.is_empty() {
        return Err(BuildError::Unacknowledged(unacknowledged));
    }
    let built = finish(d, sel, |c, f| match prior.and_then(|p| p.secret_ids.get(&(c, f))) {
        Some(id) => Ok(*id),
        None => random_uuid(e).map_err(|e| BuildError::Io(e.to_string())),
    })?;
    validate_payload(&built.payload).map_err(BuildError::Invalid)?;
    Ok(built)
}

/// The item hashes `sel` would publish now, with the given secret ids (a missing one counts as changed).
pub fn item_hashes(
    vault: &Vault,
    sel: &PublishSelection,
    secret_ids: &BTreeMap<(Uuid, SecretField), Uuid>,
) -> Result<BTreeMap<Uuid, String>, BuildError> {
    let d = draft(vault, sel)?;
    Ok(finish(d, sel, |c, f| Ok(secret_ids.get(&(c, f)).copied().unwrap_or(Uuid::nil())))?.item_hashes)
}

/// The published items that would be published differently now (changed, new in a selected folder, or gone).
/// A selection that cannot be resolved any more marks every published item.
pub fn changed_since_publish(vault: &Vault, p: &PublicationRecord) -> Result<BTreeSet<Uuid>, VaultError> {
    let now = match item_hashes(vault, &p.selection, &p.secret_ids) {
        Ok(h) => h,
        Err(BuildError::Vault(e)) => return Err(e),
        Err(_) => return Ok(p.item_hashes.keys().copied().collect()),
    };
    let mut changed: BTreeSet<Uuid> =
        now.iter().filter(|(id, h)| p.item_hashes.get(*id) != Some(*h)).map(|(id, _)| *id).collect();
    changed.extend(p.item_hashes.keys().filter(|id| !now.contains_key(*id)));
    Ok(changed)
}
