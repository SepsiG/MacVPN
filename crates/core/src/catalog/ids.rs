//! Namespaced local ids of catalog items (plan Task 6, "Resolved points": namespaced ids).
//!
//! A catalog item's row on the subscriber (its `connections.id` or `folders.id`) is a UUID v8 derived from the
//! catalog id, the kind and the publisher's item id with a domain-separated SHA-256. So it is
//! - stable across catalog versions and Macs (a restore or a re-subscribe gives the same ids, and the restored
//!   secrets, pins and links attach again),
//! - UUID-shaped, as the control API and the tables require,
//! - never equal for two catalogs, or for a folder and a connection with the same item id.

use crate::models::uuid_string;
use sha2::{Digest, Sha256};
use uuid::{Builder, Uuid};

const LOCAL_ID_DOMAIN: &[u8] = b"macvpn-catalog-item-v1\n";

/// What a catalog item is on the subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CatalogItemKind {
    /// The root folder named after the catalog.
    Root,
    Folder,
    Connection,
}

impl CatalogItemKind {
    /// The storage name (`catalog_items.kind`), also part of the id derivation.
    pub fn as_str(self) -> &'static str {
        match self {
            CatalogItemKind::Root => "root",
            CatalogItemKind::Folder => "folder",
            CatalogItemKind::Connection => "connection",
        }
    }

    pub fn parse(s: &str) -> Option<CatalogItemKind> {
        [CatalogItemKind::Root, CatalogItemKind::Folder, CatalogItemKind::Connection]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// UUID v8 from SHA-256("macvpn-catalog-item-v1\n" ‖ kind ‖ "\n" ‖ catalog_id ‖ "\n" ‖ item_id), the ids as
/// upper-case hyphenated text: stable across versions and devices, UUID-shaped for the control API, never equal for
/// two catalogs.
pub fn local_id(catalog_id: Uuid, kind: CatalogItemKind, item_id: Uuid) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(LOCAL_ID_DOMAIN);
    hash.update(kind.as_str().as_bytes());
    hash.update(b"\n");
    hash.update(uuid_string(&catalog_id).as_bytes());
    hash.update(b"\n");
    hash.update(uuid_string(&item_id).as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Builder::from_custom_bytes(bytes).into_uuid()
}

/// The local id of a catalog's root folder: `local_id(catalog_id, Root, catalog_id)`.
pub fn root_folder_id(catalog_id: Uuid) -> Uuid {
    local_id(catalog_id, CatalogItemKind::Root, catalog_id)
}
