//! The names LinVPN gives NetworkManager: the derived connection UUID (resolved point 3: also linvpn-logd's
//! ownership proof) and the tunnel interface names. A contract between the app and `linvpn-logd`: never change the
//! derivation without a new domain string.

use sha2::{Digest, Sha256};
use uuid::Uuid;

const DOMAIN: &[u8] = b"linvpn-nm-v1\0";
pub const IFACE_WIREGUARD: &str = "lvw";
pub const IFACE_OPENVPN: &str = "lvo";
/// The `NativeController` service id of a managed L2TP / Cisco connection.
pub const SERVICE_PREFIX: &str = "linvpn-";

/// `UUIDv8(SHA-256(DOMAIN ‖ uid LE ‖ id))`: version 8, RFC 4122 variant.
pub fn nm_uuid(uid: u32, id: &Uuid) -> Uuid {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(uid.to_le_bytes());
    h.update(id.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0F) | 0x80;
    b[8] = (b[8] & 0x3F) | 0x80;
    Uuid::from_bytes(b)
}

/// The same derivation written out byte by byte, as `linvpn-logd`'s documentation states it (the pinned test
/// compares both, so a refactor of [`nm_uuid`] cannot silently change it).
pub fn nm_uuid_reference(uid: u32, id: &Uuid) -> String {
    let mut input = DOMAIN.to_vec();
    input.extend_from_slice(&uid.to_le_bytes());
    input.extend_from_slice(id.as_bytes());
    let d = Sha256::digest(&input);
    let mut b: Vec<u8> = d[..16].to_vec();
    b[6] = (b[6] & 0x0F) | 0x80;
    b[8] = (b[8] & 0x3F) | 0x80;
    Uuid::from_slice(&b).expect("16 bytes").hyphenated().to_string()
}

/// `<prefix><8 lower-case hex digits of SHA-256(id)>` (11 characters; IFNAMSIZ is 16 with the NUL).
pub fn iface(prefix: &str, id: &Uuid) -> String {
    let d = Sha256::digest(id.as_bytes());
    format!("{prefix}{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

/// `linvpn-<UUID upper-case>` (the managed L2TP / Cisco service id; resolved point 2).
pub fn service_id(id: &Uuid) -> String {
    format!("{SERVICE_PREFIX}{}", id.hyphenated().to_string().to_uppercase())
}

/// The id of [`service_id`], or `None`.
pub fn parse_service_id(s: &str) -> Option<Uuid> {
    crate::models::parse_uuid(s.strip_prefix(SERVICE_PREFIX)?)
}
