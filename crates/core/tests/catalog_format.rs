//! The signed and encrypted catalog file (spec 3, plan Task 4): the container, the order of the checks, the
//! distinct but non-leaky errors, rollback protection, the size cap and the successor key.

use macvpn_core::catalog::format::{
    AAD_DOMAIN, CatalogError, CatalogErrorKind, CatalogHeaderInput, FORMAT, MAGIC, MAX_CATALOG_BYTES, MAX_HEADER_BYTES,
    OpenRequest, SIGNATURE_DOMAIN, Trust, open_catalog, peek_header, seal_catalog,
};
use macvpn_core::catalog::keys::{AdminKey, Fingerprint, PublisherKey, TeamKey};
use macvpn_core::catalog::payload::{
    CatalogConnection, CatalogFolder, CatalogPayload, InvalidCatalog, PAYLOAD_VERSION,
};
use macvpn_core::date::Date;
use macvpn_core::models::{OTPSetting, VPNKind};
use macvpn_core::vault::FixedEntropy;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::Zeroizing;

const CATALOG_NAME: &str = "Acme Team Catalog";
const CONNECTION_NAME: &str = "Acme VPN Budapest";
const CONFIG: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\n";

fn catalog_id() -> Uuid {
    Uuid::from_u128(0xC0FFEE00_0000_4000_8000_000000000001)
}

fn payload() -> CatalogPayload {
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: vec![CatalogFolder {
            id: Uuid::from_u128(0xF0),
            parent: None,
            name: "Offices".into(),
            color: None,
            position: 0,
        }],
        connections: vec![CatalogConnection {
            id: Uuid::from_u128(0xC1),
            name: CONNECTION_NAME.into(),
            kind: VPNKind::Openvpn,
            folder: Some(Uuid::from_u128(0xF0)),
            color: None,
            config: Zeroizing::new(CONFIG.into()),
            native: None,
            otp: OTPSetting::default(),
            slot: None,
            secret_refs: BTreeMap::new(),
        }],
        credential_slots: vec![],
        shared_secrets: BTreeMap::new(),
    }
}

struct Fixture {
    admin: AdminKey,
    team: TeamKey,
    entropy: FixedEntropy,
}

fn fixture() -> Fixture {
    let entropy = FixedEntropy::new(42);
    let admin = AdminKey::generate(&entropy).unwrap();
    let team = TeamKey::generate(&entropy).unwrap();
    Fixture { admin, team, entropy }
}

fn input(version: u64, successor: Option<PublisherKey>) -> CatalogHeaderInput {
    CatalogHeaderInput {
        catalog_id: catalog_id(),
        name: CATALOG_NAME.into(),
        version,
        created: Date::from_time_interval_since_1970(1_800_000_000.0),
        successor_key: successor,
    }
}

fn seal(f: &Fixture, version: u64) -> Vec<u8> {
    seal_catalog(input(version, None), &payload(), &f.team, &f.admin, &f.entropy).unwrap()
}

fn fresh_trust(admin: &AdminKey) -> Trust {
    Trust { pinned: admin.public().fingerprint(), publisher_key: None, successor: None }
}

fn request<'a>(trust: &'a Trust, team: &'a TeamKey) -> OpenRequest<'a> {
    OpenRequest { trust, catalog_id: None, applied_version: None, team_key: team }
}

fn open(bytes: &[u8], f: &Fixture) -> Result<macvpn_core::catalog::format::OpenedCatalog, CatalogError> {
    let trust = fresh_trust(&f.admin);
    open_catalog(bytes, &request(&trust, &f.team))
}

fn header_len(bytes: &[u8]) -> usize {
    u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize
}

/// Rebuilds a file with a changed header and a valid signature (the publisher's own key), so the checks after the
/// signature can be reached.
fn resign(bytes: &[u8], admin: &AdminKey, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let len = header_len(bytes);
    let header = &bytes[12..12 + len];
    let sealed = &bytes[12 + len..bytes.len() - 64];
    let mut value: serde_json::Value = serde_json::from_slice(header).unwrap();
    edit(&mut value);
    let new_header = serde_json::to_vec(&value).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(new_header.len() as u32).to_be_bytes());
    out.extend_from_slice(&new_header);
    out.extend_from_slice(sealed);
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&out);
    out.extend_from_slice(&admin.sign(&message));
    out
}

// MARK: - round trip

#[test]
fn round_trip_with_a_fresh_trust_and_with_the_key_known() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let opened = open(&bytes, &f).unwrap();
    assert_eq!(opened.payload, payload());
    assert_eq!(opened.header.name, CATALOG_NAME);
    assert_eq!(opened.header.version, 1);
    assert_eq!(opened.header.catalog_id, catalog_id());
    assert_eq!(opened.header.format, FORMAT);
    assert_eq!(opened.header.kdf, "none");
    assert_eq!(opened.header.enc, "xchacha20poly1305");
    assert_eq!(opened.header.publisher_key, f.admin.public());
    assert_eq!(opened.header.publisher_key_id, f.admin.public().fingerprint());
    assert_eq!(opened.header.created, Date::from_time_interval_since_1970(1_800_000_000.0));
    assert!(!opened.signed_by_successor);
    assert!(opened.findings.risky.is_empty());
    assert_eq!(opened.content_hash, <[u8; 32]>::from(Sha256::digest(&bytes)));

    let trust = Trust { publisher_key: Some(f.admin.public()), ..fresh_trust(&f.admin) };
    let req = OpenRequest { trust: &trust, catalog_id: Some(catalog_id()), applied_version: None, team_key: &f.team };
    assert_eq!(open_catalog(&bytes, &req).unwrap().payload, payload());
}

#[test]
fn the_file_layout() {
    let f = fixture();
    let bytes = seal(&f, 1);
    assert_eq!(&bytes[..8], MAGIC);
    let len = header_len(&bytes);
    assert!(len > 0 && len <= MAX_HEADER_BYTES);
    let header: serde_json::Value = serde_json::from_slice(&bytes[12..12 + len]).unwrap();
    assert_eq!(header["format"], 1);
    assert_eq!(header["kdf"], "none");
    // The signature covers the domain and every byte before it.
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&bytes[..bytes.len() - 64]);
    let signature: [u8; 64] = bytes[bytes.len() - 64..].try_into().unwrap();
    assert!(f.admin.public().verify(&message, &signature));
    // Nothing of the payload is in clear.
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(CONNECTION_NAME));
    assert!(!text.contains("vpn.example.com"));
    assert!(AAD_DOMAIN.starts_with(b"macvpn-catalog-v1"));
    // peek_header reads the header without any trust, and offers only the name for display (review L2).
    assert_eq!(peek_header(&bytes).unwrap().display_name(), CATALOG_NAME);
    assert_eq!(open(&bytes, &f).unwrap().header.catalog_id, catalog_id());
}

#[test]
fn every_seal_takes_a_fresh_nonce() {
    let f = fixture();
    let a = seal(&f, 1);
    let b = seal(&f, 1);
    assert_ne!(a, b);
    assert_ne!(open(&a, &f).unwrap().header.nonce, open(&b, &f).unwrap().header.nonce);
}

// MARK: - the errors

#[test]
fn a_wrong_team_key_is_wrong_team_key() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let other = TeamKey::generate(&FixedEntropy::new(7)).unwrap();
    let trust = fresh_trust(&f.admin);
    assert_eq!(open_catalog(&bytes, &request(&trust, &other)).err(), Some(CatalogError::WrongTeamKey));
}

#[test]
fn a_wrong_pinned_fingerprint_is_an_unknown_publisher() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let stranger = AdminKey::generate(&FixedEntropy::new(9)).unwrap();
    let trust = fresh_trust(&stranger);
    assert_eq!(open_catalog(&bytes, &request(&trust, &f.team)).err(), Some(CatalogError::UnknownPublisher));
    // The fingerprint matches but the full key known from earlier differs.
    let trust = Trust { publisher_key: Some(stranger.public()), ..fresh_trust(&f.admin) };
    assert_eq!(open_catalog(&bytes, &request(&trust, &f.team)).err(), Some(CatalogError::UnknownPublisher));
}

#[test]
fn a_flipped_byte_in_the_sealed_payload_or_the_signature_is_a_bad_signature() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let start = 12 + header_len(&bytes);
    for i in start..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert_eq!(open(&b, &f).err(), Some(CatalogError::BadSignature), "byte {i}");
    }
}

#[test]
fn a_flipped_byte_in_the_header_never_opens() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let len = header_len(&bytes);
    // A changed letter of the name keeps the JSON valid: only the signature catches it.
    let at = bytes.windows(CATALOG_NAME.len()).position(|w| w == CATALOG_NAME.as_bytes()).unwrap();
    let mut b = bytes.clone();
    b[at] = b'B';
    assert_eq!(open(&b, &f).err(), Some(CatalogError::BadSignature));
    for i in 0..12 + len {
        for bit in [0x01u8, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= bit;
            let err = open(&b, &f).err().unwrap_or_else(|| panic!("byte {i} opened"));
            assert!(
                matches!(
                    err,
                    CatalogError::NotACatalog
                        | CatalogError::Truncated
                        | CatalogError::BadHeader
                        | CatalogError::NewerFormat(_)
                        | CatalogError::UnknownPublisher
                        | CatalogError::BadSignature
                ),
                "byte {i}: {err:?}"
            );
        }
    }
}

#[test]
fn truncation_at_every_cut_point() {
    let f = fixture();
    let bytes = seal(&f, 1);
    for cut in 0..bytes.len() {
        let err = open(&bytes[..cut], &f).unwrap_err();
        assert!(matches!(err, CatalogError::Truncated | CatalogError::BadSignature), "cut {cut}: {err:?}");
    }
}

#[test]
fn not_a_catalog() {
    let f = fixture();
    let mut bytes = seal(&f, 1);
    bytes[0] = b'X';
    assert_eq!(open(&bytes, &f).err(), Some(CatalogError::NotACatalog));
    assert_eq!(open(b"PK\x03\x04 a zip file, not a catalog", &f).err(), Some(CatalogError::NotACatalog));
    assert_eq!(open(b"MVPN", &f).err(), Some(CatalogError::Truncated));
}

#[test]
fn versions_same_lower_and_higher() {
    let f = fixture();
    let bytes = seal(&f, 5);
    let trust = fresh_trust(&f.admin);
    let at = |applied: u64| OpenRequest {
        trust: &trust,
        catalog_id: None,
        applied_version: Some(applied),
        team_key: &f.team,
    };
    assert_eq!(open_catalog(&bytes, &at(5)).err(), Some(CatalogError::SameVersion));
    assert_eq!(open_catalog(&bytes, &at(6)).err(), Some(CatalogError::Rollback { applied: 6, offered: 5 }));
    assert_eq!(open_catalog(&bytes, &at(4)).unwrap().header.version, 5);
    // The version check comes before decryption: a rollback with a wrong team key is still a rollback.
    let other = TeamKey::generate(&FixedEntropy::new(7)).unwrap();
    let req = OpenRequest { trust: &trust, catalog_id: None, applied_version: Some(6), team_key: &other };
    assert_eq!(open_catalog(&bytes, &req).err(), Some(CatalogError::Rollback { applied: 6, offered: 5 }));
}

#[test]
fn another_catalog_id_is_wrong_catalog() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let trust = fresh_trust(&f.admin);
    let req =
        OpenRequest { trust: &trust, catalog_id: Some(Uuid::from_u128(1)), applied_version: None, team_key: &f.team };
    assert_eq!(open_catalog(&bytes, &req).err(), Some(CatalogError::WrongCatalog));
}

#[test]
fn the_size_cap_is_checked_before_parsing() {
    let f = fixture();
    let mut bytes = vec![0u8; MAX_CATALOG_BYTES + 1];
    assert_eq!(open(&bytes, &f).err(), Some(CatalogError::TooLarge));
    bytes[..8].copy_from_slice(MAGIC);
    assert_eq!(open(&bytes, &f).err(), Some(CatalogError::TooLarge));
    assert_eq!(peek_header(&bytes).err(), Some(CatalogError::TooLarge));
}

#[test]
fn a_header_length_out_of_range_is_truncated() {
    let f = fixture();
    let bytes = seal(&f, 1);
    for len in [0u32, (MAX_HEADER_BYTES + 1) as u32, u32::MAX, (bytes.len()) as u32] {
        let mut b = bytes.clone();
        b[8..12].copy_from_slice(&len.to_be_bytes());
        assert_eq!(open(&b, &f).err(), Some(CatalogError::Truncated), "{len}");
    }
}

#[test]
fn header_rules() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let format2 = resign(&bytes, &f.admin, |h| h["format"] = 2.into());
    assert_eq!(open(&format2, &f).err(), Some(CatalogError::NewerFormat(2)));
    let argon = resign(&bytes, &f.admin, |h| h["kdf"] = "argon2id".into());
    assert_eq!(open(&argon, &f).err(), Some(CatalogError::BadHeader));
    let enc = resign(&bytes, &f.admin, |h| h["enc"] = "aes256gcm".into());
    assert_eq!(open(&enc, &f).err(), Some(CatalogError::BadHeader));
    let unknown = resign(&bytes, &f.admin, |h| h["extra"] = 1.into());
    assert_eq!(open(&unknown, &f).err(), Some(CatalogError::BadHeader));
    let name = resign(&bytes, &f.admin, |h| h["name"] = "bad\nname".into());
    assert_eq!(open(&name, &f).err(), Some(CatalogError::BadHeader));
    let version0 = resign(&bytes, &f.admin, |h| h["version"] = 0.into());
    assert_eq!(open(&version0, &f).err(), Some(CatalogError::BadHeader));
    let id = resign(&bytes, &f.admin, |h| h["publisher_key_id"] = "0000-0000-0000-0000-0000-0000-0000-0000".into());
    assert_eq!(open(&id, &f).err(), Some(CatalogError::BadHeader));
    let own = f.admin.public();
    let successor_self = resign(&bytes, &f.admin, |h| h["successor_key"] = h["publisher_key"].clone());
    assert_eq!(open(&successor_self, &f).err(), Some(CatalogError::BadHeader));
    assert_eq!(own, f.admin.public());
    // A duplicate key (serde_json would keep the last one).
    let len = header_len(&bytes);
    let header = String::from_utf8(bytes[12..12 + len].to_vec()).unwrap();
    let dup = header.replacen("\"kdf\":\"none\"", "\"kdf\":\"none\",\"kdf\":\"none\"", 1);
    assert_ne!(dup, header);
    let mut b = MAGIC.to_vec();
    b.extend_from_slice(&(dup.len() as u32).to_be_bytes());
    b.extend_from_slice(dup.as_bytes());
    b.extend_from_slice(&bytes[12 + len..]);
    assert_eq!(open(&b, &f).err(), Some(CatalogError::BadHeader));
    // The header is bound to the payload: a valid header of another catalog with this payload does not decrypt.
    let moved = resign(&bytes, &f.admin, |h| h["version"] = 2.into());
    assert_eq!(open(&moved, &f).err(), Some(CatalogError::WrongTeamKey));
}

#[test]
fn seal_refuses_what_no_subscriber_could_open() {
    let f = fixture();
    let mut p = payload();
    p.connections[0].name = String::new();
    assert_eq!(
        seal_catalog(input(1, None), &p, &f.team, &f.admin, &f.entropy).err(),
        Some(CatalogError::Invalid(InvalidCatalog::ConnectionName))
    );
    let mut bad = input(1, None);
    bad.name = "line\nbreak".into();
    assert_eq!(seal_catalog(bad, &payload(), &f.team, &f.admin, &f.entropy).err(), Some(CatalogError::BadHeader));
    assert_eq!(
        seal_catalog(input(0, None), &payload(), &f.team, &f.admin, &f.entropy).err(),
        Some(CatalogError::BadHeader)
    );
    assert_eq!(
        seal_catalog(input(1, Some(f.admin.public())), &payload(), &f.team, &f.admin, &f.entropy).err(),
        Some(CatalogError::BadHeader)
    );
}

#[test]
fn errors_are_distinct_and_leak_nothing() {
    let all = [
        CatalogError::NotACatalog,
        CatalogError::Truncated,
        CatalogError::TooLarge,
        CatalogError::NewerFormat(2),
        CatalogError::BadHeader,
        CatalogError::UnknownPublisher,
        CatalogError::BadSignature,
        CatalogError::WrongCatalog,
        CatalogError::SameVersion,
        CatalogError::Rollback { applied: 7, offered: 3 },
        CatalogError::WrongTeamKey,
        CatalogError::Invalid(InvalidCatalog::Config { connection: Uuid::from_u128(0xC1) }),
    ];
    let messages: Vec<String> = all.iter().map(|e| e.to_string()).collect();
    for (i, m) in messages.iter().enumerate() {
        for (j, n) in messages.iter().enumerate() {
            if i != j {
                assert_ne!(m, n);
            }
        }
        for secret in [CATALOG_NAME, CONNECTION_NAME, "vpn.example.com", "client\ndev"] {
            assert!(!m.contains(secret), "{m}");
        }
        // Review L5: the unauthenticated format number is never shown.
        if matches!(all[i], CatalogError::NewerFormat(_)) {
            assert!(!m.contains('2'), "{m}");
        }
    }
    assert!(messages[9].contains('7') && messages[9].contains('3'));
    assert_eq!(CatalogError::WrongTeamKey.kind(), Some(CatalogErrorKind::WrongTeamKey));
    assert_eq!(CatalogError::Invalid(InvalidCatalog::Malformed).kind(), Some(CatalogErrorKind::Invalid));
    assert_eq!(CatalogError::SameVersion.kind(), None);
    assert_eq!(CatalogError::Unavailable("x".into()).kind(), None);
}

/// A file built by hand around `plaintext`, with this fixture's header, team key and signature.
fn with_plaintext(f: &Fixture, plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::AeadInOut;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    let template = seal(f, 1);
    let len = header_len(&template);
    let header = template[12..12 + len].to_vec();
    let nonce = open(&template, f).unwrap().header.nonce;
    let mut aad = AAD_DOMAIN.to_vec();
    aad.extend_from_slice(&template[..12 + len]);
    let cipher = XChaCha20Poly1305::new_from_slice(f.team.as_bytes()).unwrap();
    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_inout_detached(&XNonce::from(nonce), &aad, (&mut buffer[..]).into()).unwrap();
    let mut out = template[..12].to_vec();
    out.extend_from_slice(&header);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&out);
    out.extend_from_slice(&f.admin.sign(&message));
    out
}

#[test]
fn the_payload_is_checked_last() {
    let f = fixture();
    let newer = br#"{"version":2,"anything":"new"}"#;
    assert_eq!(open(&with_plaintext(&f, newer), &f).err(), Some(CatalogError::NewerFormat(2)));
    let malformed = br#"{"version":1}"#;
    assert_eq!(open(&with_plaintext(&f, malformed), &f).err(), Some(CatalogError::Invalid(InvalidCatalog::Malformed)));
    let forbidden = br#"{"version":1,"folders":[],"connections":[{"id":"00000000-0000-4000-8000-0000000000C1","name":"x","kind":"openvpn","folderId":null,"color":null,"config":"c2NyaXB0LXNlY3VyaXR5IDIK","native":null,"otp":{"enabled":false,"separator":"none"},"slot":null,"secretRefs":{}}],"credentialSlots":[],"sharedSecrets":{}}"#;
    assert_eq!(
        open(&with_plaintext(&f, forbidden), &f).err(),
        Some(CatalogError::Invalid(InvalidCatalog::Config { connection: Uuid::from_u128(0x4000_8000_0000_0000_00C1) }))
    );
    assert_eq!(CatalogError::from(InvalidCatalog::NewerVersion(3)), CatalogError::NewerFormat(3));
}

// MARK: - successor key

#[test]
fn a_catalog_signed_by_the_announced_successor_opens() {
    let f = fixture();
    let backup = AdminKey::generate(&FixedEntropy::new(77)).unwrap();
    let v1 = seal_catalog(input(1, Some(backup.public())), &payload(), &f.team, &f.admin, &f.entropy).unwrap();
    let opened = open(&v1, &f).unwrap();
    assert_eq!(opened.header.successor_key, Some(backup.public()));

    let v2 = seal_catalog(input(2, None), &payload(), &f.team, &backup, &f.entropy).unwrap();
    let trust = Trust {
        pinned: f.admin.public().fingerprint(),
        publisher_key: Some(f.admin.public()),
        successor: Some(backup.public()),
    };
    let req =
        OpenRequest { trust: &trust, catalog_id: Some(catalog_id()), applied_version: Some(1), team_key: &f.team };
    let opened = open_catalog(&v2, &req).unwrap();
    assert!(opened.signed_by_successor);
    assert_eq!(opened.header.publisher_key, backup.public());

    // Without the announcement, the backup key is unknown.
    let trust = Trust { successor: None, ..trust };
    let req =
        OpenRequest { trust: &trust, catalog_id: Some(catalog_id()), applied_version: Some(1), team_key: &f.team };
    assert_eq!(open_catalog(&v2, &req).err(), Some(CatalogError::UnknownPublisher));
    // An unannounced key is unknown too.
    let stranger = AdminKey::generate(&FixedEntropy::new(78)).unwrap();
    let v3 = seal_catalog(input(3, None), &payload(), &f.team, &stranger, &f.entropy).unwrap();
    let trust = Trust { successor: Some(backup.public()), ..trust };
    let req = OpenRequest { trust: &trust, catalog_id: None, applied_version: None, team_key: &f.team };
    assert_eq!(open_catalog(&v3, &req).err(), Some(CatalogError::UnknownPublisher));
}

// MARK: - robustness

/// xorshift64*: deterministic, no new crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn random_bytes_and_mutations_never_panic_or_open() {
    let f = fixture();
    let bytes = seal(&f, 1);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..300 {
        let n = rng.below(512);
        let random: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        assert!(open(&random, &f).is_err());
        let mut framed = MAGIC.to_vec();
        framed.extend_from_slice(&random);
        assert!(open(&framed, &f).is_err());
    }
    for _ in 0..2000 {
        let mut b = bytes.clone();
        for _ in 0..1 + rng.below(4) {
            match rng.below(3) {
                0 => {
                    let i = rng.below(b.len());
                    b[i] = rng.next() as u8;
                }
                1 => {
                    let i = rng.below(b.len());
                    b.remove(i);
                }
                _ => {
                    let i = rng.below(b.len() + 1);
                    b.insert(i, rng.next() as u8);
                }
            }
        }
        if b == bytes {
            continue;
        }
        let err = open(&b, &f).expect_err("a mutated file must not open");
        assert_ne!(err, CatalogError::WrongTeamKey);
        let _ = peek_header(&b);
    }
}

#[test]
fn fingerprint_type_is_reexported_for_trust() {
    // Trust pins the 16-byte fingerprint; parsing what a user typed gives the same value.
    let f = fixture();
    let typed = f.admin.public().fingerprint().to_text().to_lowercase();
    let trust = Trust { pinned: Fingerprint::parse(&typed).unwrap(), publisher_key: None, successor: None };
    assert!(open_catalog(&seal(&f, 1), &request(&trust, &f.team)).is_ok());
}
