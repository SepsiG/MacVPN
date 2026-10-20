//! The catalog payload and its validation (spec 2 and 3, plan Task 3). A catalog is untrusted input: every rule is
//! exercised with a minimal crafted payload.

use macvpn_core::catalog::payload::{
    CatalogCollection, CatalogConnection, CatalogFolder, CatalogPayload, CredentialSlot, InvalidCatalog,
    MAX_CATALOG_CONFIG_BYTES, MAX_CATALOG_CONNECTIONS, MAX_CATALOG_FOLDERS, MAX_CONNECTION_NAME_CHARACTERS,
    MAX_CREDENTIAL_SLOTS, MAX_SHARED_SECRETS, PAYLOAD_VERSION, PersonalField, decode_payload, encode_payload,
    personal_fields, validate_payload,
};
use macvpn_core::importer;
use macvpn_core::models::{NativeSettings, OTPSeparator, OTPSetting, SecretField, VPNKind};
use macvpn_core::vault::FolderColor;
use std::collections::BTreeMap;
use uuid::Uuid;
use zeroize::Zeroizing;

const OPENVPN: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\n";
const WIREGUARD: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = \
                         10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = \
                         0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";
const SECRET_CONFIG_TEXT: &str = "remote vpn.example.com 1194";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x1000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn connection(n: u128, name: &str, kind: VPNKind, config: &str) -> CatalogConnection {
    CatalogConnection {
        id: id(n),
        name: name.into(),
        kind,
        folder: None,
        color: None,
        config: Zeroizing::new(config.into()),
        native: None,
        otp: OTPSetting::default(),
        slot: None,
        secret_refs: BTreeMap::new(),
    }
}

fn native(n: u128, name: &str, kind: VPNKind) -> CatalogConnection {
    let mut c = connection(n, name, kind, "");
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: String::new(),
        group_name: if kind == VPNKind::Cisco { "staff".into() } else { String::new() },
        send_all_traffic: false,
    });
    c
}

fn empty() -> CatalogPayload {
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: vec![],
        connections: vec![],
        credential_slots: vec![],
        shared_secrets: BTreeMap::new(),
    }
}

/// Every kind, nested folders, a slot and two shared secrets.
fn sample() -> CatalogPayload {
    let folders = vec![
        CatalogFolder {
            id: id(100),
            parent: None,
            name: "Offices".into(),
            color: Some(FolderColor::Blue),
            position: 0,
        },
        CatalogFolder { id: id(101), parent: Some(id(100)), name: "Budapest".into(), color: None, position: 1 },
        CatalogFolder {
            id: id(102),
            parent: Some(id(101)),
            name: "Lab".into(),
            color: Some(FolderColor::Pink),
            position: 0,
        },
    ];
    let mut ovpn = connection(1, "Acme VPN", VPNKind::Openvpn, OPENVPN);
    ovpn.folder = Some(id(102));
    ovpn.color = Some(FolderColor::Red);
    ovpn.slot = Some(id(200));
    ovpn.otp = OTPSetting::new(true, OTPSeparator::Comma);
    ovpn.secret_refs.insert(SecretField::KeyPassword, id(301));
    let mut wg = connection(2, "WireGuard lab", VPNKind::Wireguard, WIREGUARD);
    wg.folder = Some(id(100));
    let sw = connection(3, "IKEv2 office", VPNKind::Strongswan, &importer::template(VPNKind::Strongswan));
    // The SSTP validator requires a user name: the catalog carries a placeholder the slot replaces at connect.
    let sstp =
        connection(4, "SSTP office", VPNKind::Sstp, &importer::template(VPNKind::Sstp).replace("user=", "user=staff"));
    let mut l2tp = native(5, "L2TP office", VPNKind::L2tp);
    l2tp.secret_refs.insert(SecretField::Psk, id(300));
    l2tp.slot = Some(id(200));
    let mut cisco = native(6, "Cisco office", VPNKind::Cisco);
    cisco.secret_refs.insert(SecretField::Psk, id(300));
    cisco.folder = Some(id(101));
    let mut secrets = BTreeMap::new();
    secrets.insert(id(300), Zeroizing::new("team-psk-value".to_string()));
    secrets.insert(id(301), Zeroizing::new("key-pass-value".to_string()));
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders,
        connections: vec![ovpn, wg, sw, sstp, l2tp, cisco],
        credential_slots: vec![CredentialSlot { id: id(200), name: "Office AD".into() }],
        shared_secrets: secrets,
    }
}

fn invalid(p: &CatalogPayload) -> InvalidCatalog {
    validate_payload(p).expect_err("the payload should be refused")
}

// MARK: - round trip

#[test]
fn the_sample_is_valid() {
    let findings = validate_payload(&sample()).unwrap();
    assert!(findings.risky.is_empty());
}

#[test]
fn encode_decode_round_trip() {
    let p = sample();
    let bytes = encode_payload(&p).unwrap();
    let back = decode_payload(&bytes).unwrap();
    assert_eq!(back, p);
    // Configs and secrets are base64 inside the JSON, never plain.
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains(SECRET_CONFIG_TEXT));
    assert!(!text.contains("team-psk-value"));
    assert!(text.contains("\"version\":1"));
}

#[test]
fn an_empty_payload_round_trips() {
    let bytes = encode_payload(&empty()).unwrap();
    assert_eq!(decode_payload(&bytes).unwrap(), empty());
}

#[test]
fn encode_refuses_an_invalid_payload() {
    let mut p = sample();
    p.connections[0].name = String::new();
    assert_eq!(encode_payload(&p).err(), Some(InvalidCatalog::ConnectionName));
}

// MARK: - JSON strictness

fn json_of(p: &CatalogPayload) -> String {
    String::from_utf8(encode_payload(p).unwrap().to_vec()).unwrap()
}

#[test]
fn a_duplicate_key_is_malformed() {
    let text = json_of(&empty());
    let dup = text.replacen("\"version\":1}", "\"version\":1,\"version\":1}", 1);
    assert_ne!(dup, text);
    assert_eq!(decode_payload(dup.as_bytes()).err(), Some(InvalidCatalog::Malformed));
    // Nested too.
    let text = json_of(&sample());
    let dup = text.replacen("\"name\":", "\"name\":\"x\",\"name\":", 1);
    assert_eq!(decode_payload(dup.as_bytes()).err(), Some(InvalidCatalog::Malformed));
}

#[test]
fn an_unknown_key_is_malformed() {
    let text = json_of(&empty());
    let extra = text.replacen("\"version\":1}", "\"version\":1,\"extra\":true}", 1);
    assert_ne!(extra, text);
    assert_eq!(decode_payload(extra.as_bytes()).err(), Some(InvalidCatalog::Malformed));
    let text = json_of(&sample());
    let extra = text.replacen("\"position\":", "\"unknown\":1,\"position\":", 1);
    assert_eq!(decode_payload(extra.as_bytes()).err(), Some(InvalidCatalog::Malformed));
}

#[test]
fn broken_json_is_malformed() {
    for bad in [&b""[..], b"[]", b"{", b"null", b"{\"version\":1}", b"\xff"] {
        assert_eq!(decode_payload(bad).err(), Some(InvalidCatalog::Malformed), "{bad:?}");
    }
    let text = json_of(&sample());
    let bad_kind = text.replacen("\"kind\":\"openvpn\"", "\"kind\":\"pptp\"", 1);
    assert_eq!(decode_payload(bad_kind.as_bytes()).err(), Some(InvalidCatalog::Malformed));
    let bad_b64 = text.replacen("\"config\":\"", "\"config\":\"*", 1);
    assert_eq!(decode_payload(bad_b64.as_bytes()).err(), Some(InvalidCatalog::Malformed));
}

#[test]
fn a_newer_payload_version_is_reported() {
    let text = json_of(&empty()).replacen("\"version\":1", "\"version\":2", 1);
    assert_eq!(decode_payload(text.as_bytes()).err(), Some(InvalidCatalog::NewerVersion(2)));
    let text = json_of(&empty()).replacen("\"version\":1", "\"version\":0", 1);
    assert_eq!(decode_payload(text.as_bytes()).err(), Some(InvalidCatalog::Malformed));
}

#[test]
fn decode_validates() {
    // Built without the encoder's check: replace a folder id in valid JSON.
    let reference = format!("\"folderId\":\"{}\"", id(100).to_string().to_uppercase());
    let text = json_of(&sample());
    assert!(text.contains(&reference));
    let text = text.replace(&reference, &format!("\"folderId\":\"{}\"", id(999).to_string().to_uppercase()));
    assert_eq!(decode_payload(text.as_bytes()).err(), Some(InvalidCatalog::UnknownFolder));
}

// MARK: - validation rules

#[test]
fn caps_per_collection() {
    let mut p = empty();
    p.connections = (0..=MAX_CATALOG_CONNECTIONS as u128)
        .map(|n| connection(n, &format!("c{n}"), VPNKind::Openvpn, OPENVPN))
        .collect();
    assert_eq!(invalid(&p), InvalidCatalog::TooMany(CatalogCollection::Connections));

    let mut p = empty();
    p.folders = (0..=MAX_CATALOG_FOLDERS as u128)
        .map(|n| CatalogFolder { id: id(n), parent: None, name: format!("f{n}"), color: None, position: 0 })
        .collect();
    assert_eq!(invalid(&p), InvalidCatalog::TooMany(CatalogCollection::Folders));

    let mut p = empty();
    p.credential_slots =
        (0..=MAX_CREDENTIAL_SLOTS as u128).map(|n| CredentialSlot { id: id(n), name: format!("s{n}") }).collect();
    assert_eq!(invalid(&p), InvalidCatalog::TooMany(CatalogCollection::CredentialSlots));

    let mut p = empty();
    p.shared_secrets = (0..=MAX_SHARED_SECRETS as u128).map(|n| (id(n), Zeroizing::new("s".into()))).collect();
    assert_eq!(invalid(&p), InvalidCatalog::TooMany(CatalogCollection::SharedSecrets));
}

#[test]
fn duplicate_ids() {
    let mut p = sample();
    p.connections[1].id = p.connections[0].id;
    assert_eq!(invalid(&p), InvalidCatalog::Duplicate);
    let mut p = sample();
    p.folders[1].id = p.folders[0].id;
    assert_eq!(invalid(&p), InvalidCatalog::Duplicate);
    let mut p = sample();
    p.credential_slots.push(CredentialSlot { id: id(200), name: "Other".into() });
    assert_eq!(invalid(&p), InvalidCatalog::Duplicate);
}

#[test]
fn folder_rules() {
    let mut p = sample();
    p.folders[0].name = " Offices".into();
    assert_eq!(invalid(&p), InvalidCatalog::FolderName);
    let mut p = sample();
    p.folders[0].name = "Bad\u{7}".into();
    assert_eq!(invalid(&p), InvalidCatalog::FolderName);
    let mut p = sample();
    p.folders[0].parent = Some(id(102));
    assert_eq!(invalid(&p), InvalidCatalog::FolderTree);
    let mut p = sample();
    p.folders[1].parent = Some(id(999));
    assert_eq!(invalid(&p), InvalidCatalog::FolderTree);
    let mut p = sample();
    p.connections[0].folder = Some(id(999));
    assert_eq!(invalid(&p), InvalidCatalog::UnknownFolder);
}

#[test]
fn connection_names() {
    for bad in ["", "  ", " padded", "tab\tname", "line\nbreak"] {
        let mut p = sample();
        p.connections[0].name = bad.into();
        assert_eq!(invalid(&p), InvalidCatalog::ConnectionName, "{bad:?}");
    }
    let mut p = sample();
    p.connections[0].name = "x".repeat(MAX_CONNECTION_NAME_CHARACTERS + 1);
    assert_eq!(invalid(&p), InvalidCatalog::ConnectionName);
    p.connections[0].name = "x".repeat(MAX_CONNECTION_NAME_CHARACTERS);
    validate_payload(&p).unwrap();
}

#[test]
fn slot_rules() {
    let mut p = sample();
    p.credential_slots[0].name = "Office AD ".into();
    assert_eq!(invalid(&p), InvalidCatalog::SlotName);
    let mut p = sample();
    p.credential_slots[0].name = String::new();
    assert_eq!(invalid(&p), InvalidCatalog::SlotName);
    let mut p = sample();
    p.connections[0].slot = Some(id(999));
    assert_eq!(invalid(&p), InvalidCatalog::UnknownSlot);
}

#[test]
fn secret_rules() {
    let mut p = sample();
    p.connections[0].secret_refs.insert(SecretField::Password, id(300));
    assert_eq!(invalid(&p), InvalidCatalog::SecretField);
    let mut p = sample();
    p.connections[0].secret_refs.insert(SecretField::Username, id(300));
    assert_eq!(invalid(&p), InvalidCatalog::SecretField);
    let mut p = sample();
    p.connections[0].secret_refs.insert(SecretField::KeyPassword, id(999));
    assert_eq!(invalid(&p), InvalidCatalog::UnknownSecret);
    let mut p = sample();
    p.shared_secrets.insert(id(300), Zeroizing::new("line\nbreak".into()));
    assert_eq!(invalid(&p), InvalidCatalog::Secret);
    let mut p = sample();
    p.shared_secrets.insert(id(300), Zeroizing::new("x".repeat(64 * 1024 + 1)));
    assert_eq!(invalid(&p), InvalidCatalog::Secret);
}

#[test]
fn config_rules() {
    let mut p = sample();
    p.connections[0].config =
        Zeroizing::new(format!("{OPENVPN}{}", "# padding\n".repeat(MAX_CATALOG_CONFIG_BYTES / 10)));
    assert_eq!(invalid(&p), InvalidCatalog::ConfigTooLarge);

    let mut p = sample();
    p.connections[0].config = Zeroizing::new(format!("{OPENVPN}script-security 2\n"));
    assert_eq!(invalid(&p), InvalidCatalog::Config { connection: id(1) });

    let mut p = sample();
    p.connections[0].config = Zeroizing::new(format!("{OPENVPN}\0"));
    assert_eq!(invalid(&p), InvalidCatalog::Config { connection: id(1) });

    let mut p = sample();
    p.connections[1].config = Zeroizing::new("[Interface]\nPostUp = /bin/sh\n".into());
    assert_eq!(invalid(&p), InvalidCatalog::Config { connection: id(2) });

    let mut p = sample();
    p.connections[2].config = Zeroizing::new("connections {\n".into());
    assert_eq!(invalid(&p), InvalidCatalog::Config { connection: id(3) });
}

#[test]
fn a_risky_directive_validates_and_is_reported() {
    let mut p = sample();
    p.connections[0].config = Zeroizing::new(format!("{OPENVPN}user nobody\n"));
    let findings = validate_payload(&p).unwrap();
    let risky = &findings.risky[&id(1)];
    assert_eq!(risky.len(), 1);
    assert_eq!(risky[0].directive, "user");
    assert_eq!(findings.risky.len(), 1);
}

#[test]
fn inline_credentials_are_refused() {
    let mut p = sample();
    p.connections[0].config = Zeroizing::new(format!("{OPENVPN}<auth-user-pass>\nuser\npass\n</auth-user-pass>\n"));
    assert_eq!(invalid(&p), InvalidCatalog::InlineCredentials { connection: id(1) });
}

/// Review M1: an inline proxy login is a user's password too.
#[test]
fn inline_proxy_credentials_are_refused() {
    let mut p = sample();
    p.connections[0].config =
        Zeroizing::new(format!("{OPENVPN}<http-proxy-user-pass>\nuser\npass\n</http-proxy-user-pass>\n"));
    assert_eq!(invalid(&p), InvalidCatalog::InlineCredentials { connection: id(1) });
}

/// Review M2: a strongSwan `secrets { … }` section (an EAP password, a PSK) is refused; a team PSK travels only
/// through `secretRefs`.
#[test]
fn a_strongswan_secrets_section_is_refused() {
    let mut p = sample();
    let with_secrets = format!(
        "{}secrets {{\n  ike-1 {{\n    secret = \"team-psk\"\n  }}\n}}\n",
        importer::template(VPNKind::Strongswan)
    );
    p.connections[2].config = Zeroizing::new(with_secrets);
    assert_eq!(invalid(&p), InvalidCatalog::InlineCredentials { connection: id(3) });
}

#[test]
fn native_settings_rules() {
    // An account name is per user.
    let mut p = sample();
    p.connections[4].native.as_mut().unwrap().account = "alice".into();
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(5) });
    // A native connection needs its settings, and has no config.
    let mut p = sample();
    p.connections[4].native = None;
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(5) });
    let mut p = sample();
    p.connections[4].config = Zeroizing::new("x".into());
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(5) });
    // The server is required; Cisco needs a group name.
    let mut p = sample();
    p.connections[4].native.as_mut().unwrap().server = String::new();
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(5) });
    let mut p = sample();
    p.connections[5].native.as_mut().unwrap().group_name = String::new();
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(6) });
    let mut p = sample();
    p.connections[5].native.as_mut().unwrap().server = "vpn\u{0}.example.com".into();
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(6) });
    // A non-native connection has no native settings.
    let mut p = sample();
    p.connections[0].native = native(9, "x", VPNKind::L2tp).native;
    assert_eq!(invalid(&p), InvalidCatalog::NativeSettings { connection: id(1) });
}

// MARK: - personal fields

#[test]
fn personal_fields_are_found() {
    let p = sample();
    assert_eq!(personal_fields(&p.connections[0]), vec![]);
    let mut c = connection(1, "x", VPNKind::Openvpn, &format!("{OPENVPN}<key>\nKEY\n</key>\n"));
    assert_eq!(personal_fields(&c), vec![PersonalField::OpenVpnInlineKey]);
    // Review L1: an inline PKCS#12 bundle holds the private key too.
    c = connection(1, "x", VPNKind::Openvpn, &format!("{OPENVPN}<pkcs12>\nMIIB\n</pkcs12>\n"));
    assert_eq!(personal_fields(&c), vec![PersonalField::OpenVpnInlineKey]);
    c = connection(2, "x", VPNKind::Wireguard, WIREGUARD);
    assert_eq!(personal_fields(&c), vec![PersonalField::WireGuardPrivateKey]);
    let without_key: String =
        WIREGUARD.lines().filter(|l| !l.starts_with("PrivateKey")).map(|l| format!("{l}\n")).collect();
    c = connection(2, "x", VPNKind::Wireguard, &without_key);
    assert_eq!(personal_fields(&c), vec![]);
    let sstp = importer::template(VPNKind::Sstp).replace("user=", "user=alice");
    c = connection(3, "x", VPNKind::Sstp, &sstp);
    assert_eq!(personal_fields(&c), vec![PersonalField::SstpUser]);
    let mut n = native(4, "x", VPNKind::L2tp);
    n.native.as_mut().unwrap().account = "alice".into();
    assert_eq!(personal_fields(&n), vec![PersonalField::NativeAccount]);
}

// MARK: - redaction

#[test]
fn debug_shows_no_config_or_secret() {
    let debug = format!("{:?}", sample());
    assert!(!debug.contains(SECRET_CONFIG_TEXT), "{debug}");
    assert!(!debug.contains("team-psk-value"));
    assert!(!debug.contains("key-pass-value"));
    assert!(debug.contains("Acme VPN"));
}

// MARK: - review L3, L4: canonical ids, strict OTP

#[test]
fn a_non_canonical_uuid_is_malformed_everywhere() {
    let text = json_of(&sample());
    // Every id of the sample is canonical (upper case); spell each kind once in lower case.
    for canonical in [
        "10000000-0000-4000-8000-000000000001", // a connection id
        "10000000-0000-4000-8000-000000000064", // a folder id and parentId
        "10000000-0000-4000-8000-0000000000C8", // a slot id and reference
        "10000000-0000-4000-8000-00000000012C", // a sharedSecrets key and a secretRefs target
    ] {
        let upper = canonical.to_uppercase();
        assert!(text.contains(&upper), "{upper}");
        for (i, _) in text.match_indices(&upper) {
            let mut one = text.clone();
            one.replace_range(i..i + upper.len(), &upper.to_lowercase());
            if one == text {
                continue;
            }
            assert_eq!(decode_payload(one.as_bytes()).err(), Some(InvalidCatalog::Malformed), "{upper} at {i}");
        }
    }
}

#[test]
fn two_spellings_of_one_shared_secret_id_are_a_duplicate() {
    let text = json_of(&sample());
    let key = "\"10000000-0000-4000-8000-00000000012C\":";
    let i = text.find(key).unwrap();
    let mut dup = text.clone();
    dup.insert_str(i, &format!("{}\"eA==\",", key.to_lowercase()));
    assert_eq!(decode_payload(dup.as_bytes()).err(), Some(InvalidCatalog::Duplicate));
}

#[test]
fn the_otp_object_is_strict() {
    let text = json_of(&sample());
    let otp = "\"otp\":{\"enabled\":true,\"separator\":\"comma\"}";
    assert!(text.contains(otp), "{text}");
    for bad in [
        "\"otp\":{\"enabled\":true,\"separator\":\"semicolon\"}",
        "\"otp\":{\"enabled\":true}",
        "\"otp\":{\"enabled\":true,\"separator\":\"comma\",\"extra\":1}",
        "\"otp\":{\"enabled\":\"yes\",\"separator\":\"comma\"}",
    ] {
        let one = text.replacen(otp, bad, 1);
        assert_eq!(decode_payload(one.as_bytes()).err(), Some(InvalidCatalog::Malformed), "{bad}");
    }
}
