//! The Connections window without a UI: the editors (dirty tracking, risky panel, saves with their validation,
//! native profile, system VPN secrets), the unsaved-changes registry and its question, the tab requests, create,
//! import (credential-file question, notes, aggregation), export and delete. The Swift app had these in
//! `AppModel` and the `…Draft` objects (UI target, untested there); the expectations follow its code.

mod common;

use common::*;
use macvpn_app_core::connections::{ConnectionsModel, PendingAction, Resolved, Tab, UnsavedChoice};
use macvpn_app_core::deps::{SecretField, SecretReader, SystemVpn};
use macvpn_app_core::editor::{EditorDeps, EditorFields, NativeFields, Separator, SystemFields, TextFields};
use macvpn_app_core::import_export;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, NativeSettings, OTPSeparator, VPNKind, uuid_string};
use std::path::PathBuf;
use std::sync::Arc;

struct Window {
    fx: Fixture,
    model: Arc<ConnectionsModel>,
    profiles: Arc<MobileconfigProfiles>,
    manager: Arc<macvpn_app_core::ConnectionManager>,
}

const CLEAN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";

fn window() -> Window {
    let fx = Fixture::new(AppLanguage::En);
    let manager = fx.manager();
    let profiles = Arc::new(MobileconfigProfiles::default());
    let deps = EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: profiles.clone(),
        clock: clock_at(1_000_000.0),
    };
    Window { model: Arc::new(ConnectionsModel::new(deps)), fx, profiles, manager }
}

impl Window {
    fn add(&self, name: &str, kind: VPNKind, config: Option<&str>) -> Connection {
        let mut c = Connection::new(name, kind);
        if kind.is_native() {
            c.native =
                Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
        }
        self.fx.store.save(&c, config).unwrap();
        self.manager.reload();
        c
    }

    fn text(&self, c: &Connection) -> TextFields {
        match self.model.open_editor(&uuid_string(&c.id)).unwrap().fields {
            EditorFields::Text(f) => f,
            other => panic!("{other:?}"),
        }
    }
}

fn key(c: &Connection) -> String {
    uuid_string(&c.id)
}

// MARK: - Text editor

#[test]
fn text_editor_loads_tracks_changes_and_saves() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("alice", &c.id, SecretField::Username);
    let f = w.text(&c);
    assert_eq!((f.name.as_str(), f.text.as_str(), f.username.as_str()), ("Office", CLEAN, "alice"));
    assert!(!w.model.has_unsaved_changes());

    let edited = TextFields {
        name: "Office 2".into(),
        password: Some("pw".into()),
        key_password: Some("kp".into()),
        ..f.clone()
    };
    let view = w.model.update_editor(&key(&c), EditorFields::Text(edited.clone())).unwrap();
    assert!(view.dirty);
    assert_eq!(w.model.view().dirty, vec![key(&c)]);
    // Back to the original: not dirty any more.
    assert!(!w.model.update_editor(&key(&c), EditorFields::Text(f.clone())).unwrap().dirty);

    let saved = w.model.save_editor(&key(&c), EditorFields::Text(edited)).unwrap();
    assert!(!saved.dirty, "{:?}", saved.issues);
    assert!(saved.issues.is_empty());
    assert_eq!(saved.saved_at, Some(1_000_000.0));
    assert_eq!(w.manager.connections()[0].name, "Office 2");
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("pw"));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword).as_deref(), Some("kp"));
    // A second open keeps the editor (no reload over the editing).
    assert_eq!(w.text(&c).name, "Office 2");
}

#[test]
fn key_password_is_only_stored_for_openvpn() {
    let w = window();
    let c = w.add("WG", VPNKind::Wireguard, Some(&macvpn_core::importer::template(VPNKind::Wireguard)));
    let f = w.text(&c);
    let edited = TextFields { key_password: Some("kp".into()), ..f };
    w.model.save_editor(&key(&c), EditorFields::Text(edited)).unwrap();
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword), None);
}

// MARK: - IKEv2 client certificate (G2 / G4)

const SWAN_PUBKEY: &str = "connections {\n  lab {\n    remote_addrs = vpn.example\n    local {\n      auth = pubkey\n    }\n    remote {\n      auth = pubkey\n    }\n    children {\n      net {\n        remote_ts = 0.0.0.0/0\n      }\n    }\n  }\n}\n";

#[test]
fn ikev2_keeps_the_key_password_and_imports_a_client_certificate_into_the_vault() {
    use macvpn_core::client_cert::{self, fixtures};
    let w = window();
    let c = w.add("Lab", VPNKind::Strongswan, Some(SWAN_PUBKEY));
    let view = w.model.open_editor(&key(&c)).unwrap();
    let cert = view.client_cert.clone().expect("the client certificate panel");
    assert!(cert.pubkey && cert.import && cert.imported.is_none());

    // G2: the key password is stored for IKEv2 too.
    let f = w.text(&c);
    w.model.save_editor(&key(&c), EditorFields::Text(TextFields { key_password: Some("kp".into()), ..f })).unwrap();
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword).as_deref(), Some("kp"));

    // G4: a PEM certificate with its key and a CA, as two files.
    let ca = fixtures::pem("CERTIFICATE", &fixtures::cert(true));
    let pair = fixtures::pem_pair();
    let view = w.model.import_client_cert(&key(&c), &[pair.as_bytes(), ca.as_bytes()]).unwrap();
    let cert = view.client_cert.clone().unwrap();
    let summary = cert.imported.clone().unwrap();
    assert_eq!((summary.form, summary.needs_password, cert.ignored), (client_cert::Form::Pem, false, 1));
    let stored = w.fx.secrets.get(&c.id, SecretField::ClientCert).unwrap();
    assert!(stored.starts_with("pem:") && !stored.contains('\n'));
    assert!(!view.dirty, "stored at once, not a draft change");
    // The web view gets the public summary only.
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("\"clientCert\"") && json.contains(&summary.sha256));
    // (The certificate is public and may show; the key never.)
    let key64 = stored.rsplit(':').next().unwrap();
    assert!(!json.contains(&key64[..40]) && !json.contains("PRIVATE"));
    // At connect the secrets carry it, as the frame lines.
    let secrets = w.fx.secrets.secrets(&c.id);
    assert_eq!(secrets.client_cert.as_deref(), Some(stored.as_str()));
    assert!(secrets.stdin_payload().contains("\nx509="));

    // The editor's "Certificates" section lists the imported client certificate first.
    let listed = view.certificates.as_ref().expect("the certificates section");
    let json = serde_json::to_value(listed).unwrap();
    assert_eq!(json["certificates"][0]["source"], "Imported client certificate", "{json}");
    assert_eq!(json["certificates"][0]["role"], "client");
    assert_eq!(json["certificates"][0]["sha256"].as_str(), Some(summary.sha256.as_str()));
    // A broken file leaves the stored one.
    let err = w.model.import_client_cert(&key(&c), &[b"-----BEGIN CERTIFICATE-----\nAA\n"]).unwrap_err();
    assert!(err.contains("PEM"), "{err}");
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::ClientCert).as_deref(), Some(stored.as_str()));

    // A PKCS#12 file replaces it and needs the password; Remove deletes it.
    let view = w.model.import_client_cert(&key(&c), &[&fixtures::p12()]).unwrap();
    assert!(view.client_cert.unwrap().imported.unwrap().needs_password);
    let view = w.model.remove_client_cert(&key(&c)).unwrap();
    assert!(view.client_cert.unwrap().imported.is_none());
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::ClientCert), None);
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword).as_deref(), Some("kp"), "the password stays");
}

#[test]
fn only_an_ikev2_editor_imports_a_client_certificate() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.model.open_editor(&key(&c)).unwrap();
    let pair = macvpn_core::client_cert::fixtures::pem_pair();
    assert!(w.model.import_client_cert(&key(&c), &[pair.as_bytes()]).is_err());
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::ClientCert), None);
    assert!(w.model.open_editor(&key(&c)).unwrap().client_cert.is_none());
    // An EAP config: no "Private key password" (pubkey false).
    let eap = SWAN_PUBKEY.replacen("auth = pubkey", "auth = eap-mschapv2", 1);
    let s = w.add("EAP", VPNKind::Strongswan, Some(&eap));
    assert!(!w.model.open_editor(&key(&s)).unwrap().client_cert.unwrap().pubkey);
}

// MARK: - WireGuard keys

const WG_PEER_KEY: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

#[test]
fn wireguard_key_pair_is_generated_into_the_draft_and_its_public_key_shown() {
    use macvpn_core::wireguard_keys::{self, KeyLine};
    let w = window();
    let c = w.add("WG", VPNKind::Wireguard, Some(&macvpn_core::importer::template(VPNKind::Wireguard)));
    let view = w.model.open_editor(&key(&c)).unwrap();
    let keys = view.wireguard.clone().expect("the key panel");
    assert_eq!((keys.private_key.as_deref(), keys.public_key.as_deref(), keys.peers), (None, None, 1));

    let entropy = macvpn_core::vault::FixedEntropy::new(7);
    let view = w.model.generate_wireguard_key(&key(&c), KeyLine::PrivateKey, &entropy).unwrap();
    assert!(view.dirty, "a generated key is an unsaved change");
    let keys = view.wireguard.clone().unwrap();
    let private = keys.private_key.clone().unwrap();
    assert_eq!(keys.public_key, wireguard_keys::public_key(&private));
    let EditorFields::Text(f) = &view.fields else { panic!() };
    assert!(f.text.contains(&format!("PrivateKey = {private}\n")), "{:?}", keys);
    assert_eq!(w.model.wireguard_secret(&key(&c), KeyLine::PrivateKey).unwrap().as_str(), private);
    // The JSON the web view gets: the panel in camelCase; the Debug form never prints the private key.
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["wireguard"]["publicKey"].as_str(), keys.public_key.as_deref());
    assert!(!format!("{keys:?}").contains(&private));

    // A second generation replaces it (the UI asked first).
    let again = w.model.generate_wireguard_key(&key(&c), KeyLine::PrivateKey, &entropy).unwrap();
    let replaced = again.wireguard.unwrap().private_key.unwrap();
    assert_ne!(replaced, private);
    let EditorFields::Text(f) = &again.fields else { panic!() };
    assert_eq!(f.text.matches("PrivateKey").count(), 1);

    // The preshared key of the only peer; saved with a peer key, the config validates.
    let with_psk = w.model.generate_wireguard_key(&key(&c), KeyLine::PresharedKey, &entropy).unwrap();
    let psk = with_psk.wireguard.unwrap().preshared_key.unwrap();
    assert!(wireguard_keys::decode_key(&psk).is_some());
    assert_eq!(w.model.wireguard_secret(&key(&c), KeyLine::PresharedKey).unwrap().as_str(), psk);
    let EditorFields::Text(f) = with_psk.fields else { panic!() };
    let text = f.text.replace("PublicKey =", &format!("PublicKey = {WG_PEER_KEY}"));
    let saved = w.model.save_editor(&key(&c), EditorFields::Text(TextFields { text, ..f })).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    assert!(w.fx.store.load_config(&c.id).unwrap().contains(&format!("PrivateKey = {replaced}")));
}

#[test]
fn an_edited_private_key_updates_the_public_key_or_shows_it_invalid() {
    let w = window();
    let c = w.add("WG", VPNKind::Wireguard, Some(&macvpn_core::importer::template(VPNKind::Wireguard)));
    let f = w.text(&c);
    // RFC 7748's Alice, pasted.
    let text = f.text.replace("PrivateKey =", "PrivateKey = dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=");
    let view = w.model.update_editor(&key(&c), EditorFields::Text(TextFields { text, ..f.clone() })).unwrap();
    let keys = view.wireguard.unwrap();
    assert_eq!(keys.public_key.as_deref(), Some("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="));
    let text = f.text.replace("PrivateKey =", "PrivateKey = not-a-key");
    let view = w.model.update_editor(&key(&c), EditorFields::Text(TextFields { text, ..f })).unwrap();
    let keys = view.wireguard.unwrap();
    assert_eq!((keys.private_key.as_deref(), keys.public_key), (Some("not-a-key"), None));
}

#[test]
fn only_a_wireguard_editor_has_the_key_panel_and_generates() {
    use macvpn_core::wireguard_keys::KeyLine;
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    let view = w.model.open_editor(&key(&c)).unwrap();
    assert!(view.wireguard.is_none());
    assert!(serde_json::to_value(&view).unwrap().get("wireguard").is_none());
    let entropy = macvpn_core::vault::FixedEntropy::new(1);
    assert!(w.model.generate_wireguard_key(&key(&c), KeyLine::PrivateKey, &entropy).is_err());
    assert_eq!(w.text(&c).text, CLEAN);
    assert!(w.model.wireguard_secret(&key(&c), KeyLine::PrivateKey).is_err());
    // Two peers: no preshared key to generate (the button is not shown).
    let two = format!("{}\n[Peer]\nPublicKey = {WG_PEER_KEY}\n", macvpn_core::importer::template(VPNKind::Wireguard));
    let wg = w.add("WG", VPNKind::Wireguard, Some(&two));
    let view = w.model.open_editor(&key(&wg)).unwrap();
    assert_eq!(view.wireguard.unwrap().peers, 2);
    assert!(w.model.generate_wireguard_key(&key(&wg), KeyLine::PresharedKey, &entropy).is_err());
}

#[test]
fn validation_problems_are_listed_with_line_numbers() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    let f = w.text(&c);
    let bad = TextFields { text: format!("{CLEAN}up /tmp/x.sh\n"), ..f };
    let view = w.model.save_editor(&key(&c), EditorFields::Text(bad)).unwrap();
    assert!(view.dirty);
    assert_eq!(view.saved_at, None);
    assert!(view.issues.iter().any(|i| i.starts_with("Line 4: ")), "{:?}", view.issues);
    assert_eq!(w.fx.store.load_config(&c.id).unwrap(), CLEAN, "not saved");
}

#[test]
fn control_characters_in_secrets_block_the_save() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    let f = w.text(&c);
    let bad = TextFields { password: Some("a\nb".into()), ..f };
    let view = w.model.save_editor(&key(&c), EditorFields::Text(bad)).unwrap();
    assert_eq!(view.issues, ["The user name, password and PSK must not contain line breaks or control characters"]);
}

#[test]
fn risky_panel_acknowledgement_and_its_reset() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    let f = w.text(&c);
    let risky = TextFields { text: format!("{CLEAN}user nobody\n"), ..f };
    let view = w.model.update_editor(&key(&c), EditorFields::Text(risky.clone())).unwrap();
    assert_eq!(view.risky.len(), 1);
    assert_eq!((view.risky[0].line, view.risky[0].directive.as_str()), (4, "user"));
    assert!(!view.acknowledges_risk);

    // Saving without the tick: the acknowledgement is asked for.
    let refused = w.model.save_editor(&key(&c), EditorFields::Text(risky.clone())).unwrap();
    assert_eq!(refused.issues, ["Acknowledge the risky settings (tick the checkbox) before saving: user"]);

    // Ticked: exactly the current set.
    let ticked = TextFields { acknowledged: ["user".to_string()].into(), ..risky };
    assert!(w.model.update_editor(&key(&c), EditorFields::Text(ticked.clone())).unwrap().acknowledges_risk);
    // A new risky directive un-ticks the box.
    let more = TextFields { text: format!("{}group nogroup\n", ticked.text), ..ticked.clone() };
    let view = w.model.update_editor(&key(&c), EditorFields::Text(more)).unwrap();
    assert!(!view.acknowledges_risk);
    assert_eq!(view.risky.len(), 2);

    let saved = w.model.save_editor(&key(&c), EditorFields::Text(ticked)).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    assert_eq!(w.manager.connections()[0].acknowledged_risky_directives, ["user"]);
}

#[test]
fn stored_acknowledgement_is_exactly_the_current_risky_set() {
    let w = window();
    let mut c = Connection::new("Office", VPNKind::Openvpn);
    c.acknowledged_risky_directives = vec!["user".into(), "group".into()];
    w.fx.store.save(&c, Some(&format!("{CLEAN}user nobody\n"))).unwrap();
    w.manager.reload();
    let f = w.text(&c);
    assert!(w.model.open_editor(&key(&c)).unwrap().acknowledges_risk);
    let saved = w.model.save_editor(&key(&c), EditorFields::Text(f)).unwrap();
    assert!(!saved.dirty);
    assert_eq!(w.manager.connections()[0].acknowledged_risky_directives, ["user"]);
    assert_eq!(w.text(&c).acknowledged, ["user".to_string()].into());
}

#[test]
fn static_challenge_replaces_the_otp_setting() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(&format!("{CLEAN}static-challenge \"Code\" 1\n")));
    assert!(w.model.open_editor(&key(&c)).unwrap().static_challenge);
}

#[test]
fn oversized_or_mismatched_fields_are_refused() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    let f = w.text(&c);
    let big = TextFields { text: "x".repeat(1_048_577), ..f.clone() };
    assert!(w.model.update_editor(&key(&c), EditorFields::Text(big)).is_err());
    let bad_name = TextFields { acknowledged: ["a b".to_string()].into(), ..f };
    assert!(w.model.update_editor(&key(&c), EditorFields::Text(bad_name)).is_err());
    assert!(w.model.update_editor(&key(&c), EditorFields::System(SystemFields::default())).is_err());
    assert!(
        w.model
            .update_editor("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", EditorFields::System(SystemFields::default()))
            .is_err()
    );
}

#[test]
fn import_issues_are_shown_once() {
    let w = window();
    let dir = w.fx.dir.path().join("import");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bad.ovpn"), "client\nremote a 1194\nup /x.sh\n").unwrap();
    let report = w.model.import_paths(&[dir.join("bad.ovpn")]);
    assert_eq!(report.notes, ["bad.ovpn: Imported, but the config has problems. Fix them in the editor (red list)."]);
    let id = w.model.selected().unwrap();
    let view = w.model.open_editor(&id).unwrap();
    assert!(view.issues.iter().any(|i| i.starts_with("Line 3: ")), "{:?}", view.issues);
    w.model.discard_unsaved();
    assert!(w.model.open_editor(&id).unwrap().issues.is_empty(), "one-time");
}

// MARK: - SSTP

fn sstp_fields(w: &Window, c: &Connection) -> macvpn_app_core::editor::SstpFields {
    match w.model.open_editor(&key(c)).unwrap().fields {
        EditorFields::Sstp(f) => f,
        other => panic!("{other:?}"),
    }
}

#[test]
fn sstp_form_saves_a_serialized_config() {
    let w = window();
    let c = w.add("SSTP", VPNKind::Sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp)));
    let f = sstp_fields(&w, &c);
    assert_eq!((f.server.as_str(), f.port), ("vpn.example.com", 443));
    let bad = macvpn_app_core::editor::SstpFields { password: Some("a\"b".into()), ..f.clone() };
    let view = w.model.update_editor(&key(&c), EditorFields::Sstp(bad.clone())).unwrap();
    assert_eq!(
        view.password_rule.as_deref(),
        Some("The SSTP password must not contain quotation marks, backslashes or control characters")
    );
    assert_eq!(w.model.save_editor(&key(&c), EditorFields::Sstp(bad)).unwrap().issues.len(), 1);

    let edited =
        macvpn_app_core::editor::SstpFields { user: "alice".into(), port: 8443, password: Some("pw".into()), ..f };
    let view = w.model.save_editor(&key(&c), EditorFields::Sstp(edited)).unwrap();
    assert!(view.issues.is_empty(), "{:?}", view.issues);
    let config = w.fx.store.load_config(&c.id).unwrap();
    assert!(config.contains("port=8443\nuser=alice\n"), "{config}");
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("pw"));
}

#[test]
fn sstp_issues_have_no_line_numbers_and_ca_import() {
    let w = window();
    let c = w.add("SSTP", VPNKind::Sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp)));
    let f = sstp_fields(&w, &c);
    let bad = macvpn_app_core::editor::SstpFields { server: "bad server".into(), ..f };
    let view = w.model.save_editor(&key(&c), EditorFields::Sstp(bad)).unwrap();
    assert!(!view.issues.is_empty());
    assert!(view.issues.iter().all(|i| !i.starts_with("Line ")), "{:?}", view.issues);

    let view = w
        .model
        .import_ca(&key(&c), Some("subject=x\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
        .unwrap();
    assert_eq!(view.cert_count, 1);
    assert_eq!(view.import_error, None);
    let view = w.model.import_ca(&key(&c), Some("not a cert")).unwrap();
    assert!(view.import_error.unwrap().starts_with("The file contains no PEM certificate"));
    assert_eq!(view.cert_count, 1, "the loaded certificate stays");
    assert!(w.model.import_ca(&key(&c), None).unwrap().import_error.is_some());
}

// MARK: - Native

fn native_fields(w: &Window, c: &Connection) -> NativeFields {
    match w.model.open_editor(&key(c)).unwrap().fields {
        EditorFields::Native(f) => f,
        other => panic!("{other:?}"),
    }
}

#[test]
fn native_save_installs_a_profile_without_the_password() {
    let w = window();
    let c = w.add("L2TP", VPNKind::L2tp, None);
    let f = native_fields(&w, &c);
    assert_eq!((f.server.as_str(), f.account.as_str()), ("vpn.example.com", "bob"));
    let edited = NativeFields {
        password: Some("topsecret".into()),
        psk: Some("sharedkey".into()),
        name: "Home".into(),
        ..f.clone()
    };
    let view = w.model.save_editor(&key(&c), EditorFields::Native(edited)).unwrap();
    assert_eq!(view.error, None);
    assert!(view.saved && !view.dirty);
    let installs = w.profiles.installs.lock().unwrap().clone();
    assert_eq!(installs.len(), 1);
    let (id, profile, file, existed) = &installs[0];
    assert_eq!((*id, file.as_str(), *existed), (c.id, "Home.mobileconfig", false));
    assert!(!profile.contains("topsecret"));
    assert!(profile.contains("c2hhcmVka2V5"), "the PSK (base64 data)");
    let saved = &w.manager.connections()[0];
    assert_eq!((saved.name.as_str(), saved.native_service_name.as_deref()), ("Home", Some("Home")));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("topsecret"));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Username).as_deref(), Some("bob"));
}

#[test]
fn native_only_otp_change_needs_no_new_profile() {
    let w = window();
    let c = w.add("L2TP", VPNKind::L2tp, None);
    let f = native_fields(&w, &c);
    let mut otp = f.otp;
    otp.enabled = true;
    otp.separator = Separator::Comma;
    let view = w.model.save_editor(&key(&c), EditorFields::Native(NativeFields { otp, ..f })).unwrap();
    assert!(view.saved);
    assert!(w.profiles.installs.lock().unwrap().is_empty());
    let saved = w.manager.connections()[0].otp;
    assert!(saved.enabled);
    assert_eq!(saved.separator, OTPSeparator::Comma);
}

#[test]
fn native_save_needs_server_and_account() {
    let w = window();
    let c = w.add("L2TP", VPNKind::L2tp, None);
    let f = native_fields(&w, &c);
    let view = w
        .model
        .save_editor(&key(&c), EditorFields::Native(NativeFields { server: String::new(), ..f.clone() }))
        .unwrap();
    assert_eq!(view.error.as_deref(), Some("Server and account name are required"));
    assert!(view.dirty && !view.saved);
    // The profile installer's failure is the error.
    *w.profiles.fail.lock().unwrap() = Some("cannot open".into());
    let view = w.model.save_editor(&key(&c), EditorFields::Native(NativeFields { name: "X".into(), ..f })).unwrap();
    assert_eq!(view.error.as_deref(), Some("cannot open"));
}

// MARK: - System VPN

const SERVICE: &str = "6A3F0B1E-2C4D-4E5F-8A9B-0C1D2E3F4A5B";

fn system_window(type_label: &str) -> Window {
    let w = window();
    w.fx.native.set_list(Ok(vec![SystemVpn::new(SERVICE, "Company", type_label, "Disconnected")]));
    w.manager.refresh();
    w
}

#[test]
fn system_secrets_save_and_forget() {
    let w = system_window("L2TP");
    let view = w.model.open_editor(SERVICE).unwrap();
    assert_eq!(view.kind, "system");
    assert!(!view.has_stored);
    let fields = SystemFields { psk: Some("k".into()), password: Some("p".into()), otp: Default::default() };
    let view = w.model.save_editor(SERVICE, EditorFields::System(fields)).unwrap();
    assert!(view.saved && view.has_stored && !view.dirty);
    let id = macvpn_core::models::parse_uuid(SERVICE).unwrap();
    assert_eq!(w.fx.secrets.get(&id, SecretField::Psk).as_deref(), Some("k"));

    let bad = SystemFields { psk: Some("a\u{7}".into()), ..SystemFields::default() };
    let view = w.model.save_editor(SERVICE, EditorFields::System(bad)).unwrap();
    assert!(view.error.is_some() && view.dirty);

    let view = w.model.forget_secrets(SERVICE).unwrap();
    assert!(!view.has_stored && !view.dirty && view.error.is_none());
    assert_eq!(w.fx.secrets.count(&id), 0);
}

#[test]
fn system_vpn_without_stored_secrets_has_no_editor() {
    let w = system_window("IKEv2");
    assert!(w.model.open_editor(SERVICE).is_err());
}

// MARK: - Unsaved changes

fn make_dirty(w: &Window, c: &Connection) {
    let f = w.text(c);
    w.model.update_editor(&key(c), EditorFields::Text(TextFields { name: "changed".into(), ..f })).unwrap();
}

#[test]
fn selection_change_asks_with_unsaved_changes() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("B", VPNKind::Openvpn, Some(CLEAN));
    assert!(w.model.select(Some(key(&a))));
    make_dirty(&w, &a);
    assert!(!w.model.select(Some(key(&b))));
    assert_eq!(w.model.pending(), Some(PendingAction::Select(Some(key(&b)))));
    assert_eq!(w.model.view().pending, Some("select"));
    assert_eq!(w.model.selected(), Some(key(&a)));

    // Cancel: nothing changes (the log request goes too).
    w.model.request_log_tab(&key(&a));
    assert_eq!(w.model.resolve(UnsavedChoice::Cancel), Resolved::Cancelled);
    assert_eq!(w.model.view().log_request, None);
    assert_eq!(w.model.selected(), Some(key(&a)));
    assert!(w.model.has_unsaved_changes());

    // Discard: the selection changes, the editing is gone.
    w.model.select(Some(key(&b)));
    assert_eq!(w.model.resolve(UnsavedChoice::Discard), Resolved::Done);
    assert_eq!(w.model.selected(), Some(key(&b)));
    assert!(!w.model.has_unsaved_changes());
    assert_eq!(w.manager.connections().iter().find(|c| c.id == a.id).unwrap().name, "A");
}

#[test]
fn save_then_proceed() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    make_dirty(&w, &a);
    assert!(!w.model.select(None));
    assert_eq!(w.model.resolve(UnsavedChoice::Save), Resolved::Done);
    assert_eq!(w.model.selected(), None);
    assert_eq!(w.manager.connections()[0].name, "changed");
}

#[test]
fn failed_save_reports_and_shows_the_editor() {
    let w = window();
    let a = w.add("Alpha", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("Beta", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    let f = w.text(&a);
    w.model.update_editor(&key(&a), EditorFields::Text(TextFields { text: format!("{CLEAN}up /x\n"), ..f })).unwrap();
    w.model.select(Some(key(&b)));
    match w.model.resolve(UnsavedChoice::Save) {
        Resolved::Failed(failure) => {
            assert_eq!(failure.title, "Saving failed");
            assert!(failure.message.starts_with("Alpha: Line 4: "), "{}", failure.message);
        }
        other => panic!("{other:?}"),
    }
    let view = w.model.view();
    assert_eq!((view.pending, view.selected.clone()), (None, Some(key(&a))));
    assert_eq!(view.settings_request, Some(key(&a)));
    assert!(w.model.has_unsaved_changes(), "the editing is kept");
    assert_eq!(w.model.take_tab_request(&key(&a)), Some(Tab::Settings));
    assert_eq!(w.model.take_tab_request(&key(&a)), None);
}

#[test]
fn window_close_and_quit_wait_for_the_answer() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    assert!(w.model.should_close_window());
    assert!(!w.model.ask_before_quit());
    make_dirty(&w, &a);
    assert!(!w.model.should_close_window());
    assert_eq!(w.model.resolve(UnsavedChoice::Discard), Resolved::CloseWindow);
    make_dirty(&w, &a);
    assert!(w.model.ask_before_quit());
    assert_eq!(w.model.view().pending, Some("quit"));
    assert_eq!(w.model.resolve(UnsavedChoice::Save), Resolved::Quit);
    assert!(!w.model.has_unsaved_changes());
    // The window closed: its editors are gone (a shown editor would load again).
    make_dirty(&w, &a);
    let epoch = w.model.view().editors_epoch;
    w.model.window_closed();
    assert!(!w.model.has_unsaved_changes());
    assert!(w.model.view().editors_epoch > epoch);
    assert_eq!(w.text(&a).name, "changed", "the saved name");
}

#[test]
fn a_selection_during_the_quit_question_waits_for_its_answer() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("B", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    make_dirty(&w, &a);
    assert!(w.model.ask_before_quit());
    // A notification click (or an Option-click debug connect) while the quit's question is shown.
    w.model.request_log_tab(&key(&b));
    assert!(!w.model.select(Some(key(&b))));
    assert_eq!(w.model.pending(), Some(PendingAction::Quit), "the quit's question stays");
    assert_eq!(w.model.view().pending, Some("quit"));
    assert_eq!(w.model.selected(), Some(key(&a)));
    // The quit is cancelled: the app goes on, the selection follows now (asking about the change first).
    assert_eq!(w.model.resolve(UnsavedChoice::Cancel), Resolved::Cancelled);
    assert_eq!(w.model.pending(), Some(PendingAction::Select(Some(key(&b)))));
    assert_eq!(w.model.view().log_request, Some(key(&b)));
    assert_eq!(w.model.resolve(UnsavedChoice::Discard), Resolved::Done);
    assert_eq!(w.model.selected(), Some(key(&b)));
    assert_eq!(w.model.take_tab_request(&key(&b)), Some(Tab::Log));
}

#[test]
fn a_selection_during_the_quit_question_follows_a_discard() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("B", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    make_dirty(&w, &a);
    assert!(w.model.ask_before_quit());
    w.model.request_log_tab(&key(&b));
    assert!(!w.model.select(Some(key(&b))));
    // Discarded: the quit goes on (the guard hears `Quit`); if the app is still running, b is shown on its Log tab.
    assert_eq!(w.model.resolve(UnsavedChoice::Discard), Resolved::Quit);
    assert_eq!(w.model.pending(), None);
    assert_eq!(w.model.selected(), Some(key(&b)));
    assert_eq!(w.model.take_tab_request(&key(&b)), Some(Tab::Log));
}

#[test]
fn a_quit_cancelled_elsewhere_dismisses_the_question() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("B", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    make_dirty(&w, &a);
    assert!(w.model.ask_before_quit());
    w.model.select(Some(key(&b)));
    // The Update window closed while its quit asked here: the question goes, the editing stays.
    w.model.quit_question_ended();
    assert_eq!(w.model.view().pending, Some("select"), "the deferred selection asks now");
    assert_eq!(w.model.resolve(UnsavedChoice::Cancel), Resolved::Cancelled);
    assert_eq!(w.model.pending(), None);
    assert!(w.model.has_unsaved_changes());
    // Without a deferred selection the window simply has no question.
    assert!(w.model.ask_before_quit());
    w.model.quit_question_ended();
    assert_eq!(w.model.view().pending, None);
    // Another pending action is not touched.
    assert!(!w.model.select(Some(key(&b))));
    w.model.quit_question_ended();
    assert_eq!(w.model.pending(), Some(PendingAction::Select(Some(key(&b)))));
}

#[test]
fn a_selection_deferred_by_the_quit_follows_when_the_window_closes() {
    let w = window();
    let a = w.add("A", VPNKind::Openvpn, Some(CLEAN));
    let b = w.add("B", VPNKind::Openvpn, Some(CLEAN));
    w.model.select(Some(key(&a)));
    make_dirty(&w, &a);
    assert!(w.model.ask_before_quit());
    w.model.select(Some(key(&b)));
    w.model.window_closed();
    assert_eq!(w.model.pending(), None);
    assert_eq!(w.model.selected(), Some(key(&b)));
}

#[test]
fn settings_request_comes_before_the_log_request() {
    let w = window();
    w.model.request_log_tab("X");
    assert_eq!(w.model.take_tab_request("Y"), None);
    assert_eq!(w.model.take_tab_request("X"), Some(Tab::Log));
    assert_eq!(w.model.take_tab_request("X"), None);
}

// MARK: - Create, import, export, delete

#[test]
fn create_saves_the_template_and_selects() {
    let w = window();
    let id = w.model.create(VPNKind::Openvpn).unwrap();
    assert_eq!(w.model.selected(), Some(uuid_string(&id)));
    let c = &w.manager.connections()[0];
    assert_eq!(c.name, "New OpenVPN");
    assert_eq!(w.fx.store.load_config(&id).unwrap(), macvpn_core::importer::template(VPNKind::Openvpn));
    let native = w.model.create(VPNKind::Cisco).unwrap();
    let c = w.manager.connections().into_iter().find(|c| c.id == native).unwrap();
    assert!(c.native.is_some());
    assert!(w.fx.store.load_config(&native).is_err());
    AppLanguage::set_thread_override(Some(AppLanguage::Hu));
    let hu = w.model.create(VPNKind::Wireguard).unwrap();
    let name = w.manager.connections().into_iter().find(|c| c.id == hu).unwrap().name;
    assert_eq!(name, macvpn_core::l10n::tr_in(AppLanguage::Hu, "New %@", &[macvpn_core::l10n::Arg::Str("WireGuard")]));
}

fn import_dir(w: &Window) -> PathBuf {
    let dir = w.fx.dir.path().join("import");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Missing engines (2.0): the "New" menu offers only the kinds the gate lets through (a note when none), "New" of a
/// gated kind is refused, and an import of a gated kind is refused after its kind is known and before anything is
/// saved.
#[test]
fn the_new_menu_and_import_follow_the_kind_gate() {
    let w = window();
    let reason = "OpenVPN is not installed. Install it in System Status first.";
    w.model.set_kind_gate(Box::new(move |kind| (kind == VPNKind::Openvpn).then(|| reason.to_string())));
    let view = w.model.view();
    let kinds: Vec<&str> = view.kinds.iter().map(|c| c.value).collect();
    assert!(!kinds.contains(&"openvpn") && kinds.contains(&"wireguard"));
    assert_eq!(kinds.len(), VPNKind::ALL.len() - 1);
    assert_eq!(view.kinds_note, None);
    assert_eq!(w.model.create(VPNKind::Openvpn).err().as_deref(), Some(reason));
    assert!(w.manager.connections().is_empty());
    let dir = import_dir(&w);
    std::fs::write(dir.join("office.ovpn"), CLEAN).unwrap();
    std::fs::write(dir.join("home.conf"), macvpn_core::importer::template(VPNKind::Wireguard)).unwrap();
    let report = w.model.import_paths(&[dir.join("office.ovpn"), dir.join("home.conf")]);
    assert_eq!(report.errors, vec![format!("office.ovpn: {reason}")]);
    let saved = w.fx.store.list().unwrap();
    assert_eq!(saved.iter().map(|c| c.kind).collect::<Vec<_>>(), [VPNKind::Wireguard], "only the WireGuard file");

    w.model.set_kind_gate(Box::new(|_| Some("No.".to_string())));
    let view = w.model.view();
    assert!(view.kinds.is_empty());
    assert_eq!(view.kinds_note.as_deref(), Some("Install the VPN tools in System Status to add connections."));
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["kindsNote"], "Install the VPN tools in System Status to add connections.");
}

#[test]
fn without_a_gate_everything_is_offered() {
    let w = window();
    let view = w.model.view();
    assert_eq!(view.kinds.len(), VPNKind::ALL.len());
    assert!(serde_json::to_value(&view).unwrap().get("kindsNote").is_none());
}

#[test]
fn import_asks_about_credential_files() {
    for answer in [true, false] {
        let w = window();
        let dir = import_dir(&w);
        std::fs::write(dir.join("auth.txt"), "vpnuser\nS3cret\n").unwrap();
        std::fs::write(dir.join("office.ovpn"), "client\nremote a 1194\nauth-user-pass auth.txt\n").unwrap();
        let questions = w.model.questions().clone();
        let answerer = std::thread::spawn(move || {
            loop {
                if let Some(q) = questions.current() {
                    assert_eq!(q.title, "Use the credentials from auth.txt for this connection?");
                    assert!(q.message.starts_with("office.ovpn refers to these files."));
                    assert_eq!((q.yes.as_str(), q.no.as_str()), ("Use", "Ignore"));
                    assert!(questions.answer(q.id, answer));
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        let report = w.model.import_paths(&[dir.join("office.ovpn")]);
        answerer.join().unwrap();
        let c = &w.manager.connections()[0];
        assert_eq!(c.name, "office");
        assert!(!w.fx.store.load_config(&c.id).unwrap().contains("S3cret"));
        if answer {
            assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("S3cret"));
            assert_eq!(
                report.notes,
                [
                    "office.ovpn: The username and password from auth.txt are stored in the vault; the file is not copied into the config."
                ]
            );
        } else {
            assert_eq!(w.fx.secrets.count(&c.id), 0);
            assert_eq!(
                report.notes,
                ["office.ovpn: The credentials in auth.txt were not used. Enter them in the editor if needed."]
            );
        }
        assert_eq!(w.model.selected(), Some(key(c)));
    }
}

#[test]
fn closing_the_window_answers_the_question_with_ignore() {
    let w = window();
    let dir = import_dir(&w);
    std::fs::write(dir.join("auth.txt"), "vpnuser\nS3cret\n").unwrap();
    std::fs::write(dir.join("office.ovpn"), "client\nremote a 1194\nauth-user-pass auth.txt\n").unwrap();
    let model = w.model.clone();
    let closer = std::thread::spawn(move || {
        while model.view().question.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        model.window_closed();
    });
    let report = w.model.import_paths(&[dir.join("office.ovpn")]);
    closer.join().unwrap();
    assert!(report.notes[0].contains("were not used"));
    assert_eq!(w.model.view().question, None);
}

#[test]
fn import_reports_are_aggregated() {
    let w = window();
    let dir = import_dir(&w);
    std::fs::write(dir.join("ca.crt"), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
    std::fs::write(dir.join("a.ovpn"), "client\nremote a 1194\nca ca.crt\nuser nobody\n").unwrap();
    std::fs::write(dir.join("p.mobileconfig"), "<plist/>").unwrap();
    std::fs::write(dir.join("bin.ovpn"), [0xffu8, 0xfe, 0x00]).unwrap();
    std::fs::write(dir.join("w.conf"), macvpn_core::importer::template(VPNKind::Wireguard)).unwrap();
    let report = w.model.import_paths(&[
        dir.join("a.ovpn"),
        dir.join("p.mobileconfig"),
        dir.join("bin.ovpn"),
        dir.join("missing.ovpn"),
        dir.clone(),
        dir.join("w.conf"),
    ]);
    assert_eq!(report.errors.len(), 4, "{report:?}");
    assert!(report.errors[0].starts_with("p.mobileconfig: A .mobileconfig profile cannot be imported into MacVPN."));
    assert_eq!(report.errors[1], "bin.ovpn: Cannot read the file");
    assert_eq!(report.errors[2], "missing.ovpn: Cannot read the file");
    assert_eq!(report.errors[3], "import: Cannot read the file");
    assert_eq!(
        report.notes[..2],
        [
            "a.ovpn: Imported, inlined: ca.crt".to_string(),
            "a.ovpn: Imported. It contains risky settings (user): review them in the editor’s yellow panel and tick the checkbox before connecting.".to_string(),
        ]
    );
    assert_eq!(report.title(), "Import Error");
    assert!(report.message().starts_with("p.mobileconfig: "));
    assert_eq!(w.manager.connections().len(), 2);
    assert_eq!(import_export::ImportReport::default().title(), "Import");
}

#[test]
fn oversized_import_is_refused() {
    let w = window();
    let dir = import_dir(&w);
    std::fs::write(dir.join("big.ovpn"), format!("client\n{}", "#".repeat(1_048_576))).unwrap();
    let report = w.model.import_paths(&[dir.join("big.ovpn")]);
    assert_eq!(report.errors, ["big.ovpn: Cannot read the file"]);
}

#[test]
fn export_warns_about_key_material() {
    let w = window();
    let config = format!("{CLEAN}<key>\nsecret\n</key>\n");
    let c = w.add("Office/1", VPNKind::Openvpn, Some(&config));
    let warning = import_export::export_warning(w.model.deps(), &c).unwrap().unwrap();
    assert_eq!(warning.title, "The config contains private keys or credentials");
    assert!(warning.message.starts_with("It contains: <key>. Anyone who has these keys"));
    let without = import_export::export_plan(w.model.deps(), &c, false).unwrap();
    assert_eq!(without.file_name, "Office-1.ovpn");
    assert!(!String::from_utf8(without.data).unwrap().contains("secret"));
    assert_eq!(without.message, "Passwords and the PSK are not included in the export.");
    let with = import_export::export_plan(w.model.deps(), &c, true).unwrap();
    assert_eq!(String::from_utf8(with.data).unwrap(), config);
    assert!(with.message.starts_with("The export INCLUDES the private keys and credentials from the config (<key>)."));

    let clean = w.add("Clean", VPNKind::Openvpn, Some(CLEAN));
    assert_eq!(import_export::export_warning(w.model.deps(), &clean).unwrap(), None);

    // G10: the server's shared tls-crypt key stays in an export without keys (the copy can connect); the warning
    // and the save panel say so.
    let shared = format!("{CLEAN}<key>\nsecret\n</key>\n<tls-crypt>\nshared\n</tls-crypt>\n");
    let c = w.add("Shared", VPNKind::Openvpn, Some(&shared));
    let warning = import_export::export_warning(w.model.deps(), &c).unwrap().unwrap();
    assert!(warning.message.starts_with("It contains: <key>. Anyone who has these keys"), "{}", warning.message);
    assert!(warning.message.ends_with(
        "Export Without Keys keeps <tls-crypt>: every user of the server has the same key, and the copy cannot connect without it."
    ));
    let without = import_export::export_plan(w.model.deps(), &c, false).unwrap();
    let text = String::from_utf8(without.data).unwrap();
    assert!(!text.contains("secret") && text.contains("<tls-crypt>\nshared\n</tls-crypt>"));
    assert!(
        without
            .message
            .starts_with("Your private keys and credentials are not included. The shared TLS key (<tls-crypt>) is:")
    );
    let with = import_export::export_plan(w.model.deps(), &c, true).unwrap();
    assert!(with.message.contains("(<key>, <tls-crypt>)"), "{}", with.message);
    // A shared key alone: no question (both choices would export the same).
    let only = w.add("Only", VPNKind::Openvpn, Some(&format!("{CLEAN}<tls-auth>\nshared\n</tls-auth>\n")));
    assert_eq!(import_export::export_warning(w.model.deps(), &only).unwrap(), None);
    let plan = import_export::export_plan(w.model.deps(), &only, false).unwrap();
    assert!(String::from_utf8(plan.data).unwrap().contains("<tls-auth>\nshared"));
    assert!(plan.message.contains("The shared TLS key (<tls-auth>) is:"));

    let native = w.add("L2TP", VPNKind::L2tp, None);
    let plan = import_export::export_plan(w.model.deps(), &native, false).unwrap();
    assert_eq!(plan.file_name, "L2TP.mobileconfig");
    assert!(!String::from_utf8(plan.data).unwrap().contains("<string>bob</string>"), "no account name");
}

#[test]
fn delete_removes_config_secrets_editor_and_selection() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("pw", &c.id, SecretField::Password);
    w.model.select(Some(key(&c)));
    make_dirty(&w, &c);
    let deleted = w.model.delete(&c.id).unwrap();
    assert_eq!(deleted.id, c.id);
    assert!(w.manager.connections().is_empty());
    assert_eq!(w.fx.secrets.count(&c.id), 0);
    assert_eq!(w.model.selected(), None);
    assert!(!w.model.has_unsaved_changes());
    assert!(w.model.delete(&c.id).is_none());
}

// MARK: - Stored secrets never reach the web view

#[test]
fn stored_secrets_are_only_flags_in_the_editor_view() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("alice", &c.id, SecretField::Username);
    w.fx.secrets.set("hunter2", &c.id, SecretField::Password);
    w.fx.secrets.set("keysecret", &c.id, SecretField::KeyPassword);
    let view = w.model.open_editor(&key(&c)).unwrap();
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("hunter2") && !json.contains("keysecret"), "{json}");
    assert!(json.contains("\"username\":\"alice\""), "the user name is not a secret: {json}");
    assert!(json.contains("\"hasStoredSecret\":{\"password\":true,\"psk\":false,\"keyPassword\":true}"), "{json}");
    let EditorFields::Text(f) = view.fields else { panic!() };
    assert_eq!((f.password, f.psk, f.key_password), (None, None, None));
    assert!(!view.dirty);
}

#[test]
fn an_untouched_secret_keeps_the_keychain_value() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("hunter2", &c.id, SecretField::Password);
    w.fx.secrets.set("keysecret", &c.id, SecretField::KeyPassword);
    let f = w.text(&c);
    let view = w.model.save_editor(&key(&c), EditorFields::Text(TextFields { name: "Renamed".into(), ..f })).unwrap();
    assert!(view.issues.is_empty() && !view.dirty, "{:?}", view.issues);
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("hunter2"));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword).as_deref(), Some("keysecret"));
    assert!(view.has_stored_secret.password && view.has_stored_secret.key_password);
}

#[test]
fn a_typed_secret_replaces_and_an_empty_one_removes() {
    let w = window();
    let c = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("old", &c.id, SecretField::Password);
    w.fx.secrets.set("keysecret", &c.id, SecretField::KeyPassword);
    let f = w.text(&c);
    let edited = TextFields { password: Some("new".into()), key_password: Some(String::new()), ..f.clone() };
    let view = w.model.update_editor(&key(&c), EditorFields::Text(edited.clone())).unwrap();
    assert!(view.dirty, "a typed or removed secret is a change");
    let view = w.model.save_editor(&key(&c), EditorFields::Text(edited)).unwrap();
    assert!(!view.dirty);
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("new"));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::KeyPassword), None, "\"Remove saved password\"");
    // The saved value is not sent back: the field is "stored" again, empty.
    let EditorFields::Text(after) = &view.fields else { panic!() };
    assert_eq!((after.password.as_deref(), after.key_password.as_deref()), (None, None));
    assert!(view.has_stored_secret.password && !view.has_stored_secret.key_password);
    assert!(!serde_json::to_string(&view).unwrap().contains("\"new\""));
}

#[test]
fn sstp_kept_password_still_follows_the_rule_and_stays() {
    let w = window();
    let c = w.add("SSTP", VPNKind::Sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp)));
    w.fx.secrets.set("good", &c.id, SecretField::Password);
    let f = sstp_fields(&w, &c);
    assert_eq!(f.password, None);
    let view = w
        .model
        .save_editor(
            &key(&c),
            EditorFields::Sstp(macvpn_app_core::editor::SstpFields { port: 444, user: "alice".into(), ..f.clone() }),
        )
        .unwrap();
    assert!(view.issues.is_empty(), "{:?}", view.issues);
    assert_eq!(view.password_rule, None);
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("good"));
    // A stored password breaking the rule (written by something else) blocks the save, as in the Swift app.
    w.fx.secrets.set("bad\"pw", &c.id, SecretField::Password);
    let view = w
        .model
        .save_editor(
            &key(&c),
            EditorFields::Sstp(macvpn_app_core::editor::SstpFields { port: 445, user: "alice".into(), ..f }),
        )
        .unwrap();
    assert_eq!(view.issues.len(), 1);
}

#[test]
fn native_kept_psk_goes_into_the_profile_and_secrets_stay() {
    let w = window();
    let c = w.add("L2TP", VPNKind::L2tp, None);
    w.fx.secrets.set("sharedkey", &c.id, SecretField::Psk);
    w.fx.secrets.set("topsecret", &c.id, SecretField::Password);
    let f = native_fields(&w, &c);
    assert_eq!((f.password.as_deref(), f.psk.as_deref()), (None, None));
    let view = w.model.save_editor(&key(&c), EditorFields::Native(NativeFields { name: "Home".into(), ..f })).unwrap();
    assert_eq!(view.error, None);
    let installs = w.profiles.installs.lock().unwrap().clone();
    assert!(installs[0].1.contains("c2hhcmVka2V5"), "the stored PSK (base64 data)");
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Password).as_deref(), Some("topsecret"));
    assert_eq!(w.fx.secrets.get(&c.id, SecretField::Psk).as_deref(), Some("sharedkey"));
    assert!(view.has_stored_secret.password && view.has_stored_secret.psk);
}

#[test]
fn system_secrets_keep_replace_and_remove() {
    let w = system_window("L2TP");
    let id = macvpn_core::models::parse_uuid(SERVICE).unwrap();
    w.fx.secrets.set("k", &id, SecretField::Psk);
    w.fx.secrets.set("p", &id, SecretField::Password);
    let view = w.model.open_editor(SERVICE).unwrap();
    assert!(view.has_stored && view.has_stored_secret.psk && view.has_stored_secret.password);
    assert!(!serde_json::to_string(&view).unwrap().contains("\"k\""));
    let fields = SystemFields { psk: None, password: Some(String::new()), otp: Default::default() };
    let view = w.model.save_editor(SERVICE, EditorFields::System(fields)).unwrap();
    assert!(view.saved);
    assert_eq!(w.fx.secrets.get(&id, SecretField::Psk).as_deref(), Some("k"), "kept");
    assert_eq!(w.fx.secrets.get(&id, SecretField::Password), None, "removed");
    assert!(view.has_stored && view.has_stored_secret.psk && !view.has_stored_secret.password);
}

/// WinVPN 2c: deleting a connection removes its profile through the platform, for every kind (the platform knows
/// what exists; macOS' `remove` does nothing), only once the connection itself is gone; a team catalog's connection
/// is never deleted here. The delete confirmation's flag follows `removes_profiles` and is absent on macOS.
#[test]
fn deleting_a_connection_removes_its_profile() {
    let w = window();
    let l2tp = w.add("Branch", VPNKind::L2tp, None);
    let ovpn = w.add("Office", VPNKind::Openvpn, Some(CLEAN));
    w.model.delete(&l2tp.id).unwrap();
    w.model.delete(&ovpn.id).unwrap();
    assert_eq!(*w.profiles.removed.lock().unwrap(), [l2tp.id, ovpn.id]);
    assert!(w.model.delete(&ovpn.id).is_none());
    assert_eq!(w.profiles.removed.lock().unwrap().len(), 2, "nothing more for a connection that is gone");

    let json = serde_json::to_value(w.model.view()).unwrap();
    assert!(json.get("nativeDeleteRemovesProfile").is_none(), "macOS: absent");
    w.profiles.removes.store(true, std::sync::atomic::Ordering::SeqCst);
    let json = serde_json::to_value(w.model.view()).unwrap();
    assert_eq!(json["nativeDeleteRemovesProfile"], true);
}

/// WinVPN 2c Task 12: the Cisco editor's **Make an L2TP/IPsec Copy** makes the copy, selects it (the editor opens
/// on it) and follows the kind gate for L2TP; only a Cisco IPsec connection has it.
#[test]
fn make_an_l2tp_copy_selects_the_copy() {
    let w = window();
    let cisco = w.add("Office", VPNKind::Cisco, None);
    let ovpn = w.add("Lab", VPNKind::Openvpn, Some(CLEAN));
    let (id, install_error) = w.model.make_l2tp_copy(&key(&cisco)).unwrap();
    assert_eq!(install_error, None);
    assert_eq!(w.model.view().selected, Some(uuid_string(&id)));
    let copy = w.manager.connections().into_iter().find(|c| c.id == id).unwrap();
    assert_eq!((copy.kind, copy.name.as_str()), (VPNKind::L2tp, "Office (L2TP)"));
    assert!(w.model.make_l2tp_copy(&key(&ovpn)).is_err());
    assert!(w.model.make_l2tp_copy("no such connection").is_err());

    let reason = "L2TP is not available.";
    w.model.set_kind_gate(Box::new(move |kind| (kind == VPNKind::L2tp).then(|| reason.to_string())));
    assert_eq!(w.model.make_l2tp_copy(&key(&cisco)).err().as_deref(), Some(reason));
    assert_eq!(w.manager.connections().len(), 3, "nothing more was made");
}

// MARK: - The platform's notes (WinVPN 2c Task 11)

/// A platform like WinVPN's: notes from the draft's settings, a CA check that counts its calls.
struct WinLike;

impl macvpn_platform_api::NativeSupport for WinLike {
    fn unsupported_reason(&self, _: &Connection, _: &[u8]) -> Option<String> {
        None
    }

    fn editor_notes(&self, c: &Connection, config: &[u8]) -> macvpn_platform_api::PlatformNotes {
        let text = String::from_utf8_lossy(config);
        let server = c.native.as_ref().map(|n| n.server.clone()).unwrap_or_default();
        macvpn_platform_api::PlatformNotes {
            reasons: text.contains("eap-tls").then(|| "Not supported here: eap-tls".to_string()).into_iter().collect(),
            summary: Some(format!("{} {server}", c.kind.raw_value())),
            warnings: text.contains("dpd_action = restart").then(|| "Ignored: dpd".to_string()).into_iter().collect(),
            insecure_cert: (c.kind == VPNKind::Sstp).then(|| "Always checked.".to_string()),
            trust_ca: matches!(c.kind, VPNKind::Sstp | VPNKind::Strongswan),
            l2tp_copy: c.kind == VPNKind::Cisco,
            no_install_step: c.kind.is_native(),
        }
    }

    fn system_psk_note(&self) -> Option<String> {
        Some("Windows keeps it.".into())
    }
}

#[derive(Default)]
struct CaCheck {
    asked: std::sync::Mutex<Vec<String>>,
}

impl macvpn_platform_api::AdminSteps for CaCheck {
    fn ca_trusted(&self, pem: &str) -> Option<bool> {
        self.asked.lock().unwrap().push(pem.to_string());
        Some(pem.contains("TRUSTED"))
    }
}

const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const TRUSTED_PEM: &str = "-----BEGIN CERTIFICATE-----\nTRUSTED\n-----END CERTIFICATE-----\n";

/// macOS (no platform set): no editor has a `platform` part, so the view-model JSON is as before.
#[test]
fn macos_editors_have_no_platform_notes() {
    let w = system_window("L2TP");
    let ikev2 = w.add("IKE", VPNKind::Strongswan, Some("connections {}\n"));
    let sstp = w.add("SSTP", VPNKind::Sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp)));
    let l2tp = w.add("L2TP", VPNKind::L2tp, None);
    for id in [key(&ikev2), key(&sstp), key(&l2tp), SERVICE.to_string()] {
        let view = w.model.open_editor(&id).unwrap();
        assert_eq!(view.platform, None);
        assert!(serde_json::to_value(&view).unwrap().get("platform").is_none(), "{id}");
    }
}

/// WinVPN: IKEv2 signs with a computer certificate from Windows' store, so the app turns the import off: the editor
/// offers none and the import itself is refused (G4 on Windows). A native platform alone (macOS has one too) does not.
#[test]
fn a_platform_with_its_own_certificate_store_imports_no_client_certificate() {
    let w = system_window("L2TP");
    w.model.set_native_platform(Arc::new(WinLike), Arc::new(CaCheck::default()));
    w.model.set_client_cert_import(false);
    let ikev2 = w.add("IKE", VPNKind::Strongswan, Some(SWAN_PUBKEY));
    let cert = w.model.open_editor(&key(&ikev2)).unwrap().client_cert.unwrap();
    assert!(cert.pubkey && !cert.import);
    let pair = macvpn_core::client_cert::fixtures::pem_pair();
    assert!(w.model.import_client_cert(&key(&ikev2), &[pair.as_bytes()]).is_err());
    assert_eq!(w.fx.secrets.get(&ikev2.id, SecretField::ClientCert), None);
}

/// The notes follow the draft (not the saved config): the IKEv2 reasons and warnings as typed, the L2TP server as
/// edited; the flags per kind; the system VPN's PSK note.
#[test]
fn the_platform_notes_follow_the_draft() {
    let w = system_window("L2TP");
    let checks = Arc::new(CaCheck::default());
    w.model.set_native_platform(Arc::new(WinLike), checks.clone());
    let ikev2 = w.add("IKE", VPNKind::Strongswan, Some("connections {}\n"));
    let view = w.model.open_editor(&key(&ikev2)).unwrap();
    let p = view.platform.clone().unwrap();
    assert_eq!(p.summary.as_deref(), Some("strongswan "));
    assert!(p.reasons.is_empty() && p.warnings.is_empty() && p.trust_ca && !p.l2tp_copy);
    let typed = TextFields { text: "auth = eap-tls\ndpd_action = restart\n".into(), ..w.text(&ikev2) };
    let p = w.model.update_editor(&key(&ikev2), EditorFields::Text(typed)).unwrap().platform.unwrap();
    assert_eq!(
        (p.reasons, p.warnings),
        (vec!["Not supported here: eap-tls".to_string()], vec!["Ignored: dpd".to_string()])
    );
    let json = serde_json::to_value(w.model.open_editor(&key(&ikev2)).unwrap()).unwrap();
    assert_eq!(json["platform"]["trustCa"], true);
    assert_eq!(json["platform"]["reasons"][0], "Not supported here: eap-tls");

    let cisco = w.add("Cisco", VPNKind::Cisco, None);
    let f = match w.model.open_editor(&key(&cisco)).unwrap().fields {
        EditorFields::Native(f) => f,
        other => panic!("{other:?}"),
    };
    let edited = NativeFields { server: "branch.example.com".into(), ..f };
    let p = w.model.update_editor(&key(&cisco), EditorFields::Native(edited)).unwrap().platform.unwrap();
    assert_eq!(p.summary.as_deref(), Some("cisco branch.example.com"), "the draft's server");
    assert!(p.l2tp_copy && p.no_install_step && !p.trust_ca);

    let system = w.model.open_editor(SERVICE).unwrap().platform.unwrap();
    assert_eq!(system.psk_note.as_deref(), Some("Windows keeps it."));
    assert_eq!(system.summary, None);
    assert!(checks.asked.lock().unwrap().is_empty(), "no CA asked about without a custom CA");
}

/// SSTP: "No verification" carries its reason; with a custom CA its trust is asked once per PEM (the editor's
/// updates do not ask again) until the trust may have changed; the PEM to trust is the draft's.
#[test]
fn the_sstp_ca_trust_is_asked_once_per_pem() {
    let w = window();
    let checks = Arc::new(CaCheck::default());
    w.model.set_native_platform(Arc::new(WinLike), checks.clone());
    let c = w.add("SSTP", VPNKind::Sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp)));
    let f = sstp_fields(&w, &c);
    let p = w.model.open_editor(&key(&c)).unwrap().platform.unwrap();
    assert_eq!(p.insecure_cert.as_deref(), Some("Always checked."));
    assert_eq!(p.ca_trusted, None, "not a custom CA");
    assert!(w.model.sstp_ca_pem(&key(&c)).is_err(), "no CA to trust");

    let ca = macvpn_app_core::editor::SstpFields {
        cert: macvpn_app_core::editor::Cert::Ca,
        ca_pem: PEM.into(),
        user: "alice".into(),
        ..f
    };
    for _ in 0..3 {
        let view = w.model.update_editor(&key(&c), EditorFields::Sstp(ca.clone())).unwrap();
        assert_eq!(view.platform.unwrap().ca_trusted, Some(false));
    }
    assert_eq!(checks.asked.lock().unwrap().len(), 1, "asked once");
    assert_eq!(w.model.sstp_ca_pem(&key(&c)).unwrap(), PEM, "the draft's CA");
    w.model.ca_trust_changed();
    w.model.open_editor(&key(&c)).unwrap();
    assert_eq!(checks.asked.lock().unwrap().len(), 2, "asked again after a trust step");

    let trusted = macvpn_app_core::editor::SstpFields { ca_pem: TRUSTED_PEM.into(), ..ca };
    let view = w.model.save_editor(&key(&c), EditorFields::Sstp(trusted)).unwrap();
    assert!(view.issues.is_empty(), "{:?}", view.issues);
    assert_eq!(view.platform.unwrap().ca_trusted, Some(true));
    // Without an editor the saved config's CA is the one to trust.
    w.model.discard_unsaved();
    w.model.window_closed();
    assert_eq!(w.model.sstp_ca_pem(&key(&c)).unwrap().trim_end(), TRUSTED_PEM.trim_end());
    let ovpn = w.add("Lab", VPNKind::Openvpn, Some(CLEAN));
    assert!(w.model.sstp_ca_pem(&key(&ovpn)).is_err());
}

/// WinVPN 2c Task 13: after an unlock (and a restore) the platform reconciles its profiles with every connection of
/// the open vault, and where installing needs no approval every L2TP / Cisco IPsec profile is installed (Cisco's
/// refusal comes back as a failure, nothing else is affected). Never while the vault is locked: the connections of
/// a locked vault are unknown, not "none".
#[test]
fn the_native_profiles_follow_the_open_vault() {
    let w = window();
    let l2tp = w.add("Branch", VPNKind::L2tp, None);
    let mut cisco = w.add("Office", VPNKind::Cisco, None);
    cisco.native.as_mut().unwrap().group_name = "staff".into();
    w.fx.store.save(&cisco, None).unwrap();
    let ovpn = w.add("Lab", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("branch-psk", &l2tp.id, SecretField::Psk);

    // macOS: the reconcile (a no-op there) and no install.
    assert!(w.model.sync_native_profiles().is_empty());
    let known: std::collections::HashSet<_> = [l2tp.id, cisco.id, ovpn.id].into();
    assert_eq!(*w.profiles.reconciled.lock().unwrap(), [known]);
    assert!(w.profiles.installs.lock().unwrap().is_empty());
    assert!(w.model.install_native_profiles().is_empty());
    assert!(w.profiles.installs.lock().unwrap().is_empty());

    // WinVPN: every native profile, as the editor builds it.
    w.profiles.silent.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(w.model.sync_native_profiles(), [(cisco.id, CISCO_REFUSED.to_string())]);
    {
        let installs = w.profiles.installs.lock().unwrap();
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].0, l2tp.id);
        assert!(
            installs[0].1.contains("YnJhbmNoLXBzaw==") && installs[0].1.contains("bob"),
            "the PSK (base64) and the account"
        );
    }
    assert_eq!(w.profiles.reconciled.lock().unwrap().len(), 2);
    assert_eq!(w.model.install_native_profiles().len(), 1, "Cisco again");
    assert_eq!(w.profiles.reconciled.lock().unwrap().len(), 2, "installs only");

    // Locked: nothing at all.
    w.manager.enter_locked();
    assert!(w.model.sync_native_profiles().is_empty());
    assert!(w.model.install_native_profiles().is_empty());
    assert_eq!(w.profiles.reconciled.lock().unwrap().len(), 2);
    assert_eq!(w.profiles.installs.lock().unwrap().len(), 2);
}

// MARK: - Client credentials (audit G1, G3, G6)

const CERT_CA: &str = include_str!("../../core/tests/fixtures/certs/ca.pem");
const CERT_CLIENT: &str = include_str!("../../core/tests/fixtures/certs/client-rsa.pem");
/// `client-rsa.pem`'s notAfter (2036-10-26 22:48:40Z).
const CLIENT_NOT_AFTER: i64 = 2_108_674_120;

/// A window whose clock says `now` (Unix seconds).
fn window_at(now: i64) -> Window {
    let fx = Fixture::new(AppLanguage::En);
    let manager = fx.manager();
    let profiles = Arc::new(MobileconfigProfiles::default());
    let deps = EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: profiles.clone(),
        clock: clock_at(now as f64),
    };
    Window { model: Arc::new(ConnectionsModel::new(deps)), fx, profiles, manager }
}

#[test]
fn the_config_text_is_masked_for_the_view_and_saved_as_it_is() {
    let w = window();
    let config = format!("{CLEAN}<key>\n-----BEGIN PRIVATE KEY-----\nKEYDATA\n-----END PRIVATE KEY-----\n</key>\n");
    let c = w.add("Keyed", VPNKind::Openvpn, Some(&config));
    let view = w.model.open_editor(&key(&c)).unwrap();
    let masked = view.masked_text.clone().expect("a masked text");
    assert!(!masked.contains("KEYDATA") && masked.contains(macvpn_core::config_secrets::MASK));
    assert_eq!(masked.lines().count(), config.lines().count());
    // The draft keeps the real text: an edit and a save write it, never the mask.
    let EditorFields::Text(f) = view.fields.clone() else { panic!() };
    assert_eq!(f.text, config);
    let text = f.text.replace("dev tun", "dev tun\nverb 3");
    let saved = w.model.save_editor(&key(&c), EditorFields::Text(TextFields { text: text.clone(), ..f })).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    let stored = w.fx.store.load_config(&c.id).unwrap();
    assert_eq!(stored, text);
    assert!(!stored.contains(macvpn_core::config_secrets::MASK));
    let json = serde_json::to_value(&saved).unwrap();
    assert!(json["maskedText"].as_str().unwrap().contains("verb 3"));
    // Nothing to mask: no masked text in the JSON at all.
    let clean = w.add("Clean", VPNKind::Openvpn, Some(CLEAN));
    let json = serde_json::to_value(w.model.open_editor(&key(&clean)).unwrap()).unwrap();
    assert!(json.get("maskedText").is_none());
    // WireGuard's keys too.
    let wg = w.add("WG", VPNKind::Wireguard, Some("[Interface]\nPrivateKey = abc=\n"));
    assert!(!w.model.open_editor(&key(&wg)).unwrap().masked_text.unwrap().contains("abc="));
}

#[test]
fn the_key_password_field_follows_the_key() {
    let w = window();
    let plain = w.add("Plain", VPNKind::Openvpn, Some(&format!("{CLEAN}<key>\nK\n</key>\n")));
    assert!(!w.model.open_editor(&key(&plain)).unwrap().key_password_used);
    let encrypted = format!(
        "{CLEAN}<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nK\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n"
    );
    let enc = w.add("Encrypted", VPNKind::Openvpn, Some(&encrypted));
    assert!(w.model.open_editor(&key(&enc)).unwrap().key_password_used);
    // Typing an encrypted key into a plain config shows the field at once.
    let f = w.text(&plain);
    let view =
        w.model.update_editor(&key(&plain), EditorFields::Text(TextFields { text: encrypted.clone(), ..f })).unwrap();
    assert!(view.key_password_used);
    // A stored key password stays removable even when the key is not encrypted.
    let stored = w.add("Stored", VPNKind::Openvpn, Some(CLEAN));
    w.fx.secrets.set("kp", &stored.id, SecretField::KeyPassword);
    assert!(w.model.open_editor(&key(&stored)).unwrap().key_password_used);
    // Only OpenVPN has one.
    let wg = w.add("WG", VPNKind::Wireguard, Some("[Interface]\n"));
    assert!(!w.model.open_editor(&key(&wg)).unwrap().key_password_used);
}

#[test]
fn the_editor_shows_the_configs_certificates_with_their_expiry() {
    let w = window_at(CLIENT_NOT_AFTER - 10 * 86_400 - 60);
    let config = format!("{CLEAN}<ca>\n{CERT_CA}</ca>\n<cert>\n{CERT_CLIENT}</cert>\n");
    let c = w.add("Cert", VPNKind::Openvpn, Some(&config));
    let view = w.model.open_editor(&key(&c)).unwrap();
    let certs = view.certificates.clone().expect("certificates").certificates;
    assert_eq!(certs.len(), 2);
    assert_eq!((certs[0].role, certs[0].source.as_str()), ("client", "<cert>"));
    assert_eq!(certs[0].subject, "CN=client one, OU=Lab, O=Example");
    assert_eq!(certs[0].issuer, "CN=Cred Test CA, O=Example, C=HU");
    assert_eq!(certs[0].key_type, "RSA 2048");
    assert_eq!((certs[0].status, certs[0].note.as_deref()), ("expiresSoon", Some("Expires in 10 days")));
    assert!(certs[0].pem.starts_with("-----BEGIN CERTIFICATE-----\nMII"));
    assert_eq!((certs[1].role, certs[1].status, certs[1].note.clone()), ("ca", "valid", None));
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["certificates"]["certificates"][0]["notAfter"].as_i64(), Some(CLIENT_NOT_AFTER));
    assert_eq!(json["certificates"]["certificates"][0]["status"], "expiresSoon");
    // The row warns as well (the earliest expiry, read at the reload).
    let expiry = w.manager.certificate_expiry();
    assert_eq!(expiry.get(&key(&c)), Some(&CLIENT_NOT_AFTER));
    let now = CLIENT_NOT_AFTER - 10 * 86_400 - 60;
    assert_eq!(
        macvpn_app_core::editor::certificate_row_warning(CLIENT_NOT_AFTER, now).as_deref(),
        Some("Certificate expires in 10 days")
    );
    assert_eq!(
        macvpn_app_core::editor::certificate_row_warning(CLIENT_NOT_AFTER, CLIENT_NOT_AFTER + 1).as_deref(),
        Some("Certificate expired")
    );
    assert_eq!(
        macvpn_app_core::editor::certificate_row_warning(CLIENT_NOT_AFTER, CLIENT_NOT_AFTER - 31 * 86_400),
        None
    );
    // Removing the certificate from the text removes it from the view.
    let EditorFields::Text(f) = view.fields else { panic!() };
    let view = w.model.update_editor(&key(&c), EditorFields::Text(TextFields { text: CLEAN.into(), ..f })).unwrap();
    assert!(view.certificates.is_none());
}

#[test]
fn an_expired_sstp_ca_and_ikev2_certificates_from_the_swanctl_folder() {
    let w = window_at(CLIENT_NOT_AFTER + 86_400);
    // SSTP: the custom CA (valid until 2046).
    let sstp = format!("server=vpn.example.com\nuser=bob\ncert=ca\n{}", {
        let c = macvpn_core::validators::SSTPConfig {
            server: "vpn.example.com".into(),
            port: 443,
            user: "bob".into(),
            cert: macvpn_core::validators::sstp::CertMode::Ca,
            route_all: true,
            peer_dns: true,
            ca_pem: CERT_CA.into(),
        };
        c.serialized()
    });
    let s = w.add("SSTP", VPNKind::Sstp, Some(&sstp));
    let certs = w.model.open_editor(&key(&s)).unwrap().certificates.unwrap().certificates;
    assert_eq!((certs[0].role, certs[0].status), ("ca", "valid"));
    // IKEv2: the files `certs` and `cacerts` name, read from the swanctl folder.
    let dir = std::env::temp_dir().join(format!("macvpn-swanctl-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("x509")).unwrap();
    std::fs::create_dir_all(dir.join("x509ca")).unwrap();
    std::fs::write(dir.join("x509/client.pem"), CERT_CLIENT).unwrap();
    std::fs::write(dir.join("x509ca/ca.pem"), CERT_CA).unwrap();
    let ike = "connections {\n  office {\n    local {\n      auth = pubkey\n      certs = client.pem\n    }\n    remote {\n      cacerts = ca.pem, missing.pem\n    }\n  }\n}\n";
    let c = w.add("IKEv2", VPNKind::Strongswan, Some(ike));
    assert!(w.model.open_editor(&key(&c)).unwrap().certificates.is_none(), "no folder set");
    w.model.set_swanctl_folder(dir.clone());
    let certs = w.model.open_editor(&key(&c)).unwrap().certificates.unwrap().certificates;
    let rows: Vec<(&str, &str, &str)> = certs.iter().map(|c| (c.role, c.source.as_str(), c.status)).collect();
    assert_eq!(rows, [("client", "client.pem", "expired"), ("ca", "ca.pem", "valid")]);
    assert_eq!(certs[0].note.as_deref(), Some("Expired"));
    let _ = std::fs::remove_dir_all(&dir);
}
