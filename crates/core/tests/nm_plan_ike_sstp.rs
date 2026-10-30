//! IKEv2 (charon-nm) and SSTP through NM plugins (L-b Task 9).
use macvpn_core::client_cert::{self, ClientCert, Form, fixtures};
use macvpn_core::models::{Connection, SecretField, VPNKind};
use macvpn_core::nm_plan::{self, Caps, ImportedCert, Input, NmValue, SecretKey, SecretValue};
use std::path::{Path, PathBuf};

fn swan(local: &str, remote_extra: &str, child: &str) -> String {
    format!(
        "connections {{\n  lab {{\n    remote_addrs = vpn.example.com\n    remote_port = 4510\n    vips = 0.0.0.0\n    local {{\n      {local}\n    }}\n    remote {{\n      auth = pubkey\n      id = vpn.example.com\n      {remote_extra}\n    }}\n    children {{\n      lab {{\n        {child}\n      }}\n    }}\n  }}\n}}\n"
    )
}
fn caps() -> Caps {
    Caps {
        swanctl_dir: Some(PathBuf::from("/home/u/.local/share/LinVPN/swanctl")),
        swanctl_ca_files: vec!["lab-ca.pem".into()],
        strongswan_remote_ts: true,
        ..Caps::default()
    }
}
fn plan(kind: VPNKind, text: &str, caps: &Caps) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    plan_with(kind, text, caps, ImportedCert::None)
}
fn plan_with(
    kind: VPNKind,
    text: &str,
    caps: &Caps,
    client_cert: ImportedCert,
) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    let c = Connection::new("IKE", kind);
    nm_plan::plan(&Input {
        connection: &c,
        config: text.as_bytes(),
        user: "linvpn-dev",
        uid: 1001,
        runtime_dir: Path::new("/r/u"),
        caps,
        client_cert,
    })
}
fn data(p: &nm_plan::NmPlan) -> std::collections::BTreeMap<String, String> {
    let NmValue::StrDict(d) = &p.settings["vpn"]["data"] else { panic!() };
    d.clone()
}

#[test]
fn eap_mschapv2_with_the_only_ca_in_linvpns_folder() {
    let p = plan(
        VPNKind::Strongswan,
        &swan("auth = eap-mschapv2\n      eap_id = alice", "", "remote_ts = 10.99.0.0/24"),
        &caps(),
    )
    .unwrap();
    assert_eq!(p.service_type, Some(nm_plan::SERVICE_STRONGSWAN));
    let d = data(&p);
    assert_eq!(d["address"], "vpn.example.com");
    assert_eq!(d["server-port"], "4510");
    assert_eq!(d["method"], "eap");
    assert_eq!(d["user"], "alice");
    assert_eq!(d["virtual"], "yes");
    assert_eq!(d["remote-identity"], "vpn.example.com");
    assert_eq!(d["certificate"], "/home/u/.local/share/LinVPN/swanctl/x509ca/lab-ca.pem");
    assert_eq!(d["remote-ts"], "10.99.0.0/24");
    assert_eq!(d["password-flags"], "1");
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())
        && matches!(s.value, SecretValue::Field(SecretField::Password))));
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(true));
}

#[test]
fn psk_on_both_sides() {
    let t = swan("auth = psk", "", "").replace("auth = pubkey", "auth = psk");
    let p = plan(VPNKind::Strongswan, &t, &caps()).unwrap();
    assert_eq!(data(&p)["method"], "psk");
    assert!(p.secrets.iter().any(
        |s| s.key == SecretKey::Plain("password".into()) && matches!(s.value, SecretValue::Field(SecretField::Psk))
    ));
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(false), "no remote_ts: full tunnel");
}

#[test]
fn a_client_certificate_comes_from_linvpns_folder_with_its_key() {
    let p = plan(VPNKind::Strongswan, &swan("auth = pubkey\n      certs = lab-client.pem", "", ""), &caps()).unwrap();
    let d = data(&p);
    assert_eq!(d["method"], "key");
    assert_eq!(d["usercert"], "/home/u/.local/share/LinVPN/swanctl/x509/lab-client.pem");
    assert_eq!(d["userkey"], "/home/u/.local/share/LinVPN/swanctl/private/lab-client.key");
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())
        && matches!(s.value, SecretValue::Field(SecretField::KeyPassword))));
}

#[test]
fn without_certs_the_imported_client_certificate_is_written_as_private_runtime_files() {
    let pem = client_cert::import(&[fixtures::pem_pair().as_bytes()]).unwrap().cert;
    let p = plan_with(VPNKind::Strongswan, &swan("auth = pubkey", "", ""), &caps(), ImportedCert::Cert(&pem)).unwrap();
    let d = data(&p);
    assert_eq!(d["method"], "key");
    assert_eq!(d["usercert"], "/r/u/client-cert.pem");
    assert_eq!(d["userkey"], "/r/u/client-key.pem");
    // The CA still comes from LinVPN's folder; the key's passphrase is the `password` secret.
    assert_eq!(d["certificate"], "/home/u/.local/share/LinVPN/swanctl/x509ca/lab-ca.pem");
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())
        && matches!(s.value, SecretValue::Field(SecretField::KeyPassword))));
    let names: Vec<&str> = p.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["client-cert.pem", "client-key.pem"]);
    let ClientCert::Pem { cert, key, .. } = &pem else { panic!() };
    assert_eq!(p.files[0].data.as_slice(), macvpn_core::x509::to_pem(cert).as_bytes());
    assert_eq!(p.files[1].data.as_slice(), key.as_bytes());
    // No key material in the settings (only paths), and none in the plan's Debug output.
    let shown = format!("{p:?}");
    assert!(!shown.contains("PRIVATE KEY") && !shown.contains("CERTIFICATE"), "{shown}");
    for value in d.values() {
        assert!(!value.contains("-----"), "{value}");
    }
}

#[test]
fn an_imported_client_certificate_known_only_by_its_form_plans_the_same_paths_without_files() {
    let t = swan("auth = pubkey", "", "");
    let p = plan_with(VPNKind::Strongswan, &t, &caps(), ImportedCert::Known(Form::Pem)).unwrap();
    assert_eq!(data(&p)["usercert"], "/r/u/client-cert.pem");
    assert_eq!(data(&p)["userkey"], "/r/u/client-key.pem");
    assert!(p.files.is_empty());
}

#[test]
fn the_configs_own_certs_win_over_the_imported_certificate() {
    let pem = client_cert::import(&[fixtures::pem_pair().as_bytes()]).unwrap().cert;
    let t = swan("auth = pubkey\n      certs = lab-client.pem", "", "");
    let p = plan_with(VPNKind::Strongswan, &t, &caps(), ImportedCert::Cert(&pem)).unwrap();
    assert_eq!(data(&p)["usercert"], "/home/u/.local/share/LinVPN/swanctl/x509/lab-client.pem");
    assert!(p.files.is_empty());
}

#[test]
fn without_certs_or_an_imported_certificate_the_reason_names_both_ways() {
    let e = plan(VPNKind::Strongswan, &swan("auth = pubkey", "", ""), &caps()).unwrap_err();
    assert!(!e.invalid_config);
    assert!(e.reasons.iter().any(|r| r.contains("Import Client Certificate") && r.contains("certs")), "{e}");
}

#[test]
fn a_pkcs12_client_certificate_is_converted_before_planning() {
    let p12 = client_cert::import(&[&fixtures::p12()]).unwrap().cert;
    let t = swan("auth = pubkey", "", "");
    // Unconverted at connect (the engine converts first): a reason.
    let e = plan_with(VPNKind::Strongswan, &t, &caps(), ImportedCert::Cert(&p12)).unwrap_err();
    assert!(!e.invalid_config && e.reasons.iter().any(|r| r.contains("PKCS#12")), "{e}");
    // Known only by its form (the editor, the row): converted at connect, so the same paths.
    let p = plan_with(VPNKind::Strongswan, &t, &caps(), ImportedCert::Known(Form::Pkcs12)).unwrap();
    assert_eq!(data(&p)["usercert"], "/r/u/client-cert.pem");
    // Not used (the config names its own certs, or does not sign with a key): no reason.
    let own = swan("auth = pubkey\n      certs = lab-client.pem", "", "");
    assert!(plan_with(VPNKind::Strongswan, &own, &caps(), ImportedCert::Cert(&p12)).is_ok());
    let eap = swan("auth = eap-mschapv2\n      eap_id = a", "", "");
    let p = plan_with(VPNKind::Strongswan, &eap, &caps(), ImportedCert::Cert(&p12)).unwrap();
    assert!(p.files.is_empty() && !data(&p).contains_key("usercert"));
}

#[test]
fn an_eap_or_psk_config_ignores_the_imported_certificate() {
    let pem = client_cert::import(&[fixtures::pem_pair().as_bytes()]).unwrap().cert;
    let t = swan("auth = psk", "", "").replace("auth = pubkey", "auth = psk");
    let p = plan_with(VPNKind::Strongswan, &t, &caps(), ImportedCert::Cert(&pem)).unwrap();
    assert!(p.files.is_empty() && !data(&p).contains_key("usercert"));
}

#[test]
fn split_ikev2_without_remote_ts_support_is_a_linux_reason() {
    let caps = Caps { strongswan_remote_ts: false, ..caps() };
    let e = plan(
        VPNKind::Strongswan,
        &swan("auth = eap-mschapv2\n      eap_id = a", "", "remote_ts = 10.99.0.0/24"),
        &caps,
    )
    .unwrap_err();
    assert!(!e.invalid_config && e.reasons[0].contains("remote_ts"));
}

#[test]
fn a_named_ca_proposals_and_a_selector_list_use_charons_semicolons() {
    let t = swan(
        "auth = eap-mschapv2\n      eap_id = alice\n      id = alice@example.com",
        "cacerts = other-ca.pem",
        "remote_ts = 10.99.0.0/24, 192.0.2.0/24\n        esp_proposals = aes256gcm16, aes128gcm16",
    )
    .replace(
        "vips = 0.0.0.0",
        "vips = 0.0.0.0\n    proposals = aes256-sha256-modp2048, aes128-sha256-ecp256\n    encap = yes",
    );
    let d = data(&plan(VPNKind::Strongswan, &t, &caps()).unwrap());
    assert_eq!(d["certificate"], "/home/u/.local/share/LinVPN/swanctl/x509ca/other-ca.pem");
    assert_eq!(d["remote-ts"], "10.99.0.0/24;192.0.2.0/24");
    assert_eq!(d["proposal"], "yes");
    assert_eq!(d["ike"], "aes256-sha256-modp2048;aes128-sha256-ecp256");
    assert_eq!(d["esp"], "aes256gcm16;aes128gcm16");
    assert_eq!(d["encap"], "yes");
    assert_eq!(d["local-identity"], "alice@example.com");
}

#[test]
fn no_ca_means_the_system_cas_with_a_warning() {
    let caps = Caps { swanctl_ca_files: vec![], ..caps() };
    let p = plan(VPNKind::Strongswan, &swan("auth = eap-mschapv2\n      eap_id = a", "", ""), &caps).unwrap();
    assert!(!data(&p).contains_key("certificate"));
    assert!(!p.warnings.is_empty());
}

#[test]
fn what_charon_nm_cannot_do_is_a_linux_reason() {
    let list = swan("auth = eap-mschapv2\n      eap_id = a", "", "")
        .replace("remote_addrs = vpn.example.com", "remote_addrs = vpn.example.com, 198.51.100.1");
    let e = plan(VPNKind::Strongswan, &list, &caps()).unwrap_err();
    assert!(!e.invalid_config && e.reasons.iter().any(|r| r.contains("more than one remote address")), "{e}");

    let xauth = swan("auth = xauth", "", "");
    let e = plan(VPNKind::Strongswan, &xauth, &caps()).unwrap_err();
    assert!(e.reasons.iter().any(|r| r.contains("local auth = xauth")), "{e}");

    let mixed = swan("auth = psk", "", "");
    let e = plan(VPNKind::Strongswan, &mixed, &caps()).unwrap_err();
    assert!(e.reasons.iter().any(|r| r.contains("remote auth = pubkey")), "{e}");
}

#[test]
fn an_invalid_swanctl_conf_is_the_validators_error() {
    let e = plan(VPNKind::Strongswan, "connections {\n  lab {\n    updown = /tmp/x\n  }\n}\n", &caps()).unwrap_err();
    assert!(e.invalid_config);
}

#[test]
fn sstp_with_its_ca_and_port() {
    let t = "server=vpn.example.com\nport=8443\nuser=alice\ncert=ca\nroute_all=no\npeer_dns=no\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n";
    let p = plan(VPNKind::Sstp, t, &caps()).unwrap();
    assert_eq!(p.service_type, Some(nm_plan::SERVICE_SSTP));
    let d = data(&p);
    assert_eq!(d["gateway"], "vpn.example.com:8443");
    assert_eq!(d["user"], "alice");
    assert_eq!(d["ca-cert"], "/r/u/sstp-ca.pem");
    assert_eq!(d["password-flags"], "1");
    assert_eq!(p.files[0].name, "sstp-ca.pem");
    assert!(p.files[0].data.starts_with(b"-----BEGIN CERTIFICATE-----\nMIIB\n"));
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())
        && matches!(s.value, SecretValue::Field(SecretField::Password))));
    assert_eq!(p.settings["ipv4"]["ignore-auto-dns"], NmValue::Bool(true));
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(true));
    let mark = std::collections::BTreeMap::from([("linvpn.classful".to_string(), "1".to_string())]);
    assert_eq!(p.settings["user"]["data"], NmValue::StrDict(mark), "split tunnel: the class-based route");
    assert!(p.warnings.is_empty());
}

#[test]
fn sstp_without_verification_is_allowed_on_linux_with_its_warning() {
    let p = plan(VPNKind::Sstp, "server=vpn.example.com\nuser=alice\ncert=insecure\n", &caps()).unwrap();
    assert_eq!(data(&p)["ignore-cert-warn"], "yes");
    assert!(!p.warnings.is_empty());
}

#[test]
fn sstp_with_the_system_cas_full_tunnel_and_ipv6_in_brackets() {
    let p = plan(VPNKind::Sstp, "server=2001:db8::1\nport=8443\nuser=alice\ncert=system\n", &caps()).unwrap();
    let d = data(&p);
    assert_eq!(d["gateway"], "[2001:db8::1]:8443");
    assert!(!d.contains_key("ca-cert") && !d.contains_key("ignore-cert-warn"));
    assert_eq!(d["refuse-pap"], "yes");
    assert_eq!(d["refuse-chap"], "yes");
    assert_eq!(d["refuse-eap"], "yes");
    assert!(p.files.is_empty());
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(false));
    assert!(!p.settings.contains_key("user"), "all traffic: no class-based route");
    assert!(!p.settings["ipv4"].contains_key("ignore-auto-dns"));
    let p = plan(VPNKind::Sstp, "server=vpn.example.com\nuser=alice\n", &caps()).unwrap();
    assert_eq!(data(&p)["gateway"], "vpn.example.com");
}

#[test]
fn an_invalid_sstp_config_is_the_validators_error() {
    let e = plan(VPNKind::Sstp, "server=vpn.example.com\n", &caps()).unwrap_err();
    assert!(e.invalid_config);
}
