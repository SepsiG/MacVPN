//! The `# macvpn-meta: {json}` line of exported text configs (plan B, resolved points "Exported metadata"): the
//! folder path (Task 16) and the linked credential's name (Task 18/19), never a secret.

use macvpn_core::exporter;
use macvpn_core::importer::{self, ExportMeta};

fn meta(folder: Option<&[&str]>, credential: Option<&str>) -> ExportMeta {
    ExportMeta {
        folder: folder.map(|f| f.iter().map(|s| s.to_string()).collect()),
        credential_name: credential.map(str::to_string),
    }
}

#[test]
fn the_line_carries_only_the_folder_and_the_credential_name() {
    assert_eq!(exporter::meta_line(&ExportMeta::default()), None, "no line without metadata");
    assert_eq!(
        exporter::meta_line(&meta(None, Some("Office AD"))).as_deref(),
        Some("# macvpn-meta: {\"credentialName\":\"Office AD\"}\n")
    );
    assert_eq!(
        exporter::meta_line(&meta(Some(&["Work", "Clients"]), Some("Office \"AD\""))).as_deref(),
        Some("# macvpn-meta: {\"credentialName\":\"Office \\\"AD\\\"\",\"folder\":[\"Work\",\"Clients\"]}\n")
    );
    let config = b"client\nremote vpn.example.com 1194\n";
    let out = exporter::with_meta(config, &meta(None, Some("Office AD")));
    assert!(out.starts_with(b"# macvpn-meta: "));
    assert!(out.ends_with(config));
    assert_eq!(exporter::with_meta(config, &ExportMeta::default()), config.to_vec());
}

#[test]
fn import_strips_a_valid_line_and_returns_the_metadata() {
    let m = meta(Some(&["Work", "Clients"]), Some("Office AD"));
    let exported = exporter::with_meta(b"client\nauth-user-pass\n", &m);
    let text = String::from_utf8(exported).unwrap();
    let (parsed, rest) = importer::take_export_meta(&text);
    assert_eq!(parsed, Some(m));
    assert_eq!(rest, "client\nauth-user-pass\n");

    // CRLF, unknown keys and null values are fine.
    let (parsed, rest) =
        importer::take_export_meta("# macvpn-meta: {\"credentialName\":\"X\",\"folder\":null,\"new\":1}\r\nclient\r\n");
    assert_eq!(parsed, Some(meta(None, Some("X"))));
    assert_eq!(rest, "client\r\n");
    // The line alone, without a newline.
    let (parsed, rest) = importer::take_export_meta("# macvpn-meta: {}");
    assert_eq!(parsed, Some(ExportMeta::default()));
    assert_eq!(rest, "");
}

#[test]
fn an_invalid_or_missing_line_stays_in_the_config() {
    let long = format!("# macvpn-meta: {{\"credentialName\":\"{}\"}}\nclient\n", "x".repeat(4100));
    for text in [
        "client\n",
        "# macvpn-meta {\"credentialName\":\"X\"}\nclient\n",
        "# macvpn-meta: not json\nclient\n",
        "# macvpn-meta: [\"X\"]\nclient\n",
        "# macvpn-meta: {\"credentialName\":5}\nclient\n",
        "# macvpn-meta: {\"credentialName\":\"\"}\nclient\n",
        "# macvpn-meta: {\"credentialName\":\"a\\nb\"}\nclient\n",
        "# macvpn-meta: {\"folder\":\"Work\"}\nclient\n",
        "# macvpn-meta: {\"folder\":[\"Work\",3]}\nclient\n",
        "# macvpn-meta: {\"folder\":[\"\"]}\nclient\n",
        "# macvpn-meta: {} trailing\nclient\n",
        "client\n# macvpn-meta: {\"credentialName\":\"X\"}\n",
        long.as_str(),
    ] {
        let (parsed, rest) = importer::take_export_meta(text);
        assert_eq!(parsed, None, "{text:?}");
        assert_eq!(rest, text);
    }
}

/// Review M3: every folder path component (and the credential name) goes through the vault's name rule
/// (`validate_folder_name` / `validate_credential_name`): a component the folder editor would refuse refuses the
/// whole line, and an accepted one comes back in its stored (cleaned) form.
#[test]
fn folder_components_and_the_credential_name_follow_the_vault_name_rule() {
    let long = "f".repeat(65);
    for text in [
        format!("# macvpn-meta: {{\"folder\":[\"Work\",\"{long}\"]}}\nclient\n"),
        format!("# macvpn-meta: {{\"credentialName\":\"{long}\"}}\nclient\n"),
        "# macvpn-meta: {\"folder\":[\"Work\",\"a\\u0007b\"]}\nclient\n".to_string(),
        "# macvpn-meta: {\"folder\":[\"a\\u2028b\"]}\nclient\n".to_string(),
        "# macvpn-meta: {\"folder\":[\"\\u200b\\u202e\"]}\nclient\n".to_string(),
        "# macvpn-meta: {\"folder\":[\"Work\",\"   \"]}\nclient\n".to_string(),
    ] {
        let (parsed, rest) = importer::take_export_meta(&text);
        assert_eq!(parsed, None, "{text:?}");
        assert_eq!(rest, text);
    }
    let sixty_four = "f".repeat(64);
    let text = format!(
        "# macvpn-meta: {{\"credentialName\":\" Office\\u202eAD \",\"folder\":[\" Work \",\"{sixty_four}\"]}}\nclient\n"
    );
    let (parsed, rest) = importer::take_export_meta(&text);
    assert_eq!(parsed, Some(meta(Some(&["Work", &sixty_four]), Some("OfficeAD"))));
    assert_eq!(rest, "client\n");
}

#[test]
fn remote_host_names_the_server_a_config_connects_to() {
    use macvpn_core::models::VPNKind;
    let host = |kind, config: &str| importer::remote_host(kind, config);
    assert_eq!(
        host(VPNKind::Openvpn, "client\n# remote commented.example\n;remote also.example\n  remote vpn.example.com 1194 udp\nremote second.example\n")
            .as_deref(),
        Some("vpn.example.com")
    );
    assert_eq!(host(VPNKind::Openvpn, "client\nremote-random\n"), None);
    assert_eq!(host(VPNKind::Openvpn, "client\nremote\n"), None);
    assert_eq!(
        host(VPNKind::Wireguard, "[Peer]\nendpoint = wg.example.org:51820\n").as_deref(),
        Some("wg.example.org")
    );
    assert_eq!(host(VPNKind::Wireguard, "[Peer]\nEndpoint = [2001:db8::1]:51820\n").as_deref(), Some("2001:db8::1"));
    assert_eq!(
        host(
            VPNKind::Strongswan,
            "connections {\n  office {\n    remote_addrs = ike.example.net, backup.example.net\n"
        )
        .as_deref(),
        Some("ike.example.net")
    );
    assert_eq!(host(VPNKind::Sstp, "server=sstp.example.com\nport=443\n").as_deref(), Some("sstp.example.com"));
    assert_eq!(host(VPNKind::L2tp, ""), None);
    // Display only: nothing that could break the question's text.
    assert_eq!(host(VPNKind::Openvpn, &format!("remote {}\n", "a".repeat(254))), None);
    assert_eq!(host(VPNKind::Sstp, "server=evil\u{1b}[2J.example\n"), None);
    assert_eq!(host(VPNKind::Sstp, "server=a\"b\n"), None);
}

/// The host only: a user name and a port are stripped, and anything that is not a host name or an IP literal (a
/// URL path, a CIDR, `%any`, stray punctuation) gives `None`.
#[test]
fn remote_host_is_a_host_name_or_an_ip_literal_only() {
    use macvpn_core::models::VPNKind;
    let host = |kind, config: &str| importer::remote_host(kind, config);
    // User info and port are stripped.
    assert_eq!(host(VPNKind::Sstp, "server=alice@sstp.example.com:443\n").as_deref(), Some("sstp.example.com"));
    assert_eq!(host(VPNKind::Sstp, "server=alice:pw@sstp.example.com\n").as_deref(), Some("sstp.example.com"));
    assert_eq!(host(VPNKind::Openvpn, "remote bob@vpn.example.com 1194\n").as_deref(), Some("vpn.example.com"));
    assert_eq!(host(VPNKind::Openvpn, "remote vpn.example.com:1194\n").as_deref(), Some("vpn.example.com"));
    assert_eq!(host(VPNKind::Wireguard, "Endpoint = me@wg.example.org:51820\n").as_deref(), Some("wg.example.org"));
    assert_eq!(host(VPNKind::Strongswan, "remote_addrs = 192.0.2.10:500\n").as_deref(), Some("192.0.2.10"));
    // IP literals.
    assert_eq!(host(VPNKind::Openvpn, "remote 192.0.2.1 1194\n").as_deref(), Some("192.0.2.1"));
    assert_eq!(host(VPNKind::Openvpn, "remote 2001:db8::7 1194\n").as_deref(), Some("2001:db8::7"));
    assert_eq!(host(VPNKind::Sstp, "server=[2001:db8::2]:443\n").as_deref(), Some("2001:db8::2"));
    // A trailing root dot goes; case is kept as written.
    assert_eq!(host(VPNKind::Openvpn, "remote VPN.Example.com. 1194\n").as_deref(), Some("VPN.Example.com"));
    // Not a host: refused.
    for (kind, config) in [
        (VPNKind::Sstp, "server=https://sstp.example.com/path\n"),
        (VPNKind::Sstp, "server=sstp.example.com/path\n"),
        (VPNKind::Sstp, "server=sstp.example.com:notaport\n"),
        (VPNKind::Sstp, "server=sstp.example.com:99999\n"),
        (VPNKind::Sstp, "server=@\n"),
        (VPNKind::Sstp, "server=a..b\n"),
        (VPNKind::Sstp, "server=-a.example\n"),
        (VPNKind::Sstp, "server=a-.example\n"),
        (VPNKind::Sstp, "server=a;b\n"),
        (VPNKind::Sstp, "server=a<b>.example\n"),
        (VPNKind::Sstp, "server=[2001:db8::2\n"),
        (VPNKind::Sstp, "server=[not-ip]:443\n"),
        (VPNKind::Strongswan, "remote_addrs = %any\n"),
        (VPNKind::Strongswan, "remote_addrs = 10.0.0.0/24\n"),
        (VPNKind::Strongswan, "remote_addrs = 10.0.0.1-10.0.0.9\n"),
        (VPNKind::Openvpn, &format!("remote {}.example 1194\n", "a".repeat(64))),
    ] {
        assert_eq!(host(kind, config), None, "{config:?}");
    }
}

/// Every text config format takes the line as a comment (a file opened elsewhere stays valid), and the import
/// strips it for each of them (Task 16).
#[test]
fn every_text_format_accepts_the_line_and_the_import_strips_it() {
    use macvpn_core::models::VPNKind;
    let line = exporter::meta_line(&meta(Some(&["Work", "Clients"]), None)).unwrap();
    for (kind, file) in [
        (VPNKind::Openvpn, "office.ovpn"),
        (VPNKind::Wireguard, "office.conf"),
        (VPNKind::Strongswan, "office.swanctl.conf"),
        (VPNKind::Sstp, "office.sstp"),
    ] {
        let template = match kind {
            VPNKind::Openvpn => "client\ndev tun\nremote vpn.example.com 1194\n".to_string(),
            _ => importer::template(kind),
        };
        let validator = macvpn_core::validators::validator(kind).unwrap();
        let with_line = format!("{line}{template}");
        // The same findings, one line further down.
        let shifted: Vec<_> = validator
            .validate(&template)
            .into_iter()
            .map(|mut i| {
                if i.line > 0 {
                    i.line += 1;
                }
                i
            })
            .collect();
        assert_eq!(validator.validate(&with_line), shifted, "{kind:?}");
        let prepared = importer::prepare(file, &with_line, &std::env::temp_dir()).unwrap();
        assert_eq!(prepared.kind, kind);
        assert_eq!(prepared.config, template, "{kind:?}");
        assert_eq!(prepared.meta.and_then(|m| m.folder), Some(vec!["Work".to_string(), "Clients".to_string()]));
    }
    // No line: no metadata.
    let plain = importer::prepare("office.ovpn", "client\nremote vpn.example.com\n", &std::env::temp_dir());
    assert_eq!(plain.unwrap().meta, None);
}
