//! The optional `dns` key of `mvpn status` (root layer 15).
use macvpn_core::status::{DnsState, parse_status};

const LINE: &str = r#"{"id":"0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0","kind":"openvpn","state":"connected","iface":"utun7","ip":"10.8.0.2","since":1700000000"#;

#[test]
fn root_status_parses_dns_and_ignores_unknown_values() {
    let without = parse_status(&format!("[{LINE}}}]")).unwrap();
    assert_eq!(without[0].dns, None, "older root layers: absent");
    for s in DnsState::ALL {
        let v = parse_status(&format!("[{LINE},\"dns\":\"{}\"}}]", s.raw())).unwrap();
        assert_eq!(v[0].dns, Some(s));
    }
    let unknown = parse_status(&format!("[{LINE},\"dns\":\"sideways\"}}]")).unwrap();
    assert_eq!(unknown[0].dns, None, "an unknown value counts as absent");
    let wrong = parse_status(&format!("[{LINE},\"dns\":3}}]")).unwrap();
    assert_eq!(wrong[0].dns, None);
}
