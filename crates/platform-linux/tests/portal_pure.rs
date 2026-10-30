use macvpn_platform_linux::pure::portal::{dark_from_color_scheme, paths_from_uris};
use std::path::PathBuf;

#[test]
fn color_scheme_values() {
    assert_eq!(dark_from_color_scheme(1), Some(true));
    assert_eq!(dark_from_color_scheme(2), Some(false));
    assert_eq!(dark_from_color_scheme(0), None);
    assert_eq!(dark_from_color_scheme(7), None);
}

#[test]
fn file_uris_only_percent_decoded() {
    assert_eq!(
        paths_from_uris(&["file:///home/ann/Office%20VPN.ovpn".into(), "file:///tmp/%C3%A1.conf".into()]),
        vec![PathBuf::from("/home/ann/Office VPN.ovpn"), PathBuf::from("/tmp/á.conf")]
    );
    // Other schemes, hosts, relative or broken escapes are dropped.
    assert!(
        paths_from_uris(&[
            "https://example.com/a.ovpn".into(),
            "file://host/a.ovpn".into(),
            "file:relative.ovpn".into(),
            "file:///a%2".into(),
            "file:///a%00b".into(),
        ])
        .is_empty()
    );
}
