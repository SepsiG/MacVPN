//! The platform-neutral network snapshot and the inert probe (auto-reconnect).

use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{Gateway, NetworkProbe, NetworkSnapshot, NoNetworkProbe, PlatformError};

#[test]
fn the_inert_probe_is_unsupported_and_its_watch_is_a_guard() {
    assert!(matches!(NoNetworkProbe.snapshot(), Err(PlatformError::Unsupported { .. })));
    assert!(NoNetworkProbe.watch(Box::new(|| {})).is_ok());
}

#[test]
fn a_snapshot_says_whether_a_network_is_there() {
    let none = NetworkSnapshot::default();
    assert!(!none.has_network());
    let s = NetworkSnapshot {
        gateway: Some(Gateway {
            ip: "192.168.1.1".parse().unwrap(),
            mac: Some([0xa4, 0x2b, 0, 0, 0, 1]),
            interface: "en0".into(),
            ssid: None,
        }),
        connected: vec![IpPrefix::parse("192.168.1.0/24").unwrap()],
    };
    assert!(s.has_network());
}
