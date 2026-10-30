//! The liveness answer of `mvpn liveness <id>` / the WinVPN Service's `liveness <id>` (dead-tunnel detection).

use macvpn_core::liveness::{Liveness, MAX_BYTES, MAX_PEERS, WgPeer};

fn peer(h: u64, rx: u64, tx: u64, k: u16, e: bool) -> WgPeer {
    WgPeer { last_handshake: (h != 0).then_some(h), rx, tx, keepalive: k, endpoint: e }
}

#[test]
fn round_trips() {
    for l in [
        Liveness::WireGuard(vec![]),
        Liveness::WireGuard(vec![peer(1_800_000_000, 12, 3456, 25, true), peer(0, 0, 148, 0, false)]),
        Liveness::OpenVpn { reconnecting_since: None },
        Liveness::OpenVpn { reconnecting_since: Some(1_800_000_123) },
    ] {
        assert_eq!(Liveness::parse(l.encode().as_bytes()), Some(l.clone()), "{l:?}");
    }
    assert_eq!(
        Liveness::WireGuard(vec![peer(1_800_000_000, 12, 3456, 25, true)]).encode(),
        "wireguard 1\npeer 1800000000 12 3456 25 1\n"
    );
    assert_eq!(Liveness::OpenVpn { reconnecting_since: Some(7) }.encode(), "openvpn reconnecting 7\n");
    assert_eq!(Liveness::OpenVpn { reconnecting_since: None }.encode(), "openvpn up\n");
}

#[test]
fn at_most_max_peers_are_encoded() {
    let many = Liveness::WireGuard(vec![peer(1, 2, 3, 0, true); MAX_PEERS + 5]);
    let Some(Liveness::WireGuard(back)) = Liveness::parse(many.encode().as_bytes()) else { panic!() };
    assert_eq!(back.len(), MAX_PEERS);
}

#[test]
fn anything_else_is_refused() {
    let max = format!("peer 1 {} 1 0 1", u64::MAX);
    let over = "peer 1 18446744073709551616 1 0 1".to_string();
    for bad in [
        "",
        "openvpn up",
        "openvpn up\n\n",
        "openvpn down\n",
        "openvpn reconnecting\n",
        "openvpn reconnecting 01\n",
        "openvpn reconnecting -1\n",
        "openvpn reconnecting 1 2\n",
        "openvpn up\npeer 1 1 1 0 1\n",
        "wireguard 1\n",
        "wireguard 0\npeer 1 1 1 0 1\n",
        "wireguard 1\npeer 1 1 1 0 2\n",
        "wireguard 1\npeer 1 1 1 65536 1\n",
        "wireguard 1\npeer 1 1 1 0\n",
        "wireguard 1\npeer 1 1 1 0 1 x\n",
        "wireguard 1\npeer 1 +1 1 0 1\n",
        "wireguard 1\npeer  1 1 0 1\n",
        "wireguard 1\nPEER 1 1 1 0 1\n",
        "wireguard 65\n",
        "wireguard 01\n",
        "WireGuard 0\n",
        "strongswan up\n",
    ] {
        assert_eq!(Liveness::parse(bad.as_bytes()), None, "{bad:?}");
    }
    assert!(Liveness::parse(format!("wireguard 1\n{max}\n").as_bytes()).is_some());
    assert_eq!(Liveness::parse(format!("wireguard 1\n{over}\n").as_bytes()), None);
    assert_eq!(Liveness::parse(&[0xff, b'\n']), None);
    let long = format!("wireguard 0\n{}", " ".repeat(MAX_BYTES));
    assert_eq!(Liveness::parse(long.as_bytes()), None);
}

#[test]
fn counters_round_trip_and_stay_strict() {
    let l = Liveness::Counters { rx: 10, tx: 444, keepalive: 25 };
    assert_eq!(l.encode(), "counters 10 444 25\n");
    assert_eq!(Liveness::parse(b"counters 10 444 25\n"), Some(l));
    assert_eq!(Liveness::parse(b"counters 10 444\n"), None);
    assert_eq!(Liveness::parse(b"counters 01 4 0\n"), None);
}
