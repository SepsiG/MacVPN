//! The WinVPN Service's debug diagnostics (WinVPN 2c, G-6): the snapshot block in macOS' shape, the WireGuard peer
//! status without keys, and that neither is written without `--debug`. Pure: every OS.

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, LogSlice, OpenVpnFacts, Request, SERVICE_VERSION, WireGuardFacts};
use macvpn_helper::windows::diagnostics::{
    self, Interface, MAX_ITEMS, PeerStatus, Route, Snapshot, peer_lines, server_of, snapshot_lines,
};
use macvpn_helper::windows::logs::FileLogStore;
use macvpn_helper::windows::service::{Caller, Engine, EngineState, Host, LogStore, Service, UpRequest};
use macvpn_helper::windows::{wg_nt, wg_plan};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use zeroize::Zeroizing;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const PRIVATE: &str = "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=";
const PUBLIC: &str = "bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=";
const PSK: &str = "bWFjdnBuLXRlc3QtcHJlc2hhcmVkLWtleS0zMmJ5dGU=";

fn wg_config() -> String {
    format!(
        "[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = {PUBLIC}\nPresharedKey = {PSK}\nAllowedIPs = 10.0.0.0/24, 192.168.50.0/24\nEndpoint = vpn.example.com:51820\n"
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sample() -> Snapshot {
    Snapshot {
        server: Some("vpn.example.com".into()),
        resolved: vec![ip("203.0.113.7")],
        routes: vec![
            Route {
                destination: ip("0.0.0.0"),
                prefix_len: 0,
                next_hop: ip("192.168.1.1"),
                interface: "Ethernet".into(),
                metric: 35,
            },
            Route {
                destination: ip("192.168.1.0"),
                prefix_len: 24,
                next_hop: ip("0.0.0.0"),
                interface: "Ethernet".into(),
                metric: 281,
            },
        ],
        dns: vec![("Ethernet".into(), vec![ip("192.168.1.1"), ip("9.9.9.9")])],
        interfaces: vec![
            Interface { name: "Ethernet".into(), up: true, addresses: vec![(ip("192.168.1.20"), 24)] },
            Interface { name: "Wi-Fi\r\nforged line".into(), up: false, addresses: Vec::new() },
        ],
        problems: Vec::new(),
    }
}

#[test]
fn the_snapshot_lines_match_the_macos_shape() {
    let lines = with_language(AppLanguage::En, || snapshot_lines("before", &sample()));
    assert_eq!(
        lines,
        [
            "▶ [WinVPN] diagnostics (before)",
            "$ resolve vpn.example.com",
            "  203.0.113.7",
            "$ IPv4 routes (2)",
            "  0.0.0.0/0 via 192.168.1.1 dev Ethernet metric 35",
            "  192.168.1.0/24 on-link dev Ethernet metric 281",
            "$ DNS servers",
            "  Ethernet: 192.168.1.1, 9.9.9.9",
            "$ interfaces (2)",
            "  Ethernet (up) 192.168.1.20/24",
            "  Wi-Fi  forged line (down)",
        ]
    );
    // Translated header, as macOS' "diagnostics (előtte)".
    let hu = with_language(AppLanguage::Hu, || snapshot_lines("x", &Snapshot::default()));
    assert_eq!(hu[0], "▶ [WinVPN] diagnosztika (x)");
    // Not resolved, no server, problems, and the bound.
    let mut s = Snapshot { resolved: Vec::new(), ..sample() };
    s.problems.push("routes: access denied".into());
    let lines = with_language(AppLanguage::En, || snapshot_lines("after", &s));
    assert_eq!(lines[2], "  (not resolved)");
    assert_eq!(lines.last().unwrap(), "  (routes: access denied)");
    let none = with_language(AppLanguage::En, || snapshot_lines("after", &Snapshot::default()));
    assert!(!none.iter().any(|l| l.starts_with("$ resolve")), "{none:?}");
    let many = Snapshot { routes: vec![sample().routes[0].clone(); MAX_ITEMS + 5], ..Snapshot::default() };
    let lines = snapshot_lines("after", &many);
    assert_eq!(lines.iter().filter(|l| l.starts_with("  0.0.0.0/0")).count(), MAX_ITEMS);
    assert!(lines.contains(&"  … 5 more".to_string()), "{lines:?}");
}

#[test]
fn the_server_is_found_as_on_macos() {
    assert_eq!(server_of(VPNKind::Wireguard, wg_config().as_bytes()).as_deref(), Some("vpn.example.com"));
    assert_eq!(
        server_of(VPNKind::Wireguard, b"[Peer]\nEndpoint = [2001:db8::1]:51820\n").as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(server_of(VPNKind::Wireguard, b"[Peer]\nEndpoint=198.51.100.4:4500\n").as_deref(), Some("198.51.100.4"));
    let ovpn =
        b"client\n<ca>\nremote inside.example 1194\n</ca>\nremote vpn.example.org 1194 udp\nremote second.example\n";
    assert_eq!(server_of(VPNKind::Openvpn, ovpn).as_deref(), Some("vpn.example.org"));
    assert_eq!(
        server_of(VPNKind::Openvpn, b"<connection>\nremote conn.example 443\n</connection>\n").as_deref(),
        Some("conn.example")
    );
    // Anything that is not a plain name or address is not resolved (and not logged).
    assert_eq!(server_of(VPNKind::Openvpn, b"remote evil$(x) 1194\n"), None);
    assert_eq!(server_of(VPNKind::Openvpn, b"dev tun\n"), None);
    assert_eq!(server_of(VPNKind::Strongswan, b"remote_addrs = vpn.example.com\n"), None);
}

#[test]
fn peer_status_has_no_keys() {
    let plan = wg_plan::parse(&wg_config()).unwrap();
    let endpoint: SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let mut block = wg_nt::encode(&plan, &[Some(endpoint)]).unwrap();
    // What wireguard-nt fills in: the interface's public key, TxBytes, RxBytes, LastHandshake (FILETIME).
    let peer = wg_nt::INTERFACE_SIZE;
    block[38..70].copy_from_slice(&[0xAB; 32]);
    block[peer + 72..peer + 74].copy_from_slice(&25u16.to_le_bytes());
    block[peer + 104..peer + 112].copy_from_slice(&2048u64.to_le_bytes());
    block[peer + 112..peer + 120].copy_from_slice(&1_572_864u64.to_le_bytes());
    let handshake_unix = 1_760_000_000u64;
    let filetime = (handshake_unix + 11_644_473_600) * 10_000_000;
    block[peer + 120..peer + 128].copy_from_slice(&filetime.to_le_bytes());

    let peers = wg_nt::peer_status(&block);
    assert_eq!(
        peers,
        [PeerStatus {
            endpoint: Some(endpoint),
            last_handshake: Some(handshake_unix),
            rx: 1_572_864,
            tx: 2048,
            allowed_ips: 2,
            keepalive: 25,
        }]
    );
    // Dead-tunnel detection reads the same block: times and counters only.
    assert_eq!(
        wg_nt::liveness(&block),
        macvpn_core::liveness::Liveness::WireGuard(vec![macvpn_core::liveness::WgPeer {
            last_handshake: Some(handshake_unix),
            rx: 1_572_864,
            tx: 2048,
            keepalive: 25,
            endpoint: true,
        }])
    );
    let text = peer_lines("WinVPN0f1e2d3c", &peers, handshake_unix + 7).join("\n");
    assert_eq!(
        text,
        "▶ [WinVPN] WireGuard peer status (WinVPN0f1e2d3c)\n  peer: endpoint 203.0.113.7:51820, allowed ips 2, \
         latest handshake 7 s ago, transfer 1.50 MiB received, 2.00 KiB sent"
    );
    // No key in any form: base64, hex, or the raw bytes' Debug output.
    let debug = format!("{peers:?}");
    for key in [PRIVATE, PUBLIC, PSK] {
        let raw = wg_plan::decode_key(key).unwrap();
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        for haystack in [&text, &debug] {
            assert!(!haystack.contains(key) && !haystack.contains(&hex), "{haystack}");
            assert!(!haystack.contains(&format!("{:?}", &raw[..4])), "{haystack}");
        }
    }
    // No handshake yet; a cut block ends the list; garbage is no peer.
    block[peer + 120..peer + 128].copy_from_slice(&0u64.to_le_bytes());
    let lines = peer_lines("x", &wg_nt::peer_status(&block), 0);
    assert!(lines[1].contains("latest handshake none yet"), "{lines:?}");
    assert!(lines[1].contains("endpoint 203.0.113.7:51820"), "{lines:?}");
    assert_eq!(wg_nt::peer_status(&block[..wg_nt::INTERFACE_SIZE + 100]), []);
    assert_eq!(wg_nt::peer_status(&[0u8; 10]), []);
    assert_eq!(peer_lines("x", &[], 0)[1], "  (no peers)");
    assert_eq!(diagnostics::bytes(512), "512 B");
}

// MARK: - The service writes them only in debug mode

#[derive(Default)]
struct Wg {
    peer_calls: Mutex<u32>,
}

impl Engine for Wg {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        req.log.line("up");
        Ok(())
    }
    fn down(&self, _id: &str) -> Result<(), String> {
        Ok(())
    }
    fn state(&self, _id: &str) -> Option<EngineState> {
        None
    }
    fn peer_status(&self, _id: &str) -> Option<(String, Vec<PeerStatus>)> {
        *self.peer_calls.lock().unwrap() += 1;
        Some(("WinVPN0f1e2d3c".into(), vec![PeerStatus { allowed_ips: 1, ..PeerStatus::default() }]))
    }
}

struct DiagHost {
    wg: Wg,
    logs: FileLogStore,
    servers: Mutex<Vec<Option<String>>>,
}

impl Host for DiagHost {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine> {
        (kind == VPNKind::Wireguard).then_some(&self.wg as &dyn Engine)
    }
    fn facts(&self) -> EngineFacts {
        EngineFacts {
            service_version: SERVICE_VERSION,
            problem: None,
            openvpn: OpenVpnFacts { version: None, path: None, dco: None, tap_windows6: None, problem: None },
            wireguard: WireGuardFacts { dll_version: Some("1.1.0".into()), problem: None },
        }
    }
    fn logs(&self) -> &dyn LogStore {
        &self.logs
    }
    fn problem(&self) -> Option<String> {
        None
    }
    fn snapshot(&self, server: Option<&str>) -> Option<Snapshot> {
        self.servers.lock().unwrap().push(server.map(str::to_string));
        Some(sample())
    }
    fn now(&self) -> u64 {
        1_760_000_000
    }
}

fn framed(config: &str) -> Vec<u8> {
    let mut v = format!("config {}\n{config}", config.len()).into_bytes();
    v.extend_from_slice(b"password=hunter22\n");
    v
}

fn run(args: &[&str]) -> (Vec<Option<String>>, u32, String) {
    let dir = std::env::temp_dir().join(format!("winvpn-diagnostics-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let host = DiagHost { wg: Wg::default(), logs: FileLogStore::new(dir.clone()), servers: Mutex::new(Vec::new()) };
    let s = Service::new(host);
    let caller = Caller { sid: "S-1-5-21-1-2-3-1001".into() };
    let req = |args: &[&str], body: &[u8]| Request {
        args: args.iter().map(|s| s.to_string()).collect(),
        body: Zeroizing::new(body.to_vec()),
    };
    let r = with_language(AppLanguage::En, || s.handle(&caller, &req(args, &framed(&wg_config()))));
    assert_eq!(r.code, 0, "{}", String::from_utf8_lossy(&r.stderr));
    let slice = LogSlice::parse(&s.handle(&caller, &req(&["log", ID, "0"], b"")).stdout).unwrap();
    let log = String::from_utf8_lossy(&slice.data).into_owned();
    let out = (s.host().servers.lock().unwrap().clone(), *s.host().wg.peer_calls.lock().unwrap(), log);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

#[test]
fn no_snapshot_without_debug() {
    let (snapshots, peer_calls, log) = run(&["up", "wireguard", ID]);
    assert_eq!((snapshots.len(), peer_calls), (0, 0));
    assert!(!log.contains("diagnostics") && !log.contains("peer status"), "{log}");

    let (snapshots, peer_calls, log) = run(&["up", "wireguard", ID, "--debug"]);
    assert_eq!(snapshots, [Some("vpn.example.com".to_string()), Some("vpn.example.com".to_string())]);
    assert_eq!(peer_calls, 1);
    let before = log.find("diagnostics (before)").expect("before");
    let up = log.find("\nup\n").expect("up");
    let peers = log.find("WireGuard peer status (WinVPN0f1e2d3c)").expect("peers");
    let after = log.find("diagnostics (after)").expect("after");
    assert!(before < up && up < peers && peers < after, "{log}");
    assert!(log.contains("  0.0.0.0/0 via 192.168.1.1 dev Ethernet metric 35"), "{log}");
    for secret in ["hunter22", PRIVATE, PUBLIC, PSK] {
        assert!(!log.contains(secret), "{secret}: {log}");
    }
}
