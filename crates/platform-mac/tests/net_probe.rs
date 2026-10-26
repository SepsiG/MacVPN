//! The macOS network probe and the network change watcher. The probe's commands run through a scripted runner over
//! the fixtures (no command runs); the connected-subnet filter is checked on fixed input and,
//! read-only, on this Mac's interfaces (properties that hold on any network, or none). The watcher only registers
//! for notifications. The one live probe is `#[ignore]` (it reads this Mac's network; run by hand).
#![cfg(target_os = "macos")]

use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{Platform, PlatformError};
use macvpn_platform_mac::api::MacPlatform;
use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::net_parse::is_tunnel_interface;
use macvpn_platform_mac::net_probe::{MacNetworkProbe, connected_prefixes, physical_prefixes};
use macvpn_platform_mac::net_watch::NetworkWatcher;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/net/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn prefix(text: &str) -> IpPrefix {
    IpPrefix::parse(text).unwrap()
}

/// Answers by command line and stdin (the two `scutil` calls differ only in their script); unknown calls succeed
/// with empty output. Records `command line` or `command line <<< stdin`.
#[derive(Default)]
struct ScriptedRunner {
    answers: HashMap<String, String>,
    calls: Mutex<Vec<String>>,
}

impl ScriptedRunner {
    fn answer(mut self, call: &str, stdout: &str) -> Self {
        self.answers.insert(call.to_string(), stdout.to_string());
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for ScriptedRunner {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        let mut call =
            std::iter::once(executable).chain(arguments.iter().map(String::as_str)).collect::<Vec<_>>().join(" ");
        if let Some(stdin) = stdin {
            call = format!("{call} <<< {stdin}");
        }
        self.calls.lock().unwrap().push(call.clone());
        Ok(CommandResult::new(0, self.answers.get(&call).map_or("", String::as_str), ""))
    }
}

const NETSTAT: &str = "/usr/sbin/netstat -rn -f inet";
const NETSTAT6: &str = "/usr/sbin/netstat -rn -f inet6";
const SCUTIL_LIST: &str = "/usr/sbin/scutil <<< list State:/Network/Service/[^/]+/IPv4\n";
const SCUTIL_SHOW: &str = "/usr/sbin/scutil <<< show State:/Network/Service/00000000-0000-0000-0000-000000000007/IPv4\nshow State:/Network/Service/00000000-0000-0000-0000-000000000001/IPv4\nshow State:/Network/Service/00000000-0000-0000-0000-000000000009/IPv4\n";
const ARP: &str = "/usr/sbin/arp -n 192.168.1.1";
const IPCONFIG: &str = "/usr/sbin/ipconfig getsummary en0";

#[test]
fn the_ipv4_gateway_mac_comes_from_the_dynamic_store() {
    let runner = ScriptedRunner::default()
        .answer(NETSTAT, &fixture("netstat-inet.txt"))
        .answer(SCUTIL_LIST, &fixture("scutil-list.txt"))
        .answer(SCUTIL_SHOW, &fixture("scutil-show.txt"))
        .answer(IPCONFIG, &fixture("ipconfig-wifi.txt"));
    let probe = MacNetworkProbe::new(runner);
    let gateway = probe.gateway().expect("a gateway");
    assert_eq!(gateway.ip, "192.168.1.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(gateway.mac, Some([0xa4, 0x2b, 0xb0, 0, 0, 1]));
    assert_eq!(gateway.interface, "en0");
    assert_eq!(gateway.ssid.as_deref(), Some("Home"));
    // The ARP cache is not read when the dynamic store knows the router.
    assert_eq!(probe.runner().calls(), [NETSTAT, SCUTIL_LIST, SCUTIL_SHOW, IPCONFIG]);
}

#[test]
fn without_the_dynamic_store_the_arp_cache_gives_the_mac() {
    let runner = ScriptedRunner::default()
        .answer(NETSTAT, &fixture("netstat-inet.txt"))
        .answer(ARP, &fixture("arp.txt"))
        .answer(IPCONFIG, &fixture("ipconfig-wifi.txt"));
    let probe = MacNetworkProbe::new(runner);
    let gateway = probe.gateway().expect("a gateway");
    assert_eq!(gateway.mac, Some([0xa4, 0x2b, 0xb0, 0, 0, 1]));
    // No service listed: no `show`.
    assert_eq!(probe.runner().calls(), [NETSTAT, SCUTIL_LIST, ARP, IPCONFIG]);
}

#[test]
fn a_redacted_ssid_and_an_incomplete_arp_entry_are_unknown() {
    let runner = ScriptedRunner::default()
        .answer(NETSTAT, &fixture("netstat-inet.txt"))
        .answer(ARP, &fixture("arp-incomplete.txt"))
        .answer(IPCONFIG, &fixture("ipconfig-redacted.txt"));
    let gateway = MacNetworkProbe::new(runner).gateway().expect("a gateway");
    assert_eq!((gateway.mac, gateway.ssid), (None, None));
}

#[test]
fn without_an_ipv4_default_route_the_ipv6_one_and_the_neighbour_table_are_used() {
    let runner = ScriptedRunner::default()
        .answer(NETSTAT6, &fixture("netstat-inet6.txt"))
        .answer("/usr/sbin/ndp -n -a", &fixture("ndp.txt"));
    let probe = MacNetworkProbe::new(runner);
    let gateway = probe.gateway().expect("a gateway");
    assert_eq!(gateway.ip, "fe80::1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(gateway.mac, Some([0xa4, 0x2b, 0xb0, 0, 0, 1]));
    assert_eq!(gateway.interface, "en0");
    assert_eq!(gateway.ssid, None);
    assert_eq!(probe.runner().calls(), [NETSTAT, NETSTAT6, "/usr/sbin/ndp -n -a", IPCONFIG]);
}

#[test]
fn no_default_route_is_no_network_and_asks_nothing_more() {
    let probe = MacNetworkProbe::new(ScriptedRunner::default());
    assert_eq!(probe.gateway(), None);
    assert_eq!(probe.runner().calls(), [NETSTAT, NETSTAT6]);
}

#[test]
fn a_command_that_cannot_run_reads_as_no_output() {
    // Every call fails (here: times out): nothing panics, there is no network.
    assert_eq!(MacNetworkProbe::new(FailingRunner).gateway(), None);
}

struct FailingRunner;

impl CommandRunner for FailingRunner {
    fn run(&self, executable: &str, _: &[String], _: Option<&str>) -> Result<CommandResult, CommandError> {
        Err(CommandError::TimedOut(executable.to_string()))
    }
}

#[test]
fn only_physical_routable_subnets_are_connected() {
    let all = vec![
        ("lo0".to_string(), prefix("127.0.0.0/8")),
        ("lo0".to_string(), prefix("::1/128")),
        ("en0".to_string(), prefix("192.168.1.0/24")),
        ("en0".to_string(), prefix("169.254.0.0/16")),
        ("en0".to_string(), prefix("fe80::/64")),
        ("en0".to_string(), prefix("2001:db8:1::/64")),
        ("en7".to_string(), prefix("192.168.1.0/24")),
        ("en8".to_string(), prefix("0.0.0.0/0")),
        ("utun4".to_string(), prefix("10.8.0.0/24")),
        ("ipsec0".to_string(), prefix("10.9.0.0/16")),
        ("bridge100".to_string(), prefix("192.168.2.0/24")),
        ("awdl0".to_string(), prefix("fe80::/64")),
    ];
    assert_eq!(physical_prefixes(all), vec![prefix("192.168.1.0/24"), prefix("2001:db8:1::/64")]);
}

/// Read-only, on this Mac: whatever the network (or none), no loopback, link-local or catch-all prefix is listed.
#[test]
fn this_macs_connected_subnets_hold_no_loopback_link_local_or_default() {
    for p in connected_prefixes() {
        assert!(!p.addr.is_loopback(), "{p:?}");
        assert!(p.len > 0, "{p:?}");
        match p.addr {
            std::net::IpAddr::V4(a) => assert!(!a.is_link_local(), "{p:?}"),
            std::net::IpAddr::V6(a) => assert_ne!(a.segments()[0] & 0xffc0, 0xfe80, "{p:?}"),
        }
    }
}

#[test]
fn the_sandbox_has_no_network() {
    let platform = MacPlatform::new(true);
    assert!(matches!(platform.network().snapshot(), Err(PlatformError::Unsupported { .. })));
    assert!(platform.network().watch(Box::new(|| {})).is_ok());
}

#[test]
fn the_network_watcher_starts_and_stops_cleanly_many_times() {
    for _ in 0..20 {
        let watcher = NetworkWatcher::start(|| {}).expect("watcher starts");
        let started = Instant::now();
        watcher.stop();
        assert!(started.elapsed() < Duration::from_secs(5), "stop took {:?}", started.elapsed());
    }
    for _ in 0..5 {
        let watcher = NetworkWatcher::start(|| {}).expect("watcher starts");
        let started = Instant::now();
        drop(watcher);
        assert!(started.elapsed() < Duration::from_secs(5), "drop took {:?}", started.elapsed());
    }
}

/// Manual, read-only: `cargo test -p macvpn-platform-mac --test net_probe -- --ignored --nocapture` prints this
/// Mac's snapshot (the gateway MAC cut to its first 3 bytes). It runs `netstat`, `scutil`, `arp`, `ndp` and
/// `ipconfig`; it sends nothing and changes nothing. Without a default route it only says so.
#[test]
#[ignore = "reads this Mac's live network; run by hand"]
fn live_snapshot_of_this_mac() {
    let snapshot = MacPlatform::new(false).network().snapshot().expect("a snapshot");
    match &snapshot.gateway {
        None => println!("no default route on a physical interface (no network)"),
        Some(g) => {
            assert!(!is_tunnel_interface(&g.interface), "{}", g.interface);
            let mac = g.mac.map(|m| format!("{:02x}:{:02x}:{:02x}:…", m[0], m[1], m[2]));
            println!("gateway {} on {}, MAC {:?}, SSID {:?}", g.ip, g.interface, mac, g.ssid);
        }
    }
    println!("connected: {:?}", snapshot.connected);
}
