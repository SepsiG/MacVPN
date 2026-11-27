//! The WinVPN Service's DNS requests over a fake engine and a DNS manager with fake NRPT rules and adapters
//! (crates/helper/src/windows/service.rs, crates/helper/src/windows/dns.rs).

use macvpn_core::dns_policy::nrpt::NrptRule;
use macvpn_core::dns_policy::{Probe, Pushed, Tunnel};
use macvpn_core::dns_settings::{DnsMode, DnsRequest};
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{
    DNS_APPLY, DNS_CHECK, DNS_RELEASE, DnsApply, EngineFacts, OpenVpnFacts, Request, Response, SERVICE_VERSION,
    WireGuardFacts,
};
use macvpn_helper::windows::dns::{AdapterDns, AdapterNet, Manager, Nrpt, VpnDns};
use macvpn_helper::windows::logs::FileLogStore;
use macvpn_helper::windows::service::{Caller, Engine, EngineState, Host, LogStore, Service, UpRequest};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const SSTP_ID: &str = "11111111-2222-3333-4444-555555555555";
const PPP: u64 = 0x0017_0000_0200_0000;
const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\nDNS = 10.99.0.53, lab.test\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 10.99.0.0/16\nEndpoint = 192.0.2.1:51820\n";

#[derive(Default)]
struct Rules(Mutex<BTreeMap<String, NrptRule>>);

impl Rules {
    fn all_keys(&self) -> Vec<String> {
        self.0.lock().unwrap().keys().cloned().collect()
    }
    fn names(&self, key: &str) -> Vec<String> {
        self.0.lock().unwrap().get(key).map(|r| r.names.clone()).unwrap_or_default()
    }
}

/// The manager's handle on the rules the test reads.
struct Shared(Arc<Rules>);

impl Nrpt for Shared {
    fn write(&self, rules: &[NrptRule]) -> Result<(), String> {
        let mut all = self.0.0.lock().unwrap();
        for r in rules {
            all.insert(r.key.clone(), r.clone());
        }
        Ok(())
    }
    fn delete(&self, prefix: &str) -> Result<usize, String> {
        let mut all = self.0.0.lock().unwrap();
        let before = all.len();
        all.retain(|k, _| !k.starts_with(prefix));
        Ok(before - all.len())
    }
    fn keys(&self) -> Result<Vec<String>, String> {
        Ok(self.0.all_keys())
    }
    fn apply(&self) -> Result<(), String> {
        Ok(())
    }
}

/// The RAS adapter [`PPP`], up while the flag is set.
struct Adapters(Arc<AtomicBool>);

impl AdapterDns for Adapters {
    fn get(&self, luid: u64) -> Option<AdapterNet> {
        (luid == PPP).then(|| AdapterNet {
            servers: vec!["10.88.0.1".into()],
            domains: vec!["sstp.example".into()],
            subnets: vec![],
        })
    }
    fn clear(&self, _luid: u64) -> Result<(), String> {
        Ok(())
    }
    fn set(&self, _luid: u64, _servers: &[String], _domains: &[String]) -> Result<(), String> {
        Ok(())
    }
    fn physical(&self) -> Option<AdapterNet> {
        None
    }
    fn is_ppp(&self, luid: u64) -> bool {
        luid == PPP && self.0.load(Ordering::SeqCst)
    }
}

/// A WireGuard engine whose connections report the config's DNS; `ended` ones are gone on their own.
#[derive(Default)]
struct Wg {
    up: Mutex<HashSet<String>>,
    ended: Mutex<HashSet<String>>,
}

impl Engine for Wg {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        self.up.lock().unwrap().insert(req.id.to_string());
        Ok(())
    }
    fn down(&self, id: &str) -> Result<(), String> {
        self.up.lock().unwrap().remove(id);
        Ok(())
    }
    fn state(&self, id: &str) -> Option<EngineState> {
        if self.ended.lock().unwrap().contains(id) {
            return None;
        }
        self.up.lock().unwrap().contains(id).then(|| EngineState {
            state: "connected",
            iface: "WinVPN0f1e2d3c".into(),
            ip: "10.0.0.2".into(),
            since: Some(1_700_000_000),
        })
    }
    fn dns_facts(&self, id: &str) -> Option<VpnDns> {
        self.up.lock().unwrap().contains(id).then(|| VpnDns {
            pushed: Some(Pushed {
                servers: vec!["10.99.0.53".into()],
                search: vec!["lab.test".into()],
                ..Pushed::default()
            }),
            pushed_full_tunnel: false,
            luid: Some(7),
            run: None,
        })
    }
}

struct TestHost {
    wg: Wg,
    logs: FileLogStore,
    dns: Option<Manager>,
}

impl Host for TestHost {
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
    fn dns(&self) -> Option<&Manager> {
        self.dns.as_ref()
    }
    fn now(&self) -> u64 {
        1_700_000_000
    }
}

struct Fixture {
    s: Service<TestHost>,
    rules: Arc<Rules>,
    ppp_up: Arc<AtomicBool>,
    dir: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(with_dns: bool) -> Fixture {
    let dir = std::env::temp_dir().join(format!("winvpn-service-dns-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let rules = Arc::new(Rules::default());
    let probe = Box::new(|_: &[String]| (Probe::Ok, "resolved".to_string()));
    let ppp_up = Arc::new(AtomicBool::new(true));
    let adapters = Box::new(Adapters(ppp_up.clone()));
    let dns = with_dns.then(|| Manager::new(Box::new(Shared(rules.clone())), adapters, probe));
    let host = TestHost { wg: Wg::default(), logs: FileLogStore::new(dir.clone()), dns };
    Fixture { s: Service::new(host), rules, ppp_up, dir }
}

fn req(args: &[&str], body: &[u8]) -> Request {
    Request { args: args.iter().map(|s| s.to_string()).collect(), body: Zeroizing::new(body.to_vec()) }
}

fn framed(config: &str, secrets: &str) -> Vec<u8> {
    let mut v = format!("config {}\n{config}", config.len()).into_bytes();
    v.extend_from_slice(secrets.as_bytes());
    v
}

fn alice() -> Caller {
    Caller { sid: "S-1-5-21-1-2-3-1001".into() }
}

fn bob() -> Caller {
    Caller { sid: "S-1-5-21-1-2-3-1002".into() }
}

fn out(r: &Response) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}

fn err(r: &Response) -> String {
    String::from_utf8_lossy(&r.stderr).trim_end().to_string()
}

fn apply_body(luid: u64, mode: DnsMode) -> Vec<u8> {
    DnsApply { request: DnsRequest { mode, ..DnsRequest::default() }, luid, tunnel: Tunnel::Split }
        .encode()
        .into_bytes()
}

#[test]
fn the_version_is_2() {
    let f = fixture(true);
    assert_eq!(out(&f.s.handle(&alice(), &req(&["version"], b""))), "2\n");
}

#[test]
fn up_applies_the_dns_status_reports_it_and_down_releases_it() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        let r = f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(r.code, 0, "{}", err(&r));
        assert_eq!(f.rules.all_keys(), [format!("WinVPN-{ID}-0")]);
        assert_eq!(f.rules.names(&format!("WinVPN-{ID}-0")), ["."]);
        let status = out(&f.s.handle(&alice(), &req(&["status"], b"")));
        assert!(status.contains("\"dns\":\"vpn\""), "{status}");
        // The connection's log has the DNS lines.
        let log = out(&f.s.handle(&alice(), &req(&["log", ID, "0"], b"")));
        assert!(log.contains("DNS mode: automatic"), "{log}");
        assert_eq!(f.s.handle(&alice(), &req(&["down", "wireguard", ID], b"")).code, 0);
        assert!(f.rules.all_keys().is_empty());
    });
}

#[test]
fn the_dns_lines_of_up_choose_the_mode() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        let r = f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "dns-mode=targeted\n")));
        assert_eq!(r.code, 0, "{}", err(&r));
        assert_eq!(f.rules.names(&format!("WinVPN-{ID}-0")), [".lab.test"]);
        assert!(out(&f.s.handle(&alice(), &req(&["status"], b""))).contains("\"dns\":\"targeted\""));
    });
}

#[test]
fn dns_check_answers_only_the_owner() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        let r = f.s.handle(&alice(), &req(&[DNS_CHECK, ID], b""));
        assert_eq!((r.code, out(&r).as_str()), (0, "vpn\n"));
        for r in [
            f.s.handle(&bob(), &req(&[DNS_CHECK, ID], b"")),
            f.s.handle(&bob(), &req(&[DNS_RELEASE, ID], b"")),
            f.s.handle(&bob(), &req(&[DNS_APPLY, ID], &apply_body(PPP, DnsMode::Automatic))),
            f.s.handle(&alice(), &req(&[DNS_APPLY, ID], &apply_body(PPP, DnsMode::Automatic))),
            f.s.handle(&alice(), &req(&[DNS_CHECK, "../x"], b"")),
        ] {
            assert_eq!((r.code, err(&r).as_str()), (1, "Invalid ID"));
        }
        assert_eq!(f.rules.all_keys().len(), 1, "nothing changed");
        // An unknown connection of the caller: no DNS session.
        let r = f.s.handle(&alice(), &req(&[DNS_CHECK, SSTP_ID], b""));
        assert_eq!((r.code, r.stdout.is_empty()), (1, true));
    });
}

#[test]
fn sstps_dns_is_applied_checked_and_released_by_its_owner_only() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        let r = f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Targeted)));
        assert_eq!((r.code, out(&r).as_str()), (0, "targeted\n"), "{}", err(&r));
        // The log lines come back for the app's own log.
        assert!(err(&r).contains("DNS mode: targeted"), "{}", err(&r));
        assert_eq!(f.rules.names(&format!("WinVPN-{SSTP_ID}-0")), [".sstp.example"]);
        for r in [
            f.s.handle(&bob(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Automatic))),
            f.s.handle(&bob(), &req(&[DNS_CHECK, SSTP_ID], b"")),
            f.s.handle(&bob(), &req(&[DNS_RELEASE, SSTP_ID], b"")),
        ] {
            assert_eq!((r.code, err(&r).as_str()), (1, "Invalid ID"));
        }
        assert_eq!(f.rules.all_keys().len(), 1);
        assert_eq!(out(&f.s.handle(&alice(), &req(&[DNS_CHECK, SSTP_ID], b""))), "targeted\n");
        // Applied again by its owner (a reconnect): allowed.
        let r = f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Strict)));
        assert_eq!(out(&r), "vpn\n");
        let r = f.s.handle(&alice(), &req(&[DNS_RELEASE, SSTP_ID], b""));
        assert_eq!(r.code, 0);
        assert!(f.rules.all_keys().is_empty());
        assert_eq!(f.s.handle(&alice(), &req(&[DNS_CHECK, SSTP_ID], b"")).code, 1);
    });
}

#[test]
fn dns_apply_names_only_a_ras_adapter_and_a_well_formed_body() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        let r = f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(7, DnsMode::Automatic)));
        assert_eq!((r.code, err(&r).as_str()), (1, "Invalid input"));
        let r = f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], b"dns-mode=automatic\n"));
        assert_eq!((r.code, err(&r).as_str()), (1, "Invalid input"));
        assert!(f.rules.all_keys().is_empty());
    });
}

#[test]
fn a_logoff_releases_the_users_sstp_dns() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Automatic)));
        f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(f.rules.all_keys().len(), 2);
        f.s.drop_user(&bob().sid);
        assert_eq!(f.rules.all_keys().len(), 2);
        f.s.drop_user(&alice().sid);
        assert!(f.rules.all_keys().is_empty());
    });
}

#[test]
fn the_start_removes_the_rules_of_connections_that_no_longer_run() {
    let f = fixture(true);
    let key = format!("WinVPN-{ID}-0");
    f.rules.0.lock().unwrap().insert(key.clone(), NrptRule { key, names: vec![".".into()], servers: vec![] });
    assert_eq!(f.s.reconcile_dns(), Ok(1));
    assert!(f.rules.all_keys().is_empty());
}

#[test]
fn without_a_dns_manager_the_requests_change_nothing() {
    with_language(AppLanguage::En, || {
        let f = fixture(false);
        f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert!(!out(&f.s.handle(&alice(), &req(&["status"], b""))).contains("\"dns\""));
        let r = f.s.handle(&alice(), &req(&[DNS_CHECK, ID], b""));
        assert_eq!((r.code, r.stdout.is_empty()), (1, true));
        let r = f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Automatic)));
        assert_eq!((r.code, err(&r).as_str()), (1, "Not available on this system yet"));
        assert_eq!(f.s.reconcile_dns(), Ok(0));
    });
}

#[test]
fn sstps_dns_ends_with_its_ras_adapter_at_the_owners_next_status() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Automatic)));
        f.s.handle(&bob(), &req(&["status"], b""));
        assert_eq!(f.rules.all_keys().len(), 1, "up, and not Bob's");
        f.ppp_up.store(false, Ordering::SeqCst);
        f.s.handle(&bob(), &req(&["status"], b""));
        assert_eq!(f.rules.all_keys().len(), 1, "only the owner's status looks");
        f.s.handle(&alice(), &req(&["status"], b""));
        assert!(f.rules.all_keys().is_empty());
        assert_eq!(f.s.handle(&alice(), &req(&[DNS_CHECK, SSTP_ID], b"")).code, 1);
    });
}

#[test]
fn a_connection_that_ended_on_its_own_loses_its_dns_at_the_next_status_or_check() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(f.rules.all_keys().len(), 1);
        f.s.host().wg.ended.lock().unwrap().insert(ID.to_string());
        let r = f.s.handle(&alice(), &req(&[DNS_CHECK, ID], b""));
        assert_eq!((r.code, r.stdout.is_empty()), (1, true));
        assert!(f.rules.all_keys().is_empty());
        // Again through the status poll.
        f.s.host().wg.ended.lock().unwrap().clear();
        f.s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(f.rules.all_keys().len(), 1);
        f.s.host().wg.ended.lock().unwrap().insert(ID.to_string());
        assert!(out(&f.s.handle(&alice(), &req(&["status"], b""))).contains("\"failed\""));
        assert!(f.rules.all_keys().is_empty());
    });
}

#[test]
fn up_never_takes_over_an_id_whose_dns_another_sid_applied() {
    with_language(AppLanguage::En, || {
        let f = fixture(true);
        f.s.handle(&alice(), &req(&[DNS_APPLY, SSTP_ID], &apply_body(PPP, DnsMode::Automatic)));
        let r = f.s.handle(&bob(), &req(&["up", "wireguard", SSTP_ID], &framed(WG, "")));
        assert_eq!((r.code, err(&r).as_str()), (1, "Invalid ID"));
        assert_eq!(f.rules.all_keys().len(), 1);
        assert_eq!(f.rules.names(&format!("WinVPN-{SSTP_ID}-0")), ["."]);
    });
}
