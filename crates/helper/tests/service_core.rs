//! The WinVPN Service's request handling over fake engines (crates/helper/src/windows/service.rs).

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, LogSlice, OpenVpnFacts, Request, SERVICE_VERSION, WireGuardFacts};
use macvpn_core::service_proto::{EngineUpdate, UPDATE_BUSY};
use macvpn_helper::windows::logs::FileLogStore;
use macvpn_helper::windows::service::{Caller, Engine, EngineState, Host, LogStore, Service, UpRequest, UpdateRefusal};
use std::sync::{Arc, Condvar, Mutex};
use zeroize::Zeroizing;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";

#[derive(Default)]
struct Fake {
    up: Mutex<Vec<String>>,
    down: Mutex<Vec<String>>,
    fail_up: Option<String>,
    fail_down: Option<String>,
    /// `state` reports an interface name and address no checked engine would (JSON metacharacters).
    bad_state: bool,
    /// The answers of `update_check` and `update` (`None`: the trait's defaults), and how often `update` ran.
    check: Option<Result<EngineUpdate, String>>,
    update: Option<Result<EngineUpdate, UpdateRefusal>>,
    updates: Mutex<u32>,
}

impl Engine for Fake {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        req.log.line("starting");
        req.log.line(&format!("password is {}", String::from_utf8_lossy(&req.secrets.pass)));
        self.up.lock().unwrap().push(req.id.to_string());
        match &self.fail_up {
            Some(m) => Err(m.clone()),
            None => Ok(()),
        }
    }
    fn down(&self, id: &str) -> Result<(), String> {
        self.down.lock().unwrap().push(id.to_string());
        match &self.fail_down {
            Some(m) => Err(m.clone()),
            None => Ok(()),
        }
    }
    fn state(&self, id: &str) -> Option<EngineState> {
        self.up.lock().unwrap().iter().any(|u| u == id).then(|| EngineState {
            state: "connected",
            iface: if self.bad_state { "x\",\"evil\":\"1".into() } else { "WinVPN0f1e2d3c".into() },
            ip: if self.bad_state { "10.0.0.2\"}".into() } else { "10.0.0.2".into() },
            since: Some(1_700_000_000),
        })
    }
    fn update_check(&self) -> Result<EngineUpdate, String> {
        self.check.clone().unwrap_or_else(|| Err("default".into()))
    }
    fn update(&self) -> Result<EngineUpdate, UpdateRefusal> {
        *self.updates.lock().unwrap() += 1;
        self.update.clone().unwrap_or_else(|| Err(UpdateRefusal::Failed("default".into())))
    }
}

struct TestHost {
    wg: Fake,
    logs: FileLogStore,
    problem: Option<String>,
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
        self.problem.clone()
    }
}

fn service() -> (Service<TestHost>, tempdir::Dir) {
    let dir = tempdir::Dir::new();
    let host = TestHost { wg: Fake::default(), logs: FileLogStore::new(dir.path().to_path_buf()), problem: None };
    (Service::new(host), dir)
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

fn err(r: &macvpn_core::service_proto::Response) -> String {
    String::from_utf8_lossy(&r.stderr).trim_end().to_string()
}

mod tempdir {
    pub struct Dir(std::path::PathBuf);
    impl Dir {
        pub fn new() -> Dir {
            let p = std::env::temp_dir().join(format!("winvpn-service-core-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn version_and_engine_answer_anyone() {
    let (s, _d) = service();
    let r = s.handle(&alice(), &req(&["version"], b""));
    assert_eq!((r.code, r.stdout.as_slice()), (0, &b"1\n"[..]));
    let r = s.handle(&bob(), &req(&["engine"], b""));
    assert_eq!(EngineFacts::parse(&r.stdout).unwrap().wireguard.dll_version.as_deref(), Some("1.1.0"));
}

#[test]
fn up_validates_owns_and_status_shows_only_the_owner() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(r.code, 0, "{}", err(&r));
        let mine = String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap();
        assert!(mine.contains(ID) && mine.contains("\"connected\""), "{mine}");
        let theirs = s.handle(&bob(), &req(&["status"], b""));
        assert_eq!(theirs.stdout, b"[]\n");
        // Bob can neither take it down, nor bring it up, nor read its log: the same answer as an unknown ID.
        for r in [
            s.handle(&bob(), &req(&["down", "wireguard", ID], b"")),
            s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, ""))),
            s.handle(&bob(), &req(&["log", ID, "0"], b"")),
            s.handle(&bob(), &req(&["auth-state", ID], b"")),
        ] {
            assert_eq!((r.code, err(&r).as_str()), (1, "Invalid ID"));
        }
        let r = s.handle(&alice(), &req(&["down", "wireguard", ID], b""));
        assert_eq!(r.code, 0);
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");
    });
}

#[test]
fn an_invalid_config_is_refused_before_the_engine_runs() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let bad = WG.replace("Address", "PostUp = calc.exe\nAddress");
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(&bad, "")));
        assert_eq!(r.code, 1);
        assert!(err(&r).starts_with("Invalid config:"), "{}", err(&r));
        assert!(s.host().wg.up.lock().unwrap().is_empty());
    });
}

#[test]
fn malformed_input_is_refused() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "wireguard", "../x"], &framed(WG, "")))), "Invalid ID");
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "wireguard", ID], b"garbage"))), "Config not provided");
        assert_eq!(s.handle(&alice(), &req(&["up", "pptp", ID], b"")).code, 2);
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "sstp", ID], b""))), "Not available on this system yet");
        assert_eq!(s.handle(&alice(), &req(&["frobnicate"], b"")).code, 2);
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID, "--accept-risky", "A"], &framed(WG, ""))).code, 2);
    });
}

#[test]
fn the_log_is_masked_and_served_in_slices() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "password=hunter22\n")));
        assert_eq!(r.code, 0);
        let slice = LogSlice::parse(&s.handle(&alice(), &req(&["log", ID, "0"], b"")).stdout).unwrap();
        let text = String::from_utf8(slice.data).unwrap();
        assert!(text.contains("starting"));
        assert!(text.contains("password is ***") && !text.contains("hunter22"), "{text}");
        assert_eq!(slice.start, 0);
        let past =
            LogSlice::parse(&s.handle(&alice(), &req(&["log", ID, &slice.size.to_string()], b"")).stdout).unwrap();
        assert!(past.data.is_empty());
        // Still readable after down (the Log tab shows why a connection ended).
        s.handle(&alice(), &req(&["down", "wireguard", ID], b""));
        assert!(s.handle(&alice(), &req(&["log", ID, "0"], b"")).code == 0);
    });
}

#[test]
fn a_failed_up_releases_the_id_and_reports_the_engines_message() {
    with_language(AppLanguage::En, || {
        let dir = tempdir::Dir::new();
        let host = TestHost {
            wg: Fake { fail_up: Some("wireguard.dll is not usable".into()), ..Fake::default() },
            logs: FileLogStore::new(dir.path().to_path_buf()),
            problem: None,
        };
        let s = Service::new(host);
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!((r.code, err(&r).as_str()), (1, "wireguard.dll is not usable"));
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");
        // Bob may use the ID now (nobody owns it).
        assert_ne!(err(&s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "Invalid ID");
    });
}

#[test]
fn limits_per_user_and_degraded_mode() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        for i in 0..macvpn_helper::windows::service::MAX_PER_USER {
            let id = format!("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1{i:02X}");
            assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", &id], &framed(WG, ""))).code, 0);
        }
        let r = s.handle(&alice(), &req(&["up", "wireguard", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1FF"], &framed(WG, "")));
        assert_eq!(err(&r), "Too many connections");
        s.drop_user(&alice().sid);
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");

        let dir = tempdir::Dir::new();
        let degraded = Service::new(TestHost {
            wg: Fake::default(),
            logs: FileLogStore::new(dir.path().to_path_buf()),
            problem: Some("unsafe folder".into()),
        });
        assert_eq!(err(&degraded.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "unsafe folder");
        assert_eq!(
            EngineFacts::parse(&degraded.handle(&alice(), &req(&["engine"], b"")).stdout).unwrap().problem.as_deref(),
            Some("unsafe folder")
        );
    });
}

#[test]
fn hungarian_requests_get_hungarian_answers() {
    let (s, _d) = service();
    let r = s.handle(&alice(), &req(&["down", "wireguard", "../x", "--lang", "hu"], b""));
    assert_eq!(err(&r), "Érvénytelen azonosító");
}

// MARK: - Beyond the plan's tests: the service's state never loses a running connection, and stays bounded.

fn service_with(wg: Fake) -> (Service<TestHost>, tempdir::Dir) {
    let dir = tempdir::Dir::new();
    let host = TestHost { wg, logs: FileLogStore::new(dir.path().to_path_buf()), problem: None };
    (Service::new(host), dir)
}

#[test]
fn dry_run_is_refused_and_never_reaches_an_engine() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID, "--dry-run"], &framed(WG, ""))).code, 2);
        assert_eq!(s.handle(&alice(), &req(&["--dry-run", "status"], b"")).code, 2);
        assert!(s.host().wg.up.lock().unwrap().is_empty());
    });
}

#[test]
fn a_failed_down_keeps_the_connection_owned() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service_with(Fake { fail_down: Some("still running".into()), ..Fake::default() });
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        let r = s.handle(&alice(), &req(&["down", "wireguard", ID], b""));
        assert_eq!((r.code, err(&r).as_str()), (1, "still running"));
        let mine = String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap();
        assert!(mine.contains(ID), "{mine}");
        assert_eq!(err(&s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "Invalid ID");
        // A logoff whose down fails keeps it too (the owner can still take it down).
        s.drop_user(&alice().sid);
        assert!(s.owners().contains(&alice().sid));
    });
}

#[test]
fn down_goes_to_the_engine_that_brought_it_up() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        // The kind of the request is only checked for its form: the recorded engine takes the connection down.
        assert_eq!(s.handle(&alice(), &req(&["down", "openvpn", ID.to_lowercase().as_str()], b"")).code, 0);
        assert_eq!(*s.host().wg.down.lock().unwrap(), vec![ID.to_string()]);
        assert_eq!(s.handle(&alice(), &req(&["down", "pptp", ID], b"")).code, 2);
    });
}

#[test]
fn a_second_up_closes_the_previous_run_first() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        assert_eq!(*s.host().wg.down.lock().unwrap(), vec![ID.to_string()]);
        assert_eq!(s.host().wg.up.lock().unwrap().len(), 2);

        let (s, _d) = service_with(Fake { fail_down: Some("still running".into()), ..Fake::default() });
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(err(&r), "Cannot close the previous connection");
        assert_eq!(s.host().wg.up.lock().unwrap().len(), 1);
        assert!(String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap().contains(ID));
    });
}

#[test]
fn status_never_renders_unchecked_engine_values() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service_with(Fake { bad_state: true, ..Fake::default() });
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        let out = String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap();
        assert!(out.contains("\"iface\":null,\"ip\":null") && !out.contains("evil"), "{out}");
        assert_eq!(macvpn_core::status::parse_status(&out).unwrap().len(), 1);
    });
}

#[test]
fn past_logs_are_bounded_per_user() {
    with_language(AppLanguage::En, || {
        let (s, d) = service();
        let max = macvpn_helper::windows::service::MAX_LOGS_PER_USER;
        let id = |i: usize| format!("0F1E2D3C-4B5A-6978-8796-A5B4C3D2{i:04X}");
        for i in 0..max + 3 {
            assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", &id(i)], &framed(WG, ""))).code, 0);
            assert_eq!(s.handle(&alice(), &req(&["down", "wireguard", &id(i)], b"")).code, 0);
        }
        for i in 0..3 {
            assert_eq!(err(&s.handle(&alice(), &req(&["log", &id(i), "0"], b""))), "Invalid ID");
        }
        assert_eq!(s.handle(&alice(), &req(&["log", &id(max + 2), "0"], b"")).code, 0);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), max);
    });
}

/// An engine whose `up` blocks until the test releases it (a connection that is still connecting).
#[derive(Default)]
struct Gate {
    entered: (Mutex<bool>, Condvar),
    released: (Mutex<bool>, Condvar),
    down: Mutex<Vec<String>>,
}

fn set(flag: &(Mutex<bool>, Condvar)) {
    *flag.0.lock().unwrap() = true;
    flag.1.notify_all();
}

fn wait(flag: &(Mutex<bool>, Condvar)) {
    let mut g = flag.0.lock().unwrap();
    while !*g {
        g = flag.1.wait(g).unwrap();
    }
}

impl Engine for Gate {
    fn up(&self, _req: &UpRequest<'_>) -> Result<(), String> {
        set(&self.entered);
        wait(&self.released);
        Ok(())
    }
    fn down(&self, id: &str) -> Result<(), String> {
        self.down.lock().unwrap().push(id.to_string());
        Ok(())
    }
    fn state(&self, _id: &str) -> Option<EngineState> {
        None
    }
}

struct GateHost {
    gate: Gate,
    logs: FileLogStore,
}

impl Host for GateHost {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine> {
        (kind == VPNKind::Wireguard).then_some(&self.gate as &dyn Engine)
    }
    fn facts(&self) -> EngineFacts {
        TestHost { wg: Fake::default(), logs: FileLogStore::new(std::env::temp_dir()), problem: None }.facts()
    }
    fn logs(&self) -> &dyn LogStore {
        &self.logs
    }
    fn problem(&self) -> Option<String> {
        None
    }
}

#[test]
fn a_down_while_connecting_wins() {
    with_language(AppLanguage::En, || {
        let dir = tempdir::Dir::new();
        let s = Arc::new(Service::new(GateHost {
            gate: Gate::default(),
            logs: FileLogStore::new(dir.path().to_path_buf()),
        }));
        let s2 = Arc::clone(&s);
        let t = std::thread::spawn(move || s2.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))));
        wait(&s.host().gate.entered);
        let mine = String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap();
        assert!(mine.contains("\"connecting\""), "{mine}");
        assert_eq!(err(&s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "Invalid ID");
        assert_eq!(
            err(&s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")))),
            "Another operation on this connection is in progress"
        );
        assert_eq!(s.handle(&alice(), &req(&["down", "wireguard", ID], b"")).code, 0);
        set(&s.host().gate.released);
        let r = t.join().unwrap();
        assert_eq!((r.code, err(&r).as_str()), (1, "The connection was taken down while connecting"));
        // The engine was told twice: the down itself, and once more after its up returned.
        assert_eq!(s.host().gate.down.lock().unwrap().len(), 2);
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");
    });
}

#[test]
fn wireguard_updates_are_the_engines_and_wait_for_every_wireguard_connection() {
    with_language(AppLanguage::En, || {
        let newer = EngineUpdate { installed: Some("1.1.0".into()), available: Some("1.2.0".into()) };
        let done = EngineUpdate { installed: Some("1.2.0".into()), available: None };
        let (s, _d) =
            service_with(Fake { check: Some(Ok(newer.clone())), update: Some(Ok(done.clone())), ..Fake::default() });
        // Anyone may ask; the answer is the engine's.
        let r = s.handle(&bob(), &req(&["wireguard-check", "--lang", "en"], b""));
        assert_eq!((r.code, EngineUpdate::parse(&r.stdout)), (0, Some(newer)));
        // Arguments beyond the command are refused (nothing of the request reaches the engine).
        assert_eq!(s.handle(&bob(), &req(&["wireguard-check", "x"], b"")).code, 2);
        assert_eq!(s.handle(&bob(), &req(&["wireguard-update", ID], b"")).code, 2);
        // While any user's WireGuard connection is recorded: busy, and the engine is not asked.
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, ""))).code, 0);
        let r = s.handle(&bob(), &req(&["wireguard-update"], b""));
        assert_eq!(r.code, UPDATE_BUSY);
        assert!(err(&r).contains("no WireGuard connection is up"), "{}", err(&r));
        assert_eq!(*s.host().wg.updates.lock().unwrap(), 0);
        assert_eq!(s.handle(&alice(), &req(&["down", "wireguard", ID], b"")).code, 0);
        let r = s.handle(&bob(), &req(&["wireguard-update"], b""));
        assert_eq!((r.code, EngineUpdate::parse(&r.stdout)), (0, Some(done)));
        assert_eq!(*s.host().wg.updates.lock().unwrap(), 1);
    });
    // The engine's own refusals: busy (exit 3) and failed (exit 1), with its message.
    for (refusal, code) in [(UpdateRefusal::Busy("busy".into()), UPDATE_BUSY), (UpdateRefusal::Failed("no".into()), 1)]
    {
        let (s, _d) =
            service_with(Fake { check: Some(Err("offline".into())), update: Some(Err(refusal)), ..Fake::default() });
        let r = s.handle(&alice(), &req(&["wireguard-update"], b""));
        assert_eq!(r.code, code);
        let r = s.handle(&alice(), &req(&["wireguard-check"], b""));
        assert_eq!((r.code, err(&r).as_str()), (1, "offline"));
    }
}

#[test]
fn a_degraded_service_updates_nothing() {
    let dir = tempdir::Dir::new();
    let host = TestHost {
        wg: Fake { update: Some(Ok(EngineUpdate { installed: None, available: None })), ..Fake::default() },
        logs: FileLogStore::new(dir.path().to_path_buf()),
        problem: Some("unsafe folder".into()),
    };
    let s = Service::new(host);
    let r = s.handle(&alice(), &req(&["wireguard-update"], b""));
    assert_eq!((r.code, err(&r).as_str()), (1, "unsafe folder"));
    assert_eq!(*s.host().wg.updates.lock().unwrap(), 0);
}
