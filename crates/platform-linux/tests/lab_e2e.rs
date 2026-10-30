#![cfg(target_os = "linux")]
//! The VPN lab end to end through the real NetworkManager (L-b Tasks 26–28): the real `Engine` on the system bus,
//! the lab's Linux client profiles, every kind connected, checked (test page, routes, DNS, liveness, traffic, logs)
//! and disconnected. Ignored everywhere (`scripts/ignored-everywhere.txt`); run only in the desktop session of the
//! test VM, one test at a time, with the lab up:
//!
//! ```text
//! scripts/lin-remote.sh desktop 'CARGO_BUILD_JOBS=2 LINVPN_LAB_DIR=$HOME/lab/linux cargo test --locked \
//!   -p macvpn-platform-linux --test lab_e2e -- --ignored --test-threads=1 --nocapture lab_openvpn'
//! ```
//!
//! `LINVPN_LAB_DIR` holds the lab's `client/linux` folder. The credentials are read from its `l2tp.txt` and
//! `cisco-ipsec.txt` sheets by this process only (never argv, env or a log: R8); every case checks that no lab
//! secret reached the connection's log or `linvpn-logd`'s answer. Every test first runs the non-interactive polkit
//! check and stops rather than write when NM would ask for a password (R1). Cases that need the lab's containers
//! stopped or restarted write a request file into `LINVPN_LAB_SIGNAL` (default `.linvpn-put/signal` of the
//! checkout) for the maintainer's root watcher.
use macvpn_app_core::failure_reason::{self, FailureKind};
use macvpn_app_core::liveness::{Health, Monitor};
use macvpn_core::client_cert;
use macvpn_core::liveness::Liveness;
use macvpn_core::logd::Request;
use macvpn_core::mfa::{self, AuthResponseKind, AuthUIStateKind};
use macvpn_core::models::{Connection, NativeSettings, OTPSeparator, Secrets, VPNKind};
use macvpn_core::nm_plan::names;
use macvpn_core::target_os::TargetOs;
use macvpn_core::validators::openvpn::OpenVPNValidator;
use macvpn_platform_api::{AuthStateReader, HelperClient, NativeController, NativeProfiles};
use macvpn_platform_linux::lin_for_tests::nm::engine::{Engine, RunView};
use macvpn_platform_linux::lin_for_tests::nm::polkit::{self, Authorization};
use macvpn_platform_linux::lin_for_tests::nm::{files, logd_client};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

const PAGE: &str = "http://10.99.0.10/cgi-bin/index.cgi";
/// The PPP gateways answer the test page too (forwarded): in a split PPP tunnel only the peer is routed on Linux.
const PAGE_L2TP_GW: &str = "http://10.99.16.1/cgi-bin/index.cgi";
const PAGE_SSTP_GW: &str = "http://10.99.17.1/cgi-bin/index.cgi";
const CONNECT_SECS: u64 = 45;
/// The journal pump copies lines for 15 s after a run ends.
const PUMP_TAIL: Duration = Duration::from_secs(16);

// ---------------------------------------------------------------------------------------------------------------
// The lab's credentials and profiles

struct Lab {
    dir: PathBuf,
    server: String,
    user: String,
    otp_user: String,
    group: String,
    password: Zeroizing<String>,
    psk: Zeroizing<String>,
    code: Zeroizing<String>,
    /// Every lab secret with its name, for the log checks (WireGuard keys included).
    secrets: Vec<(&'static str, Zeroizing<String>)>,
}

fn sheet_field(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')))
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| panic!("the lab sheet has no `{name}` line"))
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
    let from = s.find(start).map(|i| i + start.len()).expect("lab sheet: account line");
    let rest = &s[from..];
    &rest[..rest.find(end).expect("lab sheet: account line")]
}

fn lab() -> Lab {
    let dir = PathBuf::from(std::env::var_os("LINVPN_LAB_DIR").expect("LINVPN_LAB_DIR: the lab's client/linux folder"));
    let l2tp = Zeroizing::new(std::fs::read_to_string(dir.join("l2tp.txt")).expect("l2tp.txt"));
    let cisco = Zeroizing::new(std::fs::read_to_string(dir.join("cisco-ipsec.txt")).expect("cisco-ipsec.txt"));
    let account = sheet_field(&l2tp, "Account name");
    let user = account.split_whitespace().next().expect("account").to_string();
    let otp_user = between(&account, "one-time code test: ", ",").trim().to_string();
    // `labuser   (one-time code test: labotp, separator ",", code 123456)`: the last "code ".
    let code = Zeroizing::new(
        between(&account[account.rfind("code ").expect("lab sheet: code")..], "code ", ")").trim().to_string(),
    );
    assert!(code.len() >= 4 && code.bytes().all(|b| b.is_ascii_digit()), "lab sheet: the one-time code is digits");
    let password = Zeroizing::new(sheet_field(&l2tp, "Password"));
    let psk = Zeroizing::new(sheet_field(&l2tp, "Pre-shared key"));
    let mut secrets = vec![("password", password.clone()), ("psk", psk.clone()), ("one-time code", code.clone())];
    let wg = Zeroizing::new(std::fs::read_to_string(dir.join("wireguard-linux.conf")).expect("wireguard-linux.conf"));
    for (name, key) in [("WireGuard private key", "PrivateKey"), ("WireGuard preshared key", "PresharedKey")] {
        if let Some(v) = wg.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        }) {
            secrets.push((name, Zeroizing::new(v)));
        }
    }
    Lab {
        server: sheet_field(&l2tp, "Server"),
        group: sheet_field(&cisco, "Group name"),
        dir,
        user,
        otp_user,
        password,
        psk,
        code,
        secrets,
    }
}

impl Lab {
    fn file(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap_or_else(|_| panic!("lab file {name}"))
    }

    fn secrets(&self, user: &str) -> Secrets {
        Secrets {
            username: Some(user.to_string()),
            password: Some(self.password.to_string()),
            psk: Some(self.psk.to_string()),
            ..Secrets::default()
        }
    }

    /// A wrong code that is not the lab's.
    fn wrong_code(&self) -> &'static str {
        if self.code.as_str() == "000000" { "111111" } else { "000000" }
    }

    /// Panics (naming the secret, never its value) if any lab secret is in `text`.
    fn assert_clean(&self, text: &str, what: &str, extra: &[(&'static str, &str)]) {
        for (name, value) in self.secrets.iter().map(|(n, v)| (*n, v.as_str())).chain(extra.iter().copied()) {
            if value.len() >= 4 && text.contains(value) {
                panic!("a lab secret ({name}) is in {what}");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The engine and the checks

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn uid() -> u32 {
    // The owner of our own /proc entry (no `unsafe` in tests).
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").expect("/proc/self"))
}

/// R1: NM must not need a password for our writes (the desktop session's user manager).
fn authorized() {
    let bus = zbus::blocking::Connection::system().expect("system bus");
    assert!(
        polkit::check_nm_write(&bus) == Authorization::Authorized,
        "not authorized without a prompt: run through `scripts/lin-remote.sh desktop`"
    );
}

/// The real engine on the system bus, one per process as in the app (a second engine's agent could not register:
/// NM allows one agent per identifier and user). Its data (logs, plan records, swanctl) is under
/// `target/tmp/lab/engine`; each case's connection has its own id, so its own log file.
fn engine(case: &str) -> Arc<Engine> {
    static ENGINE: std::sync::OnceLock<Arc<Engine>> = std::sync::OnceLock::new();
    authorized();
    say(&format!("case {case}"));
    ENGINE
        .get_or_init(|| {
            let data = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lab").join("engine");
            let _ = std::fs::remove_dir_all(&data);
            std::fs::create_dir_all(&data).unwrap();
            let user = std::env::var("USER").expect("USER");
            let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
            Engine::new(zbus::blocking::Connection::system, false, user, uid(), runtime, data)
        })
        .clone()
}

/// Disconnects every run of the engine when dropped: a failed check (a panic) leaves no tunnel up.
struct Cleanup(Arc<Engine>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for r in self.0.runs() {
            let _ = self.0.deactivate(&r.id);
        }
    }
}

/// What NM shows about the active connections' IPv4 addresses (diagnostics for the IKEv2 counters).
fn nm_addresses() -> String {
    let mut out = String::new();
    for line in sh("nmcli", &["-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active"]).lines() {
        let uuid = line.split(':').nth(1).unwrap_or("");
        let addrs = sh("nmcli", &["-t", "-g", "IP4.ADDRESS", "connection", "show", uuid]);
        out.push_str(&format!("  {line} -> {}\n", addrs.trim()));
    }
    out
}

fn say(msg: &str) {
    println!("[{:.0}] {msg}", now());
}

fn sh(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap_or_else(|e| panic!("{program}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

thread_local! {
    static PAGE_URL: std::cell::Cell<&'static str> = const { std::cell::Cell::new(PAGE) };
}

/// For a PPP kind (SSTP, L2TP): when the lab's services network is not routed (a split PPP tunnel routes only the
/// peer on Linux), the test page is asked from the PPP gateway instead, and that is said.
fn pick_page(kind: VPNKind) {
    PAGE_URL.with(|p| p.set(PAGE));
    let gw = match kind {
        VPNKind::Sstp => PAGE_SSTP_GW,
        VPNKind::L2tp => PAGE_L2TP_GW,
        _ => return,
    };
    if page().is_none() {
        say(&format!(
            "split PPP tunnel: the services network is not routed (10.99.0.10 via {}); using the gateway page",
            route_dev("10.99.0.10")
        ));
        PAGE_URL.with(|p| p.set(gw));
    }
}

/// The test page through whatever route the system has (`None`: no answer within 5 s).
fn page() -> Option<String> {
    let url = PAGE_URL.with(std::cell::Cell::get);
    let out = Command::new("curl").args(["-s", "--max-time", "5", url]).output().ok()?;
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.success() && body.contains("MacVPN lab: OK")).then_some(body)
}

fn page_via(expected: &str) -> String {
    for _ in 0..5 {
        if let Some(body) = page() {
            assert!(body.contains(&format!("via: {expected}")), "the test page names another server: {body}");
            return body;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("the test page did not answer through the tunnel (expected via {expected})");
}

/// The device `ip route get <dst>` names.
fn route_dev(dst: &str) -> String {
    let out = sh("ip", &["route", "get", dst]);
    out.split_whitespace().skip_while(|w| *w != "dev").nth(1).unwrap_or("").to_string()
}

fn log_text(e: &Engine, id: &Uuid) -> String {
    std::fs::read_to_string(e.log_file(id)).unwrap_or_default()
}

fn log_lines(e: &Engine, id: &Uuid) -> Vec<String> {
    log_text(e, id).lines().map(str::to_string).collect()
}

fn run_of(e: &Engine, id: &Uuid) -> Option<RunView> {
    e.runs().into_iter().find(|r| r.id == *id)
}

/// Waits for `connected` (≤ `CONNECT_SECS`); `Err` with the log when the run ended or the time ran out.
fn wait_connected(e: &Engine, id: &Uuid) -> Result<RunView, String> {
    let deadline = Instant::now() + Duration::from_secs(CONNECT_SECS);
    while Instant::now() < deadline {
        match run_of(e, id) {
            Some(r) if r.state == "connected" && r.ip.is_some() => return Ok(r),
            Some(_) => {}
            None => {
                std::thread::sleep(PUMP_TAIL);
                return Err(format!("the run ended:\n{}{}", log_text(e, id), logd_dump(id)));
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("not connected within {CONNECT_SECS} s:\n{}", log_text(e, id)))
}

/// Waits until the run is gone (≤ `secs`); `true` when it is.
fn wait_gone(e: &Engine, id: &Uuid, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if run_of(e, id).is_none() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// NM still knows the profile (active or saved).
fn nm_has(nm_uuid: &str) -> bool {
    sh("nmcli", &["-t", "-f", "UUID", "connection", "show"]).lines().any(|l| l.trim() == nm_uuid)
}

/// Disconnects, then checks that NM's profile and the runtime directory are gone, waits for the journal pump, and
/// checks the log and logd's answer for lab secrets. Returns the log.
fn finish(lab: &Lab, e: &Engine, id: &Uuid, extra: &[(&'static str, &str)]) -> String {
    let nm_uuid = names::nm_uuid(uid(), id).to_string();
    let started = Instant::now();
    e.deactivate(id).expect("down");
    let deadline = Instant::now() + Duration::from_secs(20);
    while nm_has(&nm_uuid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(!nm_has(&nm_uuid), "NM still has the volatile profile after down");
    say(&format!("down: NM profile gone after {:.1} s", started.elapsed().as_secs_f64()));
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        assert!(!files::dir_for(Path::new(&runtime), &nm_uuid).exists(), "the runtime directory is left");
    }
    settle(lab, e, id, extra)
}

/// After a run ended: waits for the journal pump, checks the log and logd's answer for lab secrets, prints the log.
fn settle(lab: &Lab, e: &Engine, id: &Uuid, extra: &[(&'static str, &str)]) -> String {
    std::thread::sleep(PUMP_TAIL);
    let log = log_text(e, id);
    lab.assert_clean(&log, "the connection log", extra);
    if let Ok(resp) = logd_client::query(&Request { connection: *id, since_usec: 0, cursor: None }) {
        let text: String = resp.lines.iter().map(|l| l.text.clone() + "\n").collect();
        lab.assert_clean(&text, "linvpn-logd's answer", extra);
    }
    println!("--- log of {id} ---\n{log}--- end of log ---");
    log
}

/// What `linvpn-logd` returns for the connection (diagnostics of a failed case).
fn logd_dump(id: &Uuid) -> String {
    match logd_client::query(&Request { connection: *id, since_usec: 0, cursor: None }) {
        Ok(r) => {
            let mut out = format!("--- linvpn-logd: {} lines, withheld {} ---\n", r.lines.len(), r.withheld);
            for l in &r.lines {
                out.push_str(&format!("{:?} {}\n", l.source, l.text));
            }
            out
        }
        Err(e) => format!("--- linvpn-logd: {e:?} ---\n"),
    }
}

fn traffic(e: &Engine, id: &Uuid) -> Option<(u64, u64)> {
    e.traffic_of(id).map(|t| (t.rx, t.tx))
}

/// The acknowledgements the app's editor would store for a config (its RISKY directives on Linux).
fn risky(config: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(config).unwrap();
    OpenVPNValidator.validate_full_for(TargetOs::Linux, text, &HashSet::new()).unacknowledged
}

fn up(e: &Engine, kind: VPNKind, id: &Uuid, config: &[u8], secrets: &Secrets) -> Result<(), String> {
    let accept = if kind == VPNKind::Openvpn { risky(config) } else { Vec::new() };
    HelperClient::up(e, kind, id, config, secrets, true, &accept)
}

/// Connects a helper kind and checks it: connected, the test page via `via`, `1.1.1.1` through the tunnel or not,
/// liveness and traffic readable and growing with the page. Returns the run.
fn connect_and_check(e: &Engine, kind: VPNKind, id: &Uuid, config: &[u8], secrets: &Secrets, via: &str) -> RunView {
    let t0 = Instant::now();
    up(e, kind, id, config, secrets).unwrap_or_else(|m| panic!("up refused: {m}"));
    let run = wait_connected(e, id).unwrap_or_else(|m| panic!("{m}"));
    say(&format!(
        "connected in {:.1} s: iface {:?}, address {}",
        t0.elapsed().as_secs_f64(),
        run.iface,
        run.ip.as_deref().unwrap_or("-").split('.').take(2).collect::<Vec<_>>().join(".") + ".x.x"
    ));
    say(&format!(
        "routes: 10.99.0.10 via {}, 1.1.1.1 via {}; NM: {}",
        route_dev("10.99.0.10"),
        route_dev("1.1.1.1"),
        sh("nmcli", &["-t", "-f", "NAME,TYPE,DEVICE,STATE", "connection", "show", "--active"]).replace('\n', " | ")
    ));
    pick_page(kind);
    let before = traffic(e, id);
    if page().is_none() {
        std::thread::sleep(Duration::from_secs(5));
        if page().is_none() {
            say(&format!("ip addr: {}", sh("ip", &["-br", "addr"]).replace('\n', " | ")));
            std::thread::sleep(PUMP_TAIL);
            panic!("no test page through the tunnel ({via}); the log:\n{}", log_text(e, id));
        }
    }
    let body = page_via(via);
    std::thread::sleep(Duration::from_millis(500));
    let after = traffic(e, id);
    say(&format!("page via {via} ({} bytes); traffic {before:?} -> {after:?}", body.len()));
    if kind != VPNKind::Strongswan || after.is_some() {
        let (b, a) = (before.expect("traffic before"), after.expect("traffic after"));
        assert!(a.0 > b.0 && a.1 > b.1, "traffic did not grow with the page: {b:?} -> {a:?}");
    }
    let live = e.liveness_of(id);
    say(&format!("liveness {live:?}"));
    if live.is_none() && kind == VPNKind::Strongswan && skip_xfrmd() {
        say("IKEv2 liveness not checked (LAB_SKIP_XFRMD: the installed linvpn-xfrmd predates its loopback fix)");
        return run;
    }
    if live.is_none() && kind == VPNKind::Strongswan {
        panic!("no IKEv2 liveness from linvpn-xfrmd; NM's active connections:\n{}", nm_addresses());
    }
    assert!(live.is_some() || kind == VPNKind::Sstp, "no liveness facts");
    run
}

// ---------------------------------------------------------------------------------------------------------------
// Task 26: OpenVPN and WireGuard

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_tun() {
    let lab = lab();
    for profile in ["openvpn-tun-dco.ovpn", "openvpn-tun-cbc.ovpn"] {
        say(&format!("== {profile} as the plain lab user, Server decides"));
        let e = engine(&format!("openvpn-tun-{}", &profile[11..14]));
        let _cleanup = Cleanup(e.clone());
        let id = Uuid::new_v4();
        let run = connect_and_check(&e, VPNKind::Openvpn, &id, &lab.file(profile), &lab.secrets(&lab.user), "openvpn");
        let iface = run.iface.clone().expect("OpenVPN's interface");
        assert!(iface.starts_with("lvo"), "LinVPN's own OpenVPN interface name: {iface}");
        assert_ne!(route_dev("1.1.1.1"), iface, "split tunnel: 1.1.1.1 must not go through the tunnel");
        assert_eq!(route_dev("10.99.0.10"), iface, "the lab's network goes through the tunnel");
        assert!(matches!(e.liveness_of(&id), Some(Liveness::Counters { .. })), "OpenVPN up: counters");
        let log = finish(&lab, &e, &id, &[]);
        assert!(
            log.contains("Connecting with NetworkManager (org.freedesktop.NetworkManager.linvpn-openvpn)"),
            "{log}"
        );
    }
}

/// A refused sign-in: one failure, classified as such, not retried (no loop of agent answers).
fn expect_refused(lab: &Lab, e: &Engine, id: &Uuid, extra: &[(&'static str, &str)]) -> String {
    let t0 = Instant::now();
    if let Ok(run) = wait_connected(e, id) {
        panic!("connected with wrong credentials: {run:?}");
    }
    assert!(wait_gone(e, id, 60), "the failed run is still there after 60 s (a retry loop?)");
    say(&format!("failed after {:.1} s", t0.elapsed().as_secs_f64()));
    let nm_uuid = names::nm_uuid(uid(), id).to_string();
    // No loop: NM does not start it again by itself.
    std::thread::sleep(Duration::from_secs(10));
    let active = sh("nmcli", &["-t", "-f", "UUID", "connection", "show", "--active"]);
    assert!(!active.lines().any(|l| l.trim() == nm_uuid), "NM activates the connection again");
    let log = settle(lab, e, id, extra);
    let lines: Vec<String> = log.lines().map(str::to_string).collect();
    let kind = failure_reason::classify(&lines);
    say(&format!("failure classified as {kind:?}; worth retrying: {}", kind.worth_retrying()));
    assert_eq!(kind, FailureKind::AuthFailed, "the app must say the sign-in was refused:\n{log}");
    assert!(!kind.worth_retrying());
    log
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_wrong_password() {
    let lab = lab();
    let e = engine("openvpn-wrong-password");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let mut secrets = lab.secrets(&lab.user);
    secrets.password = Some("not-the-lab-password-1".into());
    up(&e, VPNKind::Openvpn, &id, &lab.file("openvpn-tun-dco.ovpn"), &secrets).unwrap();
    let log = expect_refused(&lab, &e, &id, &[]);
    assert!(log.contains("AUTH_FAILED"), "the log names AUTH_FAILED:\n{log}");
}

/// MFA 1: the static challenge (SCRV1): the code asked before connecting, packed into the password as app-core does.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_static_challenge() {
    let lab = lab();
    let config = lab.file("openvpn-static-challenge.ovpn");
    let challenge = mfa::static_challenge(std::str::from_utf8(&config).unwrap()).expect("static-challenge line");
    say(&format!("static challenge: format {:?}, echo {}", challenge.format, challenge.echo));

    say("== the right code");
    let e = engine("openvpn-static");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let packed = mfa::apply_static_challenge(&challenge, &lab.code, &lab.secrets(&lab.otp_user)).unwrap();
    assert!(packed.challenge_packed);
    let packed_pw = Zeroizing::new(packed.password.clone().unwrap());
    connect_and_check(&e, VPNKind::Openvpn, &id, &config, &packed, "openvpn");
    assert!(e.read(&id).is_none(), "no dynamic challenge with the static one");
    finish(&lab, &e, &id, &[("packed password", packed_pw.as_str())]);

    say("== a wrong code");
    let e = engine("openvpn-static-wrong");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let wrong = mfa::apply_static_challenge(&challenge, lab.wrong_code(), &lab.secrets(&lab.otp_user)).unwrap();
    let wrong_pw = Zeroizing::new(wrong.password.clone().unwrap());
    up(&e, VPNKind::Openvpn, &id, &config, &wrong).unwrap();
    let log = expect_refused(&lab, &e, &id, &[("packed password", wrong_pw.as_str())]);
    assert!(log.contains("AUTH_FAILED"), "{log}");
}

/// Waits for a pending dynamic challenge (≤ 45 s); `None` when the run ended or none came.
fn wait_challenge(e: &Engine, id: &Uuid, after_seq: i64) -> Option<mfa::AuthUIState> {
    let deadline = Instant::now() + Duration::from_secs(CONNECT_SECS);
    while Instant::now() < deadline {
        if let Some(s) = e.read(id).filter(|s| s.state == AuthUIStateKind::Challenge && s.seq > after_seq) {
            return Some(s);
        }
        run_of(e, id)?;
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// MFA 2: the dynamic challenge (CRV1): the plain password connects, the server answers with a challenge, NM's
/// plugin asks the agent (hint), the app reads it (`AuthStateReader`) and responds. `L04_CRV1_DELAY` (seconds,
/// default 0) waits before the answer: the spike's measurement of how long NM keeps the request.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_crv1() {
    let lab = lab();
    let delay: u64 = std::env::var("L04_CRV1_DELAY").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let config = lab.file("openvpn-tun-dco.ovpn");

    say(&format!("== the right code after {delay} s"));
    let e = engine("openvpn-crv1");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    up(&e, VPNKind::Openvpn, &id, &config, &lab.secrets(&lab.otp_user)).unwrap();
    let t0 = Instant::now();
    let c = wait_challenge(&e, &id, -1).unwrap_or_else(|| panic!("no challenge:\n{}", log_text(&e, &id)));
    say(&format!(
        "challenge after {:.1} s: method {:?}, text {:?}, echo {:?}, deadline in {:.0} s",
        t0.elapsed().as_secs_f64(),
        c.method,
        c.text,
        c.echo,
        c.deadline.map_or(f64::NAN, |d| d - now())
    ));
    std::thread::sleep(Duration::from_secs(delay));
    let answered = Instant::now();
    e.respond(&id, AuthResponseKind::Crv1, &lab.code).unwrap_or_else(|m| panic!("respond after {delay} s: {m}"));
    let run = wait_connected(&e, &id).unwrap_or_else(|m| panic!("after the code ({delay} s wait): {m}"));
    say(&format!("connected {:.1} s after the code; iface {:?}", answered.elapsed().as_secs_f64(), run.iface));
    page_via("openvpn");
    let after = e.read(&id).map(|s| s.state);
    say(&format!("challenge state after connect: {after:?}"));
    finish(&lab, &e, &id, &[]);

    say("== a wrong code");
    let e = engine("openvpn-crv1-wrong");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    up(&e, VPNKind::Openvpn, &id, &config, &lab.secrets(&lab.otp_user)).unwrap();
    let c = wait_challenge(&e, &id, -1).unwrap_or_else(|| panic!("no challenge:\n{}", log_text(&e, &id)));
    e.respond(&id, AuthResponseKind::Crv1, lab.wrong_code()).unwrap();
    // A new challenge (the plugin asks again with the password, the server challenges again) is the app's code
    // window once more: the user decides; cancel it as the window's Cancel does.
    let rechallenged = wait_challenge(&e, &id, c.seq);
    if let Some(next) = &rechallenged {
        say(&format!("challenge again after the wrong code (seq {} -> {}): cancelled", c.seq, next.seq));
        e.respond(&id, AuthResponseKind::Cancel, "").unwrap();
        assert!(wait_challenge(&e, &id, next.seq).is_none(), "a loop of challenges after Cancel");
    }
    let rechallenges = usize::from(rechallenged.is_some());
    say(&format!("re-challenges after the wrong code: {rechallenges}"));
    expect_refused(&lab, &e, &id, &[]);
}

/// MFA 3: "code appended to the password" (the connection's OTP setting, separator ","), as app-core's
/// `apply_code` builds it; then a wrong appended code.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_append_code() {
    let lab = lab();
    let config = lab.file("openvpn-tun-dco.ovpn");
    for sep in [OTPSeparator::Comma, OTPSeparator::None, OTPSeparator::Colon] {
        say(&format!("== the right code, separator {}", sep.raw_value()));
        let e = engine(&format!("openvpn-append-{}", sep.raw_value()));
        let _cleanup = Cleanup(e.clone());
        let id = Uuid::new_v4();
        let s = mfa::apply_code(&lab.code, sep, &lab.secrets(&lab.otp_user), VPNKind::Openvpn).unwrap();
        let combined = Zeroizing::new(s.password.clone().unwrap());
        connect_and_check(&e, VPNKind::Openvpn, &id, &config, &s, "openvpn");
        assert!(e.read(&id).is_none(), "no dynamic challenge with the appended code");
        finish(&lab, &e, &id, &[("combined password", combined.as_str())]);
    }
    say("== a wrong appended code");
    let e = engine("openvpn-append-wrong");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let s =
        mfa::apply_code(lab.wrong_code(), OTPSeparator::Comma, &lab.secrets(&lab.otp_user), VPNKind::Openvpn).unwrap();
    let combined = Zeroizing::new(s.password.clone().unwrap());
    up(&e, VPNKind::Openvpn, &id, &config, &s).unwrap();
    // The server does not know "password,wrong": AUTH_FAILED without a challenge.
    expect_refused(&lab, &e, &id, &[("combined password", combined.as_str())]);
}

/// `labfull`, Server decides: the pushed `redirect-gateway def1` takes the default route (decision 8).
#[test]
#[ignore = "lab: the VM's desktop session, the lab up (cuts the VM's internet while connected)"]
fn lab_openvpn_pushed_full_tunnel() {
    let lab = lab();
    let e = engine("openvpn-full");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let run = connect_and_check(
        &e,
        VPNKind::Openvpn,
        &id,
        &lab.file("openvpn-tun-dco.ovpn"),
        &lab.secrets("labfull"),
        "openvpn",
    );
    let iface = run.iface.clone().unwrap();
    let dev = route_dev("1.1.1.1");
    say(&format!("1.1.1.1 goes through {dev}"));
    let log = finish(&lab, &e, &id, &[]);
    assert_eq!(dev, iface, "Server decides with a pushed redirect-gateway: everything through the tunnel\n{log}");
}

/// `labfull` with the config set to Never (`pull-filter ignore "redirect-gateway"`): the push is ignored.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_never_ignores_the_push() {
    let lab = lab();
    let e = engine("openvpn-never");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let mut config = lab.file("openvpn-tun-dco.ovpn");
    config.extend_from_slice(b"pull-filter ignore \"redirect-gateway\"\n");
    let run = connect_and_check(&e, VPNKind::Openvpn, &id, &config, &lab.secrets("labfull"), "openvpn");
    let dev = route_dev("1.1.1.1");
    say(&format!("1.1.1.1 goes through {dev}"));
    finish(&lab, &e, &id, &[]);
    assert_ne!(Some(dev), run.iface, "Never: the default route stays");
}

/// A client certificate and key without a password inline: no key password is asked (none given), it connects.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_openvpn_key_without_password() {
    let lab = lab();
    let cert = String::from_utf8(lab.file("swanctl/x509/lab-client.pem")).unwrap();
    let key = Zeroizing::new(String::from_utf8(lab.file("swanctl/private/lab-client.key")).unwrap());
    assert!(!key.contains("ENCRYPTED"), "the lab's client key is expected without a password");
    let mut config = String::from_utf8(lab.file("openvpn-tun-dco.ovpn")).unwrap();
    config.push_str(&format!("<cert>\n{}</cert>\n<key>\n{}</key>\n", cert, key.as_str()));
    let e = engine("openvpn-key-no-password");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let secrets = lab.secrets(&lab.user);
    assert!(secrets.key_password.is_none());
    connect_and_check(&e, VPNKind::Openvpn, &id, config.as_bytes(), &secrets, "openvpn");
    let log = finish(&lab, &e, &id, &[]);
    // The key has no password: NM is told none is needed (no agent request, no prompt).
    assert!(log.contains("vpn.data cert-pass-flags = 4"), "{log}");
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_wireguard() {
    let lab = lab();
    let e = engine("wireguard");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let run = connect_and_check(
        &e,
        VPNKind::Wireguard,
        &id,
        &lab.file("wireguard-linux.conf"),
        &Secrets::default(),
        "wireguard",
    );
    let iface = run.iface.clone().unwrap();
    assert_eq!(route_dev("10.99.0.10"), iface);
    assert_ne!(route_dev("1.1.1.1"), iface);
    match e.liveness_of(&id) {
        Some(Liveness::Counters { keepalive, .. }) => assert_eq!(keepalive, 25),
        other => panic!("WireGuard liveness: {other:?}"),
    }
    finish(&lab, &e, &id, &[]);
}

/// Stopped outside LinVPN (`nmcli connection down`, as GNOME's menu): the run ends as the user's stop, which
/// app-core shows as off and does not reconnect.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_external_disconnect() {
    let lab = lab();
    for (kind, file, via) in [
        (VPNKind::Wireguard, "wireguard-linux.conf", "wireguard"),
        (VPNKind::Openvpn, "openvpn-tun-dco.ovpn", "openvpn"),
    ] {
        say(&format!("== {kind:?}"));
        let e = engine(&format!("external-down-{}", kind.raw_value()));
        let _cleanup = Cleanup(e.clone());
        let id = Uuid::new_v4();
        connect_and_check(&e, kind, &id, &lab.file(file), &lab.secrets(&lab.user), via);
        let nm_uuid = names::nm_uuid(uid(), &id).to_string();
        say(&sh("nmcli", &["connection", "down", &nm_uuid]));
        assert!(wait_gone(&e, &id, 15), "the run is still there after nmcli down");
        let lines = log_lines(&e, &id);
        let kind_seen = failure_reason::classify(&lines);
        say(&format!("after nmcli down: {kind_seen:?}, stopped by user: {}", failure_reason::stopped_by_user(&lines)));
        settle(&lab, &e, &id, &[]);
        assert!(!nm_has(&nm_uuid), "the volatile profile is gone");
        assert_eq!(kind_seen, FailureKind::StoppedByUser, "{kind:?}: an outside stop must not be reconnected");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Task 27: L2TP, IKEv2, Cisco IPsec, SSTP, DNS

fn native(lab: &Lab, kind: VPNKind) -> Connection {
    let mut c = Connection::new(format!("Lab {}", kind.display_name()), kind);
    c.native = Some(NativeSettings {
        server: lab.server.clone(),
        account: lab.user.clone(),
        group_name: if kind == VPNKind::Cisco { lab.group.clone() } else { String::new() },
        send_all_traffic: false,
    });
    c
}

/// A managed native connection: Save (`build` + `install`), `start`, checks, `stop`; with `user`/`secrets` given.
fn native_case(lab: &Lab, e: &Engine, kind: VPNKind, secrets: &Secrets, via: &str) {
    let mut c = native(lab, kind);
    if let Some(u) = secrets.username.as_deref() {
        c.native.as_mut().unwrap().account = u.to_string();
    }
    let profile = e.build(&c, &lab.psk).unwrap();
    e.install(&c.id, &profile.data, &profile.file_name, false).unwrap();
    let service = e.managed_service_id(&c.id).unwrap();
    assert!(NativeController::list(e).unwrap().iter().any(|v| v.id == service), "the list names {service}");
    let t0 = Instant::now();
    e.start(&service, None, secrets).unwrap_or_else(|m| panic!("start: {m}"));
    let run = wait_connected(e, &c.id).unwrap_or_else(|m| panic!("{m}"));
    say(&format!("connected in {:.1} s, iface {:?}", t0.elapsed().as_secs_f64(), run.iface));
    let listed = NativeController::list(e).unwrap().into_iter().find(|v| v.id == service).unwrap();
    say(&format!("listed status {:?}", listed.status));
    pick_page(kind);
    let before = NativeController::traffic(e, &service).map(|t| (t.rx, t.tx));
    page_via(via);
    let after = NativeController::traffic(e, &service).map(|t| (t.rx, t.tx));
    say(&format!("traffic {before:?} -> {after:?}; address {:?}", NativeController::address(e, &service).is_some()));
    let (b, a) = (before.expect("traffic"), after.expect("traffic"));
    assert!(a.0 > b.0, "traffic grew");
    let tun =
        run.iface.clone().or_else(|| NativeController::address(e, &service).map(|_| String::new())).unwrap_or_default();
    say(&format!("1.1.1.1 via {} (tunnel {tun:?})", route_dev("1.1.1.1")));
    assert_eq!(route_dev("1.1.1.1"), route_dev("192.0.2.1"), "split: the default route stays");
    let combined = secrets.password.clone().unwrap_or_default();
    e.stop(&service).unwrap();
    let nm_uuid = names::nm_uuid(uid(), &c.id).to_string();
    assert!(wait_gone(e, &c.id, 20));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!nm_has(&nm_uuid), "the volatile profile is gone");
    settle(lab, e, &c.id, &[("combined password", combined.as_str())]);
    e.remove(&c.id);
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_l2tp() {
    let lab = lab();
    let e = engine("l2tp");
    let _cleanup = Cleanup(e.clone());
    say("== L2TP/IPsec, PSK + password");
    native_case(&lab, &e, VPNKind::L2tp, &lab.secrets(&lab.user), "ipsec");
    say("== L2TP/IPsec, the one-time-code user with the code appended");
    let s = mfa::apply_code(&lab.code, OTPSeparator::Comma, &lab.secrets(&lab.otp_user), VPNKind::L2tp).unwrap();
    native_case(&lab, &e, VPNKind::L2tp, &s, "ipsec");
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_cisco() {
    let lab = lab();
    let e = engine("cisco");
    let _cleanup = Cleanup(e.clone());
    say("== Cisco IPsec (vpnc), group + PSK + XAuth password");
    native_case(&lab, &e, VPNKind::Cisco, &lab.secrets(&lab.user), "ipsec");
    say("== Cisco IPsec, the one-time-code user with the code appended");
    let s = mfa::apply_code(&lab.code, OTPSeparator::Comma, &lab.secrets(&lab.otp_user), VPNKind::Cisco).unwrap();
    native_case(&lab, &e, VPNKind::Cisco, &s, "ipsec");
}

/// `LAB_SKIP_XFRMD=1`: the IKEv2 counter checks are skipped (an installed `linvpn-xfrmd` older than its loopback
/// fix answers `N` for every IKEv2 connection).
fn skip_xfrmd() -> bool {
    std::env::var_os("LAB_SKIP_XFRMD").is_some()
}

/// IKEv2 traffic comes from `linvpn-xfrmd` (the SAs' counters): it must grow at least by what the pages carried.
fn ikev2_case(lab: &Lab, e: &Engine, config: &[u8], secrets: &Secrets) {
    let id = Uuid::new_v4();
    connect_and_check(e, VPNKind::Strongswan, &id, config, secrets, "ipsec");
    let xfrm_if = sh("ip", &["-o", "link", "show"]).lines().find_map(|l| {
        l.split(": ").nth(1).filter(|n| n.starts_with("nm-xfrm")).map(|n| n.split('@').next().unwrap().to_string())
    });
    let sysfs = |n: &str| {
        let r = |f: &str| {
            std::fs::read_to_string(format!("/sys/class/net/{n}/statistics/{f}")).ok()?.trim().parse::<u64>().ok()
        };
        Some((r("rx_bytes")?, r("tx_bytes")?))
    };
    if let Some(n) = &xfrm_if {
        let b = sysfs(n);
        let _ = page();
        say(&format!("charon-nm's XFRM interface {n}: sysfs counters {b:?} -> {:?} with one page", sysfs(n)));
    } else {
        say("no nm-xfrm interface");
    }
    if skip_xfrmd() && traffic(e, &id).is_none() {
        let combined = secrets.password.clone().unwrap_or_default();
        finish(lab, e, &id, &[("combined password", combined.as_str())]);
        return;
    }
    let Some(before) = traffic(e, &id) else {
        panic!("no IKEv2 traffic from linvpn-xfrmd; NM's active connections:\n{}", nm_addresses());
    };
    let mut body_bytes = 0;
    for _ in 0..20 {
        body_bytes += page().expect("page").len();
    }
    std::thread::sleep(Duration::from_millis(500));
    let after = traffic(e, &id).unwrap();
    let rx = after.0 - before.0;
    say(&format!("20 pages: {body_bytes} body bytes; IKEv2 rx grew {rx}, tx grew {}", after.1 - before.1));
    assert!(rx as usize >= body_bytes && (rx as usize) < body_bytes * 40, "rx {rx} vs body {body_bytes}");
    assert!(matches!(e.liveness_of(&id), Some(Liveness::Counters { keepalive: 0, .. })));
    let combined = secrets.password.clone().unwrap_or_default();
    let key_password = secrets.key_password.clone().unwrap_or_default();
    finish(lab, e, &id, &[("combined password", combined.as_str()), ("key password", key_password.as_str())]);
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_ikev2_eap() {
    let lab = lab();
    let e = engine("ikev2-eap");
    let _cleanup = Cleanup(e.clone());
    // The server's certificate is checked against the lab CA in LinVPN's swanctl folder (resolved point 18).
    std::fs::create_dir_all(e.data.join("swanctl/x509ca")).unwrap();
    std::fs::copy(lab.dir.join("swanctl/x509ca/lab-ca.pem"), e.data.join("swanctl/x509ca/lab-ca.pem")).unwrap();
    say("== IKEv2 EAP-MSCHAPv2");
    ikev2_case(&lab, &e, &lab.file("ikev2-eap.swanctl.conf"), &lab.secrets(&lab.user));
    say("== IKEv2 EAP, the one-time-code user with the code appended");
    let s = mfa::apply_code(&lab.code, OTPSeparator::Comma, &lab.secrets(&lab.otp_user), VPNKind::Strongswan).unwrap();
    let config = String::from_utf8(lab.file("ikev2-eap.swanctl.conf")).unwrap();
    let config = config.replace(&format!("eap_id = {}", lab.user), &format!("eap_id = {}", lab.otp_user));
    ikev2_case(&lab, &e, config.as_bytes(), &s);
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_ikev2_psk() {
    let lab = lab();
    let e = engine("ikev2-psk");
    let _cleanup = Cleanup(e.clone());
    ikev2_case(&lab, &e, &lab.file("ikev2-psk.swanctl.conf"), &lab.secrets(&lab.user));
}

fn copy_swanctl(lab: &Lab, e: &Engine) {
    for sub in ["x509ca", "x509", "private"] {
        let to = e.data.join("swanctl").join(sub);
        std::fs::create_dir_all(&to).unwrap();
        for f in std::fs::read_dir(lab.dir.join("swanctl").join(sub)).unwrap().flatten() {
            std::fs::copy(f.path(), to.join(f.file_name())).unwrap();
        }
    }
    sh("chmod", &["-R", "go-rwx", e.data.join("swanctl").to_str().unwrap()]);
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_ikev2_cert() {
    let lab = lab();
    // A config without `certs` uses the certificate imported in the app (resolved point 18, G4); with `certs` the
    // swanctl folder's file wins.
    let without_certs =
        String::from_utf8(lab.file("ikev2-cert.swanctl.conf")).unwrap().replace("certs = lab-client.pem", "");
    let without_certs = without_certs.into_bytes();
    say("== the client certificate imported in the app (PEM certificate + key)");
    let e = engine("ikev2-cert-pem");
    let _cleanup = Cleanup(e.clone());
    // Only the CA in the folder: the certificate comes from the vault.
    std::fs::create_dir_all(e.data.join("swanctl/x509ca")).unwrap();
    std::fs::copy(lab.dir.join("swanctl/x509ca/lab-ca.pem"), e.data.join("swanctl/x509ca/lab-ca.pem")).unwrap();
    let cert = lab.file("swanctl/x509/lab-client.pem");
    let key = Zeroizing::new(lab.file("swanctl/private/lab-client.key"));
    let imported = client_cert::import(&[&cert, &key]).unwrap();
    let mut s = lab.secrets(&lab.user);
    s.client_cert = Some(imported.cert.stored().to_string());
    ikev2_case(&lab, &e, &without_certs, &s);

    say("== a PKCS#12 file imported in the app (converted with openssl at connect)");
    let e = engine("ikev2-cert-p12");
    let _cleanup = Cleanup(e.clone());
    let work = e.data.join("p12");
    std::fs::create_dir_all(&work).unwrap();
    sh("chmod", &["700", work.to_str().unwrap()]);
    let p12_password = Zeroizing::new(format!("p12-{}", Uuid::new_v4().simple()));
    std::fs::write(work.join("pass"), p12_password.as_bytes()).unwrap();
    let out = sh(
        "openssl",
        &[
            "pkcs12",
            "-export",
            "-in",
            lab.dir.join("swanctl/x509/lab-client.pem").to_str().unwrap(),
            "-inkey",
            lab.dir.join("swanctl/private/lab-client.key").to_str().unwrap(),
            "-passout",
            &format!("file:{}", work.join("pass").display()),
            "-out",
            work.join("client.p12").to_str().unwrap(),
        ],
    );
    let p12 = std::fs::read(work.join("client.p12")).unwrap_or_else(|_| panic!("openssl pkcs12: {out}"));
    std::fs::remove_dir_all(&work).unwrap();
    let imported = client_cert::import(&[&p12]).unwrap();
    assert!(imported.cert.needs_password());
    let mut s = lab.secrets(&lab.user);
    s.client_cert = Some(imported.cert.stored().to_string());
    s.key_password = Some(p12_password.to_string());
    ikev2_case(&lab, &e, &without_certs, &s);
    say("== the PKCS#12 file with a wrong password: refused before NM");
    s.key_password = Some("wrong-p12-password".into());
    let err = up(&e, VPNKind::Strongswan, &Uuid::new_v4(), &without_certs, &s).unwrap_err();
    say(&format!("refused: {err}"));
    assert!(!err.contains(p12_password.as_str()));
    say("== the swanctl folder (certs = lab-client.pem)");
    let e = engine("ikev2-cert-folder");
    let _cleanup = Cleanup(e.clone());
    copy_swanctl(&lab, &e);
    ikev2_case(&lab, &e, &lab.file("ikev2-cert.swanctl.conf"), &lab.secrets(&lab.user));
    let _ = std::fs::remove_dir_all(e.data.join("swanctl"));
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_sstp() {
    let lab = lab();
    for file in ["sstp-ca.sstp", "sstp-ca-alt-port.sstp", "sstp-no-verification.sstp"] {
        say(&format!("== {file}"));
        let e = engine(&format!("sstp-{}", file.trim_end_matches(".sstp")));
        let _cleanup = Cleanup(e.clone());
        let id = Uuid::new_v4();
        connect_and_check(&e, VPNKind::Sstp, &id, &lab.file(file), &lab.secrets(&lab.user), "sstp");
        finish(&lab, &e, &id, &[]);
    }
    say("== sstp-system-ca.sstp (the lab CA is not in the system store: a certificate error)");
    let e = engine("sstp-system-ca");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    up(&e, VPNKind::Sstp, &id, &lab.file("sstp-system-ca.sstp"), &lab.secrets(&lab.user)).unwrap();
    assert!(wait_connected(&e, &id).is_err(), "connected without trusting the lab CA");
    assert!(wait_gone(&e, &id, 60));
    let log = settle(&lab, &e, &id, &[]);
    say(&format!("classified as {:?}", failure_reason::classify(&log.lines().map(str::to_string).collect::<Vec<_>>())));
}

/// `resolvectl` for the tunnel's link.
fn link_dns(iface: &str) -> String {
    sh("resolvectl", &["status", iface])
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up (cuts the VM's internet while labfull is connected)"]
fn lab_dns_split_and_full() {
    let lab = lab();
    say("== split (plain user, Server decides)");
    let e = engine("dns-split");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let run = connect_and_check(
        &e,
        VPNKind::Openvpn,
        &id,
        &lab.file("openvpn-tun-dco.ovpn"),
        &lab.secrets(&lab.user),
        "openvpn",
    );
    let iface = run.iface.clone().unwrap();
    let status = link_dns(&iface);
    let q = sh("resolvectl", &["query", "whoami.lab.test"]);
    let ex = sh("resolvectl", &["query", "--cache=no", "example.com"]);
    println!("{status}\n{q}\n{ex}");
    finish(&lab, &e, &id, &[]);
    assert!(q.contains("10.99.0.10") && q.contains(&iface), "whoami.lab.test through the tunnel's link: {q}");
    assert!(status.contains("-DefaultRoute"), "split: no default DNS route on the tunnel link: {status}");
    assert!(!ex.contains(&format!("-- link: {iface}")), "example.com must not use the tunnel's DNS: {ex}");

    say("== full (labfull, Server decides)");
    let e = engine("dns-full");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let run = connect_and_check(
        &e,
        VPNKind::Openvpn,
        &id,
        &lab.file("openvpn-tun-dco.ovpn"),
        &lab.secrets("labfull"),
        "openvpn",
    );
    let iface = run.iface.clone().unwrap();
    let status = link_dns(&iface);
    let q = sh("resolvectl", &["query", "whoami.lab.test"]);
    println!("{status}\n{q}");
    finish(&lab, &e, &id, &[]);
    assert!(q.contains("10.99.0.10"), "{q}");
    assert!(status.contains("+DefaultRoute"), "full: the default DNS route on the tunnel link: {status}");
}

// ---------------------------------------------------------------------------------------------------------------
// Task 28: liveness, logs

fn signal(name: &str) {
    let dir = std::env::var_os("LINVPN_LAB_SIGNAL")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("../../.linvpn-put/signal"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), b"").unwrap();
    say(&format!("asked the maintainer's watcher: {name}"));
    let deadline = Instant::now() + Duration::from_secs(60);
    while dir.join(name).exists() {
        assert!(Instant::now() < deadline, "the maintainer's root watcher did not take `{name}` within 60 s");
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// WireGuard up and used; the lab's WireGuard container stopped (the maintainer's watcher): the counter rule
/// (`COUNTER_SILENCE`) must call it dead within ≈ 230 s, as the app's monitor does; the container is started again.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up, the maintainer's root watcher running"]
fn lab_liveness_dead_peer() {
    let lab = lab();
    let e = engine("liveness-wireguard");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    connect_and_check(&e, VPNKind::Wireguard, &id, &lab.file("wireguard-linux.conf"), &Secrets::default(), "wireguard");
    let mut monitor = Monitor::default();
    let key = id.to_string();
    for _ in 0..3 {
        let _ = page();
        let h = monitor.observe(&key, now(), &e.liveness_of(&id).unwrap());
        assert!(matches!(h, Health::Alive { .. }), "alive before the stop: {h:?}");
        std::thread::sleep(Duration::from_secs(10));
    }
    signal("stop-wireguard");
    let stopped = Instant::now();
    let mut dead_after = None;
    while stopped.elapsed() < Duration::from_secs(320) {
        let _ = page();
        let facts = e.liveness_of(&id).unwrap();
        let h = monitor.observe(&key, now(), &facts);
        say(&format!("{:>4.0} s after the stop: {facts:?} -> {h:?}", stopped.elapsed().as_secs_f64()));
        if h == Health::Dead {
            dead_after = Some(stopped.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    signal("start-wireguard");
    finish(&lab, &e, &id, &[]);
    let dead_after = dead_after.expect("never dead within 320 s of the stop");
    say(&format!("dead {:.0} s after the stop", dead_after.as_secs_f64()));
    assert!(dead_after <= Duration::from_secs(240));
}

/// OpenVPN up; the lab's OpenVPN container restarted (the maintainer's watcher): what NM's VPN state and the
/// liveness facts show, and whether the tunnel carries traffic again by itself (for Task 29's note).
#[test]
#[ignore = "lab: the VM's desktop session, the lab up, the maintainer's root watcher running"]
fn lab_openvpn_server_restart() {
    let lab = lab();
    let e = engine("openvpn-server-restart");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    connect_and_check(&e, VPNKind::Openvpn, &id, &lab.file("openvpn-tun-dco.ovpn"), &lab.secrets(&lab.user), "openvpn");
    let mut monitor = Monitor::default();
    let key = id.to_string();
    signal("restart-openvpn");
    let t0 = Instant::now();
    let mut back = None;
    let mut seen_reconnecting = false;
    while t0.elapsed() < Duration::from_secs(300) {
        let ok = page().is_some_and(|b| b.contains("via: openvpn"));
        let run = run_of(&e, &id);
        let facts = e.liveness_of(&id);
        let h = facts.as_ref().map(|f| monitor.observe(&key, now(), f));
        seen_reconnecting |= matches!(facts, Some(Liveness::OpenVpn { reconnecting_since: Some(_) }));
        say(&format!(
            "{:>4.0} s: page {ok}, run {:?}, facts {facts:?} -> {h:?}",
            t0.elapsed().as_secs_f64(),
            run.as_ref().map(|r| r.state)
        ));
        if run.is_none() {
            break;
        }
        if ok && t0.elapsed() > Duration::from_secs(5) {
            back = Some(t0.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    say(&format!("traffic again after {back:?}; Liveness::OpenVpn reconnecting seen: {seen_reconnecting}"));
    if run_of(&e, &id).is_some() {
        finish(&lab, &e, &id, &[]);
    } else {
        settle(&lab, &e, &id, &[]);
    }
}

#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_logd_lines() {
    let lab = lab();
    for (kind, file, via) in
        [(VPNKind::Sstp, "sstp-ca.sstp", "sstp"), (VPNKind::Openvpn, "openvpn-tun-dco.ovpn", "openvpn")]
    {
        say(&format!("== {kind:?}"));
        logd_case(&lab, kind, file, via);
    }
}

fn logd_case(lab: &Lab, kind: VPNKind, file: &str, via: &str) {
    let e = engine(&format!("logd-{}", kind.raw_value()));
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    let since_usec = (now() * 1e6) as u64;
    connect_and_check(&e, kind, &id, &lab.file(file), &lab.secrets(&lab.user), via);
    std::thread::sleep(Duration::from_secs(3));
    let resp = logd_client::query(&Request { connection: id, since_usec, cursor: None }).expect("linvpn-logd answers");
    let nm_uuid = names::nm_uuid(uid(), &id).to_string();
    let nm_lines = resp.lines.iter().filter(|l| l.text.contains(&nm_uuid)).count();
    let own = |l: &&macvpn_core::logd::Line| l.source != macvpn_core::logd::Source::NetworkManager;
    let plugin_lines = resp.lines.iter().filter(own).count();
    say(&format!(
        "logd: {} lines ({nm_lines} naming the NM UUID, {plugin_lines} plugin/OpenVPN), withheld {}",
        resp.lines.len(),
        resp.withheld
    ));
    for l in resp.lines.iter().take(40) {
        println!("  {:?} {}", l.source, l.text);
    }
    assert!(nm_lines > 0 && plugin_lines > 0, "NetworkManager and the plugin's lines of our connection");
    let other = logd_client::query(&Request { connection: Uuid::new_v4(), since_usec, cursor: None }).unwrap();
    assert!(other.lines.is_empty(), "another connection id gets nothing");

    std::thread::sleep(Duration::from_secs(2));
    let file = log_text(&e, &id);
    let copied = file.lines().filter(|l| l.contains(" [")).count();
    say(&format!("the Log tab's file: {} lines, {copied} journal copies", file.lines().count()));
    assert!(copied > 0, "the pump copied journal lines:\n{file}");
    HelperClient::clear_log(&*e, &id, "Log cleared").unwrap();
    let cleared = log_text(&e, &id);
    say(&format!("after Clear Log…: {} lines", cleared.lines().count()));
    let again = logd_client::query(&Request { connection: id, since_usec, cursor: None }).unwrap();
    assert!(again.lines.len() >= resp.lines.len(), "the journal keeps them (the clear is LinVPN's copy only)");
    finish(lab, &e, &id, &[]);
}

// ---------------------------------------------------------------------------------------------------------------
// System VPNs (CP-system-vpn, created here: GNOME's dialog would not save it)

type DbusSettings = std::collections::HashMap<String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>>;

fn ov<'a>(v: impl Into<zbus::zvariant::Value<'a>>) -> zbus::zvariant::OwnedValue {
    zbus::zvariant::OwnedValue::try_from(v.into()).unwrap()
}

/// A user-owned NM WireGuard profile from the lab's `wireguard-linux.conf` (in memory only, autoconnect off,
/// `permissions = ["user:<me>"]`): what GNOME Settings makes for a user, without its keyring.
fn system_wireguard_settings(lab: &Lab, uuid: &str) -> DbusSettings {
    use std::collections::HashMap;
    let conf = Zeroizing::new(String::from_utf8(lab.file("wireguard-linux.conf")).unwrap());
    let get = |k: &str| {
        conf.lines()
            .find_map(|l| l.split_once('=').filter(|(a, _)| a.trim() == k).map(|(_, v)| v.trim().to_string()))
            .unwrap_or_else(|| panic!("wireguard-linux.conf: {k}"))
    };
    let user = std::env::var("USER").unwrap();
    let (addr, prefix) =
        get("Address").split_once('/').map(|(a, p)| (a.to_string(), p.parse::<u32>().unwrap())).unwrap();
    let allowed: Vec<String> = get("AllowedIPs").split(',').map(|s| s.trim().to_string()).collect();
    let mut peer: HashMap<String, zbus::zvariant::OwnedValue> = HashMap::new();
    peer.insert("public-key".into(), ov(get("PublicKey")));
    peer.insert("endpoint".into(), ov(get("Endpoint")));
    peer.insert("allowed-ips".into(), ov(allowed));
    peer.insert("persistent-keepalive".into(), ov(get("PersistentKeepalive").parse::<u32>().unwrap()));
    peer.insert("preshared-key".into(), ov(get("PresharedKey")));
    peer.insert("preshared-key-flags".into(), ov(0u32));
    let mut address: HashMap<String, zbus::zvariant::OwnedValue> = HashMap::new();
    address.insert("address".into(), ov(addr));
    address.insert("prefix".into(), ov(prefix));
    let mut s: DbusSettings = HashMap::new();
    s.entry("connection".into()).or_default().extend([
        ("id".to_string(), ov("Lab WG (system)")),
        ("uuid".to_string(), ov(uuid.to_string())),
        ("type".to_string(), ov("wireguard")),
        ("interface-name".to_string(), ov("wg-labsys")),
        ("autoconnect".to_string(), ov(false)),
        ("permissions".to_string(), ov(vec![format!("user:{user}:")])),
    ]);
    s.entry("wireguard".into()).or_default().extend([
        ("private-key".to_string(), ov(get("PrivateKey"))),
        ("private-key-flags".to_string(), ov(0u32)),
        ("peers".to_string(), ov(vec![peer])),
    ]);
    s.entry("ipv4".into())
        .or_default()
        .extend([("method".to_string(), ov("manual")), ("address-data".to_string(), ov(vec![address]))]);
    s.entry("ipv6".into()).or_default().insert("method".into(), ov("disabled"));
    s
}

/// The user's own NM WireGuard profile is a system VPN: listed read-only with its type, started and stopped through
/// `NativeController` (page, traffic), never edited or deleted by LinVPN; the test removes the profile afterwards.
#[test]
#[ignore = "lab: the VM's desktop session, the lab up"]
fn lab_system_vpn() {
    let lab = lab();
    let e = engine("system-vpn");
    let _cleanup = Cleanup(e.clone());
    let bus = zbus::blocking::Connection::system().unwrap();
    let uuid = Uuid::new_v4().to_string();
    let settings = system_wireguard_settings(&lab, &uuid);
    let args: std::collections::HashMap<String, zbus::zvariant::OwnedValue> = std::collections::HashMap::new();
    // AddConnection2, flags 0x2: in memory only (never on disk); no interactive authorization.
    let reply = bus
        .call_method(
            Some("org.freedesktop.NetworkManager"),
            "/org/freedesktop/NetworkManager/Settings",
            Some("org.freedesktop.NetworkManager.Settings"),
            "AddConnection2",
            &(settings, 0x2u32, args),
        )
        .expect("AddConnection2");
    let (path, _): (zbus::zvariant::OwnedObjectPath, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) =
        reply.body().deserialize().unwrap();
    let remove = || {
        let _ = bus.call_method(
            Some("org.freedesktop.NetworkManager"),
            path.as_str(),
            Some("org.freedesktop.NetworkManager.Settings.Connection"),
            "Delete",
            &(),
        );
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let listed = NativeController::list(&*e).unwrap();
        let mine = listed.iter().find(|v| v.id == uuid).cloned();
        say(&format!("listed: {mine:?}"));
        let mine = mine.expect("the user's WireGuard profile is listed as a system VPN");
        assert_eq!(mine.type_label, "WireGuard (app)");
        assert_eq!(mine.status, "Disconnected");
        assert!(e.managed_service_id(&Uuid::parse_str(&uuid).unwrap()) != Some(uuid.clone()));
        let t0 = Instant::now();
        e.start(&uuid, None, &Secrets::default()).unwrap_or_else(|m| panic!("start: {m}"));
        let deadline = Instant::now() + Duration::from_secs(CONNECT_SECS);
        loop {
            let s = NativeController::list(&*e).unwrap().into_iter().find(|v| v.id == uuid).unwrap().status;
            if s == "Connected" {
                break;
            }
            assert!(Instant::now() < deadline, "not connected: {s}");
            std::thread::sleep(Duration::from_millis(250));
        }
        say(&format!(
            "connected in {:.1} s; address {}",
            t0.elapsed().as_secs_f64(),
            NativeController::address(&*e, &uuid).is_some()
        ));
        let before = NativeController::traffic(&*e, &uuid).map(|t| (t.rx, t.tx));
        page_via("wireguard");
        let after = NativeController::traffic(&*e, &uuid).map(|t| (t.rx, t.tx));
        say(&format!("traffic {before:?} -> {after:?}"));
        assert!(after.unwrap().0 > before.unwrap().0);
        e.stop(&uuid).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        let s = NativeController::list(&*e).unwrap().into_iter().find(|v| v.id == uuid).unwrap().status;
        assert_eq!(s, "Disconnected");
        assert!(nm_has(&uuid), "LinVPN never deletes a system VPN");
    }));
    remove();
    assert!(!nm_has(&uuid), "the test's profile is removed");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

/// The class-based route of a split PPP tunnel (lb-fix2's NM dispatcher script): the class network on the PPP
/// interface (metric 50) and the server's /32 through the physical interface while connected, both gone after the
/// disconnect; none with "Send all traffic" (`route_all=yes`).
#[test]
#[ignore = "lab: the VM's desktop session, the lab up (cuts the VM's internet while route_all=yes is connected)"]
fn lab_sstp_classful_route() {
    let lab = lab();
    let script = sh("stat", &["-c", "%U:%G %a", "/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route"]);
    say(&format!("dispatcher script: {}", script.trim()));
    assert_eq!(script.trim(), "root:root 755");
    let routes = || sh("ip", &["-4", "route", "show"]);
    let server = lab.server.clone();

    say("== split (route_all=no)");
    let e = engine("sstp-classful");
    let _cleanup = Cleanup(e.clone());
    let id = Uuid::new_v4();
    up(&e, VPNKind::Sstp, &id, &lab.file("sstp-ca.sstp"), &lab.secrets(&lab.user)).unwrap();
    wait_connected(&e, &id).unwrap_or_else(|m| panic!("{m}"));
    std::thread::sleep(Duration::from_secs(3));
    let r = routes();
    let class: Vec<&str> = r.lines().filter(|l| l.starts_with("10.0.0.0/8") && l.contains("ppp")).collect();
    let host: Vec<&str> = r.lines().filter(|l| l.starts_with(&format!("{server} ")) && !l.contains("ppp")).collect();
    say(&format!("class route: {class:?}; server route: {}", host.len()));
    // The script keeps the default gateway reachable: no class route when the gateway is inside the class network
    // (the lab's 10.99.x.x addresses are class A, 10.0.0.0/8).
    let gw = sh("ip", &["-4", "route", "show", "default"]);
    let gw_in_class = gw.split_whitespace().skip_while(|w| *w != "via").nth(1).is_some_and(|g| g.starts_with("10."));
    if gw_in_class {
        say("the default gateway is inside 10.0.0.0/8 on this machine: the script must add no class route");
        assert!(class.is_empty(), "a class route that would hide the default gateway:\n{r}");
    } else {
        assert!(class.iter().any(|l| l.contains("metric 50")), "the class network on pppN, metric 50:\n{r}");
        assert!(!host.is_empty(), "the server's /32 through the physical interface:\n{r}");
        let services = page_via("sstp");
        say(&format!("the services network answers through the tunnel ({} bytes)", services.len()));
    }
    finish(&lab, &e, &id, &[]);
    std::thread::sleep(Duration::from_secs(2));
    let r = routes();
    assert!(!r.lines().any(|l| l.starts_with("10.0.0.0/8")), "the class route is gone after the disconnect:\n{r}");

    say("== Always (route_all=yes)");
    let id = Uuid::new_v4();
    let config = String::from_utf8(lab.file("sstp-ca.sstp")).unwrap().replace("route_all=no", "route_all=yes");
    up(&e, VPNKind::Sstp, &id, config.as_bytes(), &lab.secrets(&lab.user)).unwrap();
    wait_connected(&e, &id).unwrap_or_else(|m| panic!("{m}"));
    std::thread::sleep(Duration::from_secs(3));
    let r = routes();
    finish(&lab, &e, &id, &[]);
    assert!(!r.lines().any(|l| l.starts_with("10.0.0.0/8")), "no class route with Always:\n{r}");
}
