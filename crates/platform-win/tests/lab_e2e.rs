//! The VPN lab end to end on Windows (WinVPN 2.1.0): as the standard user, through the **installed** WinVPN Service
//! (OpenVPN, WireGuard) and the real RAS (L2TP, IKEv2, SSTP) with the app's own `HelperClient` (`RasHelper`), the
//! lab's Windows client profiles connected, checked (the test page through the tunnel, traffic, the logs) and
//! disconnected. Ignored everywhere (`scripts/ignored-everywhere.txt`).
//!
//! The service refuses network logons and RAS dials need an interactive logon, so these run only in the user's
//! desktop session (a one-shot scheduled task with `/IT`, as `scripts/win-smoke.sh` starts the smoke run), one test
//! at a time, with the lab up:
//!
//! ```text
//! cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-platform-win --test lab_e2e -- --ignored \
//!   --test-threads=1 --nocapture lab_win_openvpn
//! ```
//!
//! `WINVPN_LAB_DIR` (default `%USERPROFILE%\lab\windows`) holds the lab's `client/windows` folder. The credentials
//! are read from its `l2tp.txt` and `cisco-ipsec.txt` sheets by this process only (never argv, env or a log); every
//! case checks that no lab secret reached the connection's log. The RAS entries live in a private phonebook of the
//! test's own temp data folder (never WinVPN's own `%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk`), cleared and deleted at
//! the end; every tunnel is taken down when a case ends, a failed check included.

#![cfg(windows)]

use macvpn_app_core::failure_reason::{self, FailureKind};
use macvpn_core::credentials;
use macvpn_core::mfa::{self, AuthResponseKind, AuthUIStateKind};
use macvpn_core::models::{Connection, NativeSettings, OTPSeparator, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_platform_api::{HelperClient, HelperTunnel};
use macvpn_platform_win::{
    RasEngineForTests, ServiceClientForTests, installed_service_client_for_tests, ras_engine_for_tests,
};
use macvpn_winsys::ras::{self as wras, Phonebook};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

const PAGE: &str = "http://10.99.0.10/cgi-bin/index.cgi";

// ---------------------------------------------------------------------------------------------------------------
// The lab's credentials and profiles

struct Lab {
    dir: PathBuf,
    server: String,
    user: String,
    otp_user: String,
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
    let dir = std::env::var_os("WINVPN_LAB_DIR").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE")).join("lab").join("windows")
    });
    let l2tp = Zeroizing::new(std::fs::read_to_string(dir.join("l2tp.txt")).expect("l2tp.txt"));
    let account = sheet_field(&l2tp, "Account name");
    let user = account.split_whitespace().next().expect("account").to_string();
    let otp_user = between(&account, "one-time code test: ", ",").trim().to_string();
    let code = Zeroizing::new(
        between(&account[account.rfind("code ").expect("lab sheet: code")..], "code ", ")").trim().to_string(),
    );
    assert!(code.len() >= 4 && code.bytes().all(|b| b.is_ascii_digit()), "lab sheet: the one-time code is digits");
    let password = Zeroizing::new(sheet_field(&l2tp, "Password"));
    let psk = Zeroizing::new(sheet_field(&l2tp, "Pre-shared key"));
    let mut secrets = vec![("password", password.clone()), ("psk", psk.clone()), ("one-time code", code.clone())];
    let wg =
        Zeroizing::new(std::fs::read_to_string(dir.join("wireguard-windows.conf")).expect("wireguard-windows.conf"));
    for (name, key) in [("WireGuard private key", "PrivateKey"), ("WireGuard preshared key", "PresharedKey")] {
        if let Some(v) = wg.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        }) {
            secrets.push((name, Zeroizing::new(v)));
        }
    }
    Lab { server: sheet_field(&l2tp, "Server"), dir, user, otp_user, password, psk, code, secrets }
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
// The app's helper over the installed service and a RAS engine of the test's own

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn say(msg: &str) {
    println!("[{:.0}] {msg}", now());
}

/// The case's world: a temp data folder (the RAS engine's private phonebook, profiles and logs), the app's
/// `HelperClient` over the installed service and that engine, the service's MFA state. On drop every connection the
/// case started is taken down, every entry of the private phonebook cleared and deleted, the folder removed.
struct Case {
    dir: PathBuf,
    engine: RasEngineForTests,
    helper: Box<dyn HelperClient>,
    service: ServiceClientForTests,
    started: std::sync::Mutex<Vec<(VPNKind, Uuid)>>,
}

impl Case {
    fn new(name: &str) -> Case {
        say(&format!("case {name}"));
        let dir = std::env::temp_dir().join(format!("winvpn-lab-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = ras_engine_for_tests(&dir);
        let helper = engine.helper_with_installed_service();
        Case { dir, engine, helper, service: installed_service_client_for_tests(), started: Default::default() }
    }

    fn up(&self, kind: VPNKind, id: &Uuid, config: &[u8], secrets: &Secrets) -> Result<(), String> {
        self.started.lock().unwrap().push((kind, *id));
        self.helper.up(kind, id, config, secrets, true, &[])
    }

    fn status_of(&self, id: &Uuid) -> Option<macvpn_core::status::RootStatus> {
        self.helper.status().ok()?.into_iter().find(|s| s.id == *id)
    }

    fn traffic(&self, kind: VPNKind, id: &Uuid) -> Option<(u64, u64)> {
        let st = self.status_of(id);
        let t = HelperTunnel {
            id,
            kind,
            iface: st.as_ref().and_then(|s| s.iface.as_deref()),
            ip: st.as_ref().and_then(|s| s.ip.as_deref()),
            since: st.as_ref().and_then(|s| s.since),
        };
        self.helper.traffic(&t).map(|r| (r.rx, r.tx))
    }

    /// The connection's log as the app reads it (the service's masked log, or the RAS log).
    fn log(&self, id: &Uuid) -> String {
        let Some(mut src) = self.helper.log_source(id) else { return String::new() };
        let mut out = Vec::new();
        let mut offset = 0u64;
        while let Some(r) = src.read(offset, 1 << 20) {
            if r.data.is_empty() {
                break;
            }
            offset = r.start + r.data.len() as u64;
            out.extend_from_slice(&r.data);
            if offset >= r.size {
                break;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn book(&self) -> Option<Phonebook> {
        Phonebook::at(self.dir.join("ras").join("WinVPN.pbk")).ok()
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        for (kind, id) in self.started.lock().unwrap().drain(..) {
            let _ = self.helper.down(kind, &id);
            self.engine.profiles().remove(&id);
        }
        if let Some(book) = self.book() {
            for name in book.names().unwrap_or_default() {
                let _ = wras::clear_psk(&book, &name);
                let _ = book.delete(&name);
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The test page through whatever route the system has (`None`: no answer within 5 s).
fn page() -> Option<String> {
    let out = Command::new("curl.exe").args(["-s", "--max-time", "5", PAGE]).output().ok()?;
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.success() && body.contains("MacVPN lab: OK")).then_some(body)
}

fn page_via(expected: &str) -> String {
    for _ in 0..8 {
        if let Some(body) = page() {
            assert!(body.contains(&format!("via: {expected}")), "the test page names another server: {body}");
            return body;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("the test page did not answer through the tunnel (expected via {expected}); route: {}", route("10.99.0.10"));
}

/// Windows' route to `dst` (interface alias and next hop), for the record.
fn route(dst: &str) -> String {
    let script = format!(
        "$r = Find-NetRoute -RemoteIPAddress {dst} -ErrorAction SilentlyContinue | Select-Object -Last 1; \
         if ($r) {{ \"$($r.InterfaceAlias) via $($r.NextHop)\" }} else {{ 'no route' }}"
    );
    let out = Command::new("powershell.exe").args(["-NoProfile", "-Command", &script]).output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

/// Waits until the service / the engine no longer lists the connection (≤ `secs`).
fn wait_gone(c: &Case, id: &Uuid, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if c.status_of(id).is_none() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn masked(ip: Option<&str>) -> String {
    ip.map_or("-".into(), |ip| ip.split('.').take(2).collect::<Vec<_>>().join(".") + ".x.x")
}

/// Connects (the call returns once connected or failed), then: listed as connected, the test page via `via`,
/// traffic readable and growing with the page.
fn connect_and_check(c: &Case, kind: VPNKind, id: &Uuid, config: &[u8], secrets: &Secrets, via: &str) {
    let t0 = Instant::now();
    c.up(kind, id, config, secrets).unwrap_or_else(|m| panic!("up refused: {m}\n--- log ---\n{}", c.log(id)));
    let st = c.status_of(id).expect("listed after up");
    say(&format!(
        "connected in {:.1} s: state {}, iface {:?}, address {}",
        t0.elapsed().as_secs_f64(),
        st.state,
        st.iface,
        masked(st.ip.as_deref())
    ));
    assert_eq!(st.state, "connected");
    let before = c.traffic(kind, id);
    let body = page_via(via);
    std::thread::sleep(Duration::from_millis(1500));
    let after = c.traffic(kind, id);
    say(&format!(
        "page via {via} ({} bytes), route {}; traffic {before:?} -> {after:?}",
        body.len(),
        route("10.99.0.10")
    ));
    let (b, a) = (before.expect("traffic before"), after.expect("traffic after"));
    assert!(a.0 > b.0 && a.1 > b.1, "traffic did not grow with the page: {b:?} -> {a:?}");
    if kind != VPNKind::Sstp && kind != VPNKind::Strongswan {
        say(&format!("liveness {:?}", c.helper.liveness(id)));
    }
}

/// Disconnects, checks it is gone and the log holds no lab secret; returns the log.
fn finish(lab: &Lab, c: &Case, kind: VPNKind, id: &Uuid, extra: &[(&'static str, &str)]) -> String {
    let t0 = Instant::now();
    c.helper.down(kind, id).expect("down");
    assert!(wait_gone(c, id, 20), "still listed 20 s after down");
    say(&format!("down in {:.1} s; page now: {}", t0.elapsed().as_secs_f64(), page().is_some()));
    settle(lab, c, id, extra)
}

fn settle(lab: &Lab, c: &Case, id: &Uuid, extra: &[(&'static str, &str)]) -> String {
    let log = c.log(id);
    lab.assert_clean(&log, "the connection log", extra);
    println!("--- log of {id} ---\n{log}--- end of log ---");
    log
}

/// A refused sign-in: `up` failed with a sign-in failure, nothing is left running, no retry by itself, the log
/// classified as the sign-in refused.
fn expect_refused(lab: &Lab, c: &Case, id: &Uuid, up: Result<(), String>, t0: Instant, extra: &[(&'static str, &str)]) {
    let message = match up {
        Ok(()) => panic!("connected with wrong credentials"),
        Err(m) => m,
    };
    say(&format!("refused after {:.1} s: {message}", t0.elapsed().as_secs_f64()));
    assert!(wait_gone(c, id, 30), "the failed connection is still listed (a retry loop?)");
    std::thread::sleep(Duration::from_secs(10));
    assert!(c.status_of(id).is_none(), "the service started it again");
    let log = settle(lab, c, id, extra);
    let lines: Vec<String> = log.lines().map(str::to_string).collect();
    let kind = failure_reason::classify(&lines);
    say(&format!(
        "failure classified as {kind:?}; worth retrying: {}; sign-in failure (asked again once): {}",
        kind.worth_retrying(),
        credentials::is_sign_in_failure(&message)
    ));
    assert_eq!(kind, FailureKind::AuthFailed, "the app must say the sign-in was refused:\n{log}");
    assert!(!kind.worth_retrying());
    assert!(log.contains("AUTH_FAILED"), "the log names AUTH_FAILED:\n{log}");
}

// ---------------------------------------------------------------------------------------------------------------
// OpenVPN and WireGuard through the installed WinVPN Service

#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_openvpn_tun() {
    let lab = lab();
    for profile in ["openvpn-tun-dco.ovpn", "openvpn-tun-cbc.ovpn"] {
        say(&format!("== {profile} as the plain lab user"));
        let c = Case::new(profile);
        let id = Uuid::new_v4();
        connect_and_check(&c, VPNKind::Openvpn, &id, &lab.file(profile), &lab.secrets(&lab.user), "openvpn");
        let log = finish(&lab, &c, VPNKind::Openvpn, &id, &[]);
        for line in log
            .lines()
            .filter(|l| l.contains("DCO version") || l.contains("device [") || l.contains("TAP-Windows Driver"))
        {
            say(&format!("driver: {}", line.trim()));
        }
    }
}

#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_openvpn_wrong_password() {
    let lab = lab();
    let c = Case::new("openvpn-wrong-password");
    let id = Uuid::new_v4();
    let mut secrets = lab.secrets(&lab.user);
    secrets.password = Some("not-the-lab-password-1".into());
    let t0 = Instant::now();
    let up = c.up(VPNKind::Openvpn, &id, &lab.file("openvpn-tun-dco.ovpn"), &secrets);
    expect_refused(&lab, &c, &id, up, t0, &[]);
}

/// MFA 1: the static challenge (SCRV1), packed into the password as app-core does; then a wrong code.
#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_openvpn_static_challenge() {
    let lab = lab();
    let config = lab.file("openvpn-static-challenge.ovpn");
    let challenge = mfa::static_challenge(std::str::from_utf8(&config).unwrap()).expect("static-challenge line");
    say(&format!("static challenge: format {:?}, echo {}", challenge.format, challenge.echo));

    say("== the right code");
    let c = Case::new("openvpn-static");
    let id = Uuid::new_v4();
    let packed = mfa::apply_static_challenge(&challenge, &lab.code, &lab.secrets(&lab.otp_user)).unwrap();
    assert!(packed.challenge_packed);
    let packed_pw = Zeroizing::new(packed.password.clone().unwrap());
    connect_and_check(&c, VPNKind::Openvpn, &id, &config, &packed, "openvpn");
    assert!(c.service.auth_state().read(&id).is_none_or(|s| s.state != AuthUIStateKind::Challenge));
    finish(&lab, &c, VPNKind::Openvpn, &id, &[("packed password", packed_pw.as_str())]);

    say("== a wrong code");
    let c = Case::new("openvpn-static-wrong");
    let id = Uuid::new_v4();
    let wrong = mfa::apply_static_challenge(&challenge, lab.wrong_code(), &lab.secrets(&lab.otp_user)).unwrap();
    let wrong_pw = Zeroizing::new(wrong.password.clone().unwrap());
    let t0 = Instant::now();
    let up = c.up(VPNKind::Openvpn, &id, &config, &wrong);
    expect_refused(&lab, &c, &id, up, t0, &[("packed password", wrong_pw.as_str())]);
}

/// Waits for a pending dynamic challenge newer than `after_seq` (≤ 45 s, or until `done` says `up` returned).
fn wait_challenge(
    c: &Case,
    id: &Uuid,
    after_seq: i64,
    done: &std::sync::atomic::AtomicBool,
) -> Option<mfa::AuthUIState> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline && !done.load(std::sync::atomic::Ordering::SeqCst) {
        if let Some(s) =
            c.service.auth_state().read(id).filter(|s| s.state == AuthUIStateKind::Challenge && s.seq > after_seq)
        {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

/// MFA 2: the dynamic challenge (CRV1): `up` waits in the service while the app reads the challenge
/// (`auth-state`) and answers it (`respond`); then a wrong code.
#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_openvpn_crv1() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let lab = lab();
    let config = lab.file("openvpn-tun-dco.ovpn");

    say("== the right code");
    let c = Case::new("openvpn-crv1");
    let id = Uuid::new_v4();
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        let up = s.spawn(|| {
            let r = c.up(VPNKind::Openvpn, &id, &config, &lab.secrets(&lab.otp_user));
            done.store(true, Ordering::SeqCst);
            r
        });
        let t0 = Instant::now();
        let ch = wait_challenge(&c, &id, -1, &done).unwrap_or_else(|| panic!("no challenge:\n{}", c.log(&id)));
        say(&format!(
            "challenge after {:.1} s: method {:?}, text {:?}, echo {:?}, deadline in {:.0} s",
            t0.elapsed().as_secs_f64(),
            ch.method,
            ch.text,
            ch.echo,
            ch.deadline.map_or(f64::NAN, |d| d - now())
        ));
        let answered = Instant::now();
        c.helper.respond(&id, AuthResponseKind::Crv1, &lab.code).unwrap_or_else(|m| panic!("respond: {m}"));
        up.join().unwrap().unwrap_or_else(|m| panic!("after the code: {m}\n{}", c.log(&id)));
        say(&format!("connected {:.1} s after the code", answered.elapsed().as_secs_f64()));
    });
    page_via("openvpn");
    say(&format!("challenge state after connect: {:?}", c.service.auth_state().read(&id).map(|s| s.state)));
    finish(&lab, &c, VPNKind::Openvpn, &id, &[]);

    say("== a wrong code");
    let c = Case::new("openvpn-crv1-wrong");
    let id = Uuid::new_v4();
    let done = AtomicBool::new(false);
    let t0 = Instant::now();
    let up = std::thread::scope(|s| {
        let up = s.spawn(|| {
            let r = c.up(VPNKind::Openvpn, &id, &config, &lab.secrets(&lab.otp_user));
            done.store(true, Ordering::SeqCst);
            r
        });
        let ch = wait_challenge(&c, &id, -1, &done).unwrap_or_else(|| panic!("no challenge:\n{}", c.log(&id)));
        c.helper.respond(&id, AuthResponseKind::Crv1, lab.wrong_code()).unwrap();
        // A new challenge is the app's code window once more: cancel it as the window's Cancel does.
        if let Some(next) = wait_challenge(&c, &id, ch.seq, &done) {
            say(&format!("challenge again after the wrong code (seq {} -> {}): cancelled", ch.seq, next.seq));
            c.helper.respond(&id, AuthResponseKind::Cancel, "").unwrap();
            assert!(wait_challenge(&c, &id, next.seq, &done).is_none(), "a loop of challenges after Cancel");
        } else {
            say("no new challenge after the wrong code");
        }
        up.join().unwrap()
    });
    expect_refused(&lab, &c, &id, up, t0, &[]);
}

/// MFA 3: the code appended to the password (separators `,`, none, `:`), as app-core's `apply_code` builds it;
/// then a wrong appended code.
#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_openvpn_append_code() {
    let lab = lab();
    let config = lab.file("openvpn-tun-dco.ovpn");
    for sep in [OTPSeparator::Comma, OTPSeparator::None, OTPSeparator::Colon] {
        say(&format!("== the right code, separator {:?}", sep.raw_value()));
        let c = Case::new("openvpn-append");
        let id = Uuid::new_v4();
        let s = mfa::apply_code(&lab.code, sep, &lab.secrets(&lab.otp_user), VPNKind::Openvpn).unwrap();
        let combined = Zeroizing::new(s.password.clone().unwrap());
        connect_and_check(&c, VPNKind::Openvpn, &id, &config, &s, "openvpn");
        finish(&lab, &c, VPNKind::Openvpn, &id, &[("combined password", combined.as_str())]);
    }
    say("== a wrong appended code");
    let c = Case::new("openvpn-append-wrong");
    let id = Uuid::new_v4();
    let s =
        mfa::apply_code(lab.wrong_code(), OTPSeparator::Comma, &lab.secrets(&lab.otp_user), VPNKind::Openvpn).unwrap();
    let combined = Zeroizing::new(s.password.clone().unwrap());
    let t0 = Instant::now();
    let up = c.up(VPNKind::Openvpn, &id, &config, &s);
    expect_refused(&lab, &c, &id, up, t0, &[("combined password", combined.as_str())]);
}

#[test]
#[ignore = "lab: the user's desktop session, the installed service, the lab up"]
fn lab_win_wireguard() {
    let lab = lab();
    let c = Case::new("wireguard");
    let id = Uuid::new_v4();
    connect_and_check(
        &c,
        VPNKind::Wireguard,
        &id,
        &lab.file("wireguard-windows.conf"),
        &Secrets::default(),
        "wireguard",
    );
    finish(&lab, &c, VPNKind::Wireguard, &id, &[]);
}

// ---------------------------------------------------------------------------------------------------------------
// RAS: L2TP/IPsec (a native connection), IKEv2 and SSTP (helper kinds), Cisco IPsec (refused by design)

fn native(lab: &Lab, kind: VPNKind) -> Connection {
    let mut c = Connection::new("Lab native", kind);
    c.native = Some(NativeSettings {
        server: lab.server.clone(),
        account: lab.user.clone(),
        group_name: if kind == VPNKind::Cisco { "labgroup".into() } else { String::new() },
        send_all_traffic: false,
    });
    c
}

#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up"]
fn lab_win_l2tp() {
    let lab = lab();
    let c = Case::new("l2tp");
    let conn = native(&lab, VPNKind::L2tp);
    let id = conn.id;
    let profile = c.engine.profiles().build(&conn, &lab.psk).unwrap();
    c.engine.profiles().install(&id, &profile.data, &profile.file_name, false).unwrap();
    c.started.lock().unwrap().push((VPNKind::L2tp, id));
    let service_id = c.engine.controller().managed_service_id(&id).unwrap();
    let t0 = Instant::now();
    c.engine
        .controller()
        .start(&service_id, Some(NativeKind::L2tp), &lab.secrets(&lab.user))
        .unwrap_or_else(|m| panic!("start: {m}\n{}", c.log(&id)));
    let ip = c.engine.controller().address(&service_id);
    say(&format!("connected in {:.1} s, address {}", t0.elapsed().as_secs_f64(), masked(ip.as_deref())));
    let before = c.engine.controller().traffic(&service_id).map(|r| (r.rx, r.tx));
    let body = page_via("ipsec");
    std::thread::sleep(Duration::from_millis(1500));
    let after = c.engine.controller().traffic(&service_id).map(|r| (r.rx, r.tx));
    say(&format!("page ({} bytes), route {}; traffic {before:?} -> {after:?}", body.len(), route("10.99.0.10")));
    let (b, a) = (before.expect("traffic before"), after.expect("traffic after"));
    assert!(a.0 > b.0 && a.1 > b.1, "traffic did not grow with the page: {b:?} -> {a:?}");
    c.engine.controller().stop(&service_id).unwrap();
    assert!(c.engine.controller().address(&service_id).is_none(), "still connected after stop");
    say(&format!("stopped; page now: {}", page().is_some()));
    settle(&lab, &c, &id, &[]);
}

#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up"]
fn lab_win_cisco_is_refused() {
    let lab = lab();
    let c = Case::new("cisco");
    let conn = native(&lab, VPNKind::Cisco);
    let reason = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        c.engine.support().unsupported_reason(&conn, b"").expect("Cisco IPsec has a reason on Windows")
    });
    say(&format!("unsupported reason: {reason}"));
    assert!(reason.starts_with("Cisco IPsec is not supported by Windows."), "{reason}");
    let profile = c.engine.profiles().build(&conn, &lab.psk).unwrap();
    let installed = c.engine.profiles().install(&conn.id, &profile.data, &profile.file_name, false);
    say(&format!("install: {installed:?}"));
    assert!(installed.is_err(), "no Windows entry for Cisco IPsec");
    assert!(c.book().is_none_or(|b| b.names().unwrap_or_default().is_empty()), "no entry was written");
}

/// A helper kind through RAS: connected, the page, traffic, down. `Err`: `up`'s message (and the log printed).
fn ras_case(lab: &Lab, c: &Case, kind: VPNKind, config: &[u8], secrets: &Secrets, via: &str) -> Result<(), String> {
    let id = Uuid::new_v4();
    let t0 = Instant::now();
    if let Err(m) = c.up(kind, &id, config, secrets) {
        say(&format!("up failed after {:.1} s: {m}", t0.elapsed().as_secs_f64()));
        let log = settle(lab, c, &id, &[]);
        let lines: Vec<String> = log.lines().map(str::to_string).collect();
        say(&format!("failure classified as {:?}", failure_reason::classify(&lines)));
        return Err(m);
    }
    let st = c.status_of(&id).expect("listed after up");
    say(&format!(
        "connected in {:.1} s: state {}, address {}",
        t0.elapsed().as_secs_f64(),
        st.state,
        masked(st.ip.as_deref())
    ));
    let before = c.traffic(kind, &id);
    let body = page_via(via);
    std::thread::sleep(Duration::from_millis(1500));
    let after = c.traffic(kind, &id);
    say(&format!("page ({} bytes), route {}; traffic {before:?} -> {after:?}", body.len(), route("10.99.0.10")));
    let (b, a) = (before.expect("traffic before"), after.expect("traffic after"));
    assert!(a.0 > b.0 && a.1 > b.1, "traffic did not grow with the page: {b:?} -> {a:?}");
    finish(lab, c, kind, &id, &[]);
    Ok(())
}

#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up, the lab CA trusted in Windows"]
fn lab_win_ikev2_eap() {
    let lab = lab();
    let c = Case::new("ikev2-eap");
    ras_case(&lab, &c, VPNKind::Strongswan, &lab.file("ikev2-eap.swanctl.conf"), &lab.secrets(&lab.user), "ipsec")
        .unwrap_or_else(|m| panic!("IKEv2 EAP: {m}"));
}

/// IKEv2 with a PSK: refused before any dial with the documented reason (the Windows client has no PSK sign-in).
#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up"]
fn lab_win_ikev2_psk_is_refused() {
    let lab = lab();
    let c = Case::new("ikev2-psk");
    let m = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        ras_case(&lab, &c, VPNKind::Strongswan, &lab.file("ikev2-psk.swanctl.conf"), &lab.secrets(&lab.user), "ipsec")
            .expect_err("IKEv2 PSK cannot connect on Windows")
    });
    assert!(m.contains("local auth = psk"), "{m}");
}

#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up, the lab CA trusted in Windows"]
fn lab_win_sstp() {
    let lab = lab();
    let mut failed = Vec::new();
    for file in ["sstp-ca.sstp", "sstp-ca-alt-port.sstp"] {
        say(&format!("== {file}"));
        let c = Case::new(file);
        if let Err(m) = ras_case(&lab, &c, VPNKind::Sstp, &lab.file(file), &lab.secrets(&lab.user), "sstp") {
            failed.push(format!("{file}: {m}"));
        }
    }
    assert!(failed.is_empty(), "{failed:#?}");
}

/// The SSTP profiles Windows cannot run as written: `cert=insecure` is refused before a dial; `system` without the
/// lab CA in Windows' store fails with a certificate reason.
#[test]
#[ignore = "lab: the user's desktop session (RAS), the lab up"]
fn lab_win_sstp_refusals() {
    let lab = lab();
    macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        say("== sstp-no-verification.sstp");
        let c = Case::new("sstp-no-verification");
        let m =
            ras_case(&lab, &c, VPNKind::Sstp, &lab.file("sstp-no-verification.sstp"), &lab.secrets(&lab.user), "sstp")
                .expect_err("Windows always checks the SSTP certificate");
        assert!(m.starts_with("Windows always checks the SSTP server's certificate."), "{m}");
        drop(c);
        say("== sstp-system-ca.sstp");
        let c = Case::new("sstp-system-ca");
        match ras_case(&lab, &c, VPNKind::Sstp, &lab.file("sstp-system-ca.sstp"), &lab.secrets(&lab.user), "sstp") {
            Ok(()) => say("connected: the lab CA is in Windows' store (trusted before)"),
            Err(m) => say(&format!("refused: {m}")),
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------
// No lab secret in WinVPN's logs this user can read

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
#[ignore = "lab: after the lab cases, in the user's session"]
fn lab_win_no_secret_in_winvpn_logs() {
    let lab = lab();
    let mut files = Vec::new();
    for root in ["LOCALAPPDATA", "ProgramData"] {
        if let Some(base) = std::env::var_os(root) {
            let dir = PathBuf::from(base).join("WinVPN").join("logs");
            // The service's own logs (`%ProgramData%\WinVPN\logs`) are SYSTEM and Administrators only: the user
            // reads a connection's log through the service (checked by every case above).
            say(&format!("{root}\\WinVPN\\logs listable by this user: {}", std::fs::read_dir(&dir).is_ok()));
            files_under(&dir, &mut files);
        }
    }
    let (mut read, mut unreadable) = (0, 0);
    for f in &files {
        match std::fs::read(f) {
            Ok(bytes) => {
                read += 1;
                let text = String::from_utf8_lossy(&bytes);
                lab.assert_clean(&text, &f.display().to_string(), &[]);
                let utf16: String = char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)))
                    .map(|r| r.unwrap_or('?'))
                    .collect();
                lab.assert_clean(&utf16, &f.display().to_string(), &[]);
            }
            Err(_) => unreadable += 1,
        }
    }
    say(&format!("WinVPN log files: {} found, {read} read, {unreadable} not readable by this user", files.len()));
}
