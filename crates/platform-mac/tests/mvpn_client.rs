//! Port of `MvpnClientTests.swift` (the status JSON tests are also in the core: `status::parse_status`).
#![cfg(target_os = "macos")]

use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{ConnectionState, Secrets, VPNKind, parse_uuid};
use macvpn_platform_mac::command::CommandResult;
use macvpn_platform_mac::mvpn_client::{ClientError, MvpnClient};
use macvpn_platform_mac::testing::MockCommandRunner;
use uuid::Uuid;

fn id() -> Uuid {
    parse_uuid("11111111-2222-3333-4444-555555555555").unwrap()
}

/// The Hungarian message is checked; `--lang` comes from the fixed language, not the machine's locale.
fn hu() {
    AppLanguage::set_thread_override(Some(AppLanguage::Hu));
}

#[test]
fn up_passes_kind_id_debug_and_secrets_on_stdin() {
    hu();
    let mock = MockCommandRunner::new();
    let secrets = Secrets { username: Some("u".into()), password: Some("p".into()), ..Secrets::default() };
    MvpnClient::new(&mock).up(VPNKind::Openvpn, &id(), b"client\n", &secrets, true, &[]).unwrap();
    let call = &mock.calls()[0];
    assert_eq!(
        call.command_line(),
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up openvpn 11111111-2222-3333-4444-555555555555 --debug --lang hu"
    );
    assert_eq!(call.stdin.as_deref(), Some("config 7\nclient\nusername=u\npassword=p\n"));
}

/// Root layer 8: `config <exact byte length>\n`, the config bytes as they are (its `password=` lines stay config),
/// then the secret lines. The secrets and the config are never in the arguments.
#[test]
fn up_frames_the_config_on_stdin() {
    hu();
    let mock = MockCommandRunner::new();
    let config = "# Irodai VPN – árvíztűrő tükörfúrógép\nserver=vpn.example.com\nuser=bob\npassword=FromConfig\n";
    let secrets = Secrets { password: Some("Titok123".into()), ..Secrets::default() };
    MvpnClient::new(&mock).up(VPNKind::Sstp, &id(), config.as_bytes(), &secrets, false, &[]).unwrap();
    let call = &mock.calls()[0];
    let expected = format!("config {}\n{config}password=Titok123\n", config.len());
    assert_ne!(config.len(), config.chars().count(), "the test needs multi-byte characters");
    assert_eq!(call.stdin.as_deref(), Some(expected.as_str()));
    assert!(
        call.arguments.iter().all(|a| !a.contains("Titok123") && !a.contains("FromConfig") && !a.contains("config"))
    );
    // Without secrets: the frame alone.
    let mock = MockCommandRunner::new();
    MvpnClient::new(&mock).up(VPNKind::Wireguard, &id(), b"[Interface]\n", &Secrets::default(), false, &[]).unwrap();
    assert_eq!(mock.calls()[0].stdin.as_deref(), Some("config 12\n[Interface]\n"));
}

#[test]
fn up_accept_risky_sorted_filtered_and_openvpn_only() {
    hu();
    let risky: Vec<String> =
        ["route-up", "auth-user-pass", "BAD", "x y", "route-up", ""].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        MvpnClient::up_arguments(VPNKind::Openvpn, &id(), false, &risky),
        ["up", "openvpn", "11111111-2222-3333-4444-555555555555", "--accept-risky", "auth-user-pass,route-up"]
    );
    assert_eq!(
        MvpnClient::up_arguments(VPNKind::Wireguard, &id(), false, &risky),
        ["up", "wireguard", "11111111-2222-3333-4444-555555555555"]
    );
    let mock = MockCommandRunner::new();
    MvpnClient::new(&mock).up(VPNKind::Openvpn, &id(), b"x", &Secrets::default(), true, &risky).unwrap();
    assert!(mock.calls()[0].command_line().ends_with("--debug --accept-risky auth-user-pass,route-up --lang hu"));
}

#[test]
fn up_failure_returns_stderr() {
    hu();
    let mock = MockCommandRunner::new();
    mock.respond(
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard 11111111-2222-3333-4444-555555555555 --lang hu",
        CommandResult::new(1, "", "AUTH_FAILED\n"),
    );
    let e = MvpnClient::new(&mock).up(VPNKind::Wireguard, &id(), b"x", &Secrets::default(), false, &[]).unwrap_err();
    assert_eq!(e.to_string(), "AUTH_FAILED");
    // No stderr: the generic message with the exit code.
    let mock = MockCommandRunner::new();
    mock.respond(
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn down sstp 11111111-2222-3333-4444-555555555555 --lang hu",
        CommandResult::exit(4),
    );
    let e = MvpnClient::new(&mock).down(VPNKind::Sstp, &id()).unwrap_err();
    assert_eq!(e.to_string(), "mvpn hiba (kilépési kód: 4)");
}

#[test]
fn up_uses_the_long_runner_status_the_quick_one_down_the_default() {
    hu();
    let (main, long, quick) = (MockCommandRunner::new(), MockCommandRunner::new(), MockCommandRunner::new());
    let status = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu";
    main.respond(status, CommandResult::exit(1));
    long.respond(status, CommandResult::exit(1));
    quick.respond(status, CommandResult::stdout("[]\n"));
    let client = MvpnClient::with_runners(&main, Some(&long), Some(&quick), None);
    client.up(VPNKind::Openvpn, &id(), b"x", &Secrets::default(), false, &[]).unwrap();
    client.down(VPNKind::Openvpn, &id()).unwrap();
    assert_eq!(client.status().unwrap(), []);
    client.respond(&id(), AuthResponseKind::Cancel, "").unwrap();
    let verbs = |m: &MockCommandRunner| m.calls().iter().map(|c| c.arguments[2].clone()).collect::<Vec<_>>();
    assert_eq!(verbs(&long), ["up"]);
    assert_eq!(verbs(&main), ["down"]);
    assert_eq!(verbs(&quick), ["status", "respond"]);
}

#[test]
fn explicit_language_wins() {
    hu();
    let mock = MockCommandRunner::new();
    MvpnClient::with_runners(&mock, None, None, Some(AppLanguage::En)).down(VPNKind::Openvpn, &id()).unwrap();
    assert!(mock.calls()[0].command_line().ends_with(" --lang en"));
}

#[test]
fn respond_sends_code_on_stdin_only() {
    hu();
    let mock = MockCommandRunner::new();
    MvpnClient::new(&mock).respond(&id(), AuthResponseKind::Crv1, "123456").unwrap();
    let call = &mock.calls()[0];
    assert_eq!(
        call.command_line(),
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn respond openvpn 11111111-2222-3333-4444-555555555555 --lang hu"
    );
    assert_eq!(call.stdin.as_deref(), Some("kind=crv1\nresponse=123456\n"));
    // An invalid code never reaches mvpn.
    let mock = MockCommandRunner::new();
    let e = MvpnClient::new(&mock).respond(&id(), AuthResponseKind::Crv1, "12\n34").unwrap_err();
    assert!(matches!(e, ClientError::Mfa(_)));
    assert!(mock.calls().is_empty());
}

#[test]
fn parse_status() {
    let mock = MockCommandRunner::new();
    mock.respond(
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang en",
        CommandResult::stdout(
            r#"[{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"connected","iface":"utun5","ip":"10.8.0.2","since":1700000000},
 {"id":"11111111-2222-3333-4444-555555555556","kind":"strongswan","state":"connecting","iface":null,"ip":null,"since":null}]"#,
        ),
    );
    let list = MvpnClient::with_runners(&mock, None, None, Some(AppLanguage::En)).status().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(
        list[0].connection_state(),
        ConnectionState::Connected {
            ip: Some("10.8.0.2".into()),
            since: Some(Date::from_time_interval_since_1970(1_700_000_000.0))
        }
    );
    assert_eq!(list[1].connection_state(), ConnectionState::Connecting);
    // Garbage is an error.
    let mock = MockCommandRunner::new();
    mock.respond("/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang en", CommandResult::stdout("nope"));
    let e = MvpnClient::with_runners(&mock, None, None, Some(AppLanguage::En)).status().unwrap_err();
    assert!(matches!(e, ClientError::Status(_)));
}

#[test]
fn failed_status_maps_to_failed() {
    hu();
    let s = macvpn_core::status::parse_status(
        r#"[{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"failed","iface":null,"ip":null,"since":null}]"#,
    )
    .unwrap();
    assert_eq!(s[0].connection_state(), ConnectionState::Failed("A kapcsolat megszakadt".into()));
}

#[test]
fn paths() {
    assert_eq!(
        MvpnClient::log_path(&id()).to_string_lossy(),
        "/var/log/macvpn/11111111-2222-3333-4444-555555555555.log"
    );
    assert_eq!(macvpn_platform_mac::mvpn_client::EXECUTABLE, "/usr/local/libexec/macvpn/mvpn");
}

/// "Clear Log…": the user's own `<id>.log` and `<id>.log.1` are emptied in place by the app (no root call), the
/// note starts the live one; another user's log, a symlink or no log at all are handled without touching anything.
#[test]
fn clear_log_empties_the_users_log_and_its_rotated_part_in_place() {
    use macvpn_core::fsx::FileOwner;
    use std::os::unix::fs::MetadataExt;
    hu();
    let dir = std::env::temp_dir().join(format!("macvpn-clear-log-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let live = dir.join("11111111-2222-3333-4444-555555555555.log");
    let rotated = dir.join("11111111-2222-3333-4444-555555555555.log.1");
    std::fs::write(&live, "old\n").unwrap();
    std::fs::write(&rotated, "older\n").unwrap();
    let me = FileOwner::from_uid(std::fs::metadata(&live).unwrap().uid());
    let mock = MockCommandRunner::new();
    let ino = std::fs::metadata(&live).unwrap().ino();
    macvpn_platform_mac::mvpn_client::clear_log_in(&dir, &id(), &me, "═══ NOTE ═══").unwrap();
    assert!(mock.calls().is_empty(), "no sudo call");
    assert_eq!(std::fs::read_to_string(&live).unwrap(), "═══ NOTE ═══\n");
    assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "");
    assert_eq!(std::fs::metadata(&live).unwrap().ino(), ino, "the same file, so the writers keep appending to it");

    // Only the live log (never rotated yet): fine.
    std::fs::remove_file(&rotated).unwrap();
    macvpn_platform_mac::mvpn_client::clear_log_in(&dir, &id(), &me, "═══ NOTE ═══").unwrap();
    // No log at all: nothing to clear.
    std::fs::remove_file(&live).unwrap();
    macvpn_platform_mac::mvpn_client::clear_log_in(&dir, &id(), &me, "═══ NOTE ═══").unwrap();
    assert!(!live.exists(), "never created");

    // Another user's log is left alone, with a clear message.
    std::fs::write(&live, "theirs\n").unwrap();
    let other = FileOwner::from_uid(std::fs::metadata(&live).unwrap().uid() + 1);
    let e = macvpn_platform_mac::mvpn_client::clear_log_in(&dir, &id(), &other, "═══ NOTE ═══").unwrap_err();
    assert_eq!(e, "A kapcsolat naplóját nem lehet törölni: egy másik felhasználóé, vagy nem írható.");
    assert_eq!(std::fs::read_to_string(&live).unwrap(), "theirs\n");

    // A symlink in place of the log is never followed.
    std::fs::remove_file(&live).unwrap();
    let target = dir.join("target");
    std::fs::write(&target, "keep\n").unwrap();
    std::os::unix::fs::symlink(&target, &live).unwrap();
    assert!(macvpn_platform_mac::mvpn_client::clear_log_in(&dir, &id(), &me, "═══ NOTE ═══").is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Root layer 10's `mvpn liveness <id>` (dead-tunnel detection): only the ID goes to the root layer; an older root
/// layer (its usage error), another failure or an answer of another form is `None` (nothing is decided).
#[test]
fn liveness_asks_with_the_id_only_and_an_older_root_layer_is_none() {
    use macvpn_core::liveness::{Liveness, WgPeer};
    let line =
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn liveness 11111111-2222-3333-4444-555555555555 --lang en";
    let client =
        |mock: &MockCommandRunner| MvpnClient::with_runners(mock, None, None, Some(AppLanguage::En)).liveness(&id());
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::stdout("wireguard 1\npeer 1700000000 10 20 25 1\n"));
    assert_eq!(
        client(&mock),
        Some(Liveness::WireGuard(vec![WgPeer {
            last_handshake: Some(1_700_000_000),
            rx: 10,
            tx: 20,
            keepalive: 25,
            endpoint: true
        }]))
    );
    assert_eq!(mock.calls()[0].command_line(), line);
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::new(1, "", "Usage: mvpn up|down <openvpn|wireguard|strongswan|sstp> <id> …"));
    assert_eq!(client(&mock), None);
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::stdout("garbage\n"));
    assert_eq!(client(&mock), None);
}

/// Root layer 11's `mvpn traffic <id>` (live traffic of a strongSwan connection): only the ID goes to the root layer;
/// an older root layer (its usage error), another failure or an answer of another form is `None` (no traffic shown).
#[test]
fn traffic_asks_with_the_id_only_and_an_older_root_layer_is_none() {
    use macvpn_core::traffic::ChildCount;
    let line = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn traffic 11111111-2222-3333-4444-555555555555 --lang en";
    let client =
        |mock: &MockCommandRunner| MvpnClient::with_runners(mock, None, None, Some(AppLanguage::En)).traffic(&id());
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::stdout("strongswan 1\nchild 7 12345 6789\n"));
    assert_eq!(client(&mock), Some(vec![ChildCount { id: 7, rx: 12345, tx: 6789 }]));
    assert_eq!(mock.calls()[0].command_line(), line);
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::new(1, "", "Usage: mvpn up|down <openvpn|wireguard|strongswan|sstp> <id> …"));
    assert_eq!(client(&mock), None);
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::stdout("bytes 1 2 3\n"));
    assert_eq!(client(&mock), None);
}

// MARK: - Root layer 13: the query daemon

/// A stand-in query daemon on a socket in a temp directory: each connection's request line is recorded and
/// answered with the next of `answers` (`None`: closed without an answer).
struct FakeDaemon {
    dir: std::path::PathBuf,
    socket: std::path::PathBuf,
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl FakeDaemon {
    fn start(answers: Vec<Option<&'static [u8]>>) -> FakeDaemon {
        Self::start_delayed(answers, std::time::Duration::ZERO)
    }

    /// Each answer after `delay` (a probe takes its time).
    fn start_delayed(answers: Vec<Option<&'static [u8]>>, delay: std::time::Duration) -> FakeDaemon {
        use std::io::{BufRead, Write};
        // Short: a Unix socket path is at most 104 bytes.
        let dir = std::env::temp_dir().join(format!("mvqc-{}", &Uuid::new_v4().to_string()[..8]));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("q.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = requests.clone();
        std::thread::spawn(move || {
            for answer in answers {
                let Ok((stream, _)) = listener.accept() else { return };
                let mut line = String::new();
                let _ = std::io::BufReader::new(&stream).read_line(&mut line);
                seen.lock().unwrap().push(line);
                std::thread::sleep(delay);
                if let Some(answer) = answer {
                    let _ = (&stream).write_all(answer);
                }
            }
        });
        FakeDaemon { dir, socket, requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn client_with<'a>(mock: &'a MockCommandRunner, socket: &std::path::Path) -> MvpnClient<'a> {
    MvpnClient::with_runners(mock, None, None, Some(AppLanguage::En)).with_query_socket(Some(socket))
}

#[test]
fn the_query_answer_format() {
    use macvpn_platform_mac::mvpn_client::parse_query_answer;
    let r = parse_query_answer(b"0\n[]\n").unwrap();
    assert_eq!((r.exit_code, r.stdout.as_str(), r.stderr.as_str()), (0, "[]\n", ""));
    assert_eq!(parse_query_answer(b"1\n").unwrap().exit_code, 1);
    assert_eq!(parse_query_answer(b"143\n").unwrap().exit_code, 143);
    for bad in [&b""[..], b"0", b"\n[]", b"-1\n", b"01\n", b"1000\n", b" 0\n", b"0 \n", b"x\n", b"0\n\xff\n"] {
        assert!(parse_query_answer(bad).is_none(), "{bad:?}");
    }
}

/// The daemon answers: no `sudo`; the request is the command and the ID only (no `--lang`).
#[test]
fn status_liveness_and_traffic_are_asked_on_the_daemon_first() {
    let id = "11111111-2222-3333-4444-555555555555";
    let status = format!(
        "0\n[{{\"id\":\"{}\",\"kind\":\"wireguard\",\"state\":\"connected\",\"iface\":\"utun5\",\"ip\":\"10.0.0.2\",\"since\":null}}]\n",
        id.to_uppercase()
    );
    let status: &'static str = Box::leak(status.into_boxed_str());
    let daemon = FakeDaemon::start(vec![
        Some(status.as_bytes()),
        Some(b"0\nwireguard 1\npeer 1700000000 10 20 25 1\n"),
        Some(b"0\nstrongswan 1\nchild 7 12345 6789\n"),
        Some(b"1\n"),
    ]);
    let mock = MockCommandRunner::new();
    let client = client_with(&mock, &daemon.socket);
    let list = client.status().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].state, "connected");
    assert!(client.liveness(&self::id()).is_some());
    assert_eq!(client.traffic(&self::id()).unwrap().len(), 1);
    // A nonzero exit is the command line's: liveness gives nothing, without asking sudo again.
    assert_eq!(client.liveness(&self::id()), None);
    assert!(mock.calls().is_empty(), "{:?}", mock.calls());
    let upper = id.to_uppercase();
    assert_eq!(
        daemon.requests(),
        [
            "status\n".to_string(),
            format!("liveness {upper}\n"),
            format!("traffic {upper}\n"),
            format!("liveness {upper}\n")
        ]
    );
}

/// A failed status on the daemon is the command line's failure (the daemon has no stderr: the generic message).
#[test]
fn a_failed_status_on_the_daemon_is_the_generic_error() {
    let daemon = FakeDaemon::start(vec![Some(b"1\n")]);
    let mock = MockCommandRunner::new();
    let e = client_with(&mock, &daemon.socket).status().unwrap_err();
    assert!(matches!(e, ClientError::Mvpn(_)));
    assert_eq!(e.to_string(), "mvpn error (exit code: 1)");
    assert!(mock.calls().is_empty());
}

/// No daemon (an older root layer, or not loaded), a refused question, a malformed answer: `sudo`, as before.
#[test]
fn without_a_good_answer_from_the_daemon_sudo_is_asked() {
    let line = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang en";
    let missing = std::env::temp_dir().join(format!("mvqc-none-{}.sock", Uuid::new_v4()));
    let mock = MockCommandRunner::new();
    mock.respond(line, CommandResult::stdout("[]\n"));
    assert_eq!(client_with(&mock, &missing).status().unwrap(), []);
    assert_eq!(mock.calls().len(), 1);
    let daemon = FakeDaemon::start(vec![None, Some(b"garbage"), Some(b"0\n\xff")]);
    for _ in 0..3 {
        let mock = MockCommandRunner::new();
        mock.respond(line, CommandResult::stdout("[]\n"));
        assert_eq!(client_with(&mock, &daemon.socket).status().unwrap(), []);
        assert_eq!(mock.calls().iter().map(|c| c.command_line()).collect::<Vec<_>>(), [line]);
    }
    assert_eq!(daemon.requests().len(), 3);
    // Not configured (tests, the default): never a socket.
    let mock = MockCommandRunner::new();
    MvpnClient::new(&mock).status().unwrap_err();
    assert_eq!(mock.calls().len(), 1);
}

/// What changes state never goes to the daemon.
#[test]
fn down_and_respond_stay_on_sudo() {
    let daemon = FakeDaemon::start(vec![]);
    let mock = MockCommandRunner::new();
    let client = client_with(&mock, &daemon.socket);
    client.down(VPNKind::Openvpn, &id()).unwrap();
    client.respond(&id(), AuthResponseKind::Crv1, "123456").unwrap();
    assert_eq!(mock.calls().len(), 2);
    assert!(daemon.requests().is_empty());
}

#[test]
fn dns_lines_only_for_root_15_or_newer() {
    use macvpn_core::dns_settings::{DnsMode, DnsRequest};
    let dns = DnsRequest { mode: DnsMode::Strict, ..Default::default() };
    for (version, sent) in [(None, false), (Some(14), false), (Some(15), true), (Some(16), true)] {
        let mock = MockCommandRunner::new();
        let client = MvpnClient::new(&mock).with_root_version(version);
        assert_eq!(client.dns_supported(), sent);
        client.up_with_dns(VPNKind::Openvpn, &id(), b"x", &Secrets::default(), false, &[], Some(&dns)).unwrap();
        let stdin = mock.calls()[0].stdin.clone().unwrap_or_default();
        assert_eq!(stdin.ends_with("dns-mode=strict\n"), sent, "{version:?}: {stdin:?}");
    }
    let read = |v: &'static str| move |_: &str| Some(v.to_string());
    assert_eq!(macvpn_platform_mac::mvpn_client::installed_root_version(read("15\n")), Some(15));
    assert_eq!(macvpn_platform_mac::mvpn_client::installed_root_version(read("x")), None);
}

#[test]
fn dns_check_reads_the_state_line() {
    use macvpn_core::status::DnsState;
    let mock = MockCommandRunner::new();
    let client = MvpnClient::new(&mock);
    // No answer configured: the mock's default (exit 0, empty) is not a state.
    assert_eq!(client.dns_check(&id()), None);
    let line = mock.calls()[0].command_line();
    assert!(line.contains("mvpn dns-check 11111111-2222-3333-4444-555555555555"), "{line}");
    mock.respond(&line, CommandResult { exit_code: 0, stdout: "fallback-full\n".into(), stderr: String::new() });
    assert_eq!(client.dns_check(&id()), Some(DnsState::FallbackFullTunnel));
    mock.respond(&line, CommandResult { exit_code: 1, stdout: String::new(), stderr: String::new() });
    assert_eq!(client.dns_check(&id()), None);
}

/// `dns-check` probes (up to 9 s in the root layer): it waits longer than the other questions, and a daemon that took
/// the question but gave no answer is never asked again through `sudo` (that would probe a second time).
#[test]
fn dns_check_waits_for_the_probe_and_is_not_repeated_through_sudo() {
    use macvpn_core::status::DnsState;
    let daemon = FakeDaemon::start_delayed(vec![Some(b"0\nfallback\n")], std::time::Duration::from_millis(2500));
    let mock = MockCommandRunner::new();
    assert_eq!(client_with(&mock, &daemon.socket).dns_check(&id()), Some(DnsState::Fallback));
    assert!(mock.calls().is_empty());
    assert_eq!(daemon.requests().len(), 1);
    let daemon = FakeDaemon::start(vec![None]);
    let mock = MockCommandRunner::new();
    assert_eq!(client_with(&mock, &daemon.socket).dns_check(&id()), None);
    assert!(mock.calls().is_empty(), "no second probe through sudo");
    // No daemon to reach (an older install, or not loaded): sudo.
    let missing = std::env::temp_dir().join(format!("mvqc-missing-{}.sock", Uuid::new_v4()));
    let mock = MockCommandRunner::new();
    let line =
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn dns-check 11111111-2222-3333-4444-555555555555 --lang en";
    mock.respond(line, CommandResult::stdout("vpn\n"));
    assert_eq!(client_with(&mock, &missing).dns_check(&id()), Some(DnsState::Vpn));
    assert_eq!(mock.calls().iter().map(|c| c.command_line()).collect::<Vec<_>>(), [line]);
}
