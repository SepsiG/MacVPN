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
