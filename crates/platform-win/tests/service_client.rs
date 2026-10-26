//! The app's client of the WinVPN Service against the service's debug console mode (`mvpn console --fake-engine`)
//! over a real pipe, as a standard user. The console exists only in debug builds, so these tests too.
#![cfg(all(windows, debug_assertions))]

use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Secrets, VPNKind};
use macvpn_core::service_proto::SERVICE_VERSION;
use macvpn_platform_win::pure::engine::{Reach, report};
use macvpn_platform_win::pure::openvpn_install::Upgrade;
use macvpn_platform_win::pure::texts;
use macvpn_platform_win::pure::wireguard_update::Offer;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const WG: &[u8] = b"[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";

fn test_pipe() -> String {
    format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4())
}

/// `mvpn console --fake-engine` on a new test pipe and data directory; stopped (stdin closed) and removed on drop.
struct Console {
    child: Child,
    pipe: String,
    data: std::path::PathBuf,
}

impl Console {
    fn start() -> Console {
        let pipe = test_pipe();
        let data = std::env::temp_dir().join(format!("winvpn-client-{}", uuid::Uuid::new_v4()));
        let mut child = Command::new(macvpn_platform_win::helper_console_for_tests())
            .args(["console", "--pipe", &pipe, "--data", data.to_str().unwrap(), "--fake-engine"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");
        Console { child, pipe, data }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

#[test]
fn the_client_connects_reads_status_and_the_log_through_the_service() {
    let c = Console::start();
    let client = macvpn_platform_win::service_client_for_tests(&c.pipe);
    let id = uuid::Uuid::new_v4();
    let secrets = Secrets { password: Some("s3cret-Pa55".into()), ..Secrets::default() };
    client.helper().up(VPNKind::Wireguard, &id, WG, &secrets, false, &[]).unwrap();
    let st = client.helper().status().unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].id, id);
    assert_eq!(st[0].state, "connected");
    // The live log through the service: the fake engine's lines, the password masked.
    let mut src = client.helper().log_source(&id).unwrap();
    let read = src.read(0, 1 << 20).unwrap();
    let text = String::from_utf8_lossy(&read.data).to_string();
    assert!(text.contains("fake engine: starting"), "{text}");
    assert!(!text.contains("s3cret-Pa55"), "{text}");
    assert!(matches!(read.identity, Some(macvpn_core::log::LogIdentity::Generation(g)) if g > 0));
    // Reading past the end gives no bytes; at most `max` bytes come back.
    assert!(src.read(read.size, 1 << 20).unwrap().data.is_empty());
    assert!(src.read(0, 4).unwrap().data.len() <= 4);
    // No MFA prompt; an MFA answer for a WireGuard connection is refused by the service.
    assert_eq!(client.auth_state().read(&id), None);
    assert!(client.helper().respond(&id, AuthResponseKind::Static, "123456").is_err());
    // An invalid code never reaches the pipe.
    let e = client.helper().respond(&id, AuthResponseKind::Static, "12\n34").unwrap_err();
    assert_eq!(e, macvpn_core::mfa::MFAError::InvalidCode.message());
    client.helper().down(VPNKind::Wireguard, &id).unwrap();
    assert!(client.helper().status().unwrap().is_empty());
    // An unknown ID: the service's own message, no log.
    let other = uuid::Uuid::new_v4();
    assert!(client.helper().down(VPNKind::Wireguard, &other).is_err());
    assert!(client.helper().log_source(&other).unwrap().read(0, 1024).is_none());
}

#[test]
fn the_service_messages_come_back_in_the_apps_language() {
    let c = Console::start();
    let client = macvpn_platform_win::service_client_for_tests(&c.pipe);
    let id = uuid::Uuid::new_v4();
    let bad = b"[Interface]\nPrivateKey = x\n";
    let en = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        client.helper().up(VPNKind::Wireguard, &id, bad, &Secrets::default(), false, &[]).unwrap_err()
    });
    let hu = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::Hu, || {
        client.helper().up(VPNKind::Wireguard, &id, bad, &Secrets::default(), false, &[]).unwrap_err()
    });
    assert!(en.starts_with("Invalid config:"), "{en}");
    assert_ne!(en, hu);
}

#[test]
fn system_status_reads_the_services_facts() {
    let c = Console::start();
    let client = macvpn_platform_win::service_client_for_tests(&c.pipe);
    let Reach::Facts(f) = client.reach() else { panic!("no facts") };
    assert_eq!(f.service_version, SERVICE_VERSION);
    assert_eq!(f.problem, None);
    let r = report(Reach::Facts(f), "2.7.8", &Upgrade::Unknown, &Offer::Unknown);
    assert_eq!(r.engine_missing, None);
    let e = r.engine.unwrap();
    assert!(e.service.ok);
    // Without OpenVPN Community the row is red with "Install"; with OpenVPN and both drivers (the maintainer's CP2
    // winget install on the test machine) it is green, and with the update check unknown it offers no action.
    if std::path::Path::new(r"C:\Program Files\OpenVPN\bin\openvpn.exe").exists() {
        assert_eq!(e.openvpn.action, None, "{:?}", e.openvpn);
        assert!(e.openvpn.ok);
    } else {
        assert_eq!(e.openvpn.action, Some("install"));
    }
}

#[test]
fn engine_updates_the_service_cannot_answer_are_unknown_never_an_error_row() {
    // The fake engine has no updates: the check is "unknown" (no row change), the update the service's message.
    let c = Console::start();
    let client = macvpn_platform_win::service_client_for_tests(&c.pipe);
    assert_eq!(client.wireguard_check(), Offer::Unknown);
    let r = client.wireguard_update();
    assert!(r.as_ref().is_err_and(|m| !m.is_empty()), "{r:?}");
    // No service at all: unknown too.
    let none = macvpn_platform_win::service_client_for_tests(&test_pipe());
    assert_eq!(none.wireguard_check(), Offer::Unknown);
    assert_eq!(none.wireguard_update(), Err(texts::service_unreachable()));
}

#[test]
fn no_service_is_engine_missing() {
    let client = macvpn_platform_win::service_client_for_tests(&test_pipe());
    assert_eq!(client.reach(), Reach::Absent);
    assert_eq!(client.helper().status().unwrap_err(), texts::service_missing());
    let id = uuid::Uuid::new_v4();
    assert_eq!(
        client.helper().up(VPNKind::Wireguard, &id, WG, &Secrets::default(), false, &[]).unwrap_err(),
        texts::service_missing()
    );
    assert_eq!(client.auth_state().read(&id), None);
    assert!(client.helper().log_source(&id).unwrap().read(0, 1024).is_none());
}

#[test]
fn a_user_owned_pipe_named_like_the_service_is_refused() {
    // The production client trusts only SYSTEM: a pipe of this user is "not the service", nothing is sent.
    use macvpn_winsys::pipe::{Endpoint, Listener};
    let pipe = test_pipe();
    let l = Listener::bind_endpoint(&pipe, Endpoint::ServiceForTests).unwrap();
    let squatter = std::thread::spawn(move || {
        let mut received = Vec::new();
        // Each client call opens one instance; read whatever arrives until the client leaves.
        for _ in 0..3 {
            if let Ok(Some((mut s, _))) = l.accept(Duration::from_secs(10)) {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                received.extend(buf);
            }
        }
        received
    });
    let client = macvpn_platform_win::service_client_trusting_system_for_tests(&pipe);
    assert_eq!(client.helper().status().unwrap_err(), texts::service_unreachable());
    let id = uuid::Uuid::new_v4();
    let secrets = Secrets { password: Some("s3cret-Pa55".into()), ..Secrets::default() };
    let e = client.helper().up(VPNKind::Wireguard, &id, WG, &secrets, false, &[]).unwrap_err();
    assert_eq!(e, texts::service_unreachable());
    assert_eq!(client.reach(), Reach::Unreachable(texts::service_unreachable()));
    assert!(squatter.join().unwrap().is_empty(), "the squatter received bytes");
}
