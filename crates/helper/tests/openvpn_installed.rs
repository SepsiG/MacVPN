//! The installed OpenVPN Community as the service sees it (read-only: detection needs no admin rights). Ignored
//! everywhere: the maintainer installs OpenVPN Community 2.7.8 with DCO and TAP-Windows6 on the test machine at
//! checkpoint CP1, then runs `cargo test --locked -p macvpn-helper --test openvpn_installed -- --ignored` as the
//! standard user (CI's windows-admin job installs it too).
#![cfg(all(windows, debug_assertions))]

#[test]
#[ignore = "needs OpenVPN Community installed (CP1; CI windows-admin installs it)"]
fn the_installed_openvpn_passes_every_trust_check() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mvpn")).arg("console-detect").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let facts = macvpn_core::service_proto::OpenVpnFacts::parse(text.trim().as_bytes()).expect("the facts as JSON");
    assert_eq!(facts.problem, None, "{text}");
    assert!(facts.dco.is_some() && facts.tap_windows6.is_some(), "{text}");
    assert!(facts.version.is_some() && facts.path.is_some(), "{text}");
}
