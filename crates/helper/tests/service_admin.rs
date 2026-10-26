//! Checks of the installed WinVPN Service (CI's windows-admin job after installing the MSI; the maintainer in an
//! elevated Git Bash on the VM).
#![cfg(windows)]

use macvpn_core::service_proto::{self as proto, EngineFacts, PIPE_NAME, SERVICE_VERSION};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::time::Duration;

fn call(args: &[&str]) -> proto::Response {
    let mut s = pipe::connect_with(PIPE_NAME, Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    proto::write_request(&mut s, args, b"").unwrap();
    proto::read_response(&mut s).unwrap()
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service"]
fn admin_the_installed_service_answers() {
    assert_eq!(call(&["version"]).stdout, format!("{SERVICE_VERSION}\n").into_bytes());
    let facts = EngineFacts::parse(&call(&["engine"]).stdout).unwrap();
    assert_eq!(facts.problem, None, "the data directory must be in order");
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service"]
fn admin_the_data_directory_is_system_and_administrators_only() {
    let out =
        std::process::Command::new(r"C:\Windows\System32\icacls.exe").arg(r"C:\ProgramData\WinVPN").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("NT AUTHORITY\\SYSTEM:(OI)(CI)(F)") || text.contains("NT AUTHORITY\\SYSTEM:(OI)(CI)F"),
        "{text}"
    );
    assert!(
        text.contains("BUILTIN\\Administrators:(OI)(CI)(F)") || text.contains("BUILTIN\\Administrators:(OI)(CI)F"),
        "{text}"
    );
    assert!(
        !text.contains("BUILTIN\\Users") && !text.contains("Everyone") && !text.contains("Authenticated Users"),
        "{text}"
    );
    // Protected: nothing inherited from C:\ProgramData.
    assert!(!text.contains("(I)"), "{text}");
}

/// The recovery settings the service sets at its start (Windows Installer cannot: error 1939).
#[test]
#[ignore = "admin: needs the installed WinVPN Service"]
fn admin_the_installed_service_restarts_after_a_failure() {
    let sc = |what: &str| {
        let out = std::process::Command::new(r"C:\Windows\System32\sc.exe").args([what, "WinVPN"]).output().unwrap();
        // One space between words: sc.exe pads its columns.
        String::from_utf8_lossy(&out.stdout).split_whitespace().collect::<Vec<_>>().join(" ")
    };
    let failure = sc("qfailure");
    assert!(failure.contains("RESET_PERIOD (in seconds) : 86400"), "{failure}");
    assert!(
        failure.contains("RESTART -- Delay = 5000 milliseconds. RESTART -- Delay = 30000 milliseconds."),
        "{failure}"
    );
    let flag = sc("qfailureflag");
    assert!(flag.contains("FAILURE_ACTIONS_ON_NONCRASH_FAILURES: TRUE"), "{flag}");
}
