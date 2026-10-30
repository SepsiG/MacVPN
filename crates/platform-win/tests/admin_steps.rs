//! The administrator steps on Windows (WinVPN 2c Task 12), as the standard user over SSH: the staged certificate
//! file and the read-only store check. The UAC steps themselves are checkpoint items (CP1): their test is ignored
//! ("desktop: UAC").

#![cfg(windows)]

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_platform_win::pure::admin_steps;
use macvpn_platform_win::{admin_steps_for_tests, admin_steps_with_trust_exe_for_tests, stage_ca_for_tests};
use std::fs;
use std::path::PathBuf;

const CA_PEM: &str = include_str!("fixtures/ca/ca.pem");
const LEAF_PEM: &str = include_str!("fixtures/ca/leaf.pem");

/// A fresh directory under the user's temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("winvpn-admin-steps-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_staged_ca_file_is_held_against_changes_and_deleted() {
    let scratch = Scratch::new();
    let der = b"\x30\x03\x02\x01\x00".to_vec();
    let (path, guard) = stage_ca_for_tests(&scratch.0, &der).unwrap();
    assert_eq!(path.parent(), Some(scratch.0.as_path()));
    let name = path.file_name().unwrap().to_str().unwrap().to_string();
    assert!(name.starts_with("ca-") && name.ends_with(".cer") && name.len() == "ca-.cer".len() + 32, "{name}");
    // The elevated step (any reader) reads exactly what WinVPN wrote; nobody can change, rename or delete it meanwhile.
    assert_eq!(fs::read(&path).unwrap(), der);
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::OpenOptions::new().append(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    assert!(fs::rename(&path, scratch.0.join("other.cer")).is_err());
    // Its path is an acceptable argument of the elevated trust step.
    let args = admin_steps::trust_step_args(&path).unwrap();
    assert_eq!(args[0], "--winvpn-trust-ca-step");
    assert_eq!(admin_steps::parse_trust_step(&args), Some(Some(path.clone())));
    assert!(admin_steps::parameters(&args).is_some());
    drop(guard);
    assert!(!path.exists(), "deleted with its guard");
    // Two stagings never share a name.
    let (a, _ga) = stage_ca_for_tests(&scratch.0, &der).unwrap();
    let (b, _gb) = stage_ca_for_tests(&scratch.0, &der).unwrap();
    assert_ne!(a, b);
}

/// The elevated trust step runs as the administrator whose credentials a standard user's UAC prompt asked for,
/// another account: the staged certificate is exactly `Shared` (that account, like every other, may read it; only
/// this user and SYSTEM may change it), whatever the folder's own permissions are.
#[test]
fn the_staged_ca_file_is_readable_by_the_administrator_the_uac_prompt_runs_the_step_as() {
    use macvpn_winsys::file::{self, Protection};
    use macvpn_winsys::sid::Sid;
    let scratch = Scratch::new();
    let private = scratch.0.join("private");
    file::create_dir(&private, Some(Protection::Private)).unwrap();
    let der = b"\x30\x03\x02\x01\x00".to_vec();
    let (path, guard) = stage_ca_for_tests(&private, &der).unwrap();
    let f = fs::File::open(&path).unwrap();
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Shared));
    let other = Sid::parse("S-1-5-21-1-2-3-1001").unwrap();
    let admin =
        [Sid::builtin_administrators(), Sid::builtin_users(), Sid::interactive(), Sid::parse("S-1-1-0").unwrap()];
    let granted = file::access_for(&f, &other, &admin).unwrap();
    const READ: u32 = 0x0012_0089;
    assert_eq!(granted & READ, READ, "{granted:#x}");
    assert_eq!(granted & (0x0002 | 0x0004 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000), 0, "{granted:#x}");
    drop(f);
    drop(guard);
}

/// A file the step's own account may not open (here: one only Administrators may read, while the tests run as a
/// standard user, as the private folder left out the elevating administrator): its own code and text, never a
/// refused CA, and the store is never touched.
#[test]
fn a_ca_file_the_elevated_step_may_not_open_is_not_readable_not_refused() {
    use macvpn_winsys::file::{self, Protection};
    let scratch = Scratch::new();
    let path = scratch.0.join(format!("ca-{}.cer", "0".repeat(32)));
    fs::write(&path, include_bytes!("fixtures/ca/ca.pem")).unwrap();
    let open = file::Open {
        read: false,
        write: true,
        append: false,
        disposition: file::Disposition::OpenExisting,
        protection: None,
        no_follow: true,
    };
    let f = file::open(&path, open).unwrap();
    file::set_protection(&f, Protection::Admins, false).unwrap();
    drop(f);
    if fs::File::open(&path).is_ok() {
        eprintln!("running as an administrator: the Administrators-only file is readable, nothing to check");
        return;
    }
    let args = admin_steps::trust_step_args(&path).unwrap();
    let code = macvpn_platform_win::trust_ca_elevated_step(&args).unwrap();
    assert_eq!(code, admin_steps::TrustStep::NotReadable.code());
}

#[test]
fn the_ca_check_reads_the_computer_root_store() {
    let steps = admin_steps_for_tests();
    // The test CA is not trusted on the test machine (the store is only read).
    assert_eq!(steps.ca_trusted(CA_PEM), Some(false));
    assert_eq!(steps.ca_trusted(LEAF_PEM), None, "not a CA: nothing to check");
    let summary = steps.ca_summary(CA_PEM).unwrap();
    assert_eq!(summary.subject, "CN=WinVPN Test CA, O=Example, C=HU");
    assert!(steps.ca_summary(LEAF_PEM).is_err());
}

/// The trust step runs only an exe administrators alone can change (the installed WinVPN): a test's own exe in
/// `target` is refused before any file is staged or any UAC prompt.
#[test]
fn the_trust_step_needs_an_installed_winvpn() {
    let refused = with_language(AppLanguage::En, || admin_steps_for_tests().trust_ca(CA_PEM));
    assert_eq!(refused, Err("Only a WinVPN installed in Program Files can add a CA to Windows.".into()));
    assert!(admin_steps_for_tests().trust_ca(LEAF_PEM).is_err(), "not a CA");
}

/// CP1 (an administrator at the desktop confirms the UAC prompt, with this build's MSI installed): the installed
/// `WinVPN.exe --winvpn-trust-ca-step` adds the test CA to the computer's Trusted Root store for server and client
/// authentication only (M-1 of the 2.0.0 security review). Remove it afterwards: `certutil -delstore Root
/// 53cdc417ceda8000a2fcfd50eb98f4d80c9cde2f` (elevated).
#[test]
#[ignore = "desktop: UAC"]
fn trusting_a_ca_adds_it_to_the_computer_root_store() {
    let steps = admin_steps_with_trust_exe_for_tests(std::path::Path::new(r"C:\Program Files\WinVPN\WinVPN.exe"));
    let done = steps.trust_ca(CA_PEM).unwrap();
    assert!(!done.is_empty());
    assert_eq!(steps.ca_trusted(CA_PEM), Some(true));
    let sha1 = macvpn_platform_win::pure::ca_trust::read(CA_PEM, 1_800_000_000).unwrap().sha1;
    let presence =
        macvpn_winsys::cert_store::presence(macvpn_winsys::cert_store::Location::LocalMachine, "Root", &sha1);
    assert_eq!(
        presence.unwrap(),
        macvpn_winsys::cert_store::Presence::Present { usage: Some(admin_steps::TLS_ONLY_EKU.to_vec()) }
    );
}
