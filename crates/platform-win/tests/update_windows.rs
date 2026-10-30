//! The WinVPN updater's Windows parts that run as a standard user (the elevated msiexec is CP2's item): the
//! deny-write hold of the verified MSI, msiexec's log created new and held (P2-L3), the relauncher's wait for msiexec
//! and its notice, and the runner that drives System32's curl.exe.

#![cfg(windows)]

use macvpn_platform_win::pure::update::{self as up, Notice};
use macvpn_winsys::file::Protection;
use macvpn_winsys::sid::Sid;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("WinVPN-test-update-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn system32() -> PathBuf {
    let curl = macvpn_platform_win::windows_curl_for_tests();
    PathBuf::from(curl.executable).parent().unwrap().to_path_buf()
}

#[test]
fn a_held_msi_can_be_read_but_not_written_renamed_or_deleted() {
    let dir = scratch("hold");
    let msi = dir.join("WinVPN-1.6.0-x64.msi");
    std::fs::write(&msi, b"package").unwrap();
    let held = macvpn_platform_win::hold_for_tests(&msi).unwrap();
    assert_eq!(std::fs::read(&msi).unwrap(), b"package", "msiexec can still read it");
    assert!(std::fs::OpenOptions::new().write(true).open(&msi).is_err(), "no writer");
    assert!(std::fs::remove_file(&msi).is_err(), "no delete");
    assert!(std::fs::rename(&msi, dir.join("other.msi")).is_err(), "no rename");
    drop(held);
    std::fs::remove_file(&msi).unwrap();
    assert!(macvpn_platform_win::hold_for_tests(&dir).is_err(), "a directory is not held");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// msiexec's log (P2-L3): created new; a folder or junction under its name is refused, a stale regular file
/// replaced; while held, msiexec (another writer) can write it, but nobody can delete or rename it, nor rename the
/// folder it is in.
#[test]
fn the_msiexec_log_is_created_new_and_held_in_place() {
    let dir = scratch("log");
    let updates = dir.join("updates");
    std::fs::create_dir(&updates).unwrap();
    let log = updates.join("msiexec-1.6.0.log");

    std::fs::write(&log, b"stale").unwrap();
    let held = macvpn_platform_win::create_log_for_tests(&log).unwrap();
    assert_eq!(std::fs::read(&log).unwrap(), b"", "a new, empty file");
    let mut writer = std::fs::OpenOptions::new().write(true).open(&log).expect("msiexec can write it");
    std::io::Write::write_all(&mut writer, b"=== Verbose logging started").unwrap();
    drop(writer);
    assert!(std::fs::remove_file(&log).is_err(), "no delete");
    assert!(std::fs::rename(&log, updates.join("other.log")).is_err(), "no rename");
    assert!(std::fs::rename(&updates, dir.join("moved")).is_err(), "its folder cannot be renamed");
    drop(held);
    std::fs::remove_file(&log).unwrap();

    // Anything but a regular file under the name stays and is refused: a folder, a junction.
    std::fs::create_dir(&log).unwrap();
    assert!(macvpn_platform_win::create_log_for_tests(&log).is_err(), "a folder is refused");
    assert!(log.is_dir(), "and left alone");
    std::fs::remove_dir(&log).unwrap();
    let elsewhere = dir.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::create_dir(&log).unwrap();
    macvpn_winsys::file::make_junction_for_tests(&log, &format!(r"\??\{}", elsewhere.display())).unwrap();
    assert!(macvpn_platform_win::create_log_for_tests(&log).is_err(), "a junction is refused");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing is written through it");
    std::fs::remove_dir(&log).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A folder only this user and SYSTEM can open, as the real `%LOCALAPPDATA%\WinVPN\updates`.
fn private_scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("WinVPN-test-update-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    macvpn_winsys::file::create_dir(&dir, Some(Protection::Private)).unwrap();
    dir
}

/// The rights an account other than this user would get (the system's access check, no sign-in): with `admin` an
/// elevated administrator, as msiexec runs after a standard user's UAC prompt (over the shoulder: an
/// administrator's credentials), else another standard user.
fn granted_to_another(path: &Path, admin: bool) -> u32 {
    let f = std::fs::File::open(path).unwrap();
    let user = Sid::parse("S-1-5-21-1-2-3-1001").unwrap();
    let mut groups =
        vec![Sid::builtin_users(), Sid::interactive(), Sid::parse("S-1-1-0").unwrap(), Sid::parse("S-1-5-11").unwrap()];
    if admin {
        groups.push(Sid::builtin_administrators());
    }
    macvpn_winsys::file::access_for(&f, &user, &groups).unwrap()
}

const READ: u32 = 0x0012_0089; // FILE_GENERIC_READ
const WRITE: u32 = 0x0012_0116; // FILE_GENERIC_WRITE
const TAKE_OVER: u32 = 0x0001_0000 | 0x0004_0000 | 0x0008_0000; // DELETE, WRITE_DAC, WRITE_OWNER

fn shape_of(path: &Path) -> Option<Protection> {
    macvpn_winsys::file::info(&std::fs::File::open(path).unwrap()).unwrap().protection
}

/// 2.1.1 on a standard user's account: the elevated msiexec runs as the administrator whose credentials the UAC
/// prompt asked for, and the log 2.1.1 created inherited the private updates folder's DACL (this user and SYSTEM):
/// "error opening the installation log file". The log is now exactly `AdminsReadWrite`: that administrator may read
/// and write it (msiexec truncates and writes it), never delete it or change its DACL; nobody else may open it.
#[test]
fn the_msiexec_log_is_writable_by_the_administrator_the_uac_prompt_runs_msiexec_as() {
    let dir = private_scratch("log-acl");
    let log = dir.join("msiexec-1.6.0.log");
    // What 2.1.1 did: a file inheriting the private folder's DACL, which the elevated account cannot open.
    std::fs::write(&log, b"").unwrap();
    assert_eq!(granted_to_another(&log, true), 0, "2.1.1's log");
    let held = macvpn_platform_win::create_log_for_tests(&log).unwrap();
    assert_eq!(shape_of(&log), Some(Protection::AdminsReadWrite));
    let admin = granted_to_another(&log, true);
    assert_eq!(admin & (READ | WRITE), READ | WRITE, "{admin:#x}");
    assert_eq!(admin & TAKE_OVER, 0, "{admin:#x}");
    assert_eq!(granted_to_another(&log, false), 0, "another standard user");
    drop(held);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The verified MSI in the private updates folder: opened to every account for reading (`Shared`: WinVPN's public,
/// signed installer), changeable only by this user and SYSTEM, then held deny-write.
#[test]
fn the_msi_is_readable_by_the_administrator_the_uac_prompt_runs_msiexec_as() {
    let dir = private_scratch("msi-acl");
    let msi = dir.join("WinVPN-1.6.0-x64.msi");
    std::fs::write(&msi, b"package").unwrap();
    assert_eq!(granted_to_another(&msi, true), 0, "2.1.1's package");
    let held = macvpn_platform_win::hold_for_msiexec_for_tests(&msi).unwrap();
    assert_eq!(shape_of(&msi), Some(Protection::Shared));
    for admin in [true, false] {
        let g = granted_to_another(&msi, admin);
        assert_eq!(g & READ, READ, "{g:#x}");
        assert_eq!(g & (0x0002 | 0x0004 | TAKE_OVER), 0, "no write, append, delete or DACL change: {g:#x}");
    }
    assert!(std::fs::OpenOptions::new().write(true).open(&msi).is_err(), "still held deny-write");
    drop(held);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The elevated step's inputs are never private: the relauncher (the last check before the UAC prompt) holds the
/// MSI and the log only with exactly the DACLs that open them to the elevated account, and refuses otherwise, so
/// nothing is elevated that msiexec could not open.
#[test]
fn the_relauncher_refuses_a_package_or_log_the_elevated_msiexec_could_not_open() {
    let dir = private_scratch("relauncher-acl");
    let msi = dir.join("WinVPN-1.6.0-x64.msi");
    let log = dir.join("msiexec-1.6.0.log");
    std::fs::write(&msi, b"package").unwrap();
    let sha256 = macvpn_core::update::sha256_hex(b"package");
    let relaunch = up::Relaunch { target: dir.join("WinVPN.exe"), msi: msi.clone(), sha256, log: log.clone() };

    // 2.1.1's files: both private by inheritance.
    std::fs::write(&log, b"").unwrap();
    let refused = macvpn_platform_win::relauncher_holds_for_tests(&relaunch, &dir).unwrap_err();
    assert!(refused.contains("package"), "{refused}");
    // The MSI opened to the installer, the log still private.
    drop(macvpn_platform_win::hold_for_msiexec_for_tests(&msi).unwrap());
    let refused = macvpn_platform_win::relauncher_holds_for_tests(&relaunch, &dir).unwrap_err();
    assert!(refused.contains("log"), "{refused}");
    // Both as the updater makes them: held.
    let log_hold = macvpn_platform_win::create_log_for_tests(&log).unwrap();
    let (held_msi, held_log) = macvpn_platform_win::relauncher_holds_for_tests(&relaunch, &dir).unwrap();
    assert_eq!(granted_to_another(&msi, true) & READ, READ);
    assert_eq!(granted_to_another(&log, true) & (READ | WRITE), READ | WRITE);
    drop((held_msi, held_log, log_hold));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_relauncher_waits_for_the_named_process_and_reads_its_exit_code() {
    let cmd = system32().join("cmd.exe");
    let mut child = Command::new(&cmd).args(["/c", "exit 1603"]).spawn().unwrap();
    // The child's handle stays open, so the PID still names it after it exited.
    assert_eq!(macvpn_platform_win::wait_for_exit_for_tests(child.id(), "CMD.EXE", Duration::from_secs(20)), Ok(1603));
    // An exited process' image cannot be read any more: it counts as gone (no notice).
    assert_eq!(
        macvpn_platform_win::wait_for_exit_for_tests(child.id(), "msiexec.exe", Duration::from_secs(20)),
        Err("Gone".to_string())
    );
    child.wait().unwrap();

    let mut slow = Command::new(&cmd).args(["/c", "ping -n 30 127.0.0.1 >nul"]).spawn().unwrap();
    assert_eq!(
        macvpn_platform_win::wait_for_exit_for_tests(slow.id(), "msiexec.exe", Duration::from_secs(20)),
        Err("NotIt".to_string()),
        "another program under the PID is not waited for"
    );
    assert_eq!(
        macvpn_platform_win::wait_for_exit_for_tests(slow.id(), "cmd.exe", Duration::from_millis(300)),
        Err("TimedOut".to_string())
    );
    slow.kill().unwrap();
    slow.wait().unwrap();
    assert_eq!(
        macvpn_platform_win::wait_for_exit_for_tests(0, "msiexec.exe", Duration::from_secs(1)),
        Err("Gone".to_string())
    );
}

#[test]
fn the_relaunchers_notice_is_shown_once_at_the_next_launch() {
    let dir = scratch("notice");
    let log = dir.join("msiexec-1.6.0.log");
    let written = macvpn_platform_win::write_notice_for_tests(&dir, 1603, &log).unwrap();
    assert_eq!(written.run.len(), 32);
    let read = Notice::parse(&std::fs::read_to_string(dir.join(up::NOTICE_FILE)).unwrap()).unwrap();
    assert_eq!(read, written);
    let (_, notice) = up::housekeeping(&dir, None, SystemTime::now());
    assert_eq!(notice, Some((written.run.clone(), written.message().unwrap())));
    assert_eq!(up::housekeeping(&dir, None, SystemTime::now()).1, None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_runner_drives_system32_programs_with_a_minimal_environment_and_a_time_limit() {
    // The updater's runner is the curl layer's (`win::curl_runner`, also tested by `tests/curl.rs`).
    let curl = macvpn_platform_win::windows_curl_for_tests();
    let runner = macvpn_platform_win::curl_runner_for_tests(30.0);
    assert!(curl.executable.to_ascii_lowercase().ends_with(r"\system32\curl.exe"), "{}", curl.executable);
    assert_eq!(curl.extra_args, ["--ssl-revoke-best-effort"]);
    let version = runner.run(&curl.executable, &["--version".to_string()], None).unwrap();
    assert_eq!(version.exit_code, 0, "{}", version.stderr);
    assert!(version.stdout.starts_with("curl "), "{}", version.stdout);

    let cmd = system32().join("cmd.exe").to_string_lossy().into_owned();
    let env = runner.run(&cmd, &["/c".to_string(), "set".to_string()], None).unwrap();
    assert!(env.stdout.lines().any(|l| l.to_ascii_lowercase().starts_with("systemroot=")), "{}", env.stdout);
    for leaked in ["USERPROFILE=", "TEMP=", "APPDATA="] {
        assert!(!env.stdout.lines().any(|l| l.to_ascii_uppercase().starts_with(leaked)), "{leaked} in {}", env.stdout);
    }

    let findstr = system32().join("findstr.exe").to_string_lossy().into_owned();
    let echoed = runner.run(&findstr, &["^".to_string()], Some("token-on-stdin\r\n")).unwrap();
    assert!(echoed.stdout.contains("token-on-stdin"), "stdin reaches the program: {echoed:?}");

    let quick = macvpn_platform_win::curl_runner_for_tests(0.3);
    let ping = system32().join("PING.EXE").to_string_lossy().into_owned();
    let stopped = quick.run(&ping, &["-n".to_string(), "30".to_string(), "127.0.0.1".to_string()], None);
    assert_eq!(stopped, Err(macvpn_platform_api::curl::CommandError::TimedOut(ping)));

    // The private directory of a download is fresh each time and removed by the curl layer's caller.
    let a = (curl.private_dir)("WinVPN-test-dl").unwrap();
    let b = (curl.private_dir)("WinVPN-test-dl").unwrap();
    assert_ne!(a, b);
    for d in [a, b] {
        assert!(d.is_dir());
        std::fs::remove_dir(d).unwrap();
    }
}
