//! Port of `CommandRunnerTests.swift`.
#![cfg(target_os = "macos")]

use macvpn_platform_mac::command::{CancelToken, CommandError, CommandRunner, ProcessCommandRunner, RunnerTimeouts};
use std::time::{Duration, Instant};

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn runs_process_with_stdin() {
    let r = ProcessCommandRunner::default().run("/bin/cat", &[], Some("hello\n")).unwrap();
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout, "hello\n");
}

#[test]
fn captures_stderr_and_exit_code() {
    let r = ProcessCommandRunner::default().run("/bin/sh", &args(&["-c", "echo oops >&2; exit 3"]), None).unwrap();
    assert_eq!(r.exit_code, 3);
    assert_eq!(r.stderr, "oops\n");
}

#[test]
fn returns_when_background_child_holds_pipe() {
    let start = Instant::now();
    let r = ProcessCommandRunner::default().run("/bin/sh", &args(&["-c", "sleep 5 & echo done"]), None).unwrap();
    assert_eq!(r.stdout, "done\n");
    assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
}

#[test]
fn timeout_returns_timed_out() {
    let start = Instant::now();
    let e = ProcessCommandRunner::new(0.5).run("/bin/sleep", &args(&["5"]), None).unwrap_err();
    assert_eq!(e, CommandError::TimedOut("/bin/sleep".into()));
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn timeout_escalates_to_sigkill() {
    // The child ignores SIGTERM: SIGKILL follows after 2 s.
    let start = Instant::now();
    let e = ProcessCommandRunner::new(0.3).run("/bin/sh", &args(&["-c", "trap '' TERM; sleep 10"]), None).unwrap_err();
    assert_eq!(e, CommandError::TimedOut("/bin/sh".into()));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(6), "{elapsed:?}");
}

#[test]
fn large_stdin_to_non_reading_child_does_not_crash_or_hang() {
    let big = "x".repeat(1_000_000);
    let r = ProcessCommandRunner::default().run("/usr/bin/true", &[], Some(&big)).unwrap();
    assert_eq!(r.exit_code, 0);
}

#[test]
fn large_stdin_is_delivered_fully() {
    let big = "y".repeat(3_000_000);
    let r = ProcessCommandRunner::default().run("/usr/bin/wc", &args(&["-c"]), Some(&big)).unwrap();
    assert_eq!(r.stdout.trim(), "3000000");
}

/// `run_bytes`: the stdin as raw bytes (not forced through UTF-8), large payloads delivered whole.
#[test]
fn bytes_stdin_is_delivered_unchanged() {
    let mut data = b"config 3\n\xff\x00\x01".to_vec();
    data.extend(std::iter::repeat_n(b'z', 1_200_000));
    let r = ProcessCommandRunner::default().run_bytes("/usr/bin/wc", &args(&["-c"]), &data).unwrap();
    assert_eq!(r.stdout.trim(), data.len().to_string());
    let r = ProcessCommandRunner::default().run_bytes("/usr/bin/od", &args(&["-An", "-tx1", "-N12"]), &data).unwrap();
    assert_eq!(r.stdout.split_whitespace().collect::<Vec<_>>()[9..], ["ff", "00", "01"]);
}

#[test]
fn large_stdout_captured_fully() {
    let r = ProcessCommandRunner::default()
        .run("/bin/sh", &args(&["-c", "head -c 2097152 /dev/zero | tr '\\0' 'a'"]), None)
        .unwrap();
    assert_eq!(r.stdout.len(), 2_097_152);
}

#[test]
fn large_stdout_and_stderr_interleaved_do_not_deadlock() {
    let r = ProcessCommandRunner::default()
        .run("/bin/sh", &args(&["-c", "head -c 1048576 /dev/zero >&2; head -c 1048576 /dev/zero"]), None)
        .unwrap();
    assert_eq!((r.stdout.len(), r.stderr.len()), (1_048_576, 1_048_576));
}

#[test]
fn cancellation_terminates_process() {
    let start = Instant::now();
    let token = CancelToken::new();
    let runner = ProcessCommandRunner::default().with_cancel(token.clone());
    let handle = std::thread::spawn(move || runner.run("/bin/sleep", &["5".to_string()], None));
    std::thread::sleep(Duration::from_millis(200));
    token.cancel();
    let result = handle.join().unwrap();
    assert_eq!(result.unwrap_err(), CommandError::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(2));
    // A cancelled token stops the next run before it starts.
    let runner = ProcessCommandRunner::default().with_cancel(token);
    assert_eq!(runner.run("/usr/bin/true", &[], None).unwrap_err(), CommandError::Cancelled);
}

#[test]
fn missing_executable_is_an_error() {
    assert!(matches!(ProcessCommandRunner::default().run("/nonexistent/x", &[], None), Err(CommandError::Io(_))));
}

#[test]
fn runner_timeout_budget() {
    // mvpn up in the worst case: 45 s lock wait + 30 s connecting + snapshots, taking down an earlier run, with MFA
    // at most 420 s more waiting for authentication (mvpn's MFA_MAX).
    assert_eq!(RunnerTimeouts::UP, 600.0);
    const { assert!(RunnerTimeouts::UP > 45.0 + 30.0 + 45.0 + 420.0) };
    assert_eq!(RunnerTimeouts::QUICK, 20.0);
    const { assert!(RunnerTimeouts::QUICK < RunnerTimeouts::STANDARD) };
    assert_eq!(RunnerTimeouts::STANDARD, ProcessCommandRunner::default().timeout);
}

#[test]
fn timeout_message_is_localized() {
    use macvpn_core::l10n::{AppLanguage, with_language};
    let e = CommandError::TimedOut("/bin/sleep".into());
    assert_eq!(with_language(AppLanguage::En, || e.to_string()), "The command was stopped after a timeout: /bin/sleep");
    assert_ne!(with_language(AppLanguage::Hu, || e.to_string()), "The command was stopped after a timeout: /bin/sleep");
}

/// `with_environment`: the child sees exactly the given variables, nothing inherited.
#[test]
fn environment_is_cleared_and_replaced() {
    let env: std::collections::BTreeMap<String, String> =
        [("PATH", "/usr/bin:/bin"), ("LANG", "C")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let r = ProcessCommandRunner::default().with_environment(env).run("/usr/bin/env", &[], None).unwrap();
    let mut lines: Vec<&str> = r.stdout.lines().collect();
    lines.sort();
    assert_eq!(lines, ["LANG=C", "PATH=/usr/bin:/bin"]);
    // Without it, the parent's environment is inherited (e.g. HOME).
    let r = ProcessCommandRunner::default().run("/usr/bin/env", &[], None).unwrap();
    assert!(r.stdout.lines().count() > 2);
}
