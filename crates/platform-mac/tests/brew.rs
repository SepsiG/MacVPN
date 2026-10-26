//! Port of `BrewBootstrapTests.swift`, plus the brew install runner (the app's `BrewInstaller`).
#![cfg(target_os = "macos")]

mod common;

use common::{Scratch, mode};
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_platform_api::{OutdatedPackage, PackageIndexUpdate};
use macvpn_platform_mac::brew::{BrewBootstrap, BrewEnvironment, BrewGuard, BrewInstaller, BrewOutdated, BrewUpdate};
use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::testing::MockCommandRunner;
use std::collections::BTreeMap;
use std::process::Command;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn environment_is_minimal() {
    let env = BrewEnvironment::make(
        &map(&[
            ("HOME", "/Users/bob"),
            ("USER", "bob"),
            ("LOGNAME", "bob"),
            ("TMPDIR", "/var/folders/x/T/"),
            ("LANG", "hu_HU.UTF-8"),
            ("PATH", "/evil:/usr/bin"),
            ("HOMEBREW_GITHUB_API_TOKEN", "t"),
            ("HOMEBREW_BREW_GIT_REMOTE", "https://evil"),
            ("DYLD_INSERT_LIBRARIES", "/x.dylib"),
            ("RUBYOPT", "-r/x"),
            ("SSH_AUTH_SOCK", "/s"),
        ]),
        "/opt/homebrew",
    );
    assert_eq!(
        env,
        map(&[
            ("HOME", "/Users/bob"),
            ("USER", "bob"),
            ("LOGNAME", "bob"),
            ("TMPDIR", "/var/folders/x/T/"),
            ("LANG", "hu_HU.UTF-8"),
            ("PATH", "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin"),
            ("HOMEBREW_NO_ENV_HINTS", "1"),
        ])
    );
    assert_eq!(
        BrewEnvironment::make(&BTreeMap::new(), "/usr/local").keys().cloned().collect::<Vec<_>>(),
        ["HOMEBREW_NO_ENV_HINTS", "PATH"]
    );
}

#[test]
fn script_aborts_when_the_download_fails() {
    let script = BrewBootstrap::script("Start", "Done", "It's broken", "/tmp/d x");
    assert!(script.starts_with("#!/bin/bash\n"));
    assert!(script.contains(&format!(
        "s=$(/usr/bin/curl -fsSL {}) || {{ echo 'It'\\''s broken'; exit 1; }}\n",
        BrewBootstrap::INSTALLER_URL
    )));
    assert!(script.contains("/bin/bash -c \"$s\"\n"));
    assert!(script.contains("trap 'rm -rf -- '\\''/tmp/d x'\\''' EXIT\n"));
    assert!(!script.contains("$(curl"));
}

/// The generated script is valid bash, and a failing download stops it before anything runs.
#[test]
fn script_is_valid_bash_and_stops_on_curl_failure() {
    let script = BrewBootstrap::script("a", "b", "FAILED", "/nonexistent");
    let check = Command::new("/bin/bash").args(["-n", "-c", &script]).status().unwrap();
    assert!(check.success());

    // curl to an unreachable local port (no network needed): the script must exit 1 and never print "b".
    let offline = script.replace(BrewBootstrap::INSTALLER_URL, "http://127.0.0.1:9/install.sh");
    let out = Command::new("/bin/bash").args(["-c", &offline]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1));
    assert!(text.contains("FAILED"));
    assert!(!text.contains("b\n"));
}

#[test]
fn write_creates_executable_in_fresh_private_directory() {
    let parent = Scratch::new("brew");
    let script = |dir: &str| format!("#!/bin/bash\necho {dir}\n");
    let a = BrewBootstrap::write(script, parent.path()).unwrap();
    let b = BrewBootstrap::write(script, parent.path()).unwrap();
    assert_ne!(a.parent(), b.parent());
    assert_eq!(a.extension().unwrap(), "command");
    assert!(a.parent().unwrap().file_name().unwrap().to_string_lossy().starts_with("macvpn-brew."));
    assert_eq!(mode(&a), 0o700);
    assert_eq!(mode(a.parent().unwrap()), 0o700);
    assert_eq!(std::fs::read_to_string(&a).unwrap(), format!("#!/bin/bash\necho {}\n", a.parent().unwrap().display()));
    assert!(BrewBootstrap::write(|_| String::new(), &parent.join("missing")).is_err());
}

/// `brew install` with live output: a stand-in `brew` prints to both streams; the chunks arrive in order, the
/// header first and the footer last, and the environment is the minimal one.
#[test]
fn installer_streams_output_with_minimal_environment() {
    let dir = Scratch::new("brew-run");
    let brew = dir.join("brew");
    std::fs::write(&brew, "#!/bin/bash\necho \"args: $*\"\necho \"err\" >&2\nenv | /usr/bin/sort\nexit 3\n").unwrap();
    common::chmod(&brew, 0o755);
    let mut output = String::new();
    let env = map(&[("HOME", "/Users/bob"), ("DYLD_INSERT_LIBRARIES", "/x.dylib"), ("HOMEBREW_X", "1")]);
    let status = with_language(AppLanguage::En, || {
        BrewInstaller::run_for_tests(&brew.to_string_lossy(), "/opt/homebrew", &env, BrewInstaller::TIMEOUT, |s| {
            output.push_str(s)
        })
    })
    .unwrap();
    assert_eq!(status, 3);
    assert!(output.starts_with("$ brew install openvpn wireguard-tools strongswan sstp-client bash\n"), "{output}");
    assert!(output.contains("args: install openvpn wireguard-tools strongswan sstp-client bash\n"), "{output}");
    assert!(output.contains("err\n"));
    assert!(output.contains("HOME=/Users/bob\n"));
    assert!(output.contains("HOMEBREW_NO_ENV_HINTS=1\n"));
    assert!(!output.contains("DYLD_INSERT_LIBRARIES"));
    assert!(!output.contains("HOMEBREW_X"));
    assert!(output.ends_with("\n✗ brew error (3)\n"), "{output}");
    assert_eq!(BrewInstaller::footer(0), "\n✓ Done.\n");
}

/// `brew install` has a time limit (30 min); past it the child is stopped and reaped, and the footer reports it.
/// Robust under load: the limit is a few seconds (bash reaches its first line well within it), and the stop is
/// measured against it with generous slack – never before the limit, and long before the 120 s the script (and its
/// background grandchild, which keeps the pipe open) would run.
#[test]
fn installer_stops_brew_after_the_time_limit() {
    assert_eq!(BrewInstaller::TIMEOUT, std::time::Duration::from_secs(1800));
    let limit = std::time::Duration::from_secs(3);
    let dir = Scratch::new("brew-timeout");
    let brew = dir.join("brew");
    // A background grandchild keeps the pipe open too: the runner must not wait for it.
    std::fs::write(&brew, "#!/bin/bash\necho started\n/bin/sleep 120 &\n/bin/sleep 120\n").unwrap();
    common::chmod(&brew, 0o755);
    let mut output = String::new();
    let start = std::time::Instant::now();
    let status = with_language(AppLanguage::En, || {
        BrewInstaller::run_for_tests(&brew.to_string_lossy(), "/opt/homebrew", &BTreeMap::new(), limit, |s| {
            output.push_str(s)
        })
    })
    .unwrap();
    let elapsed = start.elapsed();
    assert!(elapsed >= limit, "stopped before the limit: {elapsed:?}");
    assert!(elapsed < limit + std::time::Duration::from_secs(60), "not stopped at the limit: {elapsed:?}");
    assert_eq!(status, 15, "SIGTERM");
    assert!(output.contains("started\n"), "{output}");
    assert!(output.ends_with("\n✗ brew error (15)\n"), "{output}");
}

/// `brew outdated` runs without Homebrew's auto-update (no network, quick), in the minimal environment.
#[test]
fn outdated_runs_offline_with_the_packages() {
    assert_eq!(
        BrewOutdated::arguments(),
        ["outdated", "--json=v2", "--formula", "openvpn", "wireguard-tools", "strongswan", "sstp-client", "bash"]
    );
    let env = BrewOutdated::environment(&map(&[("HOME", "/Users/bob"), ("HOMEBREW_X", "1")]), "/opt/homebrew");
    assert_eq!(env.get("HOMEBREW_NO_AUTO_UPDATE").map(String::as_str), Some("1"));
    assert_eq!(env.get("HOME").map(String::as_str), Some("/Users/bob"));
    assert!(!env.contains_key("HOMEBREW_X"));
    assert_eq!(BrewOutdated::TIMEOUT, 20.0);
}

#[test]
fn outdated_json_is_parsed_robustly() {
    let json = r#"Warning: a tap's notice
{
  "formulae": [
    {"name": "bash", "installed_versions": ["5.2.15", "5.2.37"], "current_version": "5.3.3", "pinned": false, "pinned_version": null},
    {"name": "openvpn", "installed_versions": ["2.6.8"], "current_version": "2.6.14", "pinned": false, "pinned_version": null},
    {"name": "strongswan", "installed_versions": ["6.0.0"], "current_version": "6.0.2", "pinned": true, "pinned_version": "6.0.0"},
    {"name": "openssl@3", "installed_versions": ["3.4.0"], "current_version": "3.5.0", "pinned": false},
    {"name": "sstp-client", "installed_versions": [], "current_version": "1.0.10"},
    {"name": "wireguard-tools", "current_version": 7},
    {"installed_versions": ["1"], "current_version": "2"}
  ],
  "casks": []
}"#;
    let found = BrewOutdated::parse(json).unwrap();
    let pkg = |n: &str, i: &str, a: &str| OutdatedPackage { name: n.into(), installed: i.into(), available: a.into() };
    // In BREW_PACKAGES' order; the pinned one, a foreign formula and incomplete entries are left out.
    assert_eq!(found, [pkg("openvpn", "2.6.8", "2.6.14"), pkg("bash", "5.2.37", "5.3.3")]);
    assert_eq!(BrewOutdated::parse(r#"{"formulae": [], "casks": []}"#), Some(vec![]));
    for bad in ["", "Error: No available formula", "{", "{\"casks\": []}", "{\"formulae\": {}}"] {
        assert_eq!(BrewOutdated::parse(bad), None, "{bad}");
    }
}

/// `brew upgrade` streams like `brew install`, with only MacVPN's formulae; a list without any never runs a bare
/// `brew upgrade` (which would upgrade everything).
#[test]
fn upgrade_streams_output_with_only_our_formulae() {
    let dir = Scratch::new("brew-upgrade");
    let brew = dir.join("brew");
    std::fs::write(&brew, "#!/bin/bash\necho \"args: $*\"\nexit 0\n").unwrap();
    common::chmod(&brew, 0o755);
    let formulae = vec!["bash".to_string(), "openssl@3".to_string(), "openvpn".to_string()];
    let mut output = String::new();
    let status = with_language(AppLanguage::En, || {
        BrewInstaller::run_upgrade_for_tests(
            &brew.to_string_lossy(),
            &formulae,
            "/opt/homebrew",
            &BTreeMap::new(),
            |s| output.push_str(s),
        )
    })
    .unwrap();
    assert_eq!(status, 0);
    assert!(output.starts_with("$ brew upgrade openvpn bash\n"), "{output}");
    assert!(output.contains("args: upgrade openvpn bash\n"), "{output}");
    assert!(output.ends_with("\n✓ Done.\n"), "{output}");
    assert_eq!(BrewInstaller::upgrade_header(&formulae), "$ brew upgrade openvpn bash\n");

    let mut nothing = String::new();
    let refused = BrewInstaller::run_upgrade_for_tests(
        &brew.to_string_lossy(),
        &["openssl@3".to_string()],
        "/opt/homebrew",
        &BTreeMap::new(),
        |s| nothing.push_str(s),
    );
    assert!(refused.is_err());
    assert!(nothing.is_empty());
}

/// The daily `brew update`: exactly `<prefix>/bin/brew update` (the prefix's brew, no `PATH` lookup), in the
/// minimal environment (no auto-update switch: updating is the point), 120 s at most. Never a real brew: the mock
/// answers.
#[test]
fn update_runs_the_prefix_brew_in_the_minimal_environment() {
    assert_eq!(BrewUpdate::arguments(), ["update"]);
    assert_eq!(BrewUpdate::TIMEOUT, 120.0);
    let app = map(&[("HOME", "/Users/bob"), ("PATH", "/evil:/usr/bin"), ("HOMEBREW_BREW_GIT_REMOTE", "https://x")]);
    let env = BrewUpdate::environment(&app, "/usr/local");
    assert_eq!(env, BrewEnvironment::make(&app, "/usr/local"));
    assert_eq!(
        env.get("PATH").map(String::as_str),
        Some("/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin")
    );
    assert!(!env.contains_key("HOMEBREW_NO_AUTO_UPDATE") && !env.contains_key("HOMEBREW_BREW_GIT_REMOTE"));

    let mock = MockCommandRunner::new();
    let guard = BrewGuard::new();
    assert_eq!(BrewUpdate::run(&mock, "/opt/homebrew", &guard), PackageIndexUpdate::Updated);
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].executable, "/opt/homebrew/bin/brew");
    assert_eq!(calls[0].command_line(), "/opt/homebrew/bin/brew update");
    assert_eq!(calls[0].stdin, None);
    assert!(guard.try_lock().is_some(), "released after the run");
}

/// A non-zero exit or a runner error (offline, the time limit) is a failure with a message for the log.
#[test]
fn a_failed_update_is_reported_for_the_log() {
    let mock = MockCommandRunner::new();
    mock.respond(
        "/opt/homebrew/bin/brew update",
        CommandResult::new(1, "", "fatal: unable to access\nError: Fetching /opt/homebrew failed!\n\n"),
    );
    assert_eq!(
        BrewUpdate::run(&mock, "/opt/homebrew", &BrewGuard::new()),
        PackageIndexUpdate::Failed("brew update exited with 1: Error: Fetching /opt/homebrew failed!".into())
    );
    struct TimedOut;
    impl CommandRunner for TimedOut {
        fn run(&self, executable: &str, _: &[String], _: Option<&str>) -> Result<CommandResult, CommandError> {
            Err(CommandError::TimedOut(executable.into()))
        }
    }
    assert!(matches!(BrewUpdate::run(&TimedOut, "/opt/homebrew", &BrewGuard::new()), PackageIndexUpdate::Failed(_)));
}

/// While another guarded brew command (an install / upgrade) holds the guard, the update is skipped without
/// running anything; `lock` waits for a running update.
#[test]
fn update_never_overlaps_another_brew_command() {
    let guard = BrewGuard::new();
    let mock = MockCommandRunner::new();
    {
        let _install = guard.lock();
        assert_eq!(BrewUpdate::run(&mock, "/opt/homebrew", &guard), PackageIndexUpdate::Busy);
        assert!(guard.try_lock().is_none());
    }
    assert!(mock.calls().is_empty(), "nothing run while busy");
    // An update in progress: an install waits for it.
    let slow = MockCommandRunner::new();
    slow.delay("/opt/homebrew/bin/brew update", std::time::Duration::from_millis(300));
    std::thread::scope(|s| {
        let update = s.spawn(|| BrewUpdate::run(&slow, "/opt/homebrew", &guard));
        while slow.calls().is_empty() {
            std::thread::yield_now();
        }
        let start = std::time::Instant::now();
        drop(guard.lock());
        assert!(start.elapsed() >= std::time::Duration::from_millis(100), "the install waited");
        assert_eq!(update.join().unwrap(), PackageIndexUpdate::Updated);
    });
}
