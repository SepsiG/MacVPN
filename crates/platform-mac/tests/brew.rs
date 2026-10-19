//! Port of `BrewBootstrapTests.swift`, plus the brew install runner (the app's `BrewInstaller`).

mod common;

use common::{Scratch, mode};
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_platform_mac::brew::{BrewBootstrap, BrewEnvironment, BrewInstaller};
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
#[test]
fn installer_stops_brew_after_the_time_limit() {
    assert_eq!(BrewInstaller::TIMEOUT, std::time::Duration::from_secs(1800));
    let dir = Scratch::new("brew-timeout");
    let brew = dir.join("brew");
    // A background grandchild keeps the pipe open too: the runner must not wait for it.
    std::fs::write(&brew, "#!/bin/bash\necho started\n/bin/sleep 30 &\n/bin/sleep 30\n").unwrap();
    common::chmod(&brew, 0o755);
    let mut output = String::new();
    let start = std::time::Instant::now();
    let status = with_language(AppLanguage::En, || {
        BrewInstaller::run_for_tests(
            &brew.to_string_lossy(),
            "/opt/homebrew",
            &BTreeMap::new(),
            std::time::Duration::from_millis(500),
            |s| output.push_str(s),
        )
    })
    .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(5), "{:?}", start.elapsed());
    assert_eq!(status, 15, "SIGTERM");
    assert!(output.contains("started\n"), "{output}");
    assert!(output.ends_with("\n✗ brew error (15)\n"), "{output}");
}
