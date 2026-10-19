//! Children never inherit the app's open descriptors (Foundation `Process` uses `POSIX_SPAWN_CLOEXEC_DEFAULT`;
//! here every spawn site marks fds ≥ 3 close-on-exec). The reviewer's probe: an fd without close-on-exec at 7.
//! One test only, in its own binary (process), so no parallel test can own fd 7 meanwhile.
#![allow(unsafe_code)]

mod common;

use common::{Scratch, chmod};
use macvpn_platform_mac::brew::{BrewInstaller, shell_quote};
use macvpn_platform_mac::command::{CommandRunner, ProcessCommandRunner};
use macvpn_platform_mac::update_installer::UpdateInstaller;
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// Prints every inherited fd ≥ 3 (`stat /dev/fd/N` only succeeds for an fd the process has; bash's redirections
/// happen in its forked children, so they add none).
const PROBE: &str =
    "for i in $(/usr/bin/seq 3 255); do /usr/bin/stat /dev/fd/$i >/dev/null 2>&1 && echo \"fd $i\"; done; echo end";

#[test]
fn children_inherit_only_the_standard_streams() {
    let file = std::fs::File::open("/etc/hosts").unwrap();
    // SAFETY: duplicates a valid fd onto 7; dup2 clears close-on-exec on the copy. This binary runs this single
    // test, so fd 7 belongs to nobody else.
    assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), 7) }, 7);
    // SAFETY: as above, a second one far up.
    let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 100) };
    assert!(high >= 100);

    // The command runner.
    let r = ProcessCommandRunner::default().run("/bin/bash", &["-c".into(), PROBE.into()], None).unwrap();
    assert_eq!(r.stdout, "end\n", "ProcessCommandRunner");
    // Not reading /etc/hosts through fd 7 either (the reviewer's probe).
    let r = ProcessCommandRunner::default().run("/bin/bash", &["-c".into(), "/bin/cat <&7".into()], None).unwrap();
    assert_ne!(r.exit_code, 0);
    assert!(!r.stdout.contains("localhost"), "{}", r.stdout);

    // brew install.
    let dir = Scratch::new("macvpn-fds");
    let brew = dir.join("brew");
    std::fs::write(&brew, format!("#!/bin/bash\n{PROBE}\n")).unwrap();
    chmod(&brew, 0o755);
    let mut output = String::new();
    BrewInstaller::run_for_tests(
        &brew.to_string_lossy(),
        "/opt/homebrew",
        &BTreeMap::new(),
        BrewInstaller::TIMEOUT,
        |s| output.push_str(s),
    )
    .unwrap();
    assert!(output.contains("end\n") && !output.contains("fd "), "brew: {output}");

    // The update helper (through the double fork).
    let marker = dir.join("out");
    let script = dir.join("s.sh");
    let m = shell_quote(&marker.to_string_lossy());
    std::fs::write(&script, format!("#!/bin/bash\n( {PROBE} ) > {m}.tmp\n/bin/mv {m}.tmp {m}\n")).unwrap();
    UpdateInstaller::launch_helper(&script).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "end\n", "update helper");

    // SAFETY: closes the two fds made above, owned by this test.
    unsafe {
        libc::close(7);
        libc::close(high);
    }
}
