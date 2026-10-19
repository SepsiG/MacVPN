//! Process checks. A recorded pid is only trusted if the process still runs (not a zombie) under the expected
//! name, so a recycled pid never makes MacVPN signal a foreign process.

use crate::exec::{Cmd, EnvMode, capture};
use crate::testmode::is_digits;

/// `ps -p <pid> -o <fields>=` output (`None` if the pid is malformed or ps fails).
fn ps(pid: &str, fields: &str) -> Option<String> {
    if !is_digits(pid) {
        return None;
    }
    let (ok, out) = capture(&Cmd::new("/bin/ps").args(["-p", pid, "-o", fields]), EnvMode::Minimal, 64 * 1024)?;
    ok.then(|| String::from_utf8_lossy(&out).into_owned())
}

/// The bash `ps -p "$pid" -o stat=,comm= | awk '$1 !~ /^Z/ && $NF ~ /<name>$/'`.
pub fn alive_as(pid: &str, name_suffix: &str) -> bool {
    ps(pid, "stat=,comm=").is_some_and(|out| out.lines().any(|l| line_matches(l, name_suffix)))
}

fn line_matches(line: &str, name_suffix: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    match (fields.first(), fields.last()) {
        (Some(stat), Some(comm)) => !stat.starts_with('Z') && comm.ends_with(name_suffix),
        _ => false,
    }
}

/// `ps -p <pid> -o comm=`
pub fn comm(pid: &str) -> Option<String> {
    ps(pid, "comm=").map(|s| s.trim_end_matches('\n').to_string())
}

/// `ps -p <pid> -o ppid=` without spaces.
pub fn ppid(pid: &str) -> Option<String> {
    ps(pid, "ppid=").map(|s| s.chars().filter(|c| !c.is_whitespace()).collect())
}

/// `pgrep <args>`: the matching pids, one per line.
pub fn pgrep(args: &[&str]) -> Vec<String> {
    capture(&Cmd::new("/usr/bin/pgrep").args(args), EnvMode::Minimal, 64 * 1024)
        .map(|(_, out)| {
            String::from_utf8_lossy(&out).lines().map(str::trim).filter(|l| is_digits(l)).map(String::from).collect()
        })
        .unwrap_or_default()
}

/// `kill -0 <pid>` (EPERM: the process exists but is not ours), for the lock check.
pub fn exists(pid: &str) -> bool {
    let Ok(n) = pid.parse::<i32>() else { return false };
    match crate::sys::kill0_raw(n) {
        Ok(()) => true,
        Err(e) => e == crate::sys::EPERM,
    }
}

/// `kill <pid>` / `kill -9 <pid>` of a validated pid.
pub fn signal(pid: &str, sig: i32) {
    if let Ok(n) = pid.parse::<i32>() {
        let _ = crate::sys::kill(n, sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_line_rules() {
        assert!(line_matches("S    /opt/homebrew/sbin/openvpn", "openvpn"));
        assert!(line_matches("Ss   mvpn-mgmt", "mvpn-mgmt"));
        assert!(!line_matches("Z    /opt/homebrew/sbin/openvpn", "openvpn"));
        assert!(!line_matches("S    sleep", "openvpn"));
        assert!(!line_matches("", "openvpn"));
    }

    #[test]
    fn own_process_is_alive_and_malformed_pids_are_not() {
        let me = std::process::id().to_string();
        assert!(exists(&me));
        assert!(comm(&me).is_some());
        assert!(!alive_as("12a", "x"));
        assert!(!alive_as("", "x"));
        assert!(!exists("x"));
    }
}
