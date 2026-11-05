//! The DNS files of a run directory (root layer 15), root-only (0600) like everything there:
//!
//! - `<run>/dns-request`: the connection's DNS settings from the `up` frame, in the frame's own `dns-*` line format
//!   (written by `up` right after the run directory is prepared; read back by the hook, WireGuard and SSTP, and
//!   after connect). Missing: the default (Automatic, nothing own), as for an `up` from an older app.
//! - `<run>/dns-session`: what the DNS manager decided for the running connection (mode, tunnel, layout, probe,
//!   consecutive failures, warning, the effective lists, since): `status` reports its state, `dns-check` continues
//!   from it.
//!
//! Both are parsed strictly (known keys only, each value checked); anything else reads as absent.

use crate::macos::dns_plan::{Effective, Layout, Probe, Tunnel, Warn};
use crate::macos::fsx;
use macvpn_core::dns_settings::{DnsMode, DnsRequest, is_dns_domain, is_dns_server};
use macvpn_core::status::DnsState;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const REQUEST: &str = "dns-request";
pub const SESSION: &str = "dns-session";
/// Either file is at most this large (the lists are bounded far below it).
const MAX: u64 = 64 * 1024;

/// A file of the run directory as the root layer trusts it: a regular file (not a symlink), not group- or
/// world-accessible, and (as root) owned by root. In test mode the owner is not checked (the tests run unprivileged).
fn read_root_private(p: &Path, test_mode: bool) -> Option<String> {
    let meta = std::fs::symlink_metadata(p).ok()?;
    if !meta.file_type().is_file() || meta.mode() & 0o077 != 0 || (!test_mode && meta.uid() != 0) {
        return None;
    }
    String::from_utf8(fsx::read_private(p, MAX)?).ok()
}

pub fn request_path(run: &Path) -> PathBuf {
    run.join(REQUEST)
}

pub fn session_path(run: &Path) -> PathBuf {
    run.join(SESSION)
}

/// Writes `<run>/dns-request` (0600).
pub fn write_request(run: &Path, r: &DnsRequest) -> std::io::Result<()> {
    fsx::write_file(&request_path(run), r.frame_lines().as_bytes(), 0o600)
}

/// `<run>/dns-request`, or the default when it is missing or not trusted (see [`read_root_private`]) or invalid.
pub fn read_request(run: &Path, test_mode: bool) -> DnsRequest {
    read_root_private(&request_path(run), test_mode).and_then(|t| DnsRequest::from_frame_lines(&t)).unwrap_or_default()
}

/// The DNS manager's record of one running connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub mode: DnsMode,
    pub tunnel: Tunnel,
    pub layout: Layout,
    pub probe: Probe,
    /// Consecutive failed probes (2 fall back, see `dns::check`).
    pub fails: u32,
    pub warn: Option<Warn>,
    pub eff: Effective,
    /// Unix time of the last layout change.
    pub since: i64,
}

impl Session {
    /// The state `status` and `dns-check` report.
    pub fn state(&self) -> DnsState {
        match (self.layout, self.warn) {
            (Layout::None, _) => DnsState::None,
            (Layout::Split, _) => DnsState::Targeted,
            (Layout::Fallback, Some(Warn::Fallback { full_tunnel: true })) => DnsState::FallbackFullTunnel,
            (Layout::Fallback, _) => DnsState::Fallback,
            (Layout::Vpn { .. }, Some(Warn::Failing)) => DnsState::Failing,
            (Layout::Vpn { .. }, _) => DnsState::Vpn,
        }
    }

    pub fn render(&self) -> String {
        let list = |v: &[String]| v.join(",");
        format!(
            "mode={}\ntunnel={}\nlayout={}\nprobe={}\nfails={}\nwarn={}\nservers={}\nsearch={}\nresolve={}\nzones={}\nsince={}\n",
            self.mode.raw(),
            self.tunnel.raw(),
            self.layout.raw(),
            self.probe.raw(),
            self.fails,
            self.warn.map_or("", Warn::raw),
            list(&self.eff.servers),
            list(&self.eff.search),
            list(&self.eff.resolve),
            list(&self.eff.zones),
            self.since,
        )
    }

    /// The strict reader of [`Session::render`]: every key exactly once, every value valid.
    pub fn parse(text: &str) -> Option<Session> {
        let mut v: [Option<&str>; 11] = [None; 11];
        const KEYS: [&str; 11] =
            ["mode", "tunnel", "layout", "probe", "fails", "warn", "servers", "search", "resolve", "zones", "since"];
        for line in text.lines() {
            let (k, val) = line.split_once('=')?;
            let i = KEYS.iter().position(|x| *x == k)?;
            if v[i].replace(val).is_some() {
                return None;
            }
        }
        let list = |s: &str, ok: fn(&str) -> bool| -> Option<Vec<String>> {
            if s.is_empty() {
                return Some(Vec::new());
            }
            let items: Vec<String> = s.split(',').map(str::to_string).collect();
            items.iter().all(|x| ok(x)).then_some(items)
        };
        let warn = match v[5]? {
            "" => None,
            w => Some(Warn::from_raw(w)?),
        };
        Some(Session {
            mode: DnsMode::from_raw(v[0]?)?,
            tunnel: Tunnel::from_raw(v[1]?)?,
            layout: Layout::from_raw(v[2]?)?,
            probe: Probe::from_raw(v[3]?)?,
            fails: v[4]?.parse().ok()?,
            warn,
            eff: Effective {
                servers: list(v[6]?, is_dns_server)?,
                search: list(v[7]?, is_dns_domain)?,
                resolve: list(v[8]?, is_dns_domain)?,
                zones: list(v[9]?, is_dns_domain)?,
            },
            since: v[10]?.parse().ok()?,
        })
    }
}

pub fn write_session(run: &Path, s: &Session) -> std::io::Result<()> {
    fsx::write_file(&session_path(run), s.render().as_bytes(), 0o600)
}

pub fn read_session(run: &Path, test_mode: bool) -> Option<Session> {
    Session::parse(&read_root_private(&session_path(run), test_mode)?)
}

/// `<run>/dns-session.released`: the session of a connection that released its DNS (`down`), kept only as the
/// memory of a failed probe for the same connection's next DNS step (OpenVPN's restart without `persist-tun`).
pub const RELEASED: &str = "dns-session.released";

/// The session leaves: `dns-session` becomes `dns-session.released` (nothing reads it as a running connection's).
pub fn retire_session(run: &Path) {
    let p = session_path(run);
    if std::fs::symlink_metadata(&p).is_ok() {
        let _ = std::fs::rename(&p, run.join(RELEASED));
    }
}

/// The released session (see [`RELEASED`]), read as strictly as the live one.
pub fn read_released(run: &Path, test_mode: bool) -> Option<Session> {
    Session::parse(&read_root_private(&run.join(RELEASED), test_mode)?)
}

/// `<run>/dns-check`: one `dns-check` of the connection at a time (`flock`), and the time of its last probe.
pub const CHECK: &str = "dns-check";

/// The connection's `dns-check` lock, released when dropped.
pub struct CheckLock(std::fs::File);

/// The lock of `<run>/dns-check` (a regular file, never through a symlink, 0600), or `None` when another check holds
/// it (or it cannot be opened). Tried a few times over 100 ms: a child process forked meanwhile holds a copy of the
/// descriptor until its `exec`.
pub fn check_lock(run: &Path) -> Option<CheckLock> {
    for i in 0..5 {
        if let Some(l) = try_check_lock(run) {
            return Some(l);
        }
        if i < 4 {
            crate::macos::exec::sleep_ms(25, false);
        }
    }
    None
}

fn try_check_lock(run: &Path) -> Option<CheckLock> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(run.join(CHECK))
        .ok()?;
    (f.metadata().ok()?.file_type().is_file() && crate::macos::sys::try_lock_exclusive(&f)).then_some(CheckLock(f))
}

impl CheckLock {
    /// The Unix time of the last probe (`None`: none yet, or not a number).
    pub fn last(&mut self) -> Option<i64> {
        use std::io::{Read, Seek};
        let mut text = String::new();
        self.0.rewind().ok()?;
        (&mut self.0).take(32).read_to_string(&mut text).ok()?;
        text.trim().parse().ok()
    }

    pub fn stamp(&mut self, t: i64) {
        use std::io::{Seek, Write};
        let _ = self.0.set_len(0).and_then(|_| self.0.rewind()).and_then(|_| writeln!(self.0, "{t}"));
    }
}

pub fn remove_released(run: &Path) {
    let _ = std::fs::remove_file(run.join(RELEASED));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("mvpn-dns-session-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn request_file_round_trip() {
        let run = tmp();
        assert_eq!(read_request(&run, true), DnsRequest::default(), "missing: the default");
        let r = DnsRequest {
            mode: DnsMode::Targeted,
            servers: vec!["10.0.0.53".into()],
            domains: vec!["corp.example".into()],
            override_vpn: true,
        };
        write_request(&run, &r).unwrap();
        assert_eq!(read_request(&run, true), r);
        std::fs::write(request_path(&run), "dns-mode=bogus\n").unwrap();
        assert_eq!(read_request(&run, true), DnsRequest::default(), "invalid: the default");
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn request_file_must_be_root_private() {
        let run = tmp();
        let r = DnsRequest { mode: DnsMode::Strict, ..Default::default() };
        write_request(&run, &r).unwrap();
        assert_eq!(read_request(&run, true), r);
        // As root the owner is checked too: the test's file is not root's.
        assert_eq!(read_request(&run, false), DnsRequest::default());
        std::fs::set_permissions(request_path(&run), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_request(&run, true), DnsRequest::default(), "group/world readable");
        std::fs::remove_file(request_path(&run)).unwrap();
        let other = run.join("other");
        std::fs::write(&other, r.frame_lines()).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&other, request_path(&run)).unwrap();
        assert_eq!(read_request(&run, true), DnsRequest::default(), "never through a symlink");
        std::fs::remove_dir_all(&run).unwrap();
    }

    #[test]
    fn session_file_round_trip() {
        let run = tmp();
        let s = Session {
            mode: DnsMode::Automatic,
            tunnel: Tunnel::Full,
            layout: Layout::Fallback,
            probe: Probe::Failed,
            fails: 2,
            warn: Some(Warn::Fallback { full_tunnel: true }),
            eff: Effective {
                servers: vec!["10.8.0.1".into(), "fd00::1".into()],
                search: vec!["corp.example".into()],
                resolve: vec![],
                zones: vec!["10.in-addr.arpa".into()],
            },
            since: 1_700_000_000,
        };
        write_session(&run, &s).unwrap();
        assert_eq!(read_session(&run, true), Some(s.clone()));
        assert_eq!(s.state(), DnsState::FallbackFullTunnel);
        let none = Session { layout: Layout::None, warn: Some(Warn::NoDns), ..s.clone() };
        assert_eq!(none.state(), DnsState::None);
        assert_eq!(
            Session { layout: Layout::Vpn { local: false }, warn: Some(Warn::Failing), ..s.clone() }.state(),
            DnsState::Failing
        );
        assert_eq!(Session { layout: Layout::Split, warn: None, ..s.clone() }.state(), DnsState::Targeted);
        for bad in [
            s.render().replace("mode=automatic", "mode=x"),
            s.render().replace("servers=10.8.0.1", "servers=x;y"),
            format!("{}mode=full\n", s.render()),
            s.render().replace("since=1700000000\n", ""),
        ] {
            assert_eq!(Session::parse(&bad), None, "{bad}");
        }
        std::fs::remove_dir_all(&run).unwrap();
    }
}
