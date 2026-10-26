//! `mvpn status`: the JSON array the app parses (`[{"id":…,"kind":…,"state":…,"iface":…,"ip":…,"since":…}]`),
//! byte for byte as the bash version printed it. This module reads the run directories and computes each
//! connection's state; [`crate::shared::status_json`] renders the JSON.

use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::log::{Log, ROOT_LOG_KEEP, ROOT_LOG_MAX, flush_root_log};
use crate::macos::openvpn::{mgmt_alive, ovpn_alive};
use crate::macos::paths::{Settings, is_dir, is_file, is_symlink};
use crate::macos::testmode::is_digits;
use crate::macos::wireguard::{is_iface, is_utun};
use crate::shared::cli::{is_kind, is_uuid};
use crate::shared::mask::Masker;
use crate::shared::status_json::{self, StatusLine};
use std::path::Path;

/// One connection's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub state: &'static str,
    pub iface: String,
    pub ip: String,
}

/// The completion check on a run directory's root-only openvpn.log.
fn ovpn_completed(d: &Path) -> bool {
    let f = d.join("openvpn.log");
    is_file(&f) && !is_symlink(&f) && crate::macos::log::ovpn_done_file(&f)
}

/// `status_one`
pub fn one(s: &Settings, d: &Path) -> State {
    let kind = fsx::cat(&d.join("kind"));
    let mut state = "failed";
    let mut iface = String::new();
    let mut ip = String::new();
    match kind.as_str() {
        "openvpn" => {
            let pid = fsx::cat(&d.join("pid"));
            if ovpn_alive(&pid) {
                // Up: the hook recorded the interface and the root-only openvpn.log says the initialization is
                // complete. A v3 layer's openvpn has no openvpn.log (update with a running tunnel): there a live,
                // verified pid + iface file means connected.
                let olog = d.join("openvpn.log");
                let legacy = !crate::macos::paths::exists(&olog) && !is_symlink(&olog);
                state = if is_file(&d.join("iface")) && (ovpn_completed(d) || legacy) {
                    "connected"
                } else if is_file(&d.join("mgmt.pid")) && !mgmt_alive(&fsx::cat(&d.join("mgmt.pid"))) {
                    // A v6+ openvpn without its bridge would hang in hold / password state: failed, so cleanup runs.
                    "failed"
                } else {
                    "connecting"
                };
            }
            iface = fsx::cat(&d.join("iface"));
            ip = fsx::cat(&d.join("ip"));
        }
        "wireguard" => {
            iface = fsx::cat(&d.join("iface"));
            if !is_iface(&iface) {
                iface.clear();
            }
            let real = if iface.is_empty() { String::new() } else { fsx::cat(&s.wg_run.join(format!("{iface}.name"))) };
            if is_utun(&real) && crate::macos::exec::quiet(&Cmd::new("/sbin/ifconfig").arg(&real), EnvMode::Minimal) {
                state = "connected";
                ip = inet_of(&real);
                iface = real;
            }
        }
        "sstp" => {
            let pid = fsx::cat(&d.join("pid"));
            if crate::macos::sstp::sstp_alive(&pid) {
                iface = fsx::cat(&d.join("iface"));
                let since = fsx::cat(&d.join("started"));
                if iface.is_empty() {
                    // Without an interface after UP_TIMEOUT + 30 s it is no longer "connecting" (e.g. what a
                    // SIGKILLed up left behind).
                    let stale = is_digits(&since)
                        && since
                            .parse::<i64>()
                            .is_ok_and(|t| crate::macos::exec::now() - t > (s.up_timeout as i64).saturating_add(30));
                    state = if stale { "failed" } else { "connecting" };
                } else if iface
                    .strip_prefix("ppp")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    && crate::macos::sstp::iface_up(s.test_mode, s.test.iface_ok, &iface)
                {
                    state = "connected";
                    ip = fsx::cat(&d.join("ip"));
                }
            }
        }
        "strongswan" => {
            let conn = fsx::cat(&d.join("conn"));
            if let Some(sw) = find_swanctl(s)
                && crate::macos::strongswan::is_name(&conn)
                && let Some(st) = crate::macos::strongswan::sa_state(&sw, &conn, mode(s))
            {
                state = st;
            }
        }
        _ => {}
    }
    if !iface.bytes().all(|b| b.is_ascii_alphanumeric()) {
        iface.clear();
    }
    if !ip.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
        ip.clear();
    }
    State { state, iface, ip }
}

fn mode(s: &Settings) -> EnvMode {
    if s.test_mode { EnvMode::Inherit } else { EnvMode::Minimal }
}

fn find_swanctl(s: &Settings) -> Option<std::path::PathBuf> {
    let b = s.brew.as_ref()?;
    [b.join("bin/swanctl"), b.join("sbin/swanctl")].into_iter().find(|c| crate::macos::exec::is_executable(c))
}

/// `ifconfig <if> | awk '/inet /{ print $2; exit }'`
fn inet_of(iface: &str) -> String {
    let Some((_, out)) = crate::macos::exec::capture(&Cmd::new("/sbin/ifconfig").arg(iface), EnvMode::Minimal, 1 << 16)
    else {
        return String::new();
    };
    String::from_utf8_lossy(&out)
        .lines()
        .find(|l| l.contains("inet "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_string()
}

/// `status_flush_openvpn`, and the size limits while a connection runs (status is what the app polls): under the
/// connection's lock taken without waiting (a running up/down does this itself), the user's log is rolled when
/// writers outside `mvpn` took it over its cap, a connected OpenVPN's root-only log (SSTP: pppd's) is copied into it
/// and then cut to its cap. Status does not know the secrets, so password- and authentication-like lines are left
/// out.
fn housekeep(s: &Settings, d: &Path, id: &str, kind: &str) {
    let engine = match kind {
        "openvpn" => Some((d.join("openvpn.log"), "")),
        "sstp" => Some((d.join("pppd.log"), "[pppd] ")),
        _ => None,
    };
    let log = s.log_file(id);
    let lock = s.run_base.join(format!(".{id}.lock"));
    if !crate::macos::lock::try_take(&lock) {
        return;
    }
    let engine = engine.filter(|(f, _)| is_file(f) && !is_symlink(f));
    if is_file(&log) && !is_symlink(&log) {
        let log = Log::capped(log, s.log_max);
        log.enforce_cap();
        if let Some((f, prefix)) = &engine {
            flush_root_log(&log, f, prefix, true, &Masker::default());
        }
    } else if let Some((f, _)) = &engine {
        crate::macos::log::trim_root_log(f, ROOT_LOG_MAX, ROOT_LOG_KEEP);
    }
    crate::macos::lock::release_try(&lock);
}

/// `status_all`
pub fn render(s: &Settings) -> String {
    let mut names: Vec<String> = std::fs::read_dir(&s.run_base)
        .map(|it| it.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    let mut lines = Vec::new();
    for id in names {
        if id.starts_with('.') {
            continue;
        }
        let d = s.run_base.join(&id);
        if !is_dir(&d) || !is_file(&d.join("kind")) || !is_uuid(&id) {
            continue;
        }
        let kind = fsx::cat(&d.join("kind"));
        if !is_kind(&kind) {
            continue;
        }
        let since = fsx::cat(&d.join("started"));
        let since = is_digits(&since).then_some(since);
        housekeep(s, &d, &id, &kind);
        let st = one(s, &d);
        lines.push(StatusLine { id, kind, state: st.state, iface: st.iface, ip: st.ip, since });
    }
    status_json::render(&lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::testmode::TestEnv;

    #[test]
    fn json_matches_the_bash_format() {
        let base = std::env::temp_dir().join(format!("mvpn-status-{}", uuid::Uuid::new_v4()));
        let id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        std::fs::create_dir_all(base.join(id)).unwrap();
        std::fs::create_dir_all(base.join("x-not-uuid")).unwrap();
        std::fs::write(base.join("x-not-uuid/kind"), "openvpn\n").unwrap();
        std::fs::write(base.join(id).join("kind"), "wireguard\n").unwrap();
        std::fs::write(base.join(id).join("iface"), "mv12345678\n").unwrap();
        let t = TestEnv { run_base: Some(base.display().to_string()), ..TestEnv::default() };
        let s = Settings::resolve(true, t, String::new());
        assert_eq!(
            render(&s),
            format!(
                "[{{\"id\":\"{id}\",\"kind\":\"wireguard\",\"state\":\"failed\",\"iface\":\"mv12345678\",\"ip\":null,\"since\":null}}]\n"
            )
        );
        let parsed = macvpn_core::status::parse_status(&render(&s)).unwrap();
        assert_eq!(parsed.len(), 1);
        fsx::remove_rf(&base);
        assert_eq!(render(&s), "[]\n");
    }

    #[test]
    fn three_fixed_states_render_as_in_1_4() {
        let base = std::env::temp_dir().join(format!("mvpn-status-{}", uuid::Uuid::new_v4()));
        let write = |id: &str, name: &str, value: &str| {
            std::fs::create_dir_all(base.join(id)).unwrap();
            std::fs::write(base.join(id).join(name), value).unwrap();
        };
        let ovpn = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        write(ovpn, "kind", "openvpn\n");
        write(ovpn, "pid", "999999999\n");
        write(ovpn, "iface", "utun7\n");
        write(ovpn, "ip", "10.8.0.2\n");
        write(ovpn, "started", "1700000000\n");
        let sstp = "1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        write(sstp, "kind", "sstp\n");
        write(sstp, "pid", "999999999\n");
        write(sstp, "iface", "ppp0\n");
        write(sstp, "started", "17x\n");
        let wg = "2F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        write(wg, "kind", "wireguard\n");
        write(wg, "iface", "mv12345678\n");
        write(wg, "started", "1700000123\n");
        write(".hidden", "kind", "openvpn\n");
        let t = TestEnv {
            run_base: Some(base.display().to_string()),
            wg_run: Some(base.join("no-wg").display().to_string()),
            log_base: Some(base.join("no-log").display().to_string()),
            brew: Some(base.join("no-brew").display().to_string()),
            ..TestEnv::default()
        };
        let s = Settings::resolve(true, t, String::new());
        assert_eq!(render(&s), crate::shared::status_json::tests::GOLDEN_1_4);
        fsx::remove_rf(&base);
    }

    #[test]
    fn status_keeps_a_running_connections_logs_under_their_caps() {
        use crate::macos::log::{FLUSH_MAX, ROOT_LOG_KEEP, ROOT_LOG_MAX};
        let base = std::env::temp_dir().join(format!("mvpn-status-{}", uuid::Uuid::new_v4()));
        let id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        let (run, logs) = (base.join("run"), base.join("log"));
        std::fs::create_dir_all(run.join(id)).unwrap();
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(run.join(id).join("kind"), "openvpn\n").unwrap();
        let line = b"2026-10-23 03:00:00 write UDPv4: Network is unreachable (fd=5,code=51)\n";
        let olog = run.join(id).join("openvpn.log");
        std::fs::write(&olog, line.repeat((ROOT_LOG_MAX as usize * 2) / line.len())).unwrap();
        let user = logs.join(format!("{id}.log"));
        std::fs::write(&user, line.repeat(100)).unwrap();
        let t = TestEnv {
            run_base: Some(run.display().to_string()),
            log_base: Some(logs.display().to_string()),
            log_max: Some(4096),
            wg_run: Some(base.join("no-wg").display().to_string()),
            brew: Some(base.join("no-brew").display().to_string()),
            ..TestEnv::default()
        };
        let s = Settings::resolve(true, t, String::new());
        render(&s);
        assert!(std::fs::metadata(&olog).unwrap().len() <= ROOT_LOG_KEEP);
        assert!(std::fs::metadata(&user).unwrap().len() <= 4096);
        assert!(std::fs::metadata(format!("{}.1", user.display())).unwrap().len() <= 4096.min(FLUSH_MAX));
        assert!(!run.join(format!(".{id}.lock")).exists());
        fsx::remove_rf(&base);
    }
}
