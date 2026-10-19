//! `mvpn status`: the JSON array the app parses (`[{"id":…,"kind":…,"state":…,"iface":…,"ip":…,"since":…}]`),
//! byte for byte as the bash version printed it.

use crate::cli::{is_kind, is_uuid};
use crate::exec::{Cmd, EnvMode};
use crate::fsx;
use crate::log::{Log, flush_root_log};
use crate::mask::Masker;
use crate::openvpn::{mgmt_alive, ovpn_alive};
use crate::paths::{Settings, is_dir, is_file, is_symlink};
use crate::testmode::is_digits;
use crate::wireguard::{is_iface, is_utun};
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
    is_file(&f) && !is_symlink(&f) && crate::log::ovpn_done_file(&f)
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
                let legacy = !crate::paths::exists(&olog) && !is_symlink(&olog);
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
            if is_utun(&real) && crate::exec::quiet(&Cmd::new("/sbin/ifconfig").arg(&real), EnvMode::Minimal) {
                state = "connected";
                ip = inet_of(&real);
                iface = real;
            }
        }
        "sstp" => {
            let pid = fsx::cat(&d.join("pid"));
            if crate::sstp::sstp_alive(&pid) {
                iface = fsx::cat(&d.join("iface"));
                let since = fsx::cat(&d.join("started"));
                if iface.is_empty() {
                    // Without an interface after UP_TIMEOUT + 30 s it is no longer "connecting" (e.g. what a
                    // SIGKILLed up left behind).
                    let stale = is_digits(&since)
                        && since
                            .parse::<i64>()
                            .is_ok_and(|t| crate::exec::now() - t > (s.up_timeout as i64).saturating_add(30));
                    state = if stale { "failed" } else { "connecting" };
                } else if iface
                    .strip_prefix("ppp")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    && crate::sstp::iface_up(s.test_mode, s.test.iface_ok, &iface)
                {
                    state = "connected";
                    ip = fsx::cat(&d.join("ip"));
                }
            }
        }
        "strongswan" => {
            let conn = fsx::cat(&d.join("conn"));
            if let Some(sw) = find_swanctl(s)
                && crate::strongswan::is_name(&conn)
                && let Some(st) = crate::strongswan::sa_state(&sw, &conn, mode(s))
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
    [b.join("bin/swanctl"), b.join("sbin/swanctl")].into_iter().find(|c| crate::exec::is_executable(c))
}

/// `ifconfig <if> | awk '/inet /{ print $2; exit }'`
fn inet_of(iface: &str) -> String {
    let Some((_, out)) = crate::exec::capture(&Cmd::new("/sbin/ifconfig").arg(iface), EnvMode::Minimal, 1 << 16) else {
        return String::new();
    };
    String::from_utf8_lossy(&out)
        .lines()
        .find(|l| l.contains("inet "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or_default()
        .to_string()
}

/// `status_flush_openvpn`: a connected OpenVPN's root-only log is copied at status time too, only under the
/// connection's lock taken without waiting (a running up/down does the copying). Status does not know the
/// secrets, so password- and authentication-like lines are left out.
fn flush_openvpn(s: &Settings, d: &Path, id: &str) {
    let log = s.log_file(id);
    let olog = d.join("openvpn.log");
    if !is_file(&log) || is_symlink(&log) || !is_file(&olog) || is_symlink(&olog) {
        return;
    }
    let lock = s.run_base.join(format!(".{id}.lock"));
    if !crate::lock::try_take(&lock) {
        return;
    }
    flush_root_log(&Log::at(log), &olog, "", true, &Masker::default());
    crate::lock::release_try(&lock);
}

fn json_str(v: &str) -> String {
    if v.is_empty() { "null".into() } else { format!("\"{v}\"") }
}

/// `status_all`
pub fn render(s: &Settings) -> String {
    let mut names: Vec<String> = std::fs::read_dir(&s.run_base)
        .map(|it| it.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    let mut out = String::from("[");
    let mut sep = "";
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
        let since = if is_digits(&since) { since } else { "null".into() };
        if kind == "openvpn" {
            flush_openvpn(s, &d, &id);
        }
        let st = one(s, &d);
        out.push_str(&format!(
            "{sep}{{\"id\":\"{id}\",\"kind\":\"{kind}\",\"state\":\"{}\",\"iface\":{},\"ip\":{},\"since\":{since}}}",
            st.state,
            json_str(&st.iface),
            json_str(&st.ip)
        ));
        sep = ",";
    }
    out.push_str("]\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testmode::TestEnv;

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
}
