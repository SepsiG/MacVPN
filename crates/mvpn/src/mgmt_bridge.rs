//! The root-side bridge between OpenVPN's management interface and the MacVPN app (spec 10f); successor of the
//! Swift `mvpn-mgmt`. Started only by `mvpn up openvpn` (in the background, `argv[0]` = `mvpn-mgmt`):
//!
//! ```text
//! mvpn-mgmt --id <uuid> --run <run dir> --ui <state dir> --uid <n> --gid <n> [--max-wait <s>]
//! ```
//!
//! - The management socket (`<run>/mgmt.sock`) is in the root 0700 run directory; this process is its only client.
//! - Input from mvpn: `<run>/mgmt-creds` (root 0600: `username=`, `password=`, `packed=`), deleted right after
//!   reading; the raw bytes are zeroed.
//! - Answers from the app: `<run>/mgmt-resp` (written by `mvpn respond`), read once, deleted, validated again.
//! - Output for the user: `<ui>/<ID>.json` (the user's, 0600, atomic, symlink-safe): only the challenge text, the
//!   echo flag, the https URL, the state and the deadline. Never a secret.
//! - Output for mvpn: `<run>/mgmt-status` (root 0600): `wait <unix time>` | `ok` | `failed` | `cancelled` | `timeout`.
//! - One authentication round (from the first wait to CONNECTED) waits at most `--max-wait` seconds in total:
//!   repeated OPEN_URL / WEB_AUTH / CR_TEXT do not extend it. After that openvpn is stopped.
//! - Only the closed [`ManagementCommand`] set is ever sent; there is no generic forwarding.
//! - The log (stdout → the connection log) gets event kinds and the web URL's host only.

use macvpn_core::management::{
    CRV1Challenge, ManagementCommand, ManagementCredentials, ManagementEvent, ManagementParser, ManagementResponse,
    ManagementStaticRequest,
};
use macvpn_core::mfa::{
    self, AuthResponseKind, AuthUIMethod, AuthUIState, AuthUIStateKind, CODE_PROMPT_TIMEOUT, WEB_AUTH_TIMEOUT,
    WebAuthURL,
};
use macvpn_core::models::{parse_uuid, uuid_string};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

fn log(s: &str) {
    out!("[mgmt] {s}");
}

/// The parsed command line.
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeArgs {
    pub id: String,
    pub run: String,
    pub ui: String,
    pub uid: u32,
    pub gid: u32,
    pub max_wait: f64,
}

impl BridgeArgs {
    /// Every key from the fixed set with a value; an absolute path without `..`, at most 200 bytes.
    pub fn parse(argv: &[String]) -> Option<BridgeArgs> {
        let mut map = std::collections::HashMap::new();
        let mut it = argv.iter();
        while let Some(key) = it.next() {
            if !["--id", "--run", "--ui", "--uid", "--gid", "--max-wait"].contains(&key.as_str()) {
                return None;
            }
            map.insert(key.as_str(), it.next()?.clone());
        }
        let id = uuid_string(&parse_uuid(map.get("--id")?)?);
        let run = map.get("--run")?.clone();
        let ui = map.get("--ui")?.clone();
        let uid = map.get("--uid")?.parse().ok()?;
        let gid = map.get("--gid")?.parse().ok()?;
        for p in [&run, &ui] {
            if !p.starts_with('/') || p.contains("/../") || p.ends_with("/..") || p.len() > 200 {
                return None;
            }
        }
        let max_wait =
            map.get("--max-wait").and_then(|v| v.parse::<i64>().ok()).map(|v| v.clamp(1, 3600)).unwrap_or(420) as f64;
        Some(BridgeArgs { id, run, ui, uid, gid, max_wait })
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// A safe directory: a real directory (not a symlink); as root owned by root and not writable by others
/// (`private`: no access for others at all).
fn trusted_directory(path: &str, private: bool, is_root: bool) -> bool {
    let Ok(m) = std::fs::symlink_metadata(path) else { return false };
    if !m.file_type().is_dir() {
        return false;
    }
    if is_root {
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return false;
        }
        if private && m.mode() & 0o077 != 0 {
            return false;
        }
    }
    true
}

/// Our own regular file with a single link (no symlink followed), at most `max` bytes; optionally removed.
fn read_private_file(path: &Path, max: u64, remove: bool) -> Option<Zeroizing<Vec<u8>>> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path);
    let result = (|| {
        let mut f = file.ok()?;
        let m = f.metadata().ok()?;
        if !m.file_type().is_file() || m.uid() != crate::sys::geteuid() || m.nlink() != 1 || m.len() > max {
            return None;
        }
        let mut data = Zeroizing::new(Vec::with_capacity(m.len() as usize));
        (&mut f).take(max).read_to_end(&mut data).ok()?;
        (data.len() as u64 == m.len()).then_some(data)
    })();
    if remove {
        let _ = std::fs::remove_file(path);
    }
    result
}

struct Bridge {
    a: BridgeArgs,
    is_root: bool,
    sock: UnixStream,
    creds: Option<ManagementCredentials>,
    temp_counter: u64,
    seq: i64,
    pending_crv1: Option<CRV1Challenge>,
    crv1_response: Option<Zeroizing<String>>,
    need_auth_waiting: bool,
    pending_static: Option<ManagementStaticRequest>,
    cr_text_pending: bool,
    awaiting_user: bool,
    deadline: Option<f64>,
    pending_timeout: f64,
    finished: bool,
    round_start: Option<f64>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(c) = &mut self.creds {
            c.username.zeroize();
            c.password.zeroize();
        }
    }
}

impl Bridge {
    /// Atomic write: a new, exclusive (O_EXCL, O_NOFOLLOW) temporary file in the same directory, 0600, optionally
    /// given to the user, then `rename` (which replaces a symlink rather than following it).
    fn write_atomic(&mut self, dir: &str, name: &str, data: &[u8], owner: Option<(u32, u32)>) -> bool {
        self.temp_counter += 1;
        let tmp = PathBuf::from(format!("{dir}/.{name}.{}.{}", std::process::id(), self.temp_counter));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp);
        let Ok(mut f) = file else { return false };
        let mut ok = f.write_all(data).is_ok();
        if ok
            && let Some((uid, gid)) = owner
            && self.is_root
        {
            ok = std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).is_ok();
        }
        if ok {
            use std::os::unix::fs::PermissionsExt;
            ok = f.set_permissions(std::fs::Permissions::from_mode(0o600)).is_ok();
        }
        drop(f);
        if ok {
            ok = std::fs::rename(&tmp, format!("{dir}/{name}")).is_ok();
        }
        if !ok {
            let _ = std::fs::remove_file(&tmp);
        }
        ok
    }

    fn ui_name(&self) -> String {
        format!("{}.json", self.a.id)
    }

    fn publish(
        &mut self,
        state: AuthUIStateKind,
        method: Option<AuthUIMethod>,
        text: Option<String>,
        echo: Option<bool>,
        url: Option<String>,
        deadline: Option<f64>,
    ) {
        if !trusted_directory(&self.a.ui, false, self.is_root) {
            log("state directory is not safe, state not written");
            return;
        }
        self.seq += 1;
        let mut s = AuthUIState::new(self.seq, state);
        s.method = method;
        s.text = text;
        s.echo = echo;
        s.url = url;
        s.deadline = deadline.map(f64::round);
        let (dir, name, owner) = (self.a.ui.clone(), self.ui_name(), Some((self.a.uid, self.a.gid)));
        if !self.write_atomic(&dir, &name, &s.encoded(), owner) {
            log("cannot write the state file");
        }
    }

    fn clear_ui(&self) {
        if trusted_directory(&self.a.ui, false, self.is_root) {
            let _ = std::fs::remove_file(format!("{}/{}", self.a.ui, self.ui_name()));
        }
    }

    fn status(&mut self, line: &str) {
        if !trusted_directory(&self.a.run, true, self.is_root) {
            return;
        }
        let run = self.a.run.clone();
        let _ = self.write_atomic(&run, "mgmt-status", format!("{line}\n").as_bytes(), None);
    }

    /// A final failure or a cancel: openvpn is stopped (SIGTERM) so it does not retry (auth-retry interact). Only
    /// the process in `<run>/pid` whose executable is named `openvpn` (pid reuse).
    fn stop_openvpn(&self) {
        let Some(data) = read_private_file(&Path::new(&self.a.run).join("pid"), 32, false) else { return };
        let Ok(text) = std::str::from_utf8(&data) else { return };
        let Ok(pid) = text.trim().parse::<i32>() else { return };
        if pid <= 1 {
            return;
        }
        let named_openvpn =
            crate::sys::exec_path(pid).is_some_and(|p| Path::new(&p).file_name().is_some_and(|n| n == "openvpn"));
        if named_openvpn {
            let _ = crate::sys::kill(pid, crate::sys::SIGTERM);
        }
    }

    /// A deadline for the user / the server, but at most the round start + `max_wait`.
    fn wait_for(&mut self, seconds: f64) -> f64 {
        let n = now();
        let start = self.round_start.unwrap_or(n);
        self.round_start = Some(start);
        let d = (n + seconds).min(start + self.a.max_wait);
        self.deadline = Some(d);
        self.status(&format!("wait {}", d.ceil() as i64));
        d
    }

    fn finish(&mut self, reason: &str, cancelled: bool, timed_out: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.awaiting_user = false;
        log(reason);
        self.status(if cancelled {
            "cancelled"
        } else if timed_out {
            "timeout"
        } else {
            "failed"
        });
        self.publish(
            if cancelled { AuthUIStateKind::Cancelled } else { AuthUIStateKind::Failed },
            None,
            None,
            None,
            None,
            None,
        );
        self.stop_openvpn();
    }

    fn send(&mut self, command: &ManagementCommand) -> bool {
        let Some(line) = command.line() else { return false };
        let data = Zeroizing::new(format!("{line}\n").into_bytes());
        drop(Zeroizing::new(line));
        self.sock.write_all(&data).is_ok()
    }

    fn send_credentials(&mut self, username: &str, password: &str) {
        let ok = self.send(&ManagementCommand::Username(username.to_string()))
            && self.send(&ManagementCommand::Password(password.to_string()));
        if !ok {
            self.finish(
                "credentials cannot be sent (empty user name, control character, or longer than 255 bytes)",
                false,
                false,
            );
            return;
        }
        log("credentials sent");
    }

    fn send_crv1(&mut self) {
        if self.pending_crv1.is_none() || self.crv1_response.is_none() {
            return;
        }
        let (Some(c), Some(response)) = (self.pending_crv1.take(), self.crv1_response.take()) else { return };
        self.need_auth_waiting = false;
        let password = Zeroizing::new(c.password(&response));
        self.send_credentials(&c.username, &password);
    }

    fn stored(&self) -> Option<(String, Zeroizing<String>, bool)> {
        self.creds
            .as_ref()
            .filter(|c| !c.username.is_empty())
            .map(|c| (c.username.clone(), Zeroizing::new(c.password.clone()), c.packed))
    }

    fn handle_event(&mut self, event: ManagementEvent) {
        if self.finished {
            return;
        }
        match event {
            ManagementEvent::Hold => {
                if self.send(&ManagementCommand::HoldRelease) {
                    log("hold released");
                }
            }
            ManagementEvent::NeedAuth(None) => {
                if self.pending_crv1.is_some() {
                    if self.crv1_response.is_some() {
                        self.send_crv1();
                    } else {
                        self.need_auth_waiting = true;
                    }
                } else if let Some((user, pass, _)) = self.stored() {
                    self.send_credentials(&user, &pass);
                } else {
                    self.finish("the server asks for a user name and password, but none is stored", false, false);
                }
            }
            ManagementEvent::NeedAuth(Some(sc)) => {
                let Some((user, pass, packed)) = self.stored() else {
                    self.finish("the server asks for a user name and password, but none is stored", false, false);
                    return;
                };
                if packed {
                    self.send_credentials(&user, &pass);
                } else {
                    self.awaiting_user = true;
                    let d = self.wait_for(CODE_PROMPT_TIMEOUT);
                    let (text, echo) = (sc.text.clone(), sc.echo);
                    self.pending_static = Some(sc);
                    self.publish(
                        AuthUIStateKind::Challenge,
                        Some(AuthUIMethod::Static),
                        Some(text),
                        Some(echo),
                        None,
                        Some(d),
                    );
                    log("static challenge received");
                }
            }
            ManagementEvent::NeedOther => {
                self.finish("OpenVPN asks for a password that MacVPN does not provide here", false, false)
            }
            ManagementEvent::DynamicChallenge(c) => {
                let (required, text, echo) = (c.response_required, c.text.clone(), c.echo);
                self.pending_crv1 = Some(c);
                self.crv1_response = None;
                if required {
                    self.awaiting_user = true;
                    let d = self.wait_for(CODE_PROMPT_TIMEOUT);
                    self.publish(
                        AuthUIStateKind::Challenge,
                        Some(AuthUIMethod::Crv1),
                        Some(text),
                        Some(echo),
                        None,
                        Some(d),
                    );
                    log("dynamic challenge received");
                } else {
                    self.crv1_response = Some(Zeroizing::new(String::new()));
                    log("dynamic challenge received (no response required)");
                }
            }
            ManagementEvent::AuthFailed => self.finish("authentication failed", false, false),
            ManagementEvent::AuthRetry => log("authentication will be retried (session expired or temporary failure)"),
            ManagementEvent::WebAuth(Some(url)) => {
                self.awaiting_user = true;
                let d = self.wait_for(self.pending_timeout);
                let host = WebAuthURL::display_host(&url);
                self.publish(AuthUIStateKind::Webauth, Some(AuthUIMethod::Webauth), None, None, Some(url), Some(d));
                log(&format!("web authentication requested: {host}"));
            }
            ManagementEvent::WebAuth(None) => {
                self.awaiting_user = true;
                let d = self.wait_for(self.pending_timeout);
                self.publish(AuthUIStateKind::Pending, None, None, None, None, Some(d));
                log("web authentication URL dropped (only https with a plain ASCII host is accepted)");
            }
            ManagementEvent::CrText { echo, text } => {
                self.cr_text_pending = true;
                self.awaiting_user = true;
                let d = self.wait_for(CODE_PROMPT_TIMEOUT);
                self.publish(
                    AuthUIStateKind::Challenge,
                    Some(AuthUIMethod::Crtext),
                    Some(text),
                    Some(echo),
                    None,
                    Some(d),
                );
                log("challenge received (CR_TEXT)");
            }
            ManagementEvent::AuthPending(timeout) => {
                self.pending_timeout = timeout.map(|t| t as f64).unwrap_or(WEB_AUTH_TIMEOUT).min(WEB_AUTH_TIMEOUT);
                if !self.awaiting_user {
                    self.awaiting_user = true;
                    let d = self.wait_for(self.pending_timeout);
                    self.publish(AuthUIStateKind::Pending, None, None, None, None, Some(d));
                }
                log("authentication pending");
            }
            ManagementEvent::Connected => {
                self.awaiting_user = false;
                self.deadline = None;
                self.round_start = None;
                self.status("ok");
                self.clear_ui();
                log("authenticated");
            }
            ManagementEvent::Fatal => self.finish("OpenVPN reported a fatal error", false, false),
            ManagementEvent::Ignored => {}
        }
    }

    fn handle_response(&mut self, r: ManagementResponse) {
        if self.finished {
            return;
        }
        let response = Zeroizing::new(r.response.clone());
        match r.kind {
            AuthResponseKind::Cancel => self.finish("cancelled by the user", true, false),
            AuthResponseKind::WebauthAck => log("web authentication opened in the browser"),
            AuthResponseKind::Crv1 => {
                if self.cr_text_pending {
                    self.cr_text_pending = false;
                    self.awaiting_user = false;
                    if !self.send(&ManagementCommand::CrResponse(response.to_string())) {
                        self.finish("the response cannot be sent (too long)", false, false);
                        return;
                    }
                    let d = self.deadline;
                    self.publish(AuthUIStateKind::Pending, None, None, None, None, d);
                    log("response sent (CR_TEXT)");
                } else if self.pending_crv1.is_some() {
                    self.crv1_response = Some(Zeroizing::new(response.to_string()));
                    self.awaiting_user = false;
                    let d = self.deadline;
                    self.publish(AuthUIStateKind::Pending, None, None, None, None, d);
                    log("response received (CRV1)");
                    if self.need_auth_waiting {
                        self.send_crv1();
                    }
                } else {
                    log("response ignored: no challenge is pending");
                }
            }
            AuthResponseKind::Static => {
                let (Some(sc), Some((user, pass, _))) = (self.pending_static.clone(), self.stored()) else {
                    log("response ignored: no static challenge is pending");
                    return;
                };
                self.pending_static = None;
                self.awaiting_user = false;
                let password = Zeroizing::new(if sc.concat {
                    format!("{}{}", pass.as_str(), response.as_str())
                } else {
                    mfa::scrv1(&pass, &response)
                });
                let d = self.deadline;
                self.publish(AuthUIStateKind::Pending, None, None, None, None, d);
                self.send_credentials(&user, &password);
            }
        }
    }
}

/// As root only the root layer's own directories: `/var/run/macvpn/<id>` and `/var/run/macvpn-ui`.
fn root_paths_ok(a: &BridgeArgs) -> bool {
    let run = Path::new(&a.run);
    let same_id = run.file_name().and_then(|n| n.to_str()).and_then(parse_uuid).map(|u| uuid_string(&u));
    run.parent() == Some(Path::new(crate::paths::RUN_BASE))
        && same_id.as_deref() == Some(a.id.as_str())
        && a.ui == crate::paths::UI_BASE
}

/// Connects to `<run>/mgmt.sock`, retrying for up to 60 s while the run directory stays trusted.
fn connect(a: &BridgeArgs, is_root: bool) -> Option<UnixStream> {
    let sock_path = format!("{}/mgmt.sock", a.run);
    let end = now() + 60.0;
    while now() < end {
        if !trusted_directory(&a.run, true, is_root) {
            std::process::exit(0);
        }
        if let Ok(s) = UnixStream::connect(&sock_path) {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

/// `mvpn-mgmt …` / `mvpn mgmt-bridge …`; returns the exit code.
pub fn main(argv: &[String]) -> i32 {
    let fail = |s: &str| {
        log(s);
        1
    };
    let Some(a) = BridgeArgs::parse(argv) else { return fail("usage error") };
    let is_root = crate::sys::geteuid() == 0;
    if is_root && !root_paths_ok(&a) {
        return fail("usage error");
    }
    if !trusted_directory(&a.run, true, is_root) {
        return fail("the run directory is not safe");
    }
    let creds_path = Path::new(&a.run).join("mgmt-creds");
    let creds = read_private_file(&creds_path, 4096, true).and_then(|d| ManagementCredentials::parse(&d));
    let _ = std::fs::remove_file(&creds_path);
    let Some(sock) = connect(&a, is_root) else { return fail("the management socket did not appear") };
    log("connected");
    let resp_path = Path::new(&a.run).join("mgmt-resp");
    let mut b = Bridge {
        a,
        is_root,
        sock,
        creds,
        temp_counter: 0,
        seq: 0,
        pending_crv1: None,
        crv1_response: None,
        need_auth_waiting: false,
        pending_static: None,
        cr_text_pending: false,
        awaiting_user: false,
        deadline: None,
        pending_timeout: WEB_AUTH_TIMEOUT,
        finished: false,
        round_start: None,
    };
    let _ = b.send(&ManagementCommand::StateOn);
    let _ = b.sock.set_read_timeout(Some(Duration::from_millis(250)));
    let mut buffer: Vec<u8> = Vec::new();
    let mut skipping = false;
    let mut chunk = [0u8; 4096];
    loop {
        match b.sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                for &byte in &chunk[..n] {
                    if byte == b'\n' {
                        if !skipping {
                            if buffer.last() == Some(&b'\r') {
                                buffer.pop();
                            }
                            let line = String::from_utf8_lossy(&buffer).into_owned();
                            b.handle_event(ManagementParser::parse(&line));
                        }
                        buffer.clear();
                        skipping = false;
                    } else if !skipping {
                        buffer.push(byte);
                        // A line that is too long is dropped up to the next line end.
                        if buffer.len() > ManagementParser::MAX_LINE_BYTES {
                            buffer.clear();
                            skipping = true;
                        }
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
        if !trusted_directory(&b.a.run, true, b.is_root) {
            break;
        }
        if let Some(data) = read_private_file(&resp_path, ManagementResponse::MAX_FILE_BYTES as u64, true) {
            match ManagementResponse::parse(&data) {
                Some(r) => b.handle_response(r),
                None => log("invalid response ignored"),
            }
        }
        if b.awaiting_user && b.deadline.is_some_and(|d| now() > d) {
            b.finish("timed out waiting for authentication", false, true);
        }
    }
    log("management connection closed");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn arguments() {
        let a = BridgeArgs::parse(&v(&[
            "--id",
            "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "--run",
            "/var/run/macvpn/x",
            "--ui",
            "/var/run/macvpn-ui",
            "--uid",
            "501",
            "--gid",
            "20",
        ]))
        .unwrap();
        assert_eq!(a.id, "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        assert_eq!(a.max_wait, 420.0);
        let base = ["--id", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--ui", "/u", "--uid", "1", "--gid", "1"];
        let with = |run: &str, extra: &[&str]| {
            let mut x = v(&base);
            x.extend(v(&["--run", run]));
            x.extend(v(extra));
            BridgeArgs::parse(&x)
        };
        assert_eq!(with("/r", &["--max-wait", "99999"]).unwrap().max_wait, 3600.0);
        assert_eq!(with("/r", &["--max-wait", "0"]).unwrap().max_wait, 1.0);
        assert!(with("relative", &[]).is_none());
        assert!(with("/a/../b", &[]).is_none());
        assert!(with("/a/..", &[]).is_none());
        assert!(with(&format!("/{}", "a".repeat(200)), &[]).is_none());
        assert!(with("/r", &["--bogus", "1"]).is_none());
        assert!(with("/r", &["--max-wait"]).is_none());
        assert!(BridgeArgs::parse(&v(&["--id", "x"])).is_none());
    }

    #[test]
    fn trusted_directories() {
        let d = std::env::temp_dir().join(format!("mvpn-bridge-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        let link = d.with_extension("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(trusted_directory(d.to_str().unwrap(), true, false));
        assert!(!trusted_directory(link.to_str().unwrap(), true, false));
        assert!(!trusted_directory(d.to_str().unwrap(), true, true), "not root-owned");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&d);
    }

    #[test]
    fn private_file_is_read_once() {
        let d = std::env::temp_dir().join(format!("mvpn-bridge-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        let f = d.join("mgmt-creds");
        std::fs::write(&f, "username=bob\npassword=x\npacked=0\n").unwrap();
        let data = read_private_file(&f, 4096, true).unwrap();
        assert_eq!(ManagementCredentials::parse(&data).unwrap().username, "bob");
        assert!(!f.exists());
        std::fs::write(&f, "x").unwrap();
        std::fs::hard_link(&f, d.join("hl")).unwrap();
        assert!(read_private_file(&f, 4096, false).is_none(), "hardlinked");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn root_only_accepts_the_root_layer_directories() {
        let mk = |run: &str, ui: &str| BridgeArgs {
            id: "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".into(),
            run: run.into(),
            ui: ui.into(),
            uid: 501,
            gid: 20,
            max_wait: 420.0,
        };
        assert!(root_paths_ok(&mk("/var/run/macvpn/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/run/macvpn/11111111-4b5a-6978-8796-a5b4c3d2e1f0", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/root", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/run/macvpn/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "/tmp")));
    }
}
