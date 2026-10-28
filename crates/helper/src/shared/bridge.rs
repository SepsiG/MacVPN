//! The root-side bridge between OpenVPN's management interface and the MacVPN app (spec 10f); successor of the
//! Swift `mvpn-mgmt`. This module is the state machine ([`Bridge`]) over any stream; the backend supplies the
//! management socket and the files ([`BridgeFiles`]; macOS: `macos::mgmt_bridge`). Started only by
//! `mvpn up openvpn` (in the background, `argv[0]` = `mvpn-mgmt`):
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
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

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

    /// A bridge inside the WinVPN Service: no run or state directory, no user ids (the service keeps the state in
    /// memory and answers for the user over its pipe). `max_wait` clamped as `--max-wait` is (not a number: `None`).
    pub fn in_process(id: &str, max_wait: f64) -> Option<BridgeArgs> {
        if max_wait.is_nan() {
            return None;
        }
        let id = uuid_string(&parse_uuid(id)?);
        Some(BridgeArgs {
            id,
            run: String::new(),
            ui: String::new(),
            uid: 0,
            gid: 0,
            max_wait: max_wait.clamp(1.0, 3600.0),
        })
    }
}

/// The bridge's `mgmt-status` line: `^(wait [0-9]{1,12}|ok|failed|cancelled|timeout)$`
pub fn valid_status(s: &str) -> bool {
    match s.strip_prefix("wait ") {
        Some(n) => (1..=12).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()),
        None => matches!(s, "ok" | "failed" | "cancelled" | "timeout"),
    }
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// What the bridge reads and writes besides the management stream: the log, the run directory (root-only) and
/// the user's state directory. The macOS backend implements it over the root-owned directories, with `O_NOFOLLOW`
/// reads and atomic writes.
pub trait BridgeFiles {
    /// One line of the bridge's log (event kinds and the web URL's host only, never a secret).
    fn log(&mut self, line: &str);
    /// The run directory is still a safe directory (private to root, as root).
    fn run_trusted(&self) -> bool;
    /// The user's state directory is a safe directory.
    fn ui_trusted(&self) -> bool;
    /// Writes `<ui>/<name>` atomically (0600, given to the user); `false` if it could not be written.
    fn write_ui(&mut self, name: &str, data: &[u8]) -> bool;
    /// Writes `<run>/<name>` atomically (root 0600); `false` if it could not be written.
    fn write_run(&mut self, name: &str, data: &[u8]) -> bool;
    /// Removes `<ui>/<name>` (best effort).
    fn remove_ui(&mut self, name: &str);
    /// The app's answer (`<run>/mgmt-resp`), read once and removed; at most `ManagementResponse::MAX_FILE_BYTES`.
    fn take_response(&mut self) -> Option<Zeroizing<Vec<u8>>>;
    /// A final failure or a cancel: openvpn is stopped so it does not retry (auth-retry interact).
    fn stop_openvpn(&mut self);
    /// Called every [`HOUSEKEEPING_SECS`] while the bridge runs (it runs as long as openvpn): the macOS backend keeps
    /// the logs under their caps there, also when the app does not poll the status.
    fn housekeeping(&mut self) {}
    /// Dead-tunnel detection: OpenVPN's tunnel after it was first connected, `Some(t)` restarting itself since the
    /// Unix time `t` (`>STATE:…,RECONNECTING`), `None` up again. Default: the run file `tunnel` (`up` |
    /// `reconnecting <t>`), which `mvpn liveness` reads.
    fn tunnel(&mut self, reconnecting_since: Option<u64>) {
        let line = match reconnecting_since {
            Some(t) => format!("reconnecting {t}\n"),
            None => "up\n".to_string(),
        };
        if self.run_trusted() {
            let _ = self.write_run("tunnel", line.as_bytes());
        }
    }
}

/// How often the bridge calls [`BridgeFiles::housekeeping`].
pub const HOUSEKEEPING_SECS: f64 = 30.0;

/// The bridge's state machine over the management stream `S`.
pub struct Bridge<S: Read + Write, F: BridgeFiles> {
    a: BridgeArgs,
    sock: S,
    files: F,
    creds: Option<ManagementCredentials>,
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
    last_housekeeping: f64,
    /// The tunnel was connected once (a later `RECONNECTING` is OpenVPN's own restart).
    was_connected: bool,
    /// OpenVPN restarts the tunnel itself (reported once per restart).
    reconnecting: bool,
}

impl<S: Read + Write, F: BridgeFiles> Drop for Bridge<S, F> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(c) = &mut self.creds {
            c.username.zeroize();
            c.password.zeroize();
        }
    }
}

impl<S: Read + Write, F: BridgeFiles> Bridge<S, F> {
    pub fn new(a: BridgeArgs, sock: S, files: F, creds: Option<ManagementCredentials>) -> Bridge<S, F> {
        Bridge {
            a,
            sock,
            files,
            creds,
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
            last_housekeeping: now(),
            was_connected: false,
            reconnecting: false,
        }
    }

    fn log(&mut self, s: &str) {
        self.files.log(s);
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
        if !self.files.ui_trusted() {
            self.log("state directory is not safe, state not written");
            return;
        }
        self.seq += 1;
        let mut s = AuthUIState::new(self.seq, state);
        s.method = method;
        s.text = text;
        s.echo = echo;
        s.url = url;
        s.deadline = deadline.map(f64::round);
        let name = self.ui_name();
        if !self.files.write_ui(&name, &s.encoded()) {
            self.log("cannot write the state file");
        }
    }

    fn clear_ui(&mut self) {
        if self.files.ui_trusted() {
            let name = self.ui_name();
            self.files.remove_ui(&name);
        }
    }

    fn status(&mut self, line: &str) {
        if !self.files.run_trusted() {
            return;
        }
        let _ = self.files.write_run("mgmt-status", format!("{line}\n").as_bytes());
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
        self.log(reason);
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
        self.files.stop_openvpn();
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
        self.log("credentials sent");
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
                    self.log("hold released");
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
                    self.log("static challenge received");
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
                    self.log("dynamic challenge received");
                } else {
                    self.crv1_response = Some(Zeroizing::new(String::new()));
                    self.log("dynamic challenge received (no response required)");
                }
            }
            ManagementEvent::AuthFailed => self.finish("authentication failed", false, false),
            ManagementEvent::AuthRetry => {
                self.log("authentication will be retried (session expired or temporary failure)")
            }
            ManagementEvent::WebAuth(Some(url)) => {
                self.awaiting_user = true;
                let d = self.wait_for(self.pending_timeout);
                let host = WebAuthURL::display_host(&url);
                self.publish(AuthUIStateKind::Webauth, Some(AuthUIMethod::Webauth), None, None, Some(url), Some(d));
                self.log(&format!("web authentication requested: {host}"));
            }
            ManagementEvent::WebAuth(None) => {
                self.awaiting_user = true;
                let d = self.wait_for(self.pending_timeout);
                self.publish(AuthUIStateKind::Pending, None, None, None, None, Some(d));
                self.log("web authentication URL dropped (only https with a plain ASCII host is accepted)");
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
                self.log("challenge received (CR_TEXT)");
            }
            ManagementEvent::AuthPending(timeout) => {
                self.pending_timeout = timeout.map(|t| t as f64).unwrap_or(WEB_AUTH_TIMEOUT).min(WEB_AUTH_TIMEOUT);
                if !self.awaiting_user {
                    self.awaiting_user = true;
                    let d = self.wait_for(self.pending_timeout);
                    self.publish(AuthUIStateKind::Pending, None, None, None, None, Some(d));
                }
                self.log("authentication pending");
            }
            ManagementEvent::Connected => {
                self.awaiting_user = false;
                self.deadline = None;
                self.round_start = None;
                self.status("ok");
                self.clear_ui();
                if self.reconnecting {
                    self.log("reconnected");
                } else {
                    self.log("authenticated");
                }
                self.was_connected = true;
                self.reconnecting = false;
                self.files.tunnel(None);
            }
            ManagementEvent::Reconnecting => {
                if self.was_connected && !self.reconnecting {
                    self.reconnecting = true;
                    self.log("reconnecting (OpenVPN restarts the tunnel)");
                    self.files.tunnel(Some(now() as u64));
                }
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
            AuthResponseKind::WebauthAck => self.log("web authentication opened in the browser"),
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
                    self.log("response sent (CR_TEXT)");
                } else if self.pending_crv1.is_some() {
                    self.crv1_response = Some(Zeroizing::new(response.to_string()));
                    self.awaiting_user = false;
                    let d = self.deadline;
                    self.publish(AuthUIStateKind::Pending, None, None, None, None, d);
                    self.log("response received (CRV1)");
                    if self.need_auth_waiting {
                        self.send_crv1();
                    }
                } else {
                    self.log("response ignored: no challenge is pending");
                }
            }
            AuthResponseKind::Static => {
                let (Some(sc), Some((user, pass, _))) = (self.pending_static.clone(), self.stored()) else {
                    self.log("response ignored: no static challenge is pending");
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

impl<S: Read + Write, F: BridgeFiles> Bridge<S, F> {
    /// The bridge's loop: `state on`, then every management line, the app's answers and the deadline, until the
    /// stream ends or the run directory is no longer safe. The backend sets a short read timeout on the stream
    /// (`WouldBlock` / `TimedOut` only poll the answers and the deadline).
    pub fn run(&mut self) {
        let _ = self.send(&ManagementCommand::StateOn);
        let mut buffer: Vec<u8> = Vec::new();
        let mut skipping = false;
        let mut chunk = [0u8; 4096];
        loop {
            match self.sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    for &byte in &chunk[..n] {
                        if byte == b'\n' {
                            if !skipping {
                                if buffer.last() == Some(&b'\r') {
                                    buffer.pop();
                                }
                                let line = String::from_utf8_lossy(&buffer).into_owned();
                                self.handle_event(ManagementParser::parse(&line));
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
            if !self.files.run_trusted() {
                break;
            }
            if let Some(data) = self.files.take_response() {
                match ManagementResponse::parse(&data) {
                    Some(r) => self.handle_response(r),
                    None => self.log("invalid response ignored"),
                }
            }
            if self.awaiting_user && self.deadline.is_some_and(|d| now() > d) {
                self.finish("timed out waiting for authentication", false, true);
            }
            let t = now();
            if !(0.0..HOUSEKEEPING_SECS).contains(&(t - self.last_housekeeping)) {
                self.last_housekeeping = t;
                self.files.housekeeping();
            }
        }
    }
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
    fn in_process_arguments_carry_only_what_the_bridge_uses() {
        let a = BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 420.0).unwrap();
        assert_eq!(a.id, "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        assert_eq!(a.max_wait, 420.0);
        assert!(a.run.is_empty() && a.ui.is_empty());
        assert!(BridgeArgs::in_process("../x", 420.0).is_none());
        assert_eq!(BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 99999.0).unwrap().max_wait, 3600.0);
        assert_eq!(BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 0.0).unwrap().max_wait, 1.0);
        assert!(BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", f64::NAN).is_none());
    }

    #[test]
    fn bridge_status_format() {
        for ok in ["wait 1760000000", "wait 1", "ok", "failed", "cancelled", "timeout"] {
            assert!(valid_status(ok), "{ok}");
        }
        for bad in ["wait ", "wait 1234567890123", "wait x", "OK", "ok ", "done"] {
            assert!(!valid_status(bad), "{bad}");
        }
    }

    /// The management stream of a test: each read hands out the next chunk (an empty chunk is a read timeout);
    /// what the bridge writes is collected.
    struct Duplex {
        reads: std::collections::VecDeque<&'static str>,
        written: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.reads.pop_front() {
                None => Ok(0),
                Some("") => Err(std::io::ErrorKind::WouldBlock.into()),
                Some(chunk) => {
                    buf[..chunk.len()].copy_from_slice(chunk.as_bytes());
                    Ok(chunk.len())
                }
            }
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The files of a test: the app's answers are handed out by poll (one entry per loop turn).
    #[derive(Default)]
    struct Files {
        log: Vec<String>,
        ui: Vec<(String, String)>,
        run: Vec<(String, String)>,
        removed: Vec<String>,
        answers: std::collections::VecDeque<Option<&'static str>>,
        stopped: u32,
    }

    impl BridgeFiles for Files {
        fn log(&mut self, line: &str) {
            self.log.push(line.to_string());
        }
        fn run_trusted(&self) -> bool {
            true
        }
        fn ui_trusted(&self) -> bool {
            true
        }
        fn write_ui(&mut self, name: &str, data: &[u8]) -> bool {
            self.ui.push((name.to_string(), String::from_utf8(data.to_vec()).unwrap()));
            true
        }
        fn write_run(&mut self, name: &str, data: &[u8]) -> bool {
            self.run.push((name.to_string(), String::from_utf8(data.to_vec()).unwrap()));
            true
        }
        fn remove_ui(&mut self, name: &str) {
            self.removed.push(name.to_string());
        }
        fn take_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
            self.answers.pop_front().flatten().map(|a| Zeroizing::new(a.as_bytes().to_vec()))
        }
        fn stop_openvpn(&mut self) {
            self.stopped += 1;
        }
    }

    const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const CONNECTED: &str = ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1\n";

    fn exchange(
        reads: &[&'static str],
        answers: &[Option<&'static str>],
        creds: (&str, &str, bool),
    ) -> (String, Files) {
        let a = BridgeArgs { id: ID.into(), run: "/run".into(), ui: "/ui".into(), uid: 501, gid: 20, max_wait: 420.0 };
        let sock = Duplex { reads: reads.iter().copied().collect(), written: Vec::new() };
        let files = Files { answers: answers.iter().copied().collect(), ..Files::default() };
        let creds = ManagementCredentials { username: creds.0.into(), password: creds.1.into(), packed: creds.2 };
        let mut b = Bridge::new(a, sock, files, Some(creds));
        b.run();
        let written = String::from_utf8(std::mem::take(&mut b.sock.written)).unwrap();
        (written, std::mem::take(&mut b.files))
    }

    fn statuses(f: &Files) -> Vec<String> {
        f.run
            .iter()
            .filter(|(name, _)| name != "tunnel")
            .map(|(name, v)| {
                assert_eq!(name, "mgmt-status");
                v.split(' ').next().unwrap().trim().to_string()
            })
            .collect()
    }

    fn tunnel(f: &Files) -> Vec<String> {
        f.run.iter().filter(|(name, _)| name == "tunnel").map(|(_, v)| v.clone()).collect()
    }

    /// Dead-tunnel detection: after the first CONNECTED, OpenVPN's own restart (`RECONNECTING`, then the states of
    /// its new attempt) is written to the run file `tunnel` once, with its start; CONNECTED again writes `up`. A
    /// RECONNECTING before the first connect is not a restart.
    #[test]
    fn openvpns_own_restart_is_written_for_liveness() {
        let (_, f) = exchange(
            &[
                ">STATE:1700000000,RECONNECTING,init_instance,,,,,\n",
                CONNECTED,
                ">STATE:1700000100,RECONNECTING,ping-restart,,,,,\n",
                ">STATE:1700000101,WAIT,,,,,,\n",
                ">STATE:1700000102,RECONNECTING,ping-restart,,,,,\n",
                CONNECTED,
            ],
            &[],
            ("alice", "pw", false),
        );
        let t = tunnel(&f);
        assert_eq!(t.len(), 3, "{t:?}");
        assert_eq!(t[0], "up\n");
        let since: u64 = t[1].strip_prefix("reconnecting ").unwrap().trim().parse().unwrap();
        assert!(since > 1_700_000_000, "the bridge's own clock");
        assert_eq!(t[2], "up\n");
        assert!(f.log.contains(&"reconnecting (OpenVPN restarts the tunnel)".to_string()), "{:?}", f.log);
        assert!(f.log.contains(&"reconnected".to_string()), "{:?}", f.log);
    }

    #[test]
    fn crv1_exchange() {
        let (written, f) = exchange(
            &[
                ">HOLD:Waiting for hold release:0\n",
                ">PASSWORD:Need 'Auth' username/password\n",
                ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Ym9i:Enter your PIN']\n",
                "",
                ">PASSWORD:Need 'Auth' username/password\n",
                CONNECTED,
            ],
            &[None, None, None, Some("kind=crv1\nresponse=123456\n")],
            ("alice", "pw", false),
        );
        assert_eq!(
            written,
            "state on\nhold release\nusername \"Auth\" \"alice\"\npassword \"Auth\" \"pw\"\n\
             username \"Auth\" \"bob\"\npassword \"Auth\" \"CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::123456\"\n"
        );
        assert_eq!(
            f.log,
            [
                "hold released",
                "credentials sent",
                "dynamic challenge received",
                "response received (CRV1)",
                "credentials sent",
                "authenticated"
            ]
        );
        assert_eq!(statuses(&f), ["wait", "ok"]);
        assert_eq!(f.ui.len(), 2);
        assert!(f.ui.iter().all(|(name, _)| *name == format!("{ID}.json")));
        assert!(f.ui[0].1.contains("\"crv1\"") && f.ui[0].1.contains("Enter your PIN"), "{}", f.ui[0].1);
        assert!(f.ui[1].1.contains("\"pending\"") && !f.ui[1].1.contains("123456"), "{}", f.ui[1].1);
        assert_eq!(f.removed, [format!("{ID}.json")]);
        assert_eq!(f.stopped, 0);
    }

    #[test]
    fn static_challenge_exchange() {
        let (written, f) = exchange(
            &[">PASSWORD:Need 'Auth' username/password SC:1,Enter the code\n", "", CONNECTED],
            &[None, Some("kind=static\nresponse=654321\n")],
            ("alice", "pw", false),
        );
        let packed = mfa::scrv1("pw", "654321");
        assert_eq!(written, format!("state on\nusername \"Auth\" \"alice\"\npassword \"Auth\" \"{packed}\"\n"));
        assert_eq!(f.log, ["static challenge received", "credentials sent", "authenticated"]);
        assert_eq!(statuses(&f), ["wait", "ok"]);
        assert!(f.ui[0].1.contains("\"static\"") && f.ui[0].1.contains("Enter the code"), "{}", f.ui[0].1);
        // Concatenated (flag 2) and already packed by the app.
        let (written, _) = exchange(
            &[">PASSWORD:Need 'Auth' username/password SC:3,Code\n", ""],
            &[None, Some("kind=static\nresponse=654321\n")],
            ("alice", "pw", false),
        );
        assert!(written.ends_with("password \"Auth\" \"pw654321\"\n"), "{written}");
        let (written, f) =
            exchange(&[">PASSWORD:Need 'Auth' username/password SC:1,Code\n"], &[], ("alice", "SCRV1:x:y", true));
        assert!(written.ends_with("password \"Auth\" \"SCRV1:x:y\"\n"), "{written}");
        assert!(f.ui.is_empty());
    }

    #[test]
    fn web_auth_exchange() {
        let (written, f) = exchange(
            &[
                ">STATE:1700000000,AUTH_PENDING,timeout 120,,\n",
                ">INFOMSG:WEB_AUTH::https://login.example.com/auth?s=1\n",
                "",
                CONNECTED,
            ],
            &[None, None, Some("kind=webauth-ack\nresponse=\n")],
            ("alice", "pw", false),
        );
        assert_eq!(written, "state on\n");
        assert_eq!(
            f.log,
            [
                "authentication pending",
                "web authentication requested: login.example.com",
                "web authentication opened in the browser",
                "authenticated"
            ]
        );
        assert_eq!(statuses(&f), ["wait", "wait", "ok"]);
        assert!(f.ui[1].1.contains(r"https:\/\/login.example.com\/auth?s=1"), "{}", f.ui[1].1);
        // Cancelled by the user: openvpn is stopped.
        let (_, f) = exchange(
            &[">INFOMSG:WEB_AUTH::https://login.example.com/auth\n", ""],
            &[None, Some("kind=cancel\nresponse=\n")],
            ("alice", "pw", false),
        );
        assert_eq!(f.log, ["web authentication requested: login.example.com", "cancelled by the user"]);
        assert_eq!(statuses(&f), ["wait", "cancelled"]);
        assert!(f.ui.last().unwrap().1.contains("\"cancelled\""), "{}", f.ui.last().unwrap().1);
        assert_eq!(f.stopped, 1);
    }
}
