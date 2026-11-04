//! The app side of the root helper (port of `MvpnClient.swift`): `sudo -n /usr/local/libexec/macvpn/mvpn …`.
//!
//! Root layer 13: the read-only questions the app polls (`status`, `liveness`, `traffic`) go first to the root
//! layer's query daemon (`mvpn serve`, socket-activated by launchd on [`QUERY_SOCKET`]), so a connected tunnel no
//! longer costs a `sudo` process every few seconds. On any failure there (no socket: an older root layer or the
//! daemon not loaded; a timeout; a malformed answer) the same question goes through `sudo -n` as before. Everything
//! that changes state stays on `sudo`.

use crate::command::{CommandError, CommandResult, CommandRunner};
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::mfa::{AuthResponseKind, MFAError};
use macvpn_core::models::{Secrets, VPNKind, uuid_string};
use macvpn_core::status::{RootStatus, StatusParseError, parse_status};
use macvpn_core::swift_str;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MvpnError {
    Failed(String),
}

impl std::fmt::Display for MvpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MvpnError::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for MvpnError {}

#[derive(Debug)]
pub enum ClientError {
    Command(CommandError),
    Mvpn(MvpnError),
    Status(StatusParseError),
    Mfa(MFAError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Command(e) => e.fmt(f),
            ClientError::Mvpn(e) => e.fmt(f),
            ClientError::Status(e) => e.fmt(f),
            ClientError::Mfa(e) => f.write_str(&e.message()),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<CommandError> for ClientError {
    fn from(e: CommandError) -> Self {
        ClientError::Command(e)
    }
}

/// "Clear Log…" of a helper kind: the user's own log in `dir` (`/var/log/macvpn`), `<id>.log` and its rotated
/// `<id>.log.1`, emptied in place by the app itself. The root layer creates both as the user's 0600 files and
/// rolls them in place (its writers append with `O_APPEND`), so no root call is needed: the app truncates only a
/// regular file of `owner`, never through a symlink, and names it from the UUID only. `note` starts the live log.
/// The engines' root-only logs in the run directory are not the Log tab's and stay as they are (the root layer's
/// copy offset into the user's log goes on from where it was).
pub fn clear_log_in(dir: &Path, id: &Uuid, owner: &FileOwner, note: &str) -> Result<(), String> {
    let live = dir.join(format!("{}.log", uuid_string(id)));
    let rotated = dir.join(format!("{}.log.1", uuid_string(id)));
    // The older part first: a failure on the live log never leaves the older lines behind a cleared live log.
    for (path, note) in [(rotated, None), (live, Some(note))] {
        macvpn_core::log::clear_file(&path, owner, note).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                l10n::tr(
                    "The connection's log cannot be cleared: it belongs to another user or cannot be written.",
                    &[],
                )
            } else {
                l10n::tr("The log could not be cleared: %@", &[Arg::Str(&e.to_string())])
            }
        })?;
    }
    Ok(())
}

pub const INSTALL_DIR: &str = "/usr/local/libexec/macvpn";
pub const EXECUTABLE: &str = "/usr/local/libexec/macvpn/mvpn";
pub const LOG_DIR: &str = "/var/log/macvpn";
/// MFA: the root helper's state files (`<id>.json`, the user's, 0600). The same literal as the helper's
/// `paths::UI_BASE` (`crates/helper/tests/paths_agree.rs`).
pub const UI_STATE_DIR: &str = "/var/run/macvpn-ui";
/// Root layer 13: the query daemon's socket (launchd's, the installing user's 0600; see the installer).
pub const QUERY_SOCKET: &str = "/var/run/macvpn-query.sock";
/// The query daemon's connection: each read and write must finish within this.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest answer read from the query daemon (the status of every connection fits many times over).
pub const QUERY_ANSWER_MAX: u64 = 1 << 20;

pub struct MvpnClient<'a> {
    /// `down` (and by default everything else).
    runner: &'a dyn CommandRunner,
    /// `up`: the longer timeout ([`crate::command::RunnerTimeouts::UP`]).
    up_runner: &'a dyn CommandRunner,
    /// `status`, `respond`: the short timeout ([`crate::command::RunnerTimeouts::QUICK`]).
    status_runner: &'a dyn CommandRunner,
    /// The language of `mvpn`'s messages. `None`: [`AppLanguage::current`] per call.
    language: Option<AppLanguage>,
    /// The query daemon's socket for `status`, `liveness` and `traffic` ([`MvpnClient::with_query_socket`]).
    /// `None` (the default, so tests with a fake runner never reach a real socket): always `sudo`.
    query_socket: Option<PathBuf>,
}

impl<'a> MvpnClient<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        MvpnClient { runner, up_runner: runner, status_runner: runner, language: None, query_socket: None }
    }

    pub fn with_runners(
        runner: &'a dyn CommandRunner,
        up_runner: Option<&'a dyn CommandRunner>,
        status_runner: Option<&'a dyn CommandRunner>,
        language: Option<AppLanguage>,
    ) -> Self {
        MvpnClient {
            runner,
            up_runner: up_runner.unwrap_or(runner),
            status_runner: status_runner.unwrap_or(runner),
            language,
            query_socket: None,
        }
    }

    /// Asks `status`, `liveness` and `traffic` on the query daemon's `socket` first (the app: [`QUERY_SOCKET`]),
    /// falling back to `sudo` on any failure there.
    pub fn with_query_socket(mut self, socket: Option<&Path>) -> Self {
        self.query_socket = socket.map(Path::to_path_buf);
        self
    }

    /// The query daemon's answer to `request` as the command line's result (its exit code and stdout; it has no
    /// stderr). `None`: no daemon is configured, or it did not give a well-formed answer in time.
    fn query(&self, request: &str) -> Option<CommandResult> {
        query_socket(self.query_socket.as_deref()?, request)
    }

    /// `request` on the query daemon, else through `sudo` with the quick runner.
    fn read_only(&self, args: &[String]) -> Result<CommandResult, ClientError> {
        match self.query(&args.join(" ")) {
            Some(result) => Ok(result),
            None => self.sudo(args, None, Some(self.status_runner)),
        }
    }

    pub fn log_path(id: &Uuid) -> PathBuf {
        PathBuf::from(format!("{LOG_DIR}/{}.log", uuid_string(id)))
    }

    /// `sudo -n mvpn <args…> --lang <en|hu>`. `--lang` is last, so an older installed `mvpn` without `--lang` still
    /// sees the right command and arguments.
    pub fn sudo_arguments(args: &[String], language: AppLanguage) -> Vec<String> {
        let mut out = vec!["-n".to_string(), EXECUTABLE.to_string()];
        out.extend(args.iter().cloned());
        out.push("--lang".into());
        out.push(language.raw_value().into());
        out
    }

    fn sudo(
        &self,
        args: &[String],
        stdin: Option<&str>,
        runner: Option<&dyn CommandRunner>,
    ) -> Result<CommandResult, ClientError> {
        let language = self.language.unwrap_or_else(AppLanguage::current);
        Ok(runner.unwrap_or(self.runner).run("/usr/bin/sudo", &Self::sudo_arguments(args, language), stdin)?)
    }

    /// `mvpn up` (root layer 8). The root layer opens no user file: `config` goes on stdin, framed, followed by
    /// the secret lines, and stdin is closed after them:
    ///
    /// ```text
    /// config <exact byte length of config>\n<config bytes>username=…\npassword=…\n…
    /// ```
    ///
    /// The whole payload is built in one buffer that is zeroed when dropped; neither the config nor a secret is
    /// ever in the arguments. `accept_risky`: the risky OpenVPN directives acknowledged for the connection; when
    /// not empty `--accept-risky a,b` (sorted), before `--lang`. Only `^[a-z0-9-]+$` names pass.
    pub fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), ClientError> {
        let args = Self::up_arguments(kind, id, debug, accept_risky);
        let payload = Self::up_stdin(config, secrets);
        let language = self.language.unwrap_or_else(AppLanguage::current);
        check(self.up_runner.run_bytes("/usr/bin/sudo", &Self::sudo_arguments(&args, language), &payload)?)
    }

    /// The framed stdin of `mvpn up` (see [`MvpnClient::up`]).
    pub fn up_stdin(config: &[u8], secrets: &Secrets) -> Zeroizing<Vec<u8>> {
        macvpn_core::helper_args::up_stdin(config, secrets)
    }

    pub fn up_arguments(kind: VPNKind, id: &Uuid, debug: bool, accept_risky: &[String]) -> Vec<String> {
        macvpn_core::helper_args::up_arguments(kind, id, debug, accept_risky)
    }

    /// `mvpn respond openvpn <id>`: the user's answer for the management bridge (MFA). The code goes only on stdin.
    pub fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), ClientError> {
        let payload = kind.stdin_payload(response).ok_or(ClientError::Mfa(MFAError::InvalidCode))?;
        let args = vec!["respond".to_string(), VPNKind::Openvpn.raw_value().to_string(), uuid_string(id)];
        check(self.sudo(&args, Some(&payload), Some(self.status_runner))?)
    }

    pub fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), ClientError> {
        let args = vec!["down".to_string(), kind.raw_value().to_string(), uuid_string(id)];
        check(self.sudo(&args, None, None)?)
    }

    /// `mvpn liveness <id>` (root layer 10): the tunnel's liveness facts. `None` on any failure, also from an older
    /// root layer (its usage error) or an answer of another form: nothing is decided then.
    pub fn liveness(&self, id: &Uuid) -> Option<macvpn_core::liveness::Liveness> {
        let args = vec![macvpn_core::liveness::LIVENESS.to_string(), uuid_string(id)];
        let result = self.read_only(&args).ok()?;
        if result.exit_code != 0 {
            return None;
        }
        macvpn_core::liveness::Liveness::parse(result.stdout.as_bytes())
    }

    /// `mvpn traffic <id>` (root layer 11): a strongSwan connection's CHILD_SA byte counters. `None` on any
    /// failure, also from an older root layer (its usage error) or an answer of another form: no traffic is shown.
    pub fn traffic(&self, id: &Uuid) -> Option<Vec<macvpn_core::traffic::ChildCount>> {
        let args = vec![macvpn_core::traffic::TRAFFIC.to_string(), uuid_string(id)];
        let result = self.read_only(&args).ok()?;
        if result.exit_code != 0 {
            return None;
        }
        macvpn_core::traffic::parse_children(result.stdout.as_bytes())
    }

    pub fn status(&self) -> Result<Vec<RootStatus>, ClientError> {
        let result = self.read_only(&["status".to_string()])?;
        let stdout = result.stdout.clone();
        check(result)?;
        parse_status(&stdout).map_err(ClientError::Status)
    }
}

fn check(result: CommandResult) -> Result<(), ClientError> {
    if result.exit_code == 0 {
        return Ok(());
    }
    let message = result.stderr.trim_matches(swift_str::is_foundation_whitespace_or_newline);
    Err(ClientError::Mvpn(MvpnError::Failed(if message.is_empty() {
        l10n::tr("mvpn error (exit code: %d)", &[Arg::Int(i64::from(result.exit_code))])
    } else {
        message.to_string()
    })))
}

/// One question to the query daemon on `socket` (`<request>\n`), its answer as the command line's result: connect,
/// write, read to the end, each read and write within [`QUERY_TIMEOUT`], at most [`QUERY_ANSWER_MAX`] bytes. `None`
/// on any failure (the caller then asks through `sudo`).
pub fn query_socket(socket: &Path, request: &str) -> Option<CommandResult> {
    use std::io::{Read, Write};
    // A Unix socket connects (to launchd's listening socket) or fails at once; nothing to time out here.
    let mut stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT)).ok()?;
    stream.write_all(format!("{request}\n").as_bytes()).ok()?;
    let mut answer = Vec::new();
    (&mut stream).take(QUERY_ANSWER_MAX + 1).read_to_end(&mut answer).ok()?;
    if answer.len() as u64 > QUERY_ANSWER_MAX {
        return None;
    }
    parse_query_answer(&answer)
}

/// The query daemon's answer, `<exit code>\n<stdout>`: the exit code 1–3 decimal digits (no sign, no leading zero),
/// the stdout UTF-8. `None` for anything else (an empty answer: the daemon refused or went away).
pub fn parse_query_answer(answer: &[u8]) -> Option<CommandResult> {
    let newline = answer.iter().position(|&b| b == b'\n')?;
    let (code, stdout) = (&answer[..newline], &answer[newline + 1..]);
    let digits =
        (1..=3).contains(&code.len()) && code.iter().all(u8::is_ascii_digit) && (code.len() == 1 || code[0] != b'0');
    if !digits {
        return None;
    }
    let exit_code = std::str::from_utf8(code).ok()?.parse().ok()?;
    let stdout = String::from_utf8(stdout.to_vec()).ok()?;
    Some(CommandResult { exit_code, stdout, stderr: String::new() })
}
