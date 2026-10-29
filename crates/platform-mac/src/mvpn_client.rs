//! The app side of the root helper (port of `MvpnClient.swift`): `sudo -n /usr/local/libexec/macvpn/mvpn …`.

use crate::command::{CommandError, CommandResult, CommandRunner};
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::mfa::{AuthResponseKind, MFAError};
use macvpn_core::models::{Secrets, VPNKind, uuid_string};
use macvpn_core::status::{RootStatus, StatusParseError, parse_status};
use macvpn_core::swift_str;
use std::path::{Path, PathBuf};
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

pub struct MvpnClient<'a> {
    /// `down` (and by default everything else).
    runner: &'a dyn CommandRunner,
    /// `up`: the longer timeout ([`crate::command::RunnerTimeouts::UP`]).
    up_runner: &'a dyn CommandRunner,
    /// `status`, `respond`: the short timeout ([`crate::command::RunnerTimeouts::QUICK`]).
    status_runner: &'a dyn CommandRunner,
    /// The language of `mvpn`'s messages. `None`: [`AppLanguage::current`] per call.
    language: Option<AppLanguage>,
}

impl<'a> MvpnClient<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        MvpnClient { runner, up_runner: runner, status_runner: runner, language: None }
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
        let result = self.sudo(&args, None, Some(self.status_runner)).ok()?;
        if result.exit_code != 0 {
            return None;
        }
        macvpn_core::liveness::Liveness::parse(result.stdout.as_bytes())
    }

    /// `mvpn traffic <id>` (root layer 11): a strongSwan connection's CHILD_SA byte counters. `None` on any
    /// failure, also from an older root layer (its usage error) or an answer of another form: no traffic is shown.
    pub fn traffic(&self, id: &Uuid) -> Option<Vec<macvpn_core::traffic::ChildCount>> {
        let args = vec![macvpn_core::traffic::TRAFFIC.to_string(), uuid_string(id)];
        let result = self.sudo(&args, None, Some(self.status_runner)).ok()?;
        if result.exit_code != 0 {
            return None;
        }
        macvpn_core::traffic::parse_children(result.stdout.as_bytes())
    }

    pub fn status(&self) -> Result<Vec<RootStatus>, ClientError> {
        let result = self.sudo(&["status".to_string()], None, Some(self.status_runner))?;
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
