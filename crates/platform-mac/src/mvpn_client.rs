//! The app side of the root helper (port of `MvpnClient.swift`): `sudo -n /usr/local/libexec/macvpn/mvpn …`.

use crate::command::{CommandError, CommandResult, CommandRunner};
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::mfa::{AuthResponseKind, MFAError};
use macvpn_core::models::{Secrets, VPNKind, uuid_string};
use macvpn_core::status::{RootStatus, StatusParseError, parse_status};
use macvpn_core::swift_str;
use std::collections::BTreeSet;
use std::path::PathBuf;
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
        let lines = secrets.stdin_payload();
        let header = format!("config {}\n", config.len());
        let mut payload = Zeroizing::new(Vec::with_capacity(header.len() + config.len() + lines.len()));
        payload.extend_from_slice(header.as_bytes());
        payload.extend_from_slice(config);
        payload.extend_from_slice(lines.as_bytes());
        payload
    }

    pub fn up_arguments(kind: VPNKind, id: &Uuid, debug: bool, accept_risky: &[String]) -> Vec<String> {
        let mut args = vec!["up".to_string(), kind.raw_value().to_string(), uuid_string(id)];
        if debug {
            args.push("--debug".into());
        }
        let names: BTreeSet<&str> = accept_risky
            .iter()
            .map(String::as_str)
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            .collect();
        if kind == VPNKind::Openvpn && !names.is_empty() {
            args.push("--accept-risky".into());
            args.push(names.into_iter().collect::<Vec<_>>().join(","));
        }
        args
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
