//! The WinVPN Service over `\\.\pipe\WinVPN` (`macvpn_core::service_proto`): the helper client, the MFA state, the
//! log source and the engine facts. Each call is one pipe connection (one `mvpn` call on macOS). The client trusts
//! only a pipe owned by SYSTEM (`ServerTrust::LocalSystem`: the owner is read from the handle and checked before a
//! byte is sent, so a squatter of the name never receives a config or a secret); debug test builds may trust a pipe
//! of this user (the service's console mode). The service answers in the app's language (`--lang`).

use crate::pure::engine::Reach;
use crate::pure::texts;
use crate::pure::wireguard_update::{self as wu, Offer};
use macvpn_core::helper_args;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::log::{LogIdentity, LogRead, LogSource};
use macvpn_core::mfa::{AuthResponseKind, AuthUIState, MFAError};
use macvpn_core::models::{Secrets, VPNKind, uuid_string};
use macvpn_core::service_proto::{self as proto, EngineFacts, LogSlice, PIPE_NAME, ProtoError, Response};
use macvpn_core::status::{RootStatus, parse_status};
use macvpn_platform_api::{AuthStateReader, HelperClient};
use macvpn_winsys::pipe::{self, PipeStream, ServerTrust};
use std::io::ErrorKind;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long a call waits for a free pipe instance.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// `up` may wait for an MFA answer (the service's limit is 30 s + 420 s).
const UP_TIMEOUT: Duration = Duration::from_secs(480);
/// `down` stops `openvpn.exe` (up to 5 s for its own exit, then 5 s after the kill) or closes an adapter.
const DOWN_TIMEOUT: Duration = Duration::from_secs(30);
/// `status`, `respond`, `auth-state`, `log`, `engine`, and every write.
const QUICK_TIMEOUT: Duration = Duration::from_secs(20);
/// `traffic`: read about once a second while a window shows it, and by the status poll; a slow service gives no
/// data rather than holding either up.
const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a call got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoAnswer {
    /// The pipe does not exist: no service.
    Absent,
    /// The answer is not this protocol: a service of another WinVPN version.
    OtherVersion,
    /// Not provably the service (another owner, an owner that cannot be read), busy, or the exchange failed.
    Unreachable,
}

impl NoAnswer {
    fn message(self) -> String {
        match self {
            NoAnswer::Absent | NoAnswer::OtherVersion => texts::service_missing(),
            NoAnswer::Unreachable => texts::service_unreachable(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceClient {
    pipe: String,
    trust: ServerTrust,
}

impl ServiceClient {
    /// `\\.\pipe\WinVPN`, owned by SYSTEM.
    pub(crate) fn production() -> ServiceClient {
        ServiceClient { pipe: PIPE_NAME.to_string(), trust: ServerTrust::LocalSystem }
    }

    /// Tests: another pipe name (`\\.\pipe\WinVPN-test-…`) with the production trust.
    pub(crate) fn trusting_system(pipe: &str) -> ServiceClient {
        ServiceClient { pipe: pipe.to_string(), trust: ServerTrust::LocalSystem }
    }

    /// Debug test builds: the service's console mode, whose pipe this user owns.
    #[cfg(debug_assertions)]
    pub(crate) fn trusting_this_user(pipe: &str) -> ServiceClient {
        ServiceClient { pipe: pipe.to_string(), trust: ServerTrust::SameUser }
    }

    /// Connects (the trust check passes before this returns), sends `args --lang <app language>` and `body`, and
    /// reads the answer within `timeout`.
    fn exchange(&self, args: &[&str], body: &[u8], timeout: Duration) -> Result<Response, NoAnswer> {
        let mut s = self.connect()?;
        let lang = AppLanguage::current().raw_value();
        let mut all: Vec<&str> = args.to_vec();
        all.extend(["--lang", lang]);
        s.set_write_timeout(Some(QUICK_TIMEOUT)).map_err(|_| NoAnswer::Unreachable)?;
        s.set_read_timeout(Some(timeout)).map_err(|_| NoAnswer::Unreachable)?;
        proto::write_request(&mut s, &all, body).map_err(|_| NoAnswer::Unreachable)?;
        proto::read_response(&mut s).map_err(|e| match e {
            ProtoError::Invalid => NoAnswer::OtherVersion,
            ProtoError::TooLarge | ProtoError::Io(_) => NoAnswer::Unreachable,
        })
    }

    fn connect(&self) -> Result<PipeStream, NoAnswer> {
        pipe::connect_with(&self.pipe, CONNECT_TIMEOUT, self.trust).map_err(|e| match e.kind() {
            ErrorKind::NotFound => NoAnswer::Absent,
            _ => NoAnswer::Unreachable,
        })
    }

    /// The answer's stdout, or the localized reason (no answer, or the service's own message).
    fn call(&self, args: &[&str], body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        check(self.exchange(args, body, timeout).map_err(NoAnswer::message)?)
    }

    /// `wireguard-check` (2b plan, fix4): the service asks the official listing itself. No answer, an older service
    /// (its usage error) or an unexpected answer = [`Offer::Unknown`].
    pub(crate) fn wireguard_check(&self) -> Offer {
        let r = self.exchange(&[proto::WIREGUARD_CHECK], b"", Duration::from_secs(wu::CHECK_SECS)).ok();
        wu::offer_from(r.as_ref().map(|r| (r.code, r.stdout.as_slice())))
    }

    /// `wireguard-update` (2b plan, fix4): the service downloads, verifies and loads the newest wireguard-nt. `Ok`:
    /// the output line; `Err`: the service's reason (busy: a WireGuard connection is up) or "not reachable".
    pub(crate) fn wireguard_update(&self) -> Result<String, String> {
        let r = self.exchange(&[proto::WIREGUARD_UPDATE], b"", Duration::from_secs(wu::UPDATE_SECS)).ok();
        let message = r.as_ref().map(|r| String::from_utf8_lossy(&r.stderr).into_owned()).unwrap_or_default();
        wu::update_outcome(
            r.as_ref().map(|r| (r.code, r.stdout.as_slice(), message.as_str())),
            texts::service_unreachable(),
        )
    }

    /// The service's `engine` answer: no pipe = `Absent`; no trusted answer, or facts that cannot be read =
    /// `Unreachable` with the reason (another version: the "missing or from another version" text).
    pub(crate) fn reach(&self) -> Reach {
        let response = match self.exchange(&["engine"], b"", QUICK_TIMEOUT) {
            Ok(r) => r,
            Err(NoAnswer::Absent) => return Reach::Absent,
            Err(e) => return Reach::Unreachable(e.message()),
        };
        // An answer of this protocol that is not our `engine` facts: a service of another version.
        match check(response).ok().and_then(|out| EngineFacts::parse(&out)) {
            Some(f) => Reach::Facts(f),
            None => Reach::Unreachable(texts::service_missing()),
        }
    }
}

/// The service's answer as a result: exit 0 = `Ok(stdout)`; otherwise its message (or the exit code), as
/// `MvpnClient`'s `check` does on macOS.
fn check(r: Response) -> Result<Vec<u8>, String> {
    if r.code == 0 {
        return Ok(r.stdout);
    }
    let message = String::from_utf8_lossy(&r.stderr).trim().to_string();
    Err(if message.is_empty() {
        l10n::tr("mvpn error (exit code: %d)", &[Arg::Int(i64::from(r.code))])
    } else {
        message
    })
}

impl HelperClient for ServiceClient {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        let out = self.call(&["status"], b"", QUICK_TIMEOUT)?;
        parse_status(&String::from_utf8_lossy(&out)).map_err(|e| e.to_string())
    }

    /// The config and the secrets go only in the body (the root layer 8 frame, one zeroized buffer), never in an
    /// argument, and only to a pipe that passed the owner check.
    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String> {
        let args = helper_args::up_arguments(kind, id, debug, accept_risky);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let body = helper_args::up_stdin(config, secrets);
        self.call(&refs, &body, UP_TIMEOUT).map(|_| ())
    }

    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
        let id = uuid_string(id);
        self.call(&["down", kind.raw_value(), &id], b"", DOWN_TIMEOUT).map(|_| ())
    }

    /// The code goes only in the body (zeroized).
    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        let body = Zeroizing::new(kind.stdin_payload(response).ok_or_else(|| MFAError::InvalidCode.message())?);
        let id = uuid_string(id);
        self.call(&["respond", VPNKind::Openvpn.raw_value(), &id], body.as_bytes(), QUICK_TIMEOUT).map(|_| ())
    }

    fn log_source(&self, id: &Uuid) -> Option<Box<dyn LogSource>> {
        Some(Box::new(PipeLogSource { client: self.clone(), id: uuid_string(id) }))
    }

    /// `clear-log <id>`: the service clears the caller's own log and writes the note itself (in the request's
    /// language, its local time), so `_note` is not sent. An older service: "update WinVPN".
    fn clear_log(&self, id: &Uuid, _note: &str) -> Result<(), String> {
        let id = uuid_string(id);
        let r = self.exchange(&[proto::CLEAR_LOG, &id], b"", QUICK_TIMEOUT).map_err(NoAnswer::message)?;
        crate::pure::engine::clear_log_answer(r.code, &String::from_utf8_lossy(&r.stderr))
    }

    /// `liveness <id>`: the tunnel's liveness facts (dead-tunnel detection). An older service answers its usage
    /// error: `None`, nothing is detected.
    fn liveness(&self, id: &Uuid) -> Option<macvpn_core::liveness::Liveness> {
        let id = uuid_string(id);
        let out = self.call(&[macvpn_core::liveness::LIVENESS, &id], b"", QUICK_TIMEOUT).ok()?;
        macvpn_core::liveness::Liveness::parse(&out)
    }

    /// OpenVPN: the service's `traffic <id>` (OpenVPN's `>BYTECOUNT`); an older service answers its usage error, and
    /// then (or with nothing to report) the adapter holding the tunnel address. WireGuard: its adapter's counters
    /// (`GetIfEntry2`), read as the user without asking the service.
    fn traffic(&self, tunnel: &macvpn_platform_api::HelperTunnel<'_>) -> Option<macvpn_platform_api::TrafficReading> {
        if tunnel.kind == VPNKind::Openvpn {
            let id = uuid_string(tunnel.id);
            let counted = self
                .call(&[macvpn_core::traffic::TRAFFIC, &id], b"", TRAFFIC_TIMEOUT)
                .ok()
                .and_then(|out| macvpn_core::traffic::ByteCount::parse(&out));
            if let Some(b) = counted {
                return Some(crate::pure::traffic::service_count_reading(&b));
            }
        }
        super::traffic::service_reading(tunnel)
    }
}

/// The MFA state the service's bridge keeps for this user's connection, with the same parser and limit as the file
/// on macOS. Nothing (no answer, another user's or an unknown ID, no prompt) is `None`.
impl AuthStateReader for ServiceClient {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        let id = uuid_string(id);
        let out = self.call(&["auth-state", &id], b"", QUICK_TIMEOUT).ok()?;
        if out.is_empty() { None } else { AuthUIState::parse(&out) }
    }
}

/// The connection's masked log, a slice per read (`log <id> <offset>`); the generation is the log's identity.
struct PipeLogSource {
    client: ServiceClient,
    id: String,
}

impl LogSource for PipeLogSource {
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead> {
        let off = offset.to_string();
        let out = self.client.call(&["log", &self.id, &off], b"", QUICK_TIMEOUT).ok()?;
        let s = LogSlice::parse(&out)?;
        // Generation 0: no log (yet).
        if s.generation == 0 {
            return None;
        }
        let mut data = s.data;
        data.truncate(max);
        Some(LogRead { identity: Some(LogIdentity::Generation(s.generation)), size: s.size, start: s.start, data })
    }
}
