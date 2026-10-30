//! The two administrator steps of the native VPNs (WinVPN 2c Task 12), the pure part: their fixed command lines
//! and what the user is told afterwards. `win::admin_steps` runs them with a UAC prompt (`ShellExecuteExW`,
//! `runas`): the installed `WinVPN.exe --winvpn-trust-ca-step "<file>"` (**Trust This CA in Windows…**) and
//! `<System32>\reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v
//! AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 2 /f` (**Allow L2TP Behind NAT…**).
//!
//! The arguments are fixed words, plus, for the trust step, the path of the certificate file WinVPN itself wrote
//! under a random name (`ca-<hex>.cer`) into the user's temp folder (the file itself readable by `BUILTIN\Users`:
//! the step runs as the administrator the UAC prompt asked for, who may be another account) and holds open against
//! changes: no text a user, a config or a catalog supplies ever reaches an elevated command line. A path that does not have exactly
//! that shape is refused rather than quoted (it never can: WinVPN builds it).
//!
//! The trust step (M-1 of the 2.0.0 security review) is WinVPN's own code, not `certutil -addstore Root`, which
//! would trust the CA for every purpose, code signing included: it checks the file again (a CA, valid now), adds the
//! certificate to the computer's Trusted Root store with the enhanced key usage property [`TLS_ONLY_EKU`] (server
//! and client authentication) set before it enters the store, reads the property back and removes the certificate
//! again when it is not exactly that ([`TrustStep`]). The app then reads the store itself ([`in_root`]).

use crate::pure::openvpn_install::{self, Outcome};
use macvpn_core::l10n::{self, Arg};
use std::path::{Path, PathBuf};

/// The arguments of `reg.exe` (Microsoft Learn, *Configure an L2TP/IPsec server behind a NAT-T device*).
const REG_ARGS: [&str; 9] = [
    "add",
    r"HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent",
    "/v",
    "AssumeUDPEncapsulationContextOnSendRule",
    "/t",
    "REG_DWORD",
    "/d",
    "2",
    "/f",
];

/// The registry key and value `reg.exe` writes (read back afterwards), and the value that allows it.
pub const NAT_KEY: &str = r"SYSTEM\CurrentControlSet\Services\PolicyAgent";
pub const NAT_VALUE: &str = "AssumeUDPEncapsulationContextOnSendRule";
pub const NAT_ALLOWED: u32 = 2;

/// `reg.exe`, in `System32` (located through the known folder, never `PATH`).
pub const REG_EXE: &str = "reg.exe";
/// The program of the trust step: the installed WinVPN itself (`std::env::current_exe`, admin-only folder).
pub const WINVPN_EXE: &str = "WinVPN.exe";
/// The trust step's first argument (`WinVPN.exe --winvpn-trust-ca-step <file>`).
pub const TRUST_STEP_ARG: &str = "--winvpn-trust-ca-step";

/// The prefix and extension of the certificate file WinVPN writes for the trust step.
pub const CA_FILE_PREFIX: &str = "ca-";
pub const CA_FILE_EXTENSION: &str = "cer";

/// The enhanced key usage the trust step gives the CA (`CERT_ENHKEY_USAGE_PROP_ID`, a DER `ExtKeyUsageSyntax`):
/// `SEQUENCE { id-kp-serverAuth (1.3.6.1.5.5.7.3.1), id-kp-clientAuth (1.3.6.1.5.5.7.3.2) }`. Windows then trusts
/// the CA for TLS servers and clients (SSTP, IKEv2, HTTPS) only: not for code signing, time stamping or e-mail.
pub const TLS_ONLY_EKU: &[u8] = &[
    0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x03, 0x02,
];

/// `--winvpn-trust-ca-step <path>`: `path` must be absolute and name a `ca-<hex>.cer` file, with no `"` or control
/// character anywhere (so it cannot end a quoted argument or add one).
pub fn trust_step_args(path: &Path) -> Result<Vec<String>, String> {
    let refused = || l10n::tr("The CA certificate could not be prepared.", &[]);
    let text = path.to_str().ok_or_else(refused)?;
    // Split here, not with `Path::file_name`: the same rule on every OS (tested on macOS too).
    let file = text.rsplit(['\\', '/']).next().ok_or_else(refused)?;
    let hex = file
        .strip_prefix(CA_FILE_PREFIX)
        .and_then(|f| f.strip_suffix(CA_FILE_EXTENSION))
        .and_then(|f| f.strip_suffix('.'))
        .ok_or_else(refused)?;
    let absolute = path.is_absolute() || (text.len() > 3 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'\\');
    if !absolute
        || hex.is_empty()
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
        || text.ends_with('\\')
        || text.chars().any(|c| c == '"' || c.is_control())
    {
        return Err(refused());
    }
    Ok(vec![TRUST_STEP_ARG.into(), text.into()])
}

/// The elevated trust step's arguments (without the program name): `None` when they are not the step (the app
/// starts normally), `Some(None)` when they are but not exactly [`trust_step_args`]'s, else the staged file.
pub fn parse_trust_step(args: &[String]) -> Option<Option<PathBuf>> {
    if args.first().map(String::as_str) != Some(TRUST_STEP_ARG) {
        return None;
    }
    let [_, path] = args else { return Some(None) };
    let path = PathBuf::from(path);
    Some(trust_step_args(&path).ok().map(|_| path))
}

/// The trust step's exit code. 0 is success; the others have bit 29 set (the customer bit: never a Win32 error or
/// an `HRESULT` Windows itself would return), as the OpenVPN step's codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStep {
    /// Added with the usage property [`TLS_ONLY_EKU`], read back.
    Added,
    /// The store held the certificate already: left as it was.
    AlreadyThere,
    /// The arguments are not [`trust_step_args`]'s.
    Arguments,
    /// The file is not a CA certificate valid now, or cannot be read.
    Refused,
    /// The store could not be opened or written.
    StoreFailed,
    /// The store did not keep the usage property; the certificate was removed again.
    NotRestricted,
    /// The step's own account may not open the file (access denied): nothing was checked. The step runs as the
    /// administrator whose credentials a standard user's UAC prompt asked for, another account than the user's.
    NotReadable,
}

const TRUST_STEP_CODES: [(TrustStep, u32); 7] = [
    (TrustStep::Added, 0),
    (TrustStep::AlreadyThere, 0x2000_0101),
    (TrustStep::Arguments, 0x2000_0102),
    (TrustStep::Refused, 0x2000_0103),
    (TrustStep::StoreFailed, 0x2000_0104),
    (TrustStep::NotRestricted, 0x2000_0105),
    (TrustStep::NotReadable, 0x2000_0106),
];

impl TrustStep {
    pub fn code(self) -> u32 {
        TRUST_STEP_CODES.iter().find(|(s, _)| *s == self).map_or(u32::MAX, |(_, c)| *c)
    }

    pub fn from_code(code: u32) -> Option<TrustStep> {
        TRUST_STEP_CODES.iter().find(|(_, c)| *c == code).map(|(s, _)| *s)
    }
}

/// The CA in the computer's Trusted Root store, as the app reads it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InRoot {
    Absent,
    /// With the usage property [`TLS_ONLY_EKU`].
    TlsOnly,
    /// Without it, or with another one.
    Unrestricted,
}

/// `presence`: `None` when the store does not hold the CA, else its usage property (`None`: not set).
pub fn in_root(presence: Option<Option<&[u8]>>) -> InRoot {
    match presence {
        None => InRoot::Absent,
        Some(Some(usage)) if usage == TLS_ONLY_EKU => InRoot::TlsOnly,
        Some(_) => InRoot::Unrestricted,
    }
}

/// The fixed arguments of `reg.exe`.
pub fn reg_args() -> Vec<String> {
    REG_ARGS.iter().map(|s| s.to_string()).collect()
}

/// The `lpParameters` text of the arguments: an argument with a space or tab is quoted. `None` for an empty
/// argument, a `"`, a control character or a quoted argument ending in `\` (no escaping is ever needed).
pub fn parameters(args: &[String]) -> Option<String> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        if arg.is_empty() || arg.chars().any(|c| c == '"' || c.is_control()) {
            return None;
        }
        if arg.contains([' ', '\t']) {
            if arg.ends_with('\\') {
                return None;
            }
            out.push(format!("\"{arg}\""));
        } else {
            out.push(arg.clone());
        }
    }
    Some(out.join(" "))
}

/// What `run_elevated` answered: the exit code, or the error that kept it from running (1223: the UAC prompt was
/// declined).
pub type RunResult = Result<u32, u32>;

fn ended_with(exe: &str, code: u32) -> String {
    l10n::tr("%@ ended with error %@.", &[Arg::Str(exe), Arg::Str(&openvpn_install::code_text(code))])
}

fn not_started(exe: &str) -> String {
    l10n::tr("%@ could not be started.", &[Arg::Str(exe)])
}

/// The answer of a run that did not succeed, else `None`.
fn failure(exe: &str, run: RunResult) -> Option<String> {
    match run {
        Ok(0) => None,
        Ok(code) => Some(ended_with(exe, code)),
        Err(code) if openvpn_install::outcome(code) == Outcome::Cancelled => Some(openvpn_install::cancelled()),
        Err(_) => Some(not_started(exe)),
    }
}

/// **Trust This CA in Windows…**: the trust step's run and the computer's Trusted Root store read back afterwards
/// (`None`: it could not be read; the step's word counts). A CA the step added must be there with
/// [`TLS_ONLY_EKU`]; one that was there before is left as it was.
pub fn trust_outcome(run: RunResult, after: Option<InRoot>) -> Result<String, String> {
    let absent = || l10n::tr("Windows did not add the CA to its trusted root store.", &[]);
    let unlimited =
        || l10n::tr("Windows could not limit the CA to server and client certificates, so it was not added.", &[]);
    let done = || l10n::tr("The CA is now trusted by Windows.", &[]);
    let code = match run {
        Ok(code) => code,
        Err(_) => return Err(failure(WINVPN_EXE, run).unwrap_or_else(|| not_started(WINVPN_EXE))),
    };
    match (TrustStep::from_code(code), after) {
        (Some(TrustStep::Added | TrustStep::AlreadyThere), Some(InRoot::Absent)) => Err(absent()),
        (Some(TrustStep::Added), Some(InRoot::Unrestricted)) | (Some(TrustStep::NotRestricted), _) => Err(unlimited()),
        (Some(TrustStep::Added | TrustStep::AlreadyThere), _) => Ok(done()),
        (Some(TrustStep::NotReadable), _) => Err(l10n::tr(
            "The administrator's account could not read the CA certificate WinVPN prepared, so it was not added.",
            &[],
        )),
        _ => Err(ended_with(WINVPN_EXE, code)),
    }
}

/// **Allow L2TP Behind NAT…**: reg.exe's run and the value read back (`None`: it could not be read; reg.exe's
/// success counts). Windows reads it at start: a restart is needed.
pub fn nat_outcome(run: RunResult, value: Option<u32>) -> Result<String, String> {
    if let Some(failed) = failure(REG_EXE, run) {
        return Err(failed);
    }
    if value.is_some_and(|v| v != NAT_ALLOWED) {
        return Err(l10n::tr("The setting was not changed.", &[]));
    }
    Ok(l10n::tr("L2TP/IPsec behind NAT is allowed. Restart Windows to apply it.", &[]))
}
