//! The administrator steps of the native VPNs (WinVPN 2c Task 12), each one UAC prompt (`elevate::run_elevated`,
//! `ShellExecuteExW` with `runas`), run by the app for the signed-in user and confirmed by an administrator, never
//! by the WinVPN Service (a standard user could otherwise make the computer trust any CA):
//!
//! - **Trust This CA in Windows…**: the PEM's first certificate (`pure::ca_trust`: a CA, valid now) is written to
//!   a new `ca-<random>.cer` in the user's temp folder, opened to every account for reading
//!   (`Protection::Shared`: a standard user's UAC prompt runs the step as the administrator whose credentials it
//!   asked for, another account, and a public certificate needs no secrecy), re-opened with `FILE_SHARE_READ` only
//!   and checked byte for byte and for that DACL (nobody can change, rename or delete it while the handle is open),
//!   then this process' own
//!   `WinVPN.exe --winvpn-trust-ca-step "<file>"` runs elevated, only when administrators alone can change that
//!   exe (an installed WinVPN): [`elevated_trust_main`] checks the file again and adds the CA to the computer's
//!   Trusted Root store **for server and client authentication only** (`macvpn_winsys::cert_store::add_with_usage`
//!   with `pure::admin_steps::TLS_ONLY_EKU`; M-1 of the 2.0.0 security review: a bare `certutil -addstore Root`
//!   would let the CA sign code the computer trusts). Afterwards the app reads the store itself (read-only: the
//!   certificate by its SHA-1 thumbprint and its usage property). The file is deleted after.
//! - **Allow L2TP Behind NAT…**: `<System32>\reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v
//!   AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 2 /f` elevated, the value read back; Windows applies
//!   it after a restart.
//!
//! `reg.exe` is found through the System known folder, never `PATH`; the arguments are fixed words and the file
//! path WinVPN built (`pure::admin_steps`).
//!
//! Nothing elevated here derives a path or setting from its own profile: the elevated process is the administrator's
//! (its `HKCU`, `%LOCALAPPDATA%` and `%TEMP%` are that account's, not the user's), so the CA file's absolute path is
//! passed on the command line, and the steps touch only `HKLM` and the computer's certificate store.

use super::elevate::run_elevated;
use super::{registry, system};
use crate::pure::admin_steps::{self, CA_FILE_EXTENSION, CA_FILE_PREFIX, REG_EXE, TLS_ONLY_EKU, TrustStep};
use crate::pure::ca_trust::{self, CaCert};
use macvpn_platform_api::{AdminSteps, CaSummary};
use macvpn_winsys::cert_store::{self, Added, Location, Presence};
use macvpn_winsys::file::{self as wfile, Protection};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_SHARE_READ, READ_CONTROL, WRITE_DAC,
};

/// The Windows administrator steps. `trust_exe`: the program of the trust step (`None`: this process' own exe; tests
/// name the installed `WinVPN.exe`).
pub(crate) struct WinAdminSteps {
    pub(crate) trust_exe: Option<PathBuf>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn prepare_failed() -> String {
    macvpn_core::l10n::tr("The CA certificate could not be prepared.", &[])
}

impl AdminSteps for WinAdminSteps {
    fn ca_summary(&self, pem: &str) -> Result<CaSummary, String> {
        ca_trust::read(pem, now()).map(|ca| ca.summary)
    }

    fn ca_trusted(&self, pem: &str) -> Option<bool> {
        let ca = ca_trust::read(pem, now()).ok()?;
        cert_store::local_machine_contains(ROOT, &ca.sha1).ok()
    }

    fn trust_ca(&self, pem: &str) -> Result<String, String> {
        let ca = ca_trust::read(pem, now())?;
        // The elevated code must be the installed code: only an exe administrators alone can change.
        let exe = match &self.trust_exe {
            Some(exe) => exe.clone(),
            None => std::env::current_exe().map_err(|_| only_installed())?,
        };
        if !matches!(macvpn_winsys::acl_check::is_admin_only(&exe), Ok(true)) {
            return Err(only_installed());
        }
        let staged = StagedCa::write(&ca)?;
        let args = admin_steps::trust_step_args(&staged.path)?;
        let parameters = admin_steps::parameters(&args).ok_or_else(prepare_failed)?;
        let run = run_elevated(&exe, &parameters);
        drop(staged);
        let after = cert_store::presence(Location::LocalMachine, ROOT, &ca.sha1).ok().map(|p| match p {
            Presence::Absent => admin_steps::in_root(None),
            Presence::Present { usage } => admin_steps::in_root(Some(usage.as_deref())),
        });
        admin_steps::trust_outcome(run, after)
    }

    fn allow_l2tp_behind_nat(&self) -> Result<String, String> {
        let parameters = admin_steps::parameters(&admin_steps::reg_args()).ok_or_else(prepare_failed)?;
        let exe = system32_tool(REG_EXE)?;
        let run = run_elevated(&exe, &parameters);
        let value = registry::read_machine_dword(admin_steps::NAT_KEY, admin_steps::NAT_VALUE);
        admin_steps::nat_outcome(run, value)
    }

    fn offered_action(&self, error: &str) -> Option<&'static str> {
        crate::pure::ras_editor::offered_action(error).map(|a| a.id())
    }
}

/// The computer's Trusted Root Certification Authorities.
const ROOT: &str = "Root";

fn only_installed() -> String {
    macvpn_core::l10n::tr("Only a WinVPN installed in Program Files can add a CA to Windows.", &[])
}

// MARK: - The elevated trust step (in `WinVPN.exe --winvpn-trust-ca-step <file>`, elevated)

/// The elevated trust step's exit code when `args` (without the program name) start with
/// `pure::admin_steps::TRUST_STEP_ARG`, else `None` (the app starts normally).
pub(crate) fn elevated_trust_main(args: &[String]) -> Option<u32> {
    let path = admin_steps::parse_trust_step(args)?;
    Some(path.map_or(TrustStep::Arguments, |p| trust_step(&p)).code())
}

/// Checked again here (the unelevated app's checks are not trusted): the staged file, read with `FILE_SHARE_READ`
/// (the app holds it the same way: nobody writes it meanwhile), is a CA certificate valid now; then it is added
/// with the TLS-only usage property.
fn trust_step(path: &Path) -> TrustStep {
    // The open below, alone: whether this account may read the file at all (never reported as a refused CA).
    if let Err(e) = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
        && e.kind() == std::io::ErrorKind::PermissionDenied
    {
        return TrustStep::NotReadable;
    }
    let der = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .and_then(|f| {
            if !f.metadata()?.is_file() {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut der = Vec::new();
            f.take(MAX_CA_FILE_BYTES + 1).read_to_end(&mut der).map(|_| der)
        });
    let Ok(der) = der else { return TrustStep::Refused };
    let Ok(ca) = ca_trust::read_der(&der, now()) else { return TrustStep::Refused };
    match cert_store::add_with_usage(Location::LocalMachine, ROOT, &ca.der, TLS_ONLY_EKU) {
        Ok(Added::New) => TrustStep::Added,
        Ok(Added::AlreadyThere) => TrustStep::AlreadyThere,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => TrustStep::NotRestricted,
        Err(_) => TrustStep::StoreFailed,
    }
}

/// More than any certificate `pure::ca_trust` accepts.
const MAX_CA_FILE_BYTES: u64 = 128 * 1024;

/// `<System32>\<name>`, which must exist.
fn system32_tool(name: &str) -> Result<PathBuf, String> {
    system::system32()
        .map(|dir| dir.join(name))
        .filter(|exe| exe.is_file())
        .ok_or_else(|| macvpn_core::l10n::tr("%@ could not be started.", &[macvpn_core::l10n::Arg::Str(name)]))
}

/// The certificate file the elevated trust step reads, held open with `FILE_SHARE_READ` only (no writer, no rename, no delete)
/// until dropped; then it is deleted.
pub(crate) struct StagedCa {
    pub(crate) path: PathBuf,
    held: Option<File>,
}

impl StagedCa {
    /// A new `ca-<32 hex>.cer` in the user's temp folder (`%LOCALAPPDATA%\Temp`, the known folder, not `TEMP`).
    pub(crate) fn write(ca: &CaCert) -> Result<StagedCa, String> {
        let dir = system::local_app_data().map(|d| d.join("Temp")).filter(|d| d.is_dir()).ok_or_else(prepare_failed)?;
        Self::write_in(&dir, &ca.der)
    }

    pub(crate) fn write_in(dir: &Path, der: &[u8]) -> Result<StagedCa, String> {
        let mut random = [0u8; 16];
        macvpn_winsys::random::fill(&mut random).map_err(|_| prepare_failed())?;
        let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!("{CA_FILE_PREFIX}{hex}.{CA_FILE_EXTENSION}"));
        // `create_new`: never an existing file or link; no sharing while it is written. Opened at once to the elevated
        // step, which may run as another account (Users read; only this user and SYSTEM may change it).
        let written = OpenOptions::new()
            .write(true)
            .access_mode(FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .and_then(|mut f| {
                wfile::set_protection(&f, Protection::Shared, false)?;
                f.write_all(der).and_then(|()| f.sync_all())
            });
        if written.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err(prepare_failed());
        }
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path);
        let staged = match held {
            Ok(file) => StagedCa { path, held: Some(file) },
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                return Err(prepare_failed());
            }
        };
        // What the elevated step will read is what WinVPN wrote (checked through the held handle).
        let Some(file) = staged.held.as_ref() else { return Err(prepare_failed()) };
        let mut back = Vec::new();
        let same = file.take(der.len() as u64 + 1).read_to_end(&mut back).is_ok() && back == der;
        let regular = file.metadata().is_ok_and(|m| m.is_file());
        let readable = wfile::has_protection(file, Protection::Shared, false).unwrap_or(false);
        if !same || !regular || !readable {
            return Err(prepare_failed());
        }
        Ok(staged)
    }
}

impl Drop for StagedCa {
    /// The held handle is closed first (it denies deleting), then the file is deleted.
    fn drop(&mut self) {
        drop(self.held.take());
        let _ = std::fs::remove_file(&self.path);
    }
}
