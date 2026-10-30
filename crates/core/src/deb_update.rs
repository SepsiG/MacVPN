//! LinVPN's `.deb` update rules, shared by the app (before it asks for the password) and the root step
//! `linvpn-install-update` (which checks everything again on its own copy): the asset name, `dpkg-deb --field`'s
//! output, the version order (numeric X.Y.Z only), the root step's exact arguments and exit codes. Pure: no `cfg`, no
//! file system.

use std::path::PathBuf;

pub const PACKAGE: &str = "linvpn";

/// Rust's `std::env::consts::ARCH` → Debian's architecture name.
pub fn deb_arch(rust_arch: &str) -> Option<&'static str> {
    match rust_arch {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

pub fn asset(version: &str, deb_arch: &str) -> String {
    format!("{PACKAGE}_{version}_{deb_arch}.deb")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    pub package: String,
    pub version: String,
    pub architecture: String,
}

/// `dpkg-deb --field <deb> Package Version Architecture`: each field exactly once.
pub fn parse_fields(output: &str) -> Option<Fields> {
    let (mut package, mut version, mut architecture) = (None, None, None);
    for line in output.lines() {
        let (key, value) = line.split_once(": ")?;
        let slot = match key {
            "Package" => &mut package,
            "Version" => &mut version,
            "Architecture" => &mut architecture,
            _ => return None,
        };
        if slot.replace(value.trim().to_string()).is_some() {
            return None;
        }
    }
    Some(Fields { package: package?, version: version?, architecture: architecture? })
}

fn numeric(version: &str) -> Option<[u64; 3]> {
    let parts: Vec<u64> = version.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    parts.try_into().ok()
}

/// `candidate` is a plain X.Y.Z newer than `installed` (none installed: any valid candidate).
pub fn is_newer(candidate: &str, installed: Option<&str>) -> bool {
    let Some(c) = numeric(candidate) else { return false };
    match installed {
        None => true,
        Some(i) => numeric(i).is_some_and(|i| c > i),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    BadArguments,
    NotRoot,
    UnsafeFile,
    BadSignature,
    WrongPackage,
    WrongArchitecture,
    WrongVersion,
    NotNewer,
    ToolFailed,
    InstallFailed,
    /// `dpkg-query` reports `linvpn` as not installed: impossible for a step that ships inside it, so refused.
    NotInstalled,
}

impl StepError {
    pub const ALL: [StepError; 11] = [
        StepError::BadArguments,
        StepError::NotRoot,
        StepError::UnsafeFile,
        StepError::BadSignature,
        StepError::WrongPackage,
        StepError::WrongArchitecture,
        StepError::WrongVersion,
        StepError::NotNewer,
        StepError::ToolFailed,
        StepError::InstallFailed,
        StepError::NotInstalled,
    ];

    /// The root step's exit code (never 0, nor pkexec's own 126 and 127). The codes are stable: a new error takes the
    /// next free number.
    pub fn code(self) -> i32 {
        match self {
            StepError::BadArguments => 10,
            StepError::NotRoot => 11,
            StepError::UnsafeFile => 12,
            StepError::BadSignature => 13,
            StepError::WrongPackage => 14,
            StepError::WrongArchitecture => 15,
            StepError::WrongVersion => 16,
            StepError::NotNewer => 17,
            StepError::ToolFailed => 18,
            StepError::InstallFailed => 19,
            StepError::NotInstalled => 20,
        }
    }

    pub fn from_code(code: i32) -> Option<StepError> {
        StepError::ALL.into_iter().find(|e| e.code() == code)
    }
}

/// The package must be ours, of this machine's architecture, exactly the signed version, and newer than the installed
/// one. Nothing installed (`None`) is refused (`NotInstalled`): the root step ships inside the installed `linvpn`, so
/// "not installed" means the version check cannot be trusted, and "no downgrade" must not fail open.
pub fn check(fields: &Fields, signed_version: &str, dpkg_arch: &str, installed: Option<&str>) -> Result<(), StepError> {
    if fields.package != PACKAGE {
        return Err(StepError::WrongPackage);
    }
    if fields.architecture != dpkg_arch {
        return Err(StepError::WrongArchitecture);
    }
    if fields.version != signed_version {
        return Err(StepError::WrongVersion);
    }
    let Some(installed) = installed else { return Err(StepError::NotInstalled) };
    if !is_newer(&fields.version, Some(installed)) {
        return Err(StepError::NotNewer);
    }
    Ok(())
}

/// `dpkg-query -W --showformat='${db:Status-Status} ${Version}' linvpn` (exit 0): `installed <version>` is the
/// installed version; another status (`config-files`, `not-installed`, `half-installed`, …) is `None`; anything else
/// (an empty version, extra words or lines) is the tool failing (`ToolFailed`).
pub fn parse_installed(output: &str) -> Result<Option<String>, StepError> {
    let line = output.strip_suffix('\n').unwrap_or(output);
    if line.contains('\n') {
        return Err(StepError::ToolFailed);
    }
    let (status, version) = line.split_once(' ').unwrap_or((line, ""));
    match status {
        "installed" if !version.is_empty() && !version.contains(' ') => Ok(Some(version.to_string())),
        "installed" | "" => Err(StepError::ToolFailed),
        _ if status.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') => Ok(None),
        _ => Err(StepError::ToolFailed),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepArgs {
    pub deb: PathBuf,
    pub sig: PathBuf,
    pub version: String,
    pub asset: String,
}

/// Exactly `--deb <abs> --sig <abs> --version X.Y.Z --asset <name>`, in this order (`<abs>`: starts with `/`).
pub fn parse_step_args(args: &[String]) -> Option<StepArgs> {
    let [d, deb, s, sig, v, version, a, asset] = args else { return None };
    if d != "--deb" || s != "--sig" || v != "--version" || a != "--asset" {
        return None;
    }
    // Absolute in the root step's (Linux) sense on every OS: a leading `/` is exactly what `Path::is_absolute` means
    // there, and the rule stays pure (no `cfg`; the tests run on every OS).
    if !deb.starts_with('/') || !sig.starts_with('/') || numeric(version).is_none() {
        return None;
    }
    Some(StepArgs { deb: PathBuf::from(deb), sig: PathBuf::from(sig), version: version.clone(), asset: asset.clone() })
}

/// The arguments the app passes ([`parse_step_args`] reads them back).
pub fn step_args(deb: &std::path::Path, sig: &std::path::Path, version: &str, asset: &str) -> Vec<std::ffi::OsString> {
    vec![
        "--deb".into(),
        deb.into(),
        "--sig".into(),
        sig.into(),
        "--version".into(),
        version.into(),
        "--asset".into(),
        asset.into(),
    ]
}
