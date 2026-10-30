//! `linvpn-install-update`: LinVPN's only code that runs as root in L-a, started by pkexec under the polkit action
//! `local.linvpn.update` (`/usr/libexec/linvpn/linvpn-install-update --deb … --sig … --version … --asset …`).
//!
//! It trusts nothing from the caller: it opens the caller's two files without following links (regular files of the
//! calling user, `PKEXEC_UID`, in a folder of that user with no group or other access), copies the package into a
//! fresh root-owned 0700 folder under /var/cache/linvpn-update while hashing it, and on that copy verifies the
//! Ed25519 signature (`linvpn-update-v1`, the asset name, the version, the hash; the keys embedded in the core),
//! that the asset is this machine's architecture, and `dpkg-deb --field`'s Package / Version / Architecture
//! (`deb_update::check`: ours, this architecture, the signed version, newer than the installed one; `linvpn` not
//! installed or `dpkg-query` failing is refused, never a free pass). Only then: `apt-get install -y <copy>` with a
//! clean environment. The copy is removed afterwards. Both files are read through their size limit, also when they
//! grow after the size check. Before anything else the step sets its own umask (022) and resource limits, so the
//! caller's (which pkexec passes on) never reach dpkg or apt. Exit codes: `deb_update::StepError::code`; 0 = installed.

use macvpn_core::deb_update::{self, StepArgs, StepError};
use macvpn_core::update::{SignatureDomain, UpdateSignature};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_DEB: u64 = 512 * 1024 * 1024;
const STAGING: &str = "/var/cache/linvpn-update";

/// A tool's output for a file (`dpkg-deb --field <deb> …`); `None`: the tool failed.
pub type FileTool = Box<dyn Fn(&Path) -> Option<String>>;

/// What the step needs from the system, as parameters (tests pass fakes).
pub struct Env {
    pub caller_uid: u32,
    pub staging: PathBuf,
    pub keys: Vec<[u8; 32]>,
    /// `dpkg --print-architecture`.
    pub dpkg_arch: Box<dyn Fn() -> Option<String>>,
    /// `dpkg-deb --field <deb> Package Version Architecture`.
    pub fields: FileTool,
    /// The installed version of `linvpn` (`dpkg-query`); `Ok(None)`: not installed (refused, `NotInstalled`);
    /// `Err(ToolFailed)`: the tool failed (refused).
    pub installed: Box<dyn Fn() -> Result<Option<String>, StepError>>,
    /// `apt-get install -y <deb>`; true: installed.
    pub apt_install: Box<dyn Fn(&Path) -> bool>,
}

fn open_callers(path: &Path, uid: u32, max: u64) -> Result<File, StepError> {
    let parent = path.parent().ok_or(StepError::UnsafeFile)?;
    let dir = std::fs::symlink_metadata(parent).map_err(|_| StepError::UnsafeFile)?;
    if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o077 != 0 {
        return Err(StepError::UnsafeFile);
    }
    let file = OpenOptions::new()
        .read(true)
        // O_NONBLOCK: a FIFO (or a device) in place of the file never blocks the open; O_NOCTTY: a terminal never
        // becomes root's controlling terminal. Neither changes reading a regular file, the only kind accepted.
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|_| StepError::UnsafeFile)?;
    let meta = file.metadata().map_err(|_| StepError::UnsafeFile)?;
    if !meta.is_file() || meta.uid() != uid || meta.len() > max || meta.nlink() != 1 {
        return Err(StepError::UnsafeFile);
    }
    Ok(file)
}

/// Copies at most `max` bytes of `source` into `out` and returns their lower-case SHA-256; more than `max` bytes (a
/// file that grew after its size was checked) is `UnsafeFile`, and nothing beyond `max + 64 KiB` is ever read.
#[doc(hidden)]
pub fn copy_hashed(source: impl Read, out: &mut impl Write, max: u64) -> Result<String, StepError> {
    let mut source = source.take(max + 1);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = source.read(&mut buf).map_err(|_| StepError::UnsafeFile)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            return Err(StepError::UnsafeFile);
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|_| StepError::ToolFailed)?;
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The signature file's text, at most `MAX_SIGNATURE_FILE_SIZE` bytes; more, or not UTF-8: `BadSignature`.
#[doc(hidden)]
pub fn read_signature(source: impl Read) -> Result<String, StepError> {
    let max = UpdateSignature::MAX_SIGNATURE_FILE_SIZE;
    let mut signature = String::new();
    source.take(max as u64 + 1).read_to_string(&mut signature).map_err(|_| StepError::BadSignature)?;
    if signature.len() > max {
        return Err(StepError::BadSignature);
    }
    Ok(signature)
}

/// The step's own process state instead of the caller's (pkexec clears the environment but passes on the umask and
/// the resource limits): umask 022, no core dumps, no file size limit, at least 1024 open files. Best effort: a limit
/// that cannot be set is left (root can set all of them).
#[allow(unsafe_code)]
pub fn harden_process() {
    let set = |resource, cur: libc::rlim_t, max: libc::rlim_t| {
        let limit = libc::rlimit { rlim_cur: cur, rlim_max: max };
        // SAFETY: `setrlimit` reads the struct it is given; a failure leaves the limit as it was.
        let _ = unsafe { libc::setrlimit(resource, &limit) };
    };
    // SAFETY: `umask` takes a mode and cannot fail.
    unsafe { libc::umask(0o022) };
    set(libc::RLIMIT_CORE, 0, 0);
    set(libc::RLIMIT_FSIZE, libc::RLIM_INFINITY, libc::RLIM_INFINITY);
    let mut nofile = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `getrlimit` writes into the struct it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) } == 0 && nofile.rlim_cur < 1024 {
        set(libc::RLIMIT_NOFILE, 1024, nofile.rlim_max.max(1024));
    }
}

/// A new 0700 folder under `staging` (created 0700 if missing), named with 16 random hex digits.
fn new_staging_dir(staging: &Path) -> Result<PathBuf, StepError> {
    std::fs::DirBuilder::new().mode(0o700).recursive(true).create(staging).map_err(|_| StepError::ToolFailed)?;
    let mut bytes = [0u8; 8];
    macvpn_unixsys::random::fill(&mut bytes).map_err(|_| StepError::ToolFailed)?;
    let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let dir = staging.join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|_| StepError::ToolFailed)?;
    Ok(dir)
}

pub fn run(args: &StepArgs, env: &Env) -> Result<(), StepError> {
    let dpkg_arch = (env.dpkg_arch)().ok_or(StepError::ToolFailed)?;
    if args.asset != deb_update::asset(&args.version, &dpkg_arch) {
        return Err(StepError::WrongArchitecture);
    }
    let source = open_callers(&args.deb, env.caller_uid, MAX_DEB)?;
    let sig_file = open_callers(&args.sig, env.caller_uid, UpdateSignature::MAX_SIGNATURE_FILE_SIZE as u64)?;
    let signature = read_signature(sig_file)?;

    let dir = new_staging_dir(&env.staging)?;
    let copy = dir.join(&args.asset);
    let result = (|| {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&copy)
            .map_err(|_| StepError::ToolFailed)?;
        let sha = copy_hashed(source, &mut out, MAX_DEB)?;
        out.sync_all().map_err(|_| StepError::ToolFailed)?;
        if !UpdateSignature::verify_for(
            SignatureDomain::LinVpnV1,
            &args.asset,
            &args.version,
            &sha,
            &signature,
            &env.keys,
        ) {
            return Err(StepError::BadSignature);
        }
        let fields = (env.fields)(&copy).and_then(|o| deb_update::parse_fields(&o)).ok_or(StepError::ToolFailed)?;
        let installed = (env.installed)()?;
        deb_update::check(&fields, &args.version, &dpkg_arch, installed.as_deref())?;
        if !(env.apt_install)(&copy) {
            return Err(StepError::InstallFailed);
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The real environment: root, the tools at their absolute paths, a clean environment for each.
#[allow(unsafe_code)]
pub fn real_env() -> Result<Env, StepError> {
    // SAFETY: `geteuid` takes no argument and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(StepError::NotRoot);
    }
    let caller_uid: u32 =
        std::env::var("PKEXEC_UID").ok().and_then(|u| u.parse().ok()).ok_or(StepError::BadArguments)?;
    let tool = |program: &'static str, args: Vec<std::ffi::OsString>| -> Option<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    Ok(Env {
        caller_uid,
        staging: PathBuf::from(STAGING),
        keys: UpdateSignature::trusted_keys(),
        dpkg_arch: Box::new(move || {
            tool("/usr/bin/dpkg", vec!["--print-architecture".into()]).map(|s| s.trim().to_string())
        }),
        fields: Box::new(move |deb| {
            tool(
                "/usr/bin/dpkg-deb",
                vec!["--field".into(), deb.into(), "Package".into(), "Version".into(), "Architecture".into()],
            )
        }),
        // dpkg-query's exit 1: no such package (never installed or purged); 0: the status decides; anything else,
        // or no start: the tool failed.
        installed: Box::new(|| {
            let out = std::process::Command::new("/usr/bin/dpkg-query")
                .args(["-W", "--showformat=${db:Status-Status} ${Version}", deb_update::PACKAGE])
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|_| StepError::ToolFailed)?;
            match out.status.code() {
                Some(0) => deb_update::parse_installed(&String::from_utf8_lossy(&out.stdout)),
                Some(1) => Ok(None),
                _ => Err(StepError::ToolFailed),
            }
        }),
        apt_install: Box::new(|deb| {
            std::process::Command::new("/usr/bin/apt-get")
                .args(["install", "-y"])
                .arg(deb)
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .env("DEBIAN_FRONTEND", "noninteractive")
                .stdin(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }),
    })
}

/// The binary's `main`: its exit code.
pub fn main() -> i32 {
    harden_process();
    let args: Vec<String> = match std::env::args_os().skip(1).map(|a| a.into_string()).collect() {
        Ok(a) => a,
        Err(_) => return StepError::BadArguments.code(),
    };
    let Some(args) = deb_update::parse_step_args(&args) else { return StepError::BadArguments.code() };
    let env = match real_env() {
        Ok(env) => env,
        Err(e) => return e.code(),
    };
    match run(&args, &env) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("linvpn-install-update: refused ({e:?})");
            e.code()
        }
    }
}
