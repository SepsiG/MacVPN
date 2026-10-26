//! Whether OpenVPN Community may be run as SYSTEM (the 2b plan's "OpenVPN's trust before every start"): the path
//! from HKLM (64-bit view), a plain file, at least the minimum version, admin-only writable (the file and every
//! folder above it), the pinned Authenticode signer; and the data-channel drivers (DCO, TAP-Windows6) with their
//! versions. Read again before every `up`: an update or a tampering in between counts. Anything that cannot be read
//! is "not there" (fail closed).

use crate::shared::l10n::tr;
use crate::windows::ovpn_args::{Driver, Version};
use crate::windows::ovpn_pins::PINS;
use macvpn_core::service_proto::OpenVpnFacts;
use macvpn_winsys::file;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    RegGetValueW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

/// An `openvpn.exe` that passed every check, and which drivers are there.
#[derive(Debug, Clone)]
pub struct Ready {
    pub exe: PathBuf,
    pub dco: bool,
    pub tap_windows6: bool,
}

impl Ready {
    pub fn has(&self, driver: Driver) -> bool {
        match driver {
            Driver::Dco => self.dco,
            Driver::TapWindows6 => self.tap_windows6,
        }
    }
}

const OPENVPN_KEY: &str = r"SOFTWARE\OpenVPN";
const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
/// The driver services of OpenVPN Community 2.7's MSI (a `wintun` key of an older installation is ignored).
const DCO_SERVICE: &str = "ovpn-dco";
const TAP_SERVICE: &str = "tap0901";
/// `Start` = 4: the driver is disabled.
const SERVICE_DISABLED: u32 = 4;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A value of `HKLM\<subkey>`: `flags` as `RegGetValueW` takes them; `None` when missing or unreadable.
fn reg_value(subkey: &str, value: &str, flags: u32) -> Option<Vec<u16>> {
    let (key, name) = (wide(subkey), wide(value));
    let mut size = 0u32;
    // SAFETY: NUL-terminated key and value names; no data buffer (a size query); `size` is a valid out pointer.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || size == 0 || size > 64 * 1024 {
        return None;
    }
    // A value that grows between the two calls fails the second (ERROR_MORE_DATA): not there.
    let mut buf = vec![0u16; (size as usize).div_ceil(2)];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: as above, with `buf` valid for writes of `len` bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    buf.truncate((len as usize) / 2);
    Some(buf)
}

/// A string value (REG_SZ, or REG_EXPAND_SZ as written when `expand_sz`), up to its NUL.
fn reg_string(subkey: &str, value: &str, extra: u32) -> Option<String> {
    let buf = reg_value(subkey, value, RRF_RT_REG_SZ | extra)?;
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end]).into_string().ok().filter(|s| !s.is_empty())
}

fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    let buf = reg_value(subkey, value, RRF_RT_REG_DWORD)?;
    (buf.len() == 2).then(|| u32::from(buf[0]) | (u32::from(buf[1]) << 16))
}

/// `C:\Windows` as Windows says it (`GetSystemWindowsDirectoryW`, never the environment).
pub fn windows_dir() -> Option<PathBuf> {
    let mut buf = [0u16; 260];
    // SAFETY: `buf` is valid for writes of its length in UTF-16 units.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    let p = PathBuf::from(OsString::from_wide(&buf[..n]));
    p.is_absolute().then_some(p)
}

/// A plain absolute path: a drive, then only normal components (no `.`, `..`, no `\\?\` or UNC).
fn is_plain(p: &Path) -> bool {
    let mut parts = p.components();
    matches!(parts.next(), Some(Component::Prefix(x)) if matches!(x.kind(), std::path::Prefix::Disk(_)))
        && matches!(parts.next(), Some(Component::RootDir))
        && parts.all(|c| matches!(c, Component::Normal(_)))
}

/// The `.sys` file a driver service's `ImagePath` names (as the registry has it, not expanded): `\SystemRoot\…`,
/// `%SystemRoot%\…`, `System32\…` (relative to the Windows folder), `\??\X:\…` or `X:\…`. Only a plain path below
/// `<windows>\System32\drivers\` or `<windows>\System32\DriverStore\FileRepository\` ending in `.sys` counts.
pub fn driver_file(windows: &Path, image_path: &str) -> Option<PathBuf> {
    let lower = image_path.to_ascii_lowercase();
    let path = if let Some(rest) = strip(image_path, &lower, r"\systemroot\") {
        windows.join(rest)
    } else if let Some(rest) = strip(image_path, &lower, r"%systemroot%\") {
        windows.join(rest)
    } else if lower.starts_with(r"system32\") {
        windows.join(image_path)
    } else if let Some(rest) = strip(image_path, &lower, r"\??\") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(image_path)
    };
    if image_path.contains('/') || !is_plain(&path) {
        return None;
    }
    let text = path.to_str()?.to_ascii_lowercase();
    let base = windows.to_str()?.to_ascii_lowercase();
    let allowed = [r"\system32\drivers\", r"\system32\driverstore\filerepository\"]
        .iter()
        .any(|dir| text.strip_prefix(&format!("{base}{dir}")).is_some_and(|rest| !rest.is_empty()));
    (allowed && text.ends_with(".sys")).then_some(path)
}

fn strip<'a>(original: &'a str, lower: &str, prefix: &str) -> Option<&'a str> {
    lower.starts_with(prefix).then(|| &original[prefix.len()..])
}

/// A regular file (no directory, no reparse point) at `path`, never through a link.
fn is_regular_file(path: &Path) -> bool {
    file::open_metadata(path, false)
        .and_then(|f| file::info(&f))
        .is_ok_and(|i| i.reparse_tag.is_none() && i.attributes & FILE_ATTRIBUTE_DIRECTORY == 0)
}

fn four_part((a, b, c, d): (u16, u16, u16, u16)) -> String {
    format!("{a}.{b}.{c}.{d}")
}

/// The version of an enabled driver service whose file is where Windows keeps drivers; `None` otherwise.
fn driver_version(service: &str, windows: &Path) -> Option<String> {
    let key = format!(r"{SERVICES_KEY}\{service}");
    if reg_dword(&key, "Start")? == SERVICE_DISABLED {
        return None;
    }
    let image = reg_string(&key, "ImagePath", RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND)?;
    let sys = driver_file(windows, &image)?;
    if !is_regular_file(&sys) {
        return None;
    }
    macvpn_winsys::version::file_version(&sys).ok().map(four_part)
}

fn not_installed() -> String {
    tr("OpenVPN Community is not installed.", &[])
}

/// The checks of `openvpn.exe` itself, in order; fills in `facts.version` once it is known.
pub fn check_exe(path: &Path, facts: &mut OpenVpnFacts) -> Result<(), String> {
    if !is_plain(path) || !is_regular_file(path) {
        return Err(not_installed());
    }
    let version =
        macvpn_winsys::version::file_version(path).map(Version::from_file_version).map_err(|_| not_installed())?;
    facts.version = Some(version.to_string());
    let min = Version::parse(&PINS.min_version).ok_or_else(not_installed)?;
    if version < min {
        return Err(tr(
            "OpenVPN Community %@ is too old (%@ or newer is needed).",
            &[&version.to_string(), &min.to_string()],
        ));
    }
    if !macvpn_winsys::acl_check::is_admin_only(path).unwrap_or(false) {
        return Err(tr("openvpn.exe is in a folder other users can change: %@", &[&path.display().to_string()]));
    }
    // M-1 of the 2.0.0 security review: the signer's name and a pinned CA key above it in the chain.
    match macvpn_winsys::trust::verify_signature(path) {
        Ok(s) if s.is_pinned(&PINS.signer, &PINS.signer_cas()) => Ok(()),
        Ok(s) if s.subject == PINS.signer => Err(tr(
            "openvpn.exe is signed by %@, but not through a certificate authority WinVPN knows. Update WinVPN.",
            &[&PINS.signer],
        )),
        _ => Err(tr("openvpn.exe is not signed by %@.", &[&PINS.signer])),
    }
}

/// The facts for `engine`, and the executable when every check passed.
pub fn detect() -> (OpenVpnFacts, Option<Ready>) {
    let mut facts = OpenVpnFacts { version: None, path: None, dco: None, tap_windows6: None, problem: None };
    if let Some(windows) = windows_dir() {
        facts.dco = driver_version(DCO_SERVICE, &windows);
        facts.tap_windows6 = driver_version(TAP_SERVICE, &windows);
    }
    let exe = reg_string(OPENVPN_KEY, "exe_path", RRF_SUBKEY_WOW6464KEY).map(PathBuf::from);
    let Some(exe) = exe else {
        facts.problem = Some(not_installed());
        return (facts, None);
    };
    facts.path = Some(exe.display().to_string());
    if let Err(problem) = check_exe(&exe, &mut facts) {
        facts.problem = Some(problem);
        return (facts, None);
    }
    let ready = Ready { exe, dco: facts.dco.is_some(), tap_windows6: facts.tap_windows6.is_some() };
    (facts, Some(ready))
}

/// [`detect`] as the engine needs it: the executable, or the reason.
pub fn ready() -> Result<Ready, String> {
    match detect() {
        (_, Some(r)) => Ok(r),
        (facts, None) => Err(facts.problem.unwrap_or_else(not_installed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> OpenVpnFacts {
        OpenVpnFacts { version: None, path: None, dco: None, tap_windows6: None, problem: None }
    }

    #[test]
    fn driver_image_paths_are_taken_only_from_the_driver_folders() {
        let w = Path::new(r"C:\Windows");
        let ok = [
            (r"\SystemRoot\System32\drivers\ovpn-dco.sys", r"C:\Windows\System32\drivers\ovpn-dco.sys"),
            (r"System32\drivers\tap0901.sys", r"C:\Windows\System32\drivers\tap0901.sys"),
            (r"%SystemRoot%\system32\DRIVERS\tap0901.sys", r"C:\Windows\system32\DRIVERS\tap0901.sys"),
            (
                r"\??\C:\Windows\System32\DriverStore\FileRepository\ovpn-dco.inf_amd64_1\ovpn-dco.sys",
                r"C:\Windows\System32\DriverStore\FileRepository\ovpn-dco.inf_amd64_1\ovpn-dco.sys",
            ),
            (r"C:\Windows\System32\drivers\ovpn-dco.sys", r"C:\Windows\System32\drivers\ovpn-dco.sys"),
        ];
        for (image, want) in ok {
            assert_eq!(driver_file(w, image), Some(PathBuf::from(want)), "{image}");
        }
        for bad in [
            r"\SystemRoot\System32\drivers\..\..\Temp\x.sys",
            r"C:\Users\Public\ovpn-dco.sys",
            r"\SystemRoot\System32\drivers\ovpn-dco.exe",
            r"\SystemRoot\System32\drivers\",
            r"\\server\share\Windows\System32\drivers\x.sys",
            r"\??\UNC\server\share\x.sys",
            r"D:\Windows\System32\drivers\x.sys",
            r"C:\Windows\System32\drivers/x.sys",
            "",
        ] {
            assert_eq!(driver_file(w, bad), None, "{bad}");
        }
    }

    #[test]
    fn the_windows_folder_comes_from_windows() {
        let w = windows_dir().unwrap();
        assert!(w.join("System32").join("kernel32.dll").is_file(), "{}", w.display());
    }

    #[test]
    fn an_executable_of_another_signer_or_in_a_user_folder_is_refused() {
        let w = windows_dir().unwrap();
        // curl.exe: an embedded signature (Microsoft's), in an admin-only folder: refused for its signer.
        let curl = w.join(r"System32\curl.exe");
        let mut facts = empty();
        assert_eq!(check_exe(&curl, &mut facts).unwrap_err(), format!("openvpn.exe is not signed by {}.", PINS.signer));
        assert!(facts.version.is_some());
        // The same file where this user can write: refused for its folder (before the signature is looked at).
        let dir = std::env::temp_dir().join(format!("winvpn-detect-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let copy = dir.join("openvpn.exe");
        std::fs::copy(&curl, &copy).unwrap();
        let e = check_exe(&copy, &mut empty()).unwrap_err();
        assert_eq!(e, format!("openvpn.exe is in a folder other users can change: {}", copy.display()));
        std::fs::remove_dir_all(&dir).unwrap();
        // Nothing there, a folder, a relative path: not installed.
        for p in [w.join(r"System32\no-such-openvpn.exe"), w.join("System32"), PathBuf::from(r"bin\openvpn.exe")] {
            assert_eq!(check_exe(&p, &mut empty()).unwrap_err(), "OpenVPN Community is not installed.", "{p:?}");
        }
    }

    #[test]
    fn detection_without_openvpn_names_the_problem() {
        let (facts, ready) = detect();
        if facts.path.is_none() {
            // The test machine (CP1 installs it): no exe_path value.
            assert!(ready.is_none());
            assert_eq!(facts.problem.as_deref(), Some("OpenVPN Community is not installed."));
            assert_eq!(super::ready().unwrap_err(), "OpenVPN Community is not installed.");
        } else {
            assert_eq!(facts.problem.is_none(), ready.is_some(), "{facts:?}");
        }
    }
}
