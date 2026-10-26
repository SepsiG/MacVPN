//! The WinVPN Service runs as LocalSystem from its install folder, so that folder must be admin-only (security
//! review part 2, P2-M2): a folder any user can change lets them replace `WinVPNService.exe`, plant a DLL it
//! imports, or swap the bundled `wireguard.dll`, and their code runs as SYSTEM at the next start. The MSI pins the
//! folder to `<Program Files>\WinVPN` and gives it an explicit, protected ACL (`app/src-tauri/wix/service.wxs.in`);
//! the service checks it again at every start and refuses to run (`sys::host`) when the check fails.
//!
//! The check is `macvpn_winsys::acl_check::is_admin_only` (the file, its folder and every ancestor), on the service's
//! own exe and on the bundled `wireguard.dll` next to it. A missing `wireguard.dll` is not this check's business: its
//! folder is the exe's, checked already, and the WireGuard engine refuses a missing DLL on its own.

use std::io;
use std::path::{Path, PathBuf};

/// The bundled wireguard-nt DLL, next to the service's exe (the MSI's `WireGuardDll` component).
pub const BUNDLED_DLL: &str = "wireguard.dll";

/// The files whose folders must be admin-only before the service runs: its exe, then the bundled DLL.
pub fn checked_files(exe: &Path) -> [PathBuf; 2] {
    [exe.to_path_buf(), exe.with_file_name(BUNDLED_DLL)]
}

/// Why the service must not run from `exe`'s folder, as one line for the service log; `None` when every file of
/// [`checked_files`] passes `is_admin_only` (a fail-closed check: an error is a refusal, except a missing DLL).
pub fn problem(exe: &Path, is_admin_only: impl Fn(&Path) -> io::Result<bool>) -> Option<String> {
    let [exe, dll] = checked_files(exe);
    let refuse = |path: &Path, why: String| {
        Some(format!(
            "refusing to start: {} {why}; reinstall WinVPN into Program Files (only administrators may change its folder)",
            path.display()
        ))
    };
    match is_admin_only(&exe) {
        Ok(true) => {}
        Ok(false) => {
            return refuse(&exe, "is not admin-only (its folder or a folder above it can be changed by others)".into());
        }
        Err(e) => return refuse(&exe, format!("cannot be checked ({:?})", e.kind())),
    }
    match is_admin_only(&dll) {
        Ok(true) => None,
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Ok(false) => refuse(&dll, "is not admin-only (it can be changed by others)".into()),
        Err(e) => refuse(&dll, format!("cannot be checked ({:?})", e.kind())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const EXE: &str = r"C:\Program Files\WinVPN\WinVPNService.exe";

    fn exe() -> PathBuf {
        PathBuf::from(EXE)
    }

    #[test]
    fn the_exe_and_the_bundled_dll_next_to_it_are_checked() {
        let [a, b] = checked_files(&exe());
        assert_eq!(a, exe());
        assert_eq!(b, exe().with_file_name("wireguard.dll"));
        let asked = RefCell::new(Vec::new());
        let ok = problem(&exe(), |p| {
            asked.borrow_mut().push(p.to_path_buf());
            Ok(true)
        });
        assert_eq!(ok, None);
        assert_eq!(*asked.borrow(), [a, b]);
    }

    #[test]
    fn a_folder_others_can_change_is_a_refusal() {
        let why = problem(&exe(), |_| Ok(false)).expect("refused");
        assert!(why.starts_with("refusing to start: "), "{why}");
        assert!(why.contains("WinVPNService.exe is not admin-only"), "{why}");
        // Only the DLL fails (its own ACL lets others write it).
        let dll = exe().with_file_name(BUNDLED_DLL);
        let why = problem(&exe(), |p| Ok(p != dll)).expect("refused");
        assert!(why.contains("wireguard.dll is not admin-only"), "{why}");
    }

    #[test]
    fn a_check_that_fails_is_a_refusal_but_a_missing_dll_is_not() {
        let denied = |_: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let why = problem(&exe(), denied).expect("refused");
        assert!(why.contains("WinVPNService.exe cannot be checked (PermissionDenied)"), "{why}");
        // The exe itself missing (impossible while it runs) is still a refusal: fail closed.
        assert!(problem(&exe(), |_| Err(io::Error::from(io::ErrorKind::NotFound))).is_some());
        let dll = exe().with_file_name(BUNDLED_DLL);
        let missing_dll = |p: &Path| if p == dll { Err(io::Error::from(io::ErrorKind::NotFound)) } else { Ok(true) };
        assert_eq!(problem(&exe(), missing_dll), None);
        let unreadable_dll =
            |p: &Path| if p == dll { Err(io::Error::from(io::ErrorKind::PermissionDenied)) } else { Ok(true) };
        assert!(problem(&exe(), unreadable_dll).is_some_and(|w| w.contains("wireguard.dll cannot be checked")));
    }
}
