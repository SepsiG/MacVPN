//! The OpenVPN Community install on a real Windows system, the half a standard user can run over SSH (2b plan,
//! Task 17): the MSI checks before any elevation, and the elevated step's refusals (which end before msiexec or
//! the SCM). The elevated install itself is a CP2 item of the maintainer (no UAC over SSH).

#![cfg(windows)]

use macvpn_core::l10n::{self, AppLanguage};
use macvpn_platform_win::pure::openvpn_install::{self as oi, Interactive, StepError, StepResult};
use macvpn_winsys::file::Protection;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

const GIT: &str = r"C:\Program Files\Git\cmd\git.exe";

fn step(args: &[&str]) -> Option<StepResult> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    macvpn_platform_win::openvpn_elevated_step(&args).map(|code| StepResult::from_code(code).expect("a step code"))
}

#[test]
fn a_file_with_the_wrong_signer_is_never_run() {
    // git.exe is validly signed, but not by the pinned OpenVPN signer: refused before any elevation.
    let r = l10n::with_language(AppLanguage::En, || macvpn_platform_win::verify_openvpn_msi_for_tests(Path::new(GIT)));
    assert!(r.unwrap_err().contains("not signed by OpenVPN Inc."));
    // Unsigned, and missing.
    let r = macvpn_platform_win::verify_openvpn_msi_for_tests(&std::env::current_exe().unwrap());
    assert_eq!(r, Err(oi::not_signed_by("OpenVPN Inc.")));
    assert!(macvpn_platform_win::verify_openvpn_msi_for_tests(Path::new(r"C:\nothing\here.msi")).is_err());
}

#[test]
fn the_app_starts_normally_without_the_step_argument() {
    assert_eq!(macvpn_platform_win::openvpn_elevated_step(&[]), None);
    assert_eq!(macvpn_platform_win::openvpn_elevated_step(&["--minimized".into()]), None);
}

#[test]
fn the_elevated_step_refuses_what_is_not_the_pinned_msi() {
    let refused = |error| Some(StepResult { msi: None, interactive: Interactive::Untouched, error: Some(error) });
    assert_eq!(step(&[oi::STEP_ARG]), refused(StepError::Arguments));
    assert_eq!(step(&[oi::STEP_ARG, "msi", "relative.msi"]), refused(StepError::Arguments));
    // Security review L-2: whether OpenVPN was absent is no argument any more.
    assert_eq!(step(&[oi::STEP_ARG, "msi", GIT, "absent"]), refused(StepError::Arguments));
    // A signed file that is not the pinned MSI, and a missing one: never handed to msiexec.
    assert_eq!(step(&[oi::STEP_ARG, "msi", GIT]), refused(StepError::NotVerified));
    assert_eq!(step(&[oi::STEP_ARG, "msi", r"C:\nothing\here.msi"]), refused(StepError::NotVerified));
}

/// Security review L-3: a UNC path is refused before anything opens it (an open would log on to that machine with
/// the approving administrator's token). TEST-NET-1 never answers, so an attempt would also take seconds.
#[test]
fn the_elevated_step_never_opens_a_unc_path() {
    let refused = |error| Some(StepResult { msi: None, interactive: Interactive::Untouched, error: Some(error) });
    for mode in ["msi", "msi-official"] {
        for path in [r"\\192.0.2.1\s\OpenVPN-2.7.9-I001-amd64.msi", r"\\?\UNC\192.0.2.1\s\x.msi", r"C:x.msi"] {
            let started = std::time::Instant::now();
            assert_eq!(step(&[oi::STEP_ARG, mode, path]), refused(StepError::Arguments), "{mode} {path}");
            assert!(started.elapsed() < std::time::Duration::from_secs(1), "{path}: {:?}", started.elapsed());
        }
    }
}

/// A fresh folder in the temp folder, removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Temp {
        let dir = std::env::temp_dir().join(format!("WinVPN-test-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Temp(dir)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" }
}

/// The elevated step copying into `root` (a private folder of this user), with msiexec replaced: the parameters
/// it would have got (never run).
fn staged_step(args: &[&str], root: &Path) -> (Option<StepResult>, Vec<String>) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let calls = RefCell::new(Vec::new());
    let code = macvpn_platform_win::openvpn_elevated_step_staged_for_tests(&args, root, &|p| {
        calls.borrow_mut().push(p.to_string());
        None
    });
    (code.map(|c| StepResult::from_code(c).expect("a step code")), calls.into_inner())
}

/// What is left in `<root>\installer` (the step removes its copy whatever happened).
fn left_in(root: &Path) -> usize {
    std::fs::read_dir(root.join("installer")).map_or(0, |d| d.count())
}

/// Security review L-1: the copy lands in a new folder of its own (random name) with the folder's protection,
/// holds the bytes the source had when it was read, and outlives a re-pointed source (a junction in the source's
/// path changed afterwards changes nothing); the folder goes with the guard.
#[test]
fn the_msi_is_copied_into_a_new_folder_that_a_repointed_source_cannot_change() {
    let t = Temp::new("stage");
    let (a, b) = (t.0.join("a"), t.0.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let name = format!("OpenVPN-2.7.9-I001-{}.msi", arch());
    std::fs::write(a.join(&name), b"the real one").unwrap();
    std::fs::write(b.join(&name), b"the other one").unwrap();
    // `x` is a junction to `a`, so the source path is `x\<name>`. Recent Windows 11 builds refuse to follow a
    // junction a standard user made (Redirection Guard, ERROR_UNTRUSTED_MOUNT_POINT): then the source is changed in
    // place instead of re-pointed.
    let x = t.0.join("x");
    macvpn_winsys::file::create_dir(&x, None).unwrap();
    macvpn_winsys::file::make_junction_for_tests(&x, &format!(r"\??\{}", a.display())).unwrap();
    let through_junction = std::fs::read(x.join(&name)).is_ok();
    let source = if through_junction { x.join(&name) } else { a.join(&name) };
    let root = t.0.join("root");
    let (copy, guard) = macvpn_platform_win::stage_openvpn_msi_for_tests(&source, &root).unwrap();
    let dir = copy.parent().unwrap().to_path_buf();
    assert_eq!(dir.parent().unwrap(), root.join("installer"));
    let random = dir.file_name().unwrap().to_str().unwrap();
    assert!(random.len() == 32 && random.bytes().all(|c| c.is_ascii_hexdigit()), "{random}");
    assert_eq!(copy.file_name().unwrap().to_str(), Some(name.as_str()));
    // Re-pointed (or rewritten) after the copy: the copy keeps what was read.
    if through_junction {
        std::fs::remove_dir(&x).unwrap();
        macvpn_winsys::file::create_dir(&x, None).unwrap();
        macvpn_winsys::file::make_junction_for_tests(&x, &format!(r"\??\{}", b.display())).unwrap();
    } else {
        std::fs::write(&source, b"the other one").unwrap();
    }
    assert_eq!(std::fs::read(&source).unwrap(), b"the other one");
    assert_eq!(std::fs::read(&copy).unwrap(), b"the real one");
    // Private like its folder; held deny-write while the guard lives.
    let f = macvpn_winsys::file::open_metadata(&copy, false).unwrap();
    assert!(macvpn_winsys::file::has_protection(&f, macvpn_winsys::file::Protection::Private, false).unwrap());
    drop(f);
    assert!(std::fs::OpenOptions::new().write(true).open(&copy).is_err(), "held deny-write");
    // A second copy gets a folder of its own.
    let (copy2, guard2) = macvpn_platform_win::stage_openvpn_msi_for_tests(&a.join(&name), &root).unwrap();
    assert_ne!(copy2.parent(), copy.parent());
    drop((guard, guard2));
    assert!(!dir.exists() && !copy2.exists());
    assert_eq!(left_in(&root), 0);
    // A name that is not an MSI name, and an installer folder that is a junction: refused, nothing copied there.
    std::fs::write(a.join("x y.msi"), b"x").unwrap();
    assert!(macvpn_platform_win::stage_openvpn_msi_for_tests(&a.join("x y.msi"), &root).is_err());
    let root2 = t.0.join("root2");
    macvpn_winsys::file::create_dir(&root2, Some(macvpn_winsys::file::Protection::Private)).unwrap();
    let installer = root2.join("installer");
    macvpn_winsys::file::create_dir(&installer, Some(macvpn_winsys::file::Protection::Private)).unwrap();
    macvpn_winsys::file::make_junction_for_tests(&installer, &format!(r"\??\{}", b.display())).unwrap();
    assert!(macvpn_platform_win::stage_openvpn_msi_for_tests(&a.join(&name), &root2).is_err());
    assert_eq!(std::fs::read_dir(&b).unwrap().count(), 1, "nothing created through the junction");
    std::fs::remove_dir(&installer).unwrap();
}

/// A test MSI database that names OpenVPN (read back through the database API) but is not signed: refused on the
/// file the app named, before anything is copied, and msiexec is never called.
#[test]
fn a_test_msi_is_never_handed_to_msiexec() {
    let t = Temp::new("staged-step");
    let root = t.0.join("root");
    // An MSI database naming OpenVPN 2.7.9 of this machine, under an official name.
    let msi = t.0.join(format!("OpenVPN-2.7.9-I001-{}.msi", arch()));
    let code = oi::openvpn_upgrade_code(std::env::consts::ARCH).unwrap();
    let rows = [
        ("ProductName", "OpenVPN"),
        ("ProductVersion", "2.7.901"),
        ("Manufacturer", "OpenVPN, Inc."),
        ("UpgradeCode", code),
    ];
    // The rows are ASCII: any code page keeps them.
    macvpn_winsys::msi::create_for_tests(&msi, 1252, &rows).unwrap();
    let props = macvpn_winsys::msi::properties(&msi).unwrap();
    assert_eq!(
        oi::msi_properties_ok(&props, std::env::consts::ARCH, "2.7.8"),
        Some(macvpn_core::service_proto::Version(2, 7, 9))
    );
    for mode in ["msi", "msi-official"] {
        let (r, calls) = staged_step(&[oi::STEP_ARG, mode, msi.to_str().unwrap()], &root);
        let r = r.unwrap();
        assert_eq!(r.error, Some(StepError::NotVerified), "{mode}");
        assert_eq!((r.msi, calls.len()), (None, 0), "{mode}");
        assert_eq!(left_in(&root), 0, "{mode}");
    }
}

/// Optional, with OpenVPN's real MSIs (downloaded by hand, never installed: msiexec is replaced):
/// `WINVPN_TEST_OPENVPN_MSI` = the pinned OpenVPN-2.7.8-I001-<arch>.msi, `WINVPN_TEST_OPENVPN_MSI_OLD` = an older
/// signed one (OpenVPN-2.6.15-I001-<arch>.msi). The pinned MSI reaches msiexec as its copy in the installer folder,
/// never by the path the app named; the older one under a newer official name is refused by its database (security
/// review L-2), signed or not.
#[test]
fn real_openvpn_msis_are_installed_from_the_copy_and_judged_by_their_database() {
    let t = Temp::new("real-msi");
    let root = t.0.join("root");
    if let Some(pinned) = std::env::var_os("WINVPN_TEST_OPENVPN_MSI") {
        let source = t.0.join(format!("OpenVPN-2.7.8-I001-{}.msi", arch()));
        std::fs::copy(&pinned, &source).unwrap();
        let (r, calls) = staged_step(&[oi::STEP_ARG, "msi", source.to_str().unwrap()], &root);
        assert_eq!(r.unwrap().error, Some(StepError::NoMsiexec), "verified, then msiexec (replaced) did not start");
        assert_eq!(calls.len(), 1);
        let installer = root.join("installer");
        assert!(calls[0].starts_with(&format!(r#"/i "{}\"#, installer.display())), "{}", calls[0]);
        assert!(!calls[0].contains(&*t.0.join("OpenVPN").display().to_string()), "{}", calls[0]);
        assert_eq!(left_in(&root), 0, "the copy is deleted");
    } else {
        eprintln!("WINVPN_TEST_OPENVPN_MSI not set: the pinned MSI's run is skipped");
    }
    if let Some(old) = std::env::var_os("WINVPN_TEST_OPENVPN_MSI_OLD") {
        let renamed = t.0.join(format!("OpenVPN-2.7.9-I001-{}.msi", arch()));
        std::fs::copy(&old, &renamed).unwrap();
        let (r, calls) = staged_step(&[oi::STEP_ARG, "msi-official", renamed.to_str().unwrap()], &root);
        assert_eq!(r.unwrap().error, Some(StepError::NotOpenVpn));
        assert!(calls.is_empty());
        assert_eq!(left_in(&root), 0);
    } else {
        eprintln!("WINVPN_TEST_OPENVPN_MSI_OLD not set: the older MSI's refusal is skipped");
    }
}

#[test]
fn the_elevated_step_refuses_an_official_msi_without_the_signer_or_its_name() {
    let refused = |error| Some(StepResult { msi: None, interactive: Interactive::Untouched, error: Some(error) });
    assert_eq!(step(&[oi::STEP_ARG, "msi-official", "relative.msi"]), refused(StepError::Arguments));
    // A validly signed file under an official name (not OpenVPN Inc.'s), under another name, and a missing one:
    // never handed to msiexec.
    let dir = std::env::temp_dir().join(format!("WinVPN-test-official-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let named = dir.join(format!("OpenVPN-9.9.9-I001-{arch}.msi"));
    std::fs::copy(GIT, &named).unwrap();
    let other = dir.join("setup.msi");
    std::fs::copy(GIT, &other).unwrap();
    for path in [&named, &other, &dir.join(format!("OpenVPN-9.9.9-I002-{arch}.msi"))] {
        let p = path.to_str().unwrap();
        assert_eq!(step(&[oi::STEP_ARG, "msi-official", p]), refused(StepError::NotVerified), "{p}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A folder only this user and SYSTEM can open (as the app's `%LOCALAPPDATA%\WinVPN\downloads`), removed on drop.
fn private_temp(name: &str) -> Temp {
    let dir = std::env::temp_dir().join(format!("WinVPN-test-{name}-{}", uuid::Uuid::new_v4()));
    macvpn_winsys::file::create_dir(&dir, Some(Protection::Private)).unwrap();
    Temp(dir)
}

/// (Whether the file is [`Protection::Shared`] exactly, whether only its owner and SYSTEM may open it.)
fn protection_of(path: &Path) -> (bool, bool) {
    let f = std::fs::File::open(path).unwrap();
    (
        macvpn_winsys::file::has_protection(&f, Protection::Shared, false).unwrap(),
        macvpn_winsys::file::grants_only_owner_and_system(&f).unwrap(),
    )
}

/// 2.1.0's "The OpenVPN installer is not signed by OpenVPN Inc." on a standard user's account: the UAC prompt asks
/// for an administrator's credentials, the elevated step runs as that administrator, and the MSI the app left in
/// its private downloads folder (this user and SYSTEM only) could not even be opened by it. The app now hands the
/// MSI over readable by `BUILTIN\Users` (every interactive account), still changeable only by this user and
/// SYSTEM: here before any check, so a refused file is shared too and removed by the caller.
#[test]
fn the_downloaded_msi_is_readable_by_the_account_the_elevated_step_runs_as() {
    let t = private_temp("hand-over");
    let downloaded = t.0.join("download.part");
    std::fs::copy(GIT, &downloaded).unwrap();
    // As downloaded: inherited from the private folder, so another account (the elevating administrator) is
    // refused.
    assert_eq!(protection_of(&downloaded), (false, true));
    let msi = t.0.join(format!("OpenVPN-2.7.8-I001-{}.msi", arch()));
    let refused = l10n::with_language(AppLanguage::En, || {
        macvpn_platform_win::hand_over_openvpn_msi_for_tests(&downloaded, &msi).map(|_| ())
    });
    let mismatch =
        l10n::with_language(AppLanguage::En, || macvpn_core::update::UpdateError::ChecksumMismatch.message());
    assert_eq!(refused, Err(mismatch));
    assert!(!downloaded.exists());
    assert_eq!(protection_of(&msi), (true, false));
}

/// The step's own account may not open the file the app named (here: a file whose DACL leaves this standard user
/// out, as the downloads folder left out the elevating administrator): its own error and text, never "not signed
/// by OpenVPN Inc." (nothing was checked), and nothing reaches msiexec.
#[test]
fn a_source_the_elevated_step_may_not_open_is_not_called_unsigned() {
    let t = Temp::new("unreadable");
    let msi = t.0.join(format!("OpenVPN-2.7.8-I001-{}.msi", arch()));
    std::fs::copy(GIT, &msi).unwrap();
    let open = macvpn_winsys::file::Open {
        read: false,
        write: true,
        append: false,
        disposition: macvpn_winsys::file::Disposition::OpenExisting,
        protection: None,
        no_follow: true,
    };
    let f = macvpn_winsys::file::open(&msi, open).unwrap();
    macvpn_winsys::file::set_protection(&f, Protection::Admins, false).unwrap();
    drop(f);
    if std::fs::File::open(&msi).is_ok() {
        eprintln!("running as an administrator: the Administrators-only file is readable, nothing to check");
        return;
    }
    let root = t.0.join("root");
    let (r, calls) = staged_step(&[oi::STEP_ARG, "msi", msi.to_str().unwrap()], &root);
    let r = r.unwrap();
    assert_eq!(r.error, Some(StepError::NotReadable));
    assert_ne!(oi::after_step(&r), Err(oi::not_signed_by("OpenVPN Inc.")));
    assert!(calls.is_empty());
    assert_eq!(left_in(&root), 0);
}

/// With OpenVPN's real pinned MSI (`WINVPN_TEST_OPENVPN_MSI`, see above): the app's whole hand-over passes, the MSI
/// is readable by every interactive account, and the elevated step, with the app's deny-write handle still open,
/// checks it again and hands its copy to msiexec (replaced).
#[test]
fn the_real_pinned_msi_is_handed_over_and_installed_from_its_copy() {
    let Some(pinned) = std::env::var_os("WINVPN_TEST_OPENVPN_MSI") else {
        eprintln!("WINVPN_TEST_OPENVPN_MSI not set: skipped");
        return;
    };
    let t = private_temp("real-hand-over");
    let downloaded = t.0.join("download.part");
    std::fs::copy(&pinned, &downloaded).unwrap();
    let msi = t.0.join(format!("OpenVPN-2.7.8-I001-{}.msi", arch()));
    let held = macvpn_platform_win::hand_over_openvpn_msi_for_tests(&downloaded, &msi).unwrap();
    assert_eq!(protection_of(&msi), (true, false));
    let root = t.0.join("root");
    let (r, calls) = staged_step(&[oi::STEP_ARG, "msi", msi.to_str().unwrap()], &root);
    assert_eq!(r.unwrap().error, Some(StepError::NoMsiexec), "verified, then msiexec (replaced) did not start");
    assert_eq!(calls.len(), 1);
    drop(held);
}
