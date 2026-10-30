#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use macvpn_core::deb_update::{StepArgs, StepError};
use macvpn_core::update::{SignatureDomain, UpdateSignature};
use macvpn_helper::linux::install_update::{self as step, Env, run};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const VERSION: &str = "2.1.0";
const ASSET: &str = "linvpn_2.1.0_amd64.deb";
const FIELDS: &str = "Package: linvpn\nVersion: 2.1.0\nArchitecture: amd64\n";

type AptCalls = Rc<RefCell<Vec<(PathBuf, Vec<u8>)>>>;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// A private folder of this user with the package `content` and a signature over `signed` (default: `content`).
fn case(content: &[u8], signed: Option<&[u8]>) -> (PathBuf, StepArgs) {
    let dir = std::env::temp_dir().join(format!("linvpn-step-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let deb = dir.join(ASSET);
    std::fs::write(&deb, content).unwrap();
    let sha: String = Sha256::digest(signed.unwrap_or(content)).iter().map(|b| format!("{b:02x}")).collect();
    let message = UpdateSignature::message_for(SignatureDomain::LinVpnV1, ASSET, VERSION, &sha).unwrap();
    let sig = dir.join(format!("{ASSET}.sig"));
    std::fs::write(&sig, macvpn_core::swift_base64::encode(&key().sign(&message).to_bytes()) + "\n").unwrap();
    let args = StepArgs { deb, sig, version: VERSION.into(), asset: ASSET.into() };
    (dir, args)
}

fn env(
    dir: &Path,
    fields: impl Fn(&Path) -> Option<String> + 'static,
    installed: Result<Option<&'static str>, StepError>,
    apt: AptCalls,
) -> Env {
    Env {
        caller_uid: std::fs::metadata(dir).unwrap().uid(),
        staging: dir.join("staging"),
        keys: vec![key().verifying_key().to_bytes()],
        dpkg_arch: Box::new(|| Some("amd64".into())),
        fields: Box::new(fields),
        installed: Box::new(move || installed.map(|v| v.map(String::from))),
        apt_install: Box::new(move |deb| {
            apt.borrow_mut().push((deb.to_path_buf(), std::fs::read(deb).unwrap()));
            true
        }),
    }
}

fn fixed(text: &'static str) -> impl Fn(&Path) -> Option<String> {
    move |_| Some(text.to_string())
}

#[test]
fn a_good_package_is_installed_from_roots_copy() {
    let (dir, args) = case(b"package A", None);
    let apt = AptCalls::default();
    assert_eq!(run(&args, &env(&dir, fixed(FIELDS), Ok(Some("2.0.5")), apt.clone())), Ok(()));
    let calls = apt.borrow();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].0.starts_with(dir.join("staging")), "{}", calls[0].0.display());
    assert_ne!(calls[0].0, args.deb);
    assert_eq!(calls[0].1, b"package A");
    assert_eq!(std::fs::read_dir(dir.join("staging")).unwrap().count(), 0, "the copy is removed");
}

#[test]
fn a_bad_signature_installs_nothing() {
    let (dir, args) = case(b"package A", Some(b"another package"));
    let apt = AptCalls::default();
    assert_eq!(run(&args, &env(&dir, fixed(FIELDS), Ok(None), apt.clone())), Err(StepError::BadSignature));
    assert!(apt.borrow().is_empty());
}

#[test]
fn a_file_swapped_after_the_check_is_not_installed() {
    let (dir, args) = case(b"package A", None);
    let apt = AptCalls::default();
    let user_file = args.deb.clone();
    // The swap happens after the copy and the signature check (when the fields are read): too late.
    let swapping = move |_: &Path| {
        std::fs::write(&user_file, b"package B").unwrap();
        Some(FIELDS.to_string())
    };
    assert_eq!(run(&args, &env(&dir, swapping, Ok(Some("2.0.5")), apt.clone())), Ok(()));
    assert_eq!(apt.borrow()[0].1, b"package A");
}

#[test]
fn wrong_package_architecture_version_or_older_are_refused() {
    for (fields, installed, expected) in [
        ("Package: evil\nVersion: 2.1.0\nArchitecture: amd64\n", Ok(Some("2.0.5")), StepError::WrongPackage),
        ("Package: linvpn\nVersion: 2.1.0\nArchitecture: arm64\n", Ok(Some("2.0.5")), StepError::WrongArchitecture),
        ("Package: linvpn\nVersion: 2.1.1\nArchitecture: amd64\n", Ok(Some("2.0.5")), StepError::WrongVersion),
        (FIELDS, Ok(Some("2.1.0")), StepError::NotNewer),
        (FIELDS, Ok(Some("2.2.0")), StepError::NotNewer),
    ] {
        let (dir, args) = case(b"package A", None);
        let apt = AptCalls::default();
        assert_eq!(run(&args, &env(&dir, fixed(fields), installed, apt.clone())), Err(expected), "{fields}");
        assert!(apt.borrow().is_empty());
    }
}

#[test]
fn the_other_architectures_asset_is_refused_before_any_file_is_opened() {
    let (dir, mut args) = case(b"package A", None);
    args.asset = "linvpn_2.1.0_arm64.deb".into();
    let apt = AptCalls::default();
    assert_eq!(run(&args, &env(&dir, fixed(FIELDS), Ok(None), apt.clone())), Err(StepError::WrongArchitecture));
}

#[test]
fn a_symlink_or_an_open_folder_is_refused() {
    let (dir, args) = case(b"package A", None);
    let real = dir.join("real.deb");
    std::fs::rename(&args.deb, &real).unwrap();
    std::os::unix::fs::symlink(&real, &args.deb).unwrap();
    let apt = AptCalls::default();
    assert_eq!(run(&args, &env(&dir, fixed(FIELDS), Ok(None), apt.clone())), Err(StepError::UnsafeFile));

    let (dir, args) = case(b"package A", None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(run(&args, &env(&dir, fixed(FIELDS), Ok(None), apt.clone())), Err(StepError::UnsafeFile));
    assert!(apt.borrow().is_empty());
}

/// LA-2: "no downgrade" fails closed. A failing `dpkg-query` is `ToolFailed`; `linvpn` reported as not installed is
/// `NotInstalled` (the step ships inside it). Neither installs anything.
#[test]
fn an_unknown_installed_version_installs_nothing() {
    for (installed, expected) in
        [(Err(StepError::ToolFailed), StepError::ToolFailed), (Ok(None), StepError::NotInstalled)]
    {
        let (dir, args) = case(b"package A", None);
        let apt = AptCalls::default();
        assert_eq!(run(&args, &env(&dir, fixed(FIELDS), installed, apt.clone())), Err(expected));
        assert!(apt.borrow().is_empty());
        assert_eq!(std::fs::read_dir(dir.join("staging")).unwrap().count(), 0, "the copy is removed");
    }
}

/// LA-1: the caller's files are read through a limit, so one that keeps growing after the size check (`fstat` at
/// open) cannot fill /var or root's memory.
#[test]
fn an_endless_package_is_cut_off_at_the_limit() {
    let dir = std::env::temp_dir().join(format!("linvpn-step-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let out_path = dir.join("copy");
    let mut out = std::fs::File::create(&out_path).unwrap();
    let endless = std::io::repeat(b'x');
    assert_eq!(step::copy_hashed(endless, &mut out, 1 << 16).err(), Some(StepError::UnsafeFile));
    assert!(std::fs::metadata(&out_path).unwrap().len() <= 1 << 16, "never more than the limit");

    let mut out = std::fs::File::create(&out_path).unwrap();
    let sha = step::copy_hashed(&[7u8; 100][..], &mut out, 100).unwrap();
    let expected: String = Sha256::digest([7u8; 100]).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(sha, expected, "exactly the limit passes");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_endless_signature_is_cut_off_at_the_limit() {
    assert_eq!(step::read_signature(std::io::repeat(b'A')), Err(StepError::BadSignature));
    let limit = UpdateSignature::MAX_SIGNATURE_FILE_SIZE;
    assert_eq!(step::read_signature(&vec![b'A'; limit + 1][..]), Err(StepError::BadSignature));
    assert_eq!(step::read_signature(&vec![b'A'; limit][..]), Ok("A".repeat(limit)));
}

/// LA-7: before any tool runs, the step sets its own umask (022) and resource limits instead of the caller's.
#[test]
#[allow(unsafe_code)]
fn the_step_sets_its_own_umask_and_limits() {
    // SAFETY: `umask` takes a mode and cannot fail; `getrlimit` writes into the struct it is given.
    let before = unsafe { libc::umask(0o077) };
    step::harden_process();
    let now = unsafe { libc::umask(before) };
    assert_eq!(now, 0o022);
    let mut core = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) }, 0);
    assert_eq!(core.rlim_cur, 0, "no core dump of root's memory");
    let mut fsize = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut fsize) }, 0);
    assert_eq!(fsize.rlim_cur, libc::RLIM_INFINITY);
    let mut nofile = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut nofile) }, 0);
    assert!(nofile.rlim_cur >= 1024, "{}", nofile.rlim_cur);
}

#[test]
fn a_fifo_in_place_of_the_package_is_refused_without_blocking() {
    let (dir, args) = case(b"package A", None);
    std::fs::remove_file(&args.deb).unwrap();
    let c = std::ffi::CString::new(args.deb.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid C string; mkfifo only creates the node.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let dir2 = dir.clone();
    std::thread::spawn(move || {
        let apt = AptCalls::default();
        let r = run(&args, &env(&dir2, fixed(FIELDS), Ok(None), apt.clone()));
        let _ = tx.send((r, apt.borrow().is_empty()));
    });
    let (r, nothing) = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the open of a FIFO never blocks");
    assert_eq!(r, Err(StepError::UnsafeFile));
    assert!(nothing);
}
