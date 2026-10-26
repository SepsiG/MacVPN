//! macvpn-winsys on a real Windows file system (Windows only; the crate is empty elsewhere).

#![cfg(windows)]

use macvpn_winsys::file::{self, Open, Protection};
use macvpn_winsys::{random, sid::Sid};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory under the user's temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "winsys-test-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_file(path: &Path, protection: Option<Protection>) -> fs::File {
    file::open(path, Open { protection, ..Open::create_new() }).unwrap()
}

#[test]
fn well_known_sids_have_their_string_form() {
    assert_eq!(Sid::local_system().to_string(), "S-1-5-18");
    assert_eq!(Sid::network().to_string(), "S-1-5-2");
    assert_eq!(Sid::builtin_users().to_string(), "S-1-5-32-545");
    assert_eq!(Sid::interactive().to_string(), "S-1-5-4");
    assert_eq!(Sid::builtin_administrators().to_string(), "S-1-5-32-544");
}

#[test]
fn sids_parse_from_their_string_form_and_sddl_aliases() {
    let me = Sid::current_user().unwrap();
    assert_eq!(Sid::parse(&me.to_string()).unwrap(), me);
    assert_eq!(Sid::parse("S-1-5-18").unwrap(), Sid::local_system());
    assert_eq!(Sid::parse("SY").unwrap(), Sid::local_system());
    assert_eq!(Sid::parse("BU").unwrap(), Sid::builtin_users());
    assert_eq!(Sid::parse("NU").unwrap(), Sid::network());
    assert_eq!(Sid::parse("BA").unwrap().to_string(), "S-1-5-32-544");
    assert_eq!(Sid::parse("AU").unwrap().to_string(), "S-1-5-11");
    assert_eq!(Sid::parse("WD").unwrap().to_string(), "S-1-1-0");
    // The machine-relative aliases: this machine's built-in Administrator (RID 500) and Guest (RID 501).
    let la = Sid::parse("LA").unwrap().to_string();
    assert!(la.starts_with("S-1-5-21-") && la.ends_with("-500"), "{la}");
    let lg = Sid::parse("LG").unwrap().to_string();
    assert_eq!(lg.strip_suffix("-501"), la.strip_suffix("-500"), "{lg} {la}");
    for bad in ["", "XX", "not a sid", "SY\0"] {
        assert!(Sid::parse(bad).is_err(), "{bad:?}");
    }
}

/// The elevation check agrees with the token's integrity level as `whoami` reports it: an elevated token is high
/// (S-1-16-12288) or system (S-1-16-16384); a standard user's is medium. (The test machine: a standard user; CI's
/// runner: an elevated administrator.)
#[test]
fn the_elevation_check_agrees_with_whoami() {
    let out = std::process::Command::new(r"C:\Windows\System32\whoami.exe").arg("/groups").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let high = text.contains("S-1-16-12288") || text.contains("S-1-16-16384");
    assert!(high || text.contains("S-1-16-8192"), "no integrity level: {text}");
    assert_eq!(macvpn_winsys::sid::this_process_is_elevated(), high, "{text}");
}

#[test]
fn the_current_user_is_a_user_sid() {
    let me = Sid::current_user().unwrap();
    let s = me.to_string();
    assert!(s.starts_with("S-1-5-21-") || s.starts_with("S-1-12-1-"), "{s}");
    assert_ne!(me, Sid::local_system());
    assert_eq!(me, Sid::current_user().unwrap());
}

#[test]
fn the_profile_list_has_the_current_users_profile_folder_expanded() {
    let me = Sid::current_user().unwrap().to_string();
    let profiles = macvpn_winsys::profiles::list().unwrap();
    let mine: Vec<_> = profiles.iter().filter(|p| p.key == me).collect();
    assert_eq!(mine.len(), 1, "{profiles:?}");
    let dir = mine[0].dir.to_str().unwrap();
    assert!(!dir.contains('%'), "{dir}");
    let home = std::env::var("USERPROFILE").unwrap();
    assert!(dir.eq_ignore_ascii_case(&home), "{dir} != {home}");
    // SYSTEM's profile is listed too (every machine has it).
    assert!(profiles.iter().any(|p| p.key == "S-1-5-18"), "{profiles:?}");
}

#[test]
fn randomness_fills_and_differs() {
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, [0u8; 64]);
    assert_ne!(a, b);
    random::fill(&mut []).unwrap();
}

#[test]
fn a_private_file_is_owned_by_the_user_and_readable_by_the_user_and_system_only() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("p"), Some(Protection::Private));
    let info = file::info(&f).unwrap();
    assert_eq!(info.owner, Sid::current_user().unwrap());
    assert_eq!(info.protection, Some(Protection::Private));
    assert_eq!(info.links, 1);
    assert_eq!(info.reparse_tag, None);
}

#[test]
fn a_shared_file_adds_read_for_users() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("s"), Some(Protection::Shared));
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Shared));
}

#[test]
fn an_inheriting_file_has_neither_shape() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("i"), None);
    assert_eq!(file::info(&f).unwrap().protection, None);
}

#[test]
fn create_new_refuses_an_existing_file() {
    let tmp = Scratch::new();
    let path = tmp.0.join("x");
    drop(new_file(&path, Some(Protection::Private)));
    let err = file::open(&path, Open { protection: Some(Protection::Private), ..Open::create_new() }).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn protection_can_be_changed_on_the_handle() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("c"), Some(Protection::Private));
    file::set_protection(&f, Protection::Shared, false).unwrap();
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Shared));
    file::set_protection(&f, Protection::Private, false).unwrap();
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Private));
}

#[test]
fn hard_links_and_identity() {
    let tmp = Scratch::new();
    let (a, b, c) = (tmp.0.join("a"), tmp.0.join("b"), tmp.0.join("c"));
    let mut fa = new_file(&a, None);
    fa.write_all(b"data").unwrap();
    drop(new_file(&c, None));
    fs::hard_link(&a, &b).unwrap();
    let ia = file::info(&fs::File::open(&a).unwrap()).unwrap();
    let ib = file::info(&fs::File::open(&b).unwrap()).unwrap();
    let ic = file::info(&fs::File::open(&c).unwrap()).unwrap();
    assert_eq!((ia.links, ib.links), (2, 2));
    assert_eq!((ia.volume, ia.id), (ib.volume, ib.id));
    assert_ne!(ia.id, ic.id);
}

#[test]
fn a_private_directory_passes_its_protection_to_new_files() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    file::create_dir(&dir, Some(Protection::Private)).unwrap();
    let handle = file::open_dir(&dir, false).unwrap();
    let info = file::info(&handle).unwrap();
    assert_eq!(info.protection, Some(Protection::Private));
    // A file created inside without its own descriptor (as SQLite creates its -wal file) gets only the inherited
    // user and SYSTEM entries: not "Private" by shape (not protected), but nobody else is in its DACL.
    let inner = new_file(&dir.join("inner"), None);
    assert!(file::grants_only_owner_and_system(&inner).unwrap());
}

#[test]
fn has_protection_names_the_shape_and_its_inheritance() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    file::create_dir(&dir, Some(Protection::Private)).unwrap();
    let d = file::open_metadata(&dir, false).unwrap();
    assert!(file::has_protection(&d, Protection::Private, true).unwrap());
    // A directory's entries are inheritable, a file's are not: each is checked as what it is.
    assert!(!file::has_protection(&d, Protection::Private, false).unwrap());
    assert!(!file::has_protection(&d, Protection::Admins, true).unwrap());
    assert!(!file::has_protection(&d, Protection::Shared, true).unwrap());
    let f = new_file(&tmp.0.join("f"), Some(Protection::Private));
    assert!(file::has_protection(&f, Protection::Private, false).unwrap());
    assert!(!file::has_protection(&f, Protection::Private, true).unwrap());
    // A directory with the temp folder's inherited permissions has no shape.
    let open = tmp.0.join("open");
    fs::create_dir(&open).unwrap();
    let o = file::open_metadata(&open, false).unwrap();
    for p in [Protection::Private, Protection::Shared, Protection::Admins] {
        assert!(!file::has_protection(&o, p, true).unwrap(), "{p:?}");
    }
}

#[test]
fn known_folders_are_absolute() {
    let pd = macvpn_winsys::known::program_data().unwrap();
    assert!(pd.is_absolute(), "{}", pd.display());
    assert!(pd.join("Microsoft").is_dir() || pd.is_dir(), "{}", pd.display());
    let system32 = macvpn_winsys::known::system32().unwrap();
    assert!(system32.join("curl.exe").is_file(), "{}", system32.display());
    let windows = macvpn_winsys::known::windows_dir().unwrap();
    assert_eq!(system32.parent(), Some(windows.as_path()));
}

#[test]
fn a_junction_is_seen_as_a_name_surrogate_reparse_point() {
    let tmp = Scratch::new();
    let target = tmp.0.join("target");
    fs::create_dir(&target).unwrap();
    let link = tmp.0.join("link");
    let status =
        std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&target).status().unwrap();
    assert!(status.success());
    let handle = file::open_dir(&link, false).unwrap();
    let tag = file::info(&handle).unwrap().reparse_tag.expect("a reparse point");
    assert!(file::is_name_surrogate(tag));
    // Following reaches the target, or Windows refuses to traverse a junction a standard user created
    // (ERROR_UNTRUSTED_MOUNT_POINT, Redirection Guard on recent Windows 11 builds); never the junction itself.
    match file::open_dir(&link, true) {
        Ok(followed) => assert_eq!(file::info(&followed).unwrap().reparse_tag, None),
        Err(e) => assert_eq!(e.raw_os_error(), Some(ERROR_UNTRUSTED_MOUNT_POINT), "{e}"),
    }
}

/// `reparse_tag_at` reads the name itself: a junction's tag, nothing for a plain directory or file, `NotFound` for
/// a missing name.
#[test]
fn reparse_tag_at_reads_the_name_itself() {
    let tmp = Scratch::new();
    let target = tmp.0.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("f"), b"x").unwrap();
    let link = tmp.0.join("link");
    let status =
        std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&link).arg(&target).status().unwrap();
    assert!(status.success());
    assert!(file::reparse_tag_at(&link).unwrap().is_some_and(file::is_name_surrogate));
    assert_eq!(file::reparse_tag_at(&target).unwrap(), None);
    assert_eq!(file::reparse_tag_at(&target.join("f")).unwrap(), None);
    assert_eq!(file::reparse_tag_at(&tmp.0.join("missing")).unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

/// winerror.h.
const ERROR_UNTRUSTED_MOUNT_POINT: i32 = 448;

#[test]
fn reparse_tag_classes() {
    assert!(file::is_name_surrogate(0xA000_000C)); // IO_REPARSE_TAG_SYMLINK
    assert!(file::is_name_surrogate(0xA000_0003)); // IO_REPARSE_TAG_MOUNT_POINT (junction)
    assert!(!file::is_name_surrogate(0x9000_601A)); // a Cloud Files placeholder (OneDrive)
    assert!(!file::is_name_surrogate(0x8000_0013)); // IO_REPARSE_TAG_DEDUP
}

#[test]
fn cloud_file_errors_are_unavailable() {
    // ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING, _NETWORK_UNAVAILABLE, _UNSUCCESSFUL, _IN_USE, _PROVIDER_TERMINATED,
    // _REQUEST_TIMEOUT (winerror.h).
    for code in [362, 388, 389, 391, 404, 426] {
        assert!(file::is_cloud_unavailable(code), "{code}");
    }
    // ERROR_ACCESS_DENIED, ERROR_CLOUD_FILE_ACCESS_DENIED (a refusal, not an outage), ERROR_UNTRUSTED_MOUNT_POINT.
    for code in [0, 5, 395, ERROR_UNTRUSTED_MOUNT_POINT] {
        assert!(!file::is_cloud_unavailable(code), "{code}");
    }
}

/// A private mutex is created with this user as its owner; opening it again reports that owner. A name nobody
/// holds any more is created anew.
#[test]
fn a_private_mutex_records_its_owner() {
    let mut nonce = [0u8; 8];
    random::fill(&mut nonce).unwrap();
    let name = format!(r"Local\winsys-test-mutex-{}-{}", std::process::id(), u64::from_le_bytes(nonce));
    let first = macvpn_winsys::mutex::create_private(&name).unwrap();
    assert_eq!(first.existing_owner, None);
    let second = macvpn_winsys::mutex::create_private(&name).unwrap();
    assert_eq!(second.existing_owner, Some(Sid::current_user().unwrap()));
    drop((first, second));
    assert_eq!(macvpn_winsys::mutex::create_private(&name).unwrap().existing_owner, None);
    assert_eq!(
        macvpn_winsys::mutex::create_private("Local\\a\0b").err().map(|e| e.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
}

#[test]
fn a_service_s_start_type_and_state_are_read_by_a_standard_user() {
    use macvpn_winsys::scm;
    // The Windows Event Log: automatic and running on every Windows.
    let s = scm::query("EventLog").unwrap();
    assert_eq!((s.start_type, s.current_state), (2, 4), "{s:?}");
    assert!(!s.is_disabled_and_stopped());
    assert!(
        scm::ServiceState { start_type: scm::START_DISABLED, current_state: scm::STATE_STOPPED }
            .is_disabled_and_stopped()
    );
    // A service that does not exist (never a real one: this test may run as an administrator in CI).
    let mut id = [0u8; 8];
    random::fill(&mut id).unwrap();
    let name = format!("WinVPN-test-{}", id.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert_eq!(scm::query(&name).unwrap_err().raw_os_error(), Some(1060), "ERROR_SERVICE_DOES_NOT_EXIST");
    let e = scm::disable_and_stop(&name, std::time::Duration::from_secs(1)).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(1060));
}
