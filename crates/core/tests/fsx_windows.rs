//! `macvpn_core::fsx` on Windows: the counterparts of `tests/fsx.rs`'s Unix assertions.

#![cfg(windows)]

use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let dir = std::env::temp_dir().join(format!("fsx-win-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn junction(link: &Path, target: &Path) {
    assert!(Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).status().unwrap().success());
}

fn me() -> FileOwner {
    FileOwner::current_user().unwrap()
}

#[test]
fn create_new_private_is_owned_by_me_and_private() {
    let tmp = Scratch::new();
    let path = tmp.0.join("p");
    let file = fsx::create_new(&path, Access::Private).unwrap();
    let stat = fsx::stat(&file).unwrap();
    assert!(fsx::has_access(&stat, Access::Private));
    assert!(!fsx::has_access(&stat, Access::Shared));
    assert_eq!(fsx::owner(&stat).unwrap(), me());
    let by_path = fsx::stat_path(&path, Follow::No).unwrap();
    assert!(fsx::has_access(&by_path, Access::Private));
}

#[test]
fn set_access_switches_between_the_shapes() {
    let tmp = Scratch::new();
    let file = fsx::create_new(&tmp.0.join("s"), Access::Private).unwrap();
    fsx::set_access(&file, Access::Shared).unwrap();
    assert!(fsx::has_access(&fsx::stat(&file).unwrap(), Access::Shared));
    fsx::set_access(&file, Access::Private).unwrap();
    assert!(fsx::has_access(&fsx::stat(&file).unwrap(), Access::Private));
}

#[test]
fn a_plain_file_has_neither_shape() {
    let tmp = Scratch::new();
    let path = tmp.0.join("plain");
    fs::write(&path, b"x").unwrap();
    let stat = fsx::stat_path(&path, Follow::No).unwrap();
    assert!(!fsx::has_access(&stat, Access::Private));
    assert!(!fsx::has_access(&stat, Access::Shared));
}

#[test]
fn create_private_dir_all_makes_every_level_private() {
    let tmp = Scratch::new();
    let leaf = tmp.0.join("a").join("b").join("c");
    fsx::create_private_dir_all(&leaf).unwrap();
    for dir in [tmp.0.join("a"), tmp.0.join("a").join("b"), leaf.clone()] {
        assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private), "{dir:?}");
    }
}

#[test]
fn ensure_private_dir_tightens_and_returns_the_owner() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    fs::create_dir(&dir).unwrap(); // inherited permissions
    assert!(!fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private));
    assert_eq!(fsx::ensure_private_dir(&dir).unwrap(), me());
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private));
}

#[test]
fn ensure_private_dir_refuses_a_junction_and_a_file() {
    let tmp = Scratch::new();
    let real = tmp.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.0.join("link");
    junction(&link, &real);
    assert_eq!(fsx::ensure_private_dir(&link).unwrap_err().kind(), ErrorKind::NotADirectory);
    let file = tmp.0.join("file");
    fs::write(&file, b"x").unwrap();
    assert_eq!(fsx::ensure_private_dir(&file).unwrap_err().kind(), ErrorKind::NotADirectory);
}

#[test]
fn files_sqlite_creates_inside_a_private_dir_inherit_user_and_system_only() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("vault");
    fsx::ensure_private_dir(&dir).unwrap();
    fs::write(dir.join("vault.db-wal"), b"x").unwrap();
    let handle = fs::File::open(dir.join("vault.db-wal")).unwrap();
    assert!(macvpn_winsys::file::grants_only_owner_and_system(&handle).unwrap());
}

#[test]
fn open_regular_refuses_a_directory_and_a_symlink() {
    let tmp = Scratch::new();
    let err = fsx::open_regular(&tmp.0, OpenFor::Read, Follow::No, false).unwrap_err();
    assert!(fsx::is_not_regular_file(&err), "{err:?}");
    let target = tmp.0.join("t");
    fs::write(&target, b"x").unwrap();
    let link = tmp.0.join("l");
    match std::os::windows::fs::symlink_file(&target, &link) {
        // ERROR_PRIVILEGE_NOT_HELD: symlinks need Developer Mode or an administrator.
        Err(e) if e.raw_os_error() == Some(1314) => eprintln!("skipped: no symlink privilege"),
        Err(e) => panic!("{e}"),
        Ok(()) => {
            let err = fsx::open_regular(&link, OpenFor::Read, Follow::No, false).unwrap_err();
            assert!(fsx::is_symlink_refused(&err), "{err:?}");
            assert!(fsx::open_regular(&link, OpenFor::Read, Follow::Yes, false).is_ok());
        }
    }
}

#[test]
fn hard_links_and_file_ids_are_real() {
    let tmp = Scratch::new();
    let (a, b, c) = (tmp.0.join("a"), tmp.0.join("b"), tmp.0.join("c"));
    fsx::create_new(&a, Access::Private).unwrap().write_all(b"a").unwrap();
    fs::write(&c, b"c").unwrap();
    let (_, single) = fsx::open_regular(&a, OpenFor::Read, Follow::No, false).unwrap();
    assert_eq!(fsx::hard_links(&single), 1);
    fs::hard_link(&a, &b).unwrap();
    let (_, shared) = fsx::open_regular(&a, OpenFor::Read, Follow::No, false).unwrap();
    assert_eq!(fsx::hard_links(&shared), 2);
    let id = |p: &Path| fsx::file_id(&fsx::stat_path(p, Follow::No).unwrap()).unwrap();
    assert_eq!(id(&a), id(&b));
    assert_ne!(id(&a), id(&c));
}

#[test]
fn atomic_write_private_leaves_a_private_file() {
    let tmp = Scratch::new();
    let path = tmp.0.join("x.json");
    fsx::atomic_write(&path, b"{}", Access::Private).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{}");
    assert!(fsx::has_access(&fsx::stat_path(&path, Follow::No).unwrap(), Access::Private));
    fsx::atomic_write(&path, b"{\"a\":1}", Access::Private).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"a\":1}");
}

#[test]
fn open_append_creates_private_and_refuses_a_junction_target() {
    let tmp = Scratch::new();
    let path = tmp.0.join("audit.log");
    let mut f = fsx::open_append(&path, Access::Private).unwrap();
    f.write_all(b"one\n").unwrap();
    assert!(fsx::has_access(&fsx::stat(&f).unwrap(), Access::Private));
}

/// The DACL of `path` in SDDL, as `icacls /save` writes it (UTF-16): an independent reading of the ACL.
fn sddl(path: &Path) -> String {
    let out = std::env::temp_dir().join(format!("fsx-win-acl-{}.txt", uuid::Uuid::new_v4()));
    let status = Command::new("icacls").arg(path).arg("/save").arg(&out).arg("/Q").status().unwrap();
    assert!(status.success(), "icacls /save {path:?}");
    let bytes = fs::read(&out).unwrap();
    fs::remove_file(&out).unwrap();
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
    let text = String::from_utf16(&units).unwrap();
    text.lines().find(|l| l.contains("D:")).unwrap_or_else(|| panic!("no DACL in {text:?}")).trim().to_string()
}

/// `icacls` says: a protected DACL with exactly two ACEs, full access for this user and for SYSTEM (inheritable
/// to files and subdirectories for a directory), nothing inherited, nobody else.
fn assert_icacls_private(path: &Path, dir: bool) {
    let sddl = sddl(path);
    eprintln!("{}: {sddl}", path.display());
    let me = macvpn_winsys::sid::Sid::current_user().unwrap();
    if let Err(e) = check_private_dacl(&sddl, &me, dir) {
        panic!("{e}");
    }
}

/// The check behind [`assert_icacls_private`], on the SDDL text. SDDL writes a well-known account as its alias
/// rather than its SID (`SY` for S-1-5-18; `LA` for this machine's built-in Administrator, RID 500, the user on a
/// CI runner), so each ACE's account is read back to its SID (`Sid::parse`, the system's own SDDL reading) before
/// the ACEs are compared; everything else in an ACE is compared as written.
fn check_private_dacl(sddl: &str, me: &macvpn_winsys::sid::Sid, dir: bool) -> Result<(), String> {
    use macvpn_winsys::sid::Sid;
    let dacl = &sddl[sddl.find("D:").ok_or_else(|| format!("no DACL: {sddl}"))? + 2..];
    let dacl = dacl.find("S:").map_or(dacl, |i| &dacl[..i]);
    let open = dacl.find('(').ok_or_else(|| format!("no ACE: {sddl}"))?;
    let (flags, aces) = dacl.split_at(open);
    if !flags.contains('P') {
        return Err(format!("not protected: {sddl}"));
    }
    let mut aces = aces
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split(")(")
        .map(|ace| {
            // type;flags;rights;object;inherited object;account
            let (head, account) = ace.rsplit_once(';').ok_or_else(|| format!("not an ACE: {ace:?} in {sddl}"))?;
            let sid = Sid::parse(account).map_err(|e| format!("account {account:?} in {sddl}: {e}"))?;
            Ok(format!("{head};{sid}"))
        })
        .collect::<Result<Vec<String>, String>>()?;
    aces.sort_unstable();
    let inherit = if dir { "OICI" } else { "" };
    let mut expected = vec![format!("A;{inherit};FA;;;{}", Sid::local_system()), format!("A;{inherit};FA;;;{me}")];
    expected.sort_unstable();
    if aces != expected {
        return Err(format!("{sddl}: ACEs {aces:?}, expected {expected:?}"));
    }
    Ok(())
}

#[test]
fn the_private_dacl_check_reads_sddl_aliases_and_stays_strict() {
    use macvpn_winsys::sid::Sid;
    // What icacls wrote on the CI runner, whose user is the built-in Administrator.
    let admin = Sid::parse("LA").unwrap();
    assert_eq!(check_private_dacl("D:P(A;;FA;;;LA)(A;;FA;;;SY)", &admin, false), Ok(()));
    assert_eq!(check_private_dacl(&format!("D:P(A;;FA;;;{admin})(A;;FA;;;S-1-5-18)"), &admin, false), Ok(()));
    assert_eq!(check_private_dacl("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LA)", &admin, true), Ok(()));
    // This user, by SID, as icacls writes any user without an alias.
    let me = Sid::current_user().unwrap();
    assert_eq!(check_private_dacl(&format!("D:P(A;;FA;;;{me})(A;;FA;;;SY)"), &me, false), Ok(()));
    // Still strict: another user (not the Administrator, whoever runs the test), a third ACE, a missing ACE, not protected, the wrong inheritance or rights.
    let other = Sid::parse("S-1-5-21-1-2-3-1001").unwrap();
    let strict = [
        ("D:P(A;;FA;;;LA)(A;;FA;;;SY)", &other, false),
        ("D:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FR;;;BU)", &admin, false),
        ("D:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FA;;;LA)", &admin, false),
        ("D:P(A;;FA;;;LA)", &admin, false),
        ("D:(A;;FA;;;LA)(A;;FA;;;SY)", &admin, false),
        ("D:P(A;;FA;;;LA)(A;;FA;;;SY)", &admin, true),
        ("D:P(A;;FR;;;LA)(A;;FA;;;SY)", &admin, false),
        ("D:P(A;ID;FA;;;LA)(A;;FA;;;SY)", &admin, false),
        ("D:P(A;;FA;;;BA)(A;;FA;;;SY)", &admin, false),
        ("D:P(A;;FA;;;LA)(A;;FA;;;XX)", &admin, false),
        ("O:LA", &admin, false),
    ];
    for (sddl, user, dir) in strict {
        assert!(check_private_dacl(sddl, user, dir).is_err(), "{sddl} for {user} (dir {dir})");
    }
}

#[test]
fn icacls_confirms_private_files_and_directories() {
    let tmp = Scratch::new();
    let file = tmp.0.join("f");
    drop(fsx::create_new(&file, Access::Private).unwrap());
    assert_icacls_private(&file, false);
    let dir = tmp.0.join("d");
    fsx::ensure_private_dir(&dir).unwrap();
    assert_icacls_private(&dir, true);
    let tightened = tmp.0.join("t");
    fs::create_dir(&tightened).unwrap();
    fsx::ensure_private_dir(&tightened).unwrap();
    assert_icacls_private(&tightened, true);
    let all = tmp.0.join("a").join("b");
    fsx::create_private_dir_all(&all).unwrap();
    assert_icacls_private(&tmp.0.join("a"), true);
    assert_icacls_private(&all, true);
    let written = tmp.0.join("w.json");
    fsx::atomic_write(&written, b"{}", Access::Private).unwrap();
    assert_icacls_private(&written, false);
    let switched = tmp.0.join("switched");
    let file = fsx::create_new(&switched, Access::Shared).unwrap();
    fsx::set_access(&file, Access::Private).unwrap();
    assert_icacls_private(&switched, false);
    let appended = tmp.0.join("audit.log");
    drop(fsx::open_append(&appended, Access::Private).unwrap());
    assert_icacls_private(&appended, false);
}

#[test]
fn a_private_file_is_owned_by_me_by_the_handle_and_by_the_path() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    assert_eq!(fsx::ensure_private_dir(&dir).unwrap(), me());
    assert_eq!(fsx::owner(&fsx::stat_path(&dir, Follow::No).unwrap()).unwrap(), me());
    assert_eq!(fsx::owner(&fsx::stat_path(&tmp.0, Follow::No).unwrap()).unwrap(), me());
}

#[test]
fn junctions_are_refused_without_follow() {
    let tmp = Scratch::new();
    let real = tmp.0.join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("f"), b"x").unwrap();
    let link = tmp.0.join("link");
    junction(&link, &real);
    // The junction itself: no access shape, its own identity.
    let stat = fsx::stat_path(&link, Follow::No).unwrap();
    assert!(!fsx::has_access(&stat, Access::Private));
    assert!(!fsx::has_access(&stat, Access::Shared));
    assert_ne!(fsx::file_id(&stat), fsx::file_id(&fsx::stat_path(&real, Follow::No).unwrap()));
    let err = fsx::open_regular(&link, OpenFor::Read, Follow::No, false).unwrap_err();
    assert!(fsx::is_symlink_refused(&err), "{err:?}");
    assert!(fsx::open_append(&link, Access::Private).is_err());
    assert!(fsx::create_new(&link, Access::Private).is_err());
}

#[test]
fn a_system_file_is_neither_private_nor_mine() {
    // A file in a system directory (owned by TrustedInstaller): readable metadata, not ours.
    let system = Path::new(r"C:\Windows\System32\notepad.exe");
    if let Ok(stat) = fsx::stat_path(system, Follow::No) {
        assert!(!fsx::has_access(&stat, Access::Private));
        assert_ne!(fsx::owner(&stat).ok(), Some(me()));
    }
}
