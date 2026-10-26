//! `C:\ProgramData\WinVPN` (spec 4.1): `run\<ID>\` and `logs\`. Any user may create folders in ProgramData, so an
//! existing `WinVPN` is used only if it is a real directory (no reparse point) owned by SYSTEM or Administrators
//! whose protected DACL grants exactly SYSTEM and Administrators full access, inherited by what is created inside;
//! anything else is not repaired (it may hold planted links): the service runs degraded with the localized reason.
//! `run` and `logs` are checked the same way. Names inside come only from canonical UUIDs.

use crate::shared::cli;
use crate::shared::l10n::tr;
use macvpn_winsys::file::{self, Open, Protection};
use macvpn_winsys::sid::Sid;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY;

#[derive(Debug)]
pub struct DataDir {
    pub root: PathBuf,
    pub run: PathBuf,
    pub logs: PathBuf,
    /// The protection of every directory and file the service creates here.
    pub protection: Protection,
    /// Who may own a directory here (SYSTEM and Administrators; the console's user in the tests).
    pub owners: Vec<Sid>,
}

pub fn unsafe_message(root: &Path) -> String {
    tr(
        "The folder %@ has unsafe permissions. An administrator must delete it, then restart the WinVPN Service.",
        &[&root.display().to_string()],
    )
}

/// The production directory, as SYSTEM.
pub fn open_service() -> Result<DataDir, String> {
    let root = macvpn_winsys::known::program_data()
        .map(|p| p.join("WinVPN"))
        .map_err(|_| unsafe_message(Path::new(r"C:\ProgramData\WinVPN")))?;
    open_at(&root, Protection::Admins, &[Sid::local_system(), Sid::builtin_administrators()])
}

/// `root` with `protection`, created when missing; every level checked (a real directory, the owner one of
/// `owners`, exactly `protection`'s DACL). The first level that fails stops: nothing is created inside a folder
/// that is not in order. Leftover run directories of an earlier run are removed.
pub fn open_at(root: &Path, protection: Protection, owners: &[Sid]) -> Result<DataDir, String> {
    for dir in [root.to_path_buf(), root.join("run"), root.join("logs")] {
        ensure_dir(&dir, protection, owners).map_err(|_| unsafe_message(root))?;
    }
    let d = DataDir {
        root: root.to_path_buf(),
        run: root.join("run"),
        logs: root.join("logs"),
        protection,
        owners: owners.to_vec(),
    };
    d.sweep_runs();
    Ok(d)
}

fn ensure_dir(dir: &Path, protection: Protection, owners: &[Sid]) -> io::Result<()> {
    match file::open_metadata(dir, false) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => match file::create_dir(dir, Some(protection)) {
            // Created by someone else in between: checked below like any existing folder.
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        },
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    if is_safe_dir(dir, protection, owners)? {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe data directory"))
    }
}

/// `dir` itself (never a link's target) is a directory, not a reparse point, owned by one of `owners`, with exactly
/// `protection` (inheritable).
fn is_safe_dir(dir: &Path, protection: Protection, owners: &[Sid]) -> io::Result<bool> {
    let f = file::open_metadata(dir, false)?;
    let info = file::info(&f)?;
    Ok(info.reparse_tag.is_none()
        && info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        && owners.contains(&info.owner)
        && file::has_protection(&f, protection, true)?)
}

impl DataDir {
    /// `engines\<name>` (2b plan, "As built (fix4)": the service's engine downloads), created when missing and
    /// checked at every call like the root (a real directory, the owner one of `owners`, exactly the protection;
    /// `engines` too). `name` is one of the service's fixed names.
    pub fn engine_dir(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an engine name"));
        }
        let engines = self.root.join("engines");
        let dir = engines.join(name);
        for d in [&self.root, &engines, &dir] {
            ensure_dir(d, self.protection, &self.owners)?;
        }
        Ok(dir)
    }

    /// `path` is a plain file the service made here: no reparse point, not a directory, the owner one of `owners`,
    /// exactly the directory's protection (not inherited: a file made by another program, curl's output, fails).
    pub fn is_own_file(&self, path: &Path) -> io::Result<bool> {
        let f = file::open_metadata(path, false)?;
        let info = file::info(&f)?;
        Ok(info.reparse_tag.is_none()
            && info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            && self.owners.contains(&info.owner)
            && file::has_protection(&f, self.protection, false)?)
    }

    /// Writes a new file `name` (letters, digits, `.`, `-`) in an engine directory: created new (never over an
    /// existing file or link), with the directory's protection.
    pub fn write_engine_file(&self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let plain = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b));
        if !plain || name.starts_with('.') || dir.parent() != Some(self.root.join("engines").as_path()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file of an engine directory"));
        }
        let path = dir.join(name);
        let mut f = file::open(&path, Open { protection: Some(self.protection), ..Open::create_new() })?;
        f.write_all(bytes)?;
        f.flush()?;
        Ok(path)
    }

    /// `run\<ID>` for a UUID `id` (canonical upper case); anything else is refused.
    #[allow(dead_code)] // the OpenVPN engine (Task 13) uses it
    fn run_dir(&self, id: &str) -> io::Result<PathBuf> {
        if !cli::is_uuid(id) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a connection ID"));
        }
        Ok(self.run.join(id.to_ascii_uppercase()))
    }

    /// A new, empty `run\<ID>` with the directory's protection (a leftover of an earlier run is removed first).
    #[allow(dead_code)] // the OpenVPN engine (Task 13) uses it
    pub fn make_run_dir(&self, id: &str) -> io::Result<PathBuf> {
        let dir = self.run_dir(id)?;
        self.remove_run_dir(id)?;
        file::create_dir(&dir, Some(self.protection))?;
        Ok(dir)
    }

    /// Writes a new file directly inside a run directory (`run\<ID>\<name>`, the name letters, digits, `.`, `_` and
    /// `-`): created new (never an existing file or link), with the directory's protection.
    #[allow(dead_code)] // the OpenVPN engine (Task 13) uses it
    pub fn write_private(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let refuse = || io::Error::new(io::ErrorKind::InvalidInput, "not a file of a run directory");
        let dir = path.parent().ok_or_else(refuse)?;
        let id = dir.file_name().and_then(|n| n.to_str()).ok_or_else(refuse)?;
        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(refuse)?;
        let plain = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        };
        if dir.parent() != Some(self.run.as_path())
            || !cli::is_uuid(id)
            || id != id.to_ascii_uppercase()
            || !plain(name)
        {
            return Err(refuse());
        }
        let mut f = file::open(path, Open { protection: Some(self.protection), ..Open::create_new() })?;
        f.write_all(bytes)?;
        f.flush()
    }

    /// Removes `run\<ID>` and what is in it; a link inside (or at its name) is removed itself, never followed.
    /// Nothing there is `Ok`.
    #[allow(dead_code)] // the OpenVPN engine (Task 13) uses it
    pub fn remove_run_dir(&self, id: &str) -> io::Result<()> {
        let dir = self.run_dir(id)?;
        match std::fs::symlink_metadata(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
            // std's remove_dir_all does not follow links (a link at the top is removed itself).
            Ok(_) => std::fs::remove_dir_all(&dir),
        }
    }

    /// Removes every run directory of an earlier run (a UUID name, a real directory); anything else in `run\` is
    /// left. Returns how many entries were left.
    pub fn sweep_runs(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.run) else { return 0 };
        let mut left = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let is_run = name.to_str().is_some_and(cli::is_uuid)
                && entry.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink());
            if !is_run || std::fs::remove_dir_all(entry.path()).is_err() {
                left += 1;
            }
        }
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("winvpn-data-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn me() -> Vec<Sid> {
        vec![Sid::current_user().unwrap()]
    }

    #[test]
    fn a_new_directory_is_created_private_with_its_folders() {
        let root = temp("new");
        let d = open_at(&root, Protection::Private, &me()).unwrap();
        for dir in [&d.root, &d.run, &d.logs] {
            assert!(is_safe_dir(dir, Protection::Private, &me()).unwrap(), "{}", dir.display());
        }
        // Opened again: the same folders pass the same check.
        open_at(&root, Protection::Private, &me()).unwrap();
        // Another owner list (SYSTEM and Administrators only) refuses this user's folder.
        let admins = [Sid::local_system(), Sid::builtin_administrators()];
        let e = open_at(&root, Protection::Private, &admins).unwrap_err();
        assert!(e.contains(&root.display().to_string()), "{e}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_existing_folder_of_another_shape_is_refused_and_left_as_it_is() {
        let root = temp("open");
        std::fs::create_dir(&root).unwrap();
        assert!(open_at(&root, Protection::Private, &me()).is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "nothing created inside");
        // A safe root with an unsafe `run` inside: refused too, and `logs` is not created.
        std::fs::remove_dir(&root).unwrap();
        file::create_dir(&root, Some(Protection::Private)).unwrap();
        std::fs::create_dir(root.join("run")).unwrap();
        // `run` was made by std inside a private folder: it inherits the entries (not protected, so no shape).
        assert!(open_at(&root, Protection::Private, &me()).is_err());
        assert!(!root.join("logs").exists());
        std::fs::remove_dir_all(&root).unwrap();
        // A file at the name is no directory.
        let file_root = temp("file");
        std::fs::write(&file_root, b"x").unwrap();
        assert!(open_at(&file_root, Protection::Private, &me()).is_err());
        std::fs::remove_file(&file_root).unwrap();
    }

    #[test]
    fn a_junction_is_never_followed() {
        let base = temp("junction");
        std::fs::create_dir(&base).unwrap();
        let target = base.join("target");
        file::create_dir(&target, Some(Protection::Private)).unwrap();
        let link = base.join("link");
        file::create_dir(&link, Some(Protection::Private)).unwrap();
        file::make_junction_for_tests(&link, &format!(r"\??\{}", target.display())).unwrap();
        assert!(open_at(&link, Protection::Private, &me()).is_err());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn run_directories_hold_private_files_by_uuid_only() {
        let root = temp("run");
        let d = open_at(&root, Protection::Private, &me()).unwrap();
        let dir = d.make_run_dir(&ID.to_ascii_lowercase()).unwrap();
        assert_eq!(dir, d.run.join(ID));
        assert!(is_safe_dir(&dir, Protection::Private, &me()).unwrap());
        d.write_private(&dir.join("config.ovpn"), b"secret").unwrap();
        let f = file::open_metadata(&dir.join("config.ovpn"), false).unwrap();
        assert!(file::has_protection(&f, Protection::Private, false).unwrap());
        drop(f);
        // Never over an existing file; never outside a run directory; never a name with a path in it.
        assert_eq!(d.write_private(&dir.join("config.ovpn"), b"x").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        for bad in [d.run.join("x.txt"), d.root.join(ID).join("a"), dir.join(".."), d.logs.join(ID).join("a")] {
            assert_eq!(d.write_private(&bad, b"x").unwrap_err().kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
        assert_eq!(d.make_run_dir("../logs").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        // A second make empties it.
        d.make_run_dir(ID).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        d.write_private(&dir.join("mgmt.pw"), b"pw").unwrap();
        d.remove_run_dir(ID).unwrap();
        assert!(!dir.exists());
        d.remove_run_dir(ID).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_sweep_removes_run_directories_and_leaves_the_rest() {
        let root = temp("sweep");
        let d = open_at(&root, Protection::Private, &me()).unwrap();
        let dir = d.make_run_dir(ID).unwrap();
        d.write_private(&dir.join("config.ovpn"), b"x").unwrap();
        std::fs::write(d.run.join("other.txt"), b"x").unwrap();
        // A UUID-named junction to a folder outside: left (not a real directory), its target untouched.
        let outside = temp("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"x").unwrap();
        let link = d.run.join("11111111-2222-3333-4444-555555555555");
        std::fs::create_dir(&link).unwrap();
        file::make_junction_for_tests(&link, &format!(r"\??\{}", outside.display())).unwrap();
        assert_eq!(d.sweep_runs(), 2);
        assert!(!dir.exists());
        assert!(d.run.join("other.txt").exists());
        assert!(outside.join("keep").exists());
        // Opening again sweeps again (what is left stays).
        open_at(&root, Protection::Private, &me()).unwrap();
        assert!(outside.join("keep").exists());
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn engine_directories_are_checked_at_every_call_and_hold_own_files_only() {
        let root = temp("engines");
        let d = open_at(&root, Protection::Private, &me()).unwrap();
        let dir = d.engine_dir("wireguard-nt").unwrap();
        assert_eq!(dir, root.join("engines").join("wireguard-nt"));
        assert!(is_safe_dir(&dir, Protection::Private, &me()).unwrap());
        for bad in ["", "..", "a/b", r"a\b", "x.y"] {
            assert_eq!(d.engine_dir(bad).unwrap_err().kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
        let f = d.write_engine_file(&dir, "wireguard.new", b"x").unwrap();
        assert!(d.is_own_file(&f).unwrap());
        assert_eq!(d.write_engine_file(&dir, "wireguard.new", b"y").unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        for (where_, name) in [(&dir, "../x"), (&dir, ".hidden"), (&d.run, "x"), (&root, "x")] {
            assert_eq!(d.write_engine_file(where_, name, b"x").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
        // A file another program made (inherited permissions, as curl's output has) is not the service's own.
        let other = dir.join("curl-output");
        std::fs::write(&other, b"x").unwrap();
        assert!(!d.is_own_file(&other).unwrap());
        assert!(!d.is_own_file(&dir).unwrap(), "a directory");
        // An engine directory replaced by a junction: refused (never followed), the target stays empty.
        let outside = temp("outside-engine");
        file::create_dir(&outside, Some(Protection::Private)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        file::create_dir(&dir, Some(Protection::Private)).unwrap();
        file::make_junction_for_tests(&dir, &format!(r"\??\{}", outside.display())).unwrap();
        assert!(d.engine_dir("wireguard-nt").is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }
}
