//! `service.log`: the service's own events, one line each (`<ISO 8601 UTC> <text>`), rotated to `service.log.1`
//! above 1 MiB. Only fixed texts, error kinds, counts, IDs and SIDs are logged (never a request's bytes, a config or
//! a secret); a line is cut at 512 bytes and its control characters become spaces. The file is created with the
//! data directory's protection and never through a reparse point; a file of another shape is not written to.

use macvpn_core::date::Date;
use macvpn_winsys::file::{self, Disposition, Open, Protection};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

pub const ROTATE_AT: u64 = 1024 * 1024;
const LINE_MAX: usize = 512;

/// A cheap handle (clones share the file); [`ServiceLog::none`] drops every line.
#[derive(Clone)]
pub struct ServiceLog(Option<Arc<Inner>>);

struct Inner {
    path: PathBuf,
    protection: Protection,
    file: Mutex<Option<File>>,
}

impl ServiceLog {
    pub fn open(path: PathBuf, protection: Protection) -> ServiceLog {
        ServiceLog(Some(Arc::new(Inner { path, protection, file: Mutex::new(None) })))
    }

    pub fn none() -> ServiceLog {
        ServiceLog(None)
    }

    pub fn line(&self, text: &str) {
        let Some(inner) = &self.0 else { return };
        let mut line = format!("{} {}", Date::now().iso8601(), text);
        if line.len() > LINE_MAX {
            let mut end = LINE_MAX;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
        }
        let mut line: String = line.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        line.push('\n');
        let mut slot = inner.file.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|f| f.metadata().map_or(true, |m| m.len() + line.len() as u64 > ROTATE_AT)) {
            *slot = None;
            let _ = std::fs::rename(&inner.path, inner.path.with_extension("log.1"));
        }
        if slot.is_none() {
            *slot = inner.open_file();
        }
        if let Some(f) = slot.as_mut()
            && f.write_all(line.as_bytes()).is_err()
        {
            *slot = None;
        }
    }
}

impl Inner {
    /// The log for appending: created with the protection, or an existing one only when it is a plain file (no
    /// reparse point, one link) with exactly that protection.
    fn open_file(&self) -> Option<File> {
        let o = Open {
            read: false,
            write: false,
            append: true,
            disposition: Disposition::OpenOrCreate,
            protection: Some(self.protection),
            no_follow: true,
        };
        let f = file::open(&self.path, o).ok()?;
        let info = file::info(&f).ok()?;
        let ok = info.reparse_tag.is_none()
            && info.links == 1
            && file::has_protection(&f, self.protection, false).unwrap_or(false);
        ok.then_some(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_stamped_cleaned_and_rotated() {
        let dir = std::env::temp_dir().join(format!("winvpn-servicelog-{}", uuid::Uuid::new_v4()));
        file::create_dir(&dir, Some(Protection::Private)).unwrap();
        let path = dir.join("service.log");
        let log = ServiceLog::open(path.clone(), Protection::Private);
        log.clone().line("starting\nforged line");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.ends_with(" starting forged line\n"), "{text}");
        assert!(text.as_bytes()[..4].iter().all(u8::is_ascii_digit) && text.contains('T'), "{text}");
        let f = file::open_metadata(&path, false).unwrap();
        assert!(file::has_protection(&f, Protection::Private, false).unwrap());
        drop(f);
        let long = "x".repeat(10_000);
        for _ in 0..(ROTATE_AT as usize / LINE_MAX + 10) {
            log.line(&long);
        }
        assert!(std::fs::metadata(&path).unwrap().len() <= ROTATE_AT);
        assert!(std::fs::metadata(dir.join("service.log.1")).unwrap().len() <= ROTATE_AT);
        assert!(std::fs::read_to_string(&path).unwrap().lines().all(|l| l.len() <= LINE_MAX));
        ServiceLog::none().line("dropped");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_file_of_another_shape_is_not_written() {
        let dir = std::env::temp_dir().join(format!("winvpn-servicelog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("service.log");
        std::fs::write(&path, b"").unwrap();
        ServiceLog::open(path.clone(), Protection::Private).line("x");
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
