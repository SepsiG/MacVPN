//! The quarantine mark (`com.apple.quarantine`) that browsers, Mail, Messages and AirDrop put on the files they
//! save: a file opened from Finder that carries it was downloaded, and its import is confirmed first. The mark is
//! only read, never removed (Gatekeeper and the other apps still see it).

use std::path::Path;

/// The extended attribute macOS marks downloaded files with.
pub const QUARANTINE_XATTR: &str = "com.apple.quarantine";

/// The file (or, for a symlink, the link or its target) carries the quarantine mark. A file whose attributes
/// cannot be read for another reason than "no such attribute" counts as marked (the import is then confirmed);
/// a missing file does not (the import reports it).
pub fn is_quarantined(path: &Path) -> bool {
    let name = c"com.apple.quarantine";
    [false, true].into_iter().any(|follow| match crate::sys::has_xattr(path, name, follow) {
        Ok(marked) => marked,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn temp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("macvpn-quarantine-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join(name);
        std::fs::write(&file, "client\n").unwrap();
        file
    }

    fn mark(path: &Path) {
        let status = Command::new("/usr/bin/xattr")
            .args(["-w", QUARANTINE_XATTR, "0083;6720a000;Safari;"])
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn a_local_file_is_not_quarantined() {
        let file = temp_file("local.ovpn");
        assert!(!is_quarantined(&file));
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_downloaded_file_is_quarantined_and_keeps_its_mark() {
        let file = temp_file("downloaded.ovpn");
        mark(&file);
        assert!(is_quarantined(&file));
        // Only read: the mark is still there.
        let out = Command::new("/usr/bin/xattr").arg("-p").arg(QUARANTINE_XATTR).arg(&file).output().unwrap();
        assert!(out.status.success());
        // A symlink to it is marked too (the import reads the target).
        let link = file.with_file_name("link.ovpn");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(is_quarantined(&link));
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_missing_file_is_not_quarantined() {
        assert!(!is_quarantined(Path::new("/nonexistent/macvpn/x.ovpn")));
    }

    #[test]
    fn a_path_with_a_nul_byte_counts_as_marked() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/a\0b.ovpn"));
        assert!(is_quarantined(path));
    }
}
