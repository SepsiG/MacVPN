//! The control-socket tests' helpers (copied from platform-mac's `tests/common` when the socket moved here, LinVPN
//! plan Task 10; the names come from the crate's own CSPRNG instead of `uuid`).
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A scratch directory, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

pub fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A scratch directory with a short name (`<temp>/mc<8 hex>`), for Unix socket paths: `sun_path` holds only
/// 104 bytes on macOS (108 on Linux). Falls back to `/tmp` when `$TMPDIR` is so long that
/// `<dir>/control/macvpn.sock` would not fit either.
pub fn short_scratch() -> Scratch {
    let id = macvpn_unixsys::random::random_32().unwrap();
    let name = format!("mc{:02x}{:02x}{:02x}{:02x}", id[0], id[1], id[2], id[3]);
    let mut dir = std::env::temp_dir().join(&name);
    if dir.join("control/macvpn.sock").as_os_str().len() >= 104 {
        dir = Path::new("/tmp").join(&name);
    }
    std::fs::create_dir(&dir).expect("short scratch dir");
    Scratch(dir)
}
