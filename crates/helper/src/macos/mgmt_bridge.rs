//! The macOS side of the management bridge (`mvpn-mgmt`, see [`crate::shared::bridge`] for the protocol): the
//! command line's root checks, the management socket (`<run>/mgmt.sock`, a Unix socket in the root 0700 run
//! directory), the credentials file and the files of [`BridgeFiles`] (root-owned directories, `O_NOFOLLOW`
//! reads, atomic writes).

use crate::shared::bridge::{Bridge, BridgeArgs, BridgeFiles, now};
use macvpn_core::management::{ManagementCredentials, ManagementResponse};
use macvpn_core::models::{parse_uuid, uuid_string};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

fn log(s: &str) {
    out!("[mgmt] {s}");
}

/// A safe directory: a real directory (not a symlink); as root owned by root and not writable by others
/// (`private`: no access for others at all).
fn trusted_directory(path: &str, private: bool, is_root: bool) -> bool {
    let Ok(m) = std::fs::symlink_metadata(path) else { return false };
    if !m.file_type().is_dir() {
        return false;
    }
    if is_root {
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return false;
        }
        if private && m.mode() & 0o077 != 0 {
            return false;
        }
    }
    true
}

/// Our own regular file with a single link (no symlink followed), at most `max` bytes; optionally removed.
fn read_private_file(path: &Path, max: u64, remove: bool) -> Option<Zeroizing<Vec<u8>>> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path);
    let result = (|| {
        let mut f = file.ok()?;
        let m = f.metadata().ok()?;
        if !m.file_type().is_file() || m.uid() != crate::macos::sys::geteuid() || m.nlink() != 1 || m.len() > max {
            return None;
        }
        let mut data = Zeroizing::new(Vec::with_capacity(m.len() as usize));
        (&mut f).take(max).read_to_end(&mut data).ok()?;
        (data.len() as u64 == m.len()).then_some(data)
    })();
    if remove {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// The bridge's files under the root layer's directories.
struct RootFiles {
    run: String,
    ui: String,
    uid: u32,
    gid: u32,
    is_root: bool,
    temp_counter: u64,
}

impl RootFiles {
    /// Atomic write: a new, exclusive (O_EXCL, O_NOFOLLOW) temporary file in the same directory, 0600, optionally
    /// given to the user, then `rename` (which replaces a symlink rather than following it).
    fn write_atomic(&mut self, dir: &str, name: &str, data: &[u8], owner: Option<(u32, u32)>) -> bool {
        self.temp_counter += 1;
        let tmp = PathBuf::from(format!("{dir}/.{name}.{}.{}", std::process::id(), self.temp_counter));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp);
        let Ok(mut f) = file else { return false };
        let mut ok = f.write_all(data).is_ok();
        if ok
            && let Some((uid, gid)) = owner
            && self.is_root
        {
            ok = std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).is_ok();
        }
        if ok {
            use std::os::unix::fs::PermissionsExt;
            ok = f.set_permissions(std::fs::Permissions::from_mode(0o600)).is_ok();
        }
        drop(f);
        if ok {
            ok = std::fs::rename(&tmp, format!("{dir}/{name}")).is_ok();
        }
        if !ok {
            let _ = std::fs::remove_file(&tmp);
        }
        ok
    }
}

impl BridgeFiles for RootFiles {
    fn log(&mut self, line: &str) {
        log(line);
    }

    fn run_trusted(&self) -> bool {
        trusted_directory(&self.run, true, self.is_root)
    }

    fn ui_trusted(&self) -> bool {
        trusted_directory(&self.ui, false, self.is_root)
    }

    fn write_ui(&mut self, name: &str, data: &[u8]) -> bool {
        let (dir, owner) = (self.ui.clone(), Some((self.uid, self.gid)));
        self.write_atomic(&dir, name, data, owner)
    }

    fn write_run(&mut self, name: &str, data: &[u8]) -> bool {
        let dir = self.run.clone();
        self.write_atomic(&dir, name, data, None)
    }

    fn remove_ui(&mut self, name: &str) {
        let _ = std::fs::remove_file(format!("{}/{name}", self.ui));
    }

    fn take_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let resp_path = Path::new(&self.run).join("mgmt-resp");
        read_private_file(&resp_path, ManagementResponse::MAX_FILE_BYTES as u64, true)
    }

    /// A final failure or a cancel: openvpn is stopped (SIGTERM) so it does not retry (auth-retry interact). Only
    /// the process in `<run>/pid` whose executable is named `openvpn` (pid reuse).
    fn stop_openvpn(&mut self) {
        let Some(data) = read_private_file(&Path::new(&self.run).join("pid"), 32, false) else { return };
        let Ok(text) = std::str::from_utf8(&data) else { return };
        let Ok(pid) = text.trim().parse::<i32>() else { return };
        if pid <= 1 {
            return;
        }
        let named_openvpn = crate::macos::sys::exec_path(pid)
            .is_some_and(|p| Path::new(&p).file_name().is_some_and(|n| n == "openvpn"));
        if named_openvpn {
            let _ = crate::macos::sys::kill(pid, crate::macos::sys::SIGTERM);
        }
    }
}

/// As root only the root layer's own directories: `/var/run/macvpn/<id>` and `/var/run/macvpn-ui`.
fn root_paths_ok(a: &BridgeArgs) -> bool {
    let run = Path::new(&a.run);
    let same_id = run.file_name().and_then(|n| n.to_str()).and_then(parse_uuid).map(|u| uuid_string(&u));
    run.parent() == Some(Path::new(crate::macos::paths::RUN_BASE))
        && same_id.as_deref() == Some(a.id.as_str())
        && a.ui == crate::macos::paths::UI_BASE
}

/// Connects to `<run>/mgmt.sock`, retrying for up to 60 s while the run directory stays trusted.
fn connect(a: &BridgeArgs, is_root: bool) -> Option<UnixStream> {
    let sock_path = format!("{}/mgmt.sock", a.run);
    let end = now() + 60.0;
    while now() < end {
        if !trusted_directory(&a.run, true, is_root) {
            std::process::exit(0);
        }
        if let Ok(s) = UnixStream::connect(&sock_path) {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

/// `mvpn-mgmt …` / `mvpn mgmt-bridge …`; returns the exit code.
pub fn main(argv: &[String]) -> i32 {
    let fail = |s: &str| {
        log(s);
        1
    };
    let Some(a) = BridgeArgs::parse(argv) else { return fail("usage error") };
    let is_root = crate::macos::sys::geteuid() == 0;
    if is_root && !root_paths_ok(&a) {
        return fail("usage error");
    }
    if !trusted_directory(&a.run, true, is_root) {
        return fail("the run directory is not safe");
    }
    let creds_path = Path::new(&a.run).join("mgmt-creds");
    let creds = read_private_file(&creds_path, 4096, true).and_then(|d| ManagementCredentials::parse(&d));
    let _ = std::fs::remove_file(&creds_path);
    let Some(sock) = connect(&a, is_root) else { return fail("the management socket did not appear") };
    log("connected");
    let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
    let files = RootFiles { run: a.run.clone(), ui: a.ui.clone(), uid: a.uid, gid: a.gid, is_root, temp_counter: 0 };
    Bridge::new(a, sock, files, creds).run();
    log("management connection closed");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_directories() {
        let d = std::env::temp_dir().join(format!("mvpn-bridge-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        let link = d.with_extension("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(trusted_directory(d.to_str().unwrap(), true, false));
        assert!(!trusted_directory(link.to_str().unwrap(), true, false));
        assert!(!trusted_directory(d.to_str().unwrap(), true, true), "not root-owned");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&d);
    }

    #[test]
    fn private_file_is_read_once() {
        let d = std::env::temp_dir().join(format!("mvpn-bridge-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        let f = d.join("mgmt-creds");
        std::fs::write(&f, "username=bob\npassword=x\npacked=0\n").unwrap();
        let data = read_private_file(&f, 4096, true).unwrap();
        assert_eq!(ManagementCredentials::parse(&data).unwrap().username, "bob");
        assert!(!f.exists());
        std::fs::write(&f, "x").unwrap();
        std::fs::hard_link(&f, d.join("hl")).unwrap();
        assert!(read_private_file(&f, 4096, false).is_none(), "hardlinked");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn root_only_accepts_the_root_layer_directories() {
        let mk = |run: &str, ui: &str| BridgeArgs {
            id: "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".into(),
            run: run.into(),
            ui: ui.into(),
            uid: 501,
            gid: 20,
            max_wait: 420.0,
        };
        assert!(root_paths_ok(&mk("/var/run/macvpn/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/run/macvpn/11111111-4b5a-6978-8796-a5b4c3d2e1f0", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/root", "/var/run/macvpn-ui")));
        assert!(!root_paths_ok(&mk("/var/run/macvpn/0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "/tmp")));
    }
}
