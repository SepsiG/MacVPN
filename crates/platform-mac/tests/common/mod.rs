#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh scratch directory under the temp dir, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    /// A path inside, not created.
    pub fn unborn(prefix: &str) -> Self {
        Scratch(std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4())))
    }

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

/// `/bin/bash -n`: the script is syntactically valid (not run).
pub fn assert_bash_syntax(script: &str) {
    let dir = Scratch::new("macvpn-syntax");
    let path = dir.join("s.sh");
    std::fs::write(&path, script).unwrap();
    let out = Command::new("/bin/bash").arg("-n").arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// Runs `/bin/bash <script file>`; (status, combined output).
pub fn run_bash_file(path: &Path) -> (i32, String) {
    let out = Command::new("/bin/bash").arg(path).stderr(std::process::Stdio::piped()).output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

/// Like Swift's `Pipe` for stdout + stderr: both into one pipe, in order.
pub fn run_bash_file_merged(path: &Path) -> (i32, String) {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let mut child =
        Command::new("/bin/bash").arg(path).stdout(writer.try_clone().unwrap()).stderr(writer).spawn().unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut reader, &mut text).unwrap();
    let status = child.wait().unwrap();
    (status.code().unwrap_or(-1), text)
}

pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

pub fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn getuid() -> u32 {
    let out = Command::new("/usr/bin/id").arg("-u").output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// A scratch directory with a short name (`<temp>/mc<8 hex>`), for Unix socket paths: `sun_path` holds only
/// 104 bytes, and the UUID-named [`Scratch`] plus a socket name would not fit. Falls back to `/tmp` when
/// `$TMPDIR` is so long that `<dir>/control/macvpn.sock` would not fit either.
pub fn short_scratch() -> Scratch {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("mc{}", &id[..8]);
    let mut dir = std::env::temp_dir().join(&name);
    if dir.join("control/macvpn.sock").as_os_str().len() >= 104 {
        dir = std::path::Path::new("/tmp").join(&name);
    }
    std::fs::create_dir(&dir).expect("short scratch dir");
    Scratch(dir)
}
