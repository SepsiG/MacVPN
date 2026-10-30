//! The control API's transport on Linux: the shared Unix socket (`macvpn_unixsys`) at
//! `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock` (spec 3.1), with `linvpn.lock` beside it as the single-instance lock
//! of the control server. `bind(dir)` ignores `dir` for the socket (as Windows' pipe does); `prepare_dir(dir)` still
//! prepares the audit file's directory under the data dir. The runtime dir must be a real directory of this uid with
//! no group or other access (the XDG spec's 0700), else `PermissionDenied`: fail closed. The sandbox's runtime dir
//! (`<sandbox>/run`) is created 0700 by `prepare_dir` itself.

use macvpn_platform_api::{BoundEndpoint, ControlTransport};
use macvpn_unixsys::{control_socket, transport};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct LinTransport {
    /// `$XDG_RUNTIME_DIR` (or the sandbox's `run`); `None`: unset.
    root: Option<PathBuf>,
    /// The sandbox creates its root; the real `$XDG_RUNTIME_DIR` must exist (logind makes it).
    create_root: bool,
}

impl LinTransport {
    pub fn production(runtime_dir: Option<PathBuf>) -> LinTransport {
        LinTransport { root: runtime_dir, create_root: false }
    }

    pub fn sandbox(run: PathBuf) -> LinTransport {
        LinTransport { root: Some(run), create_root: true }
    }

    /// Tests: an existing root.
    #[doc(hidden)]
    pub fn under(root: &Path) -> LinTransport {
        LinTransport { root: Some(root.to_path_buf()), create_root: false }
    }

    #[doc(hidden)]
    pub fn without_runtime_dir() -> LinTransport {
        LinTransport { root: None, create_root: false }
    }

    fn checked_root(&self) -> io::Result<PathBuf> {
        let root =
            self.root.clone().ok_or_else(|| io::Error::new(ErrorKind::Unsupported, "XDG_RUNTIME_DIR is not set"))?;
        if self.create_root {
            control_socket::prepare_dir(&root)?;
        }
        let meta = std::fs::symlink_metadata(&root)?;
        // SAFETY: `getuid` takes no argument and cannot fail.
        let uid = unsafe { libc::getuid() };
        if !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("{} is not a private directory of this user", root.display()),
            ));
        }
        Ok(root)
    }
}

impl ControlTransport for LinTransport {
    fn bind(&self, _dir: &Path) -> io::Result<BoundEndpoint> {
        let root = self.checked_root()?;
        let ours = root.join("linvpn");
        control_socket::prepare_dir(&ours)?;
        let control = ours.join("control");
        control_socket::prepare_dir(&control)?;
        let bound = control_socket::bind_at(&control, "linvpn.sock", "linvpn.lock")?;
        transport::endpoint(bound, control.join("linvpn.sock"))
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        macvpn_unixsys::random::random_32()
    }

    fn is_already_closed(&self, e: &io::Error) -> bool {
        control_socket::is_already_closed(e)
    }

    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        control_socket::prepare_dir(dir)
    }
}
