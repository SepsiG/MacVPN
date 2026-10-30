//! The control API's transport on macOS (moved from the app in 1.5): the Unix socket of [`crate::control_socket`]
//! as platform-api's [`ControlTransport`]. The listener and stream wrappers live in `macvpn-unixsys` (shared with
//! Linux, LinVPN plan Task 10).

use crate::control_socket;
use macvpn_platform_api::{BoundEndpoint, ControlTransport};
use std::io;
use std::path::Path;

pub use macvpn_unixsys::transport::{UnixControlListener, UnixControlStream};

/// The platform socket (`control_socket`): `<dir>/macvpn.sock`, guarded by the instance lock.
pub struct Transport;

impl ControlTransport for Transport {
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint> {
        let bound = control_socket::bind(dir)?;
        // The `ControlListener` (with the instance lock) is the guard the server drops last.
        macvpn_unixsys::transport::endpoint(bound, control_socket::socket_path(dir))
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        control_socket::random_32()
    }

    fn is_already_closed(&self, e: &io::Error) -> bool {
        control_socket::is_already_closed(e)
    }

    /// `control_socket::prepare_dir` (the owner checked against `getuid()` before the mode is tightened).
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        control_socket::prepare_dir(dir)
    }
}
