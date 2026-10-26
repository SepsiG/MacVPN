//! The live system VPN list: [`SystemVpnWatch`] over `winsys::ras::Watcher`, which wakes for a RAS connection that
//! starts or ends anywhere (a hint only: Windows does not report every connect, failure or hang-up, and nothing in
//! a network logon — the RAS spike) and for a change in the phonebook folders: the user's
//! `%APPDATA%\Microsoft\Network\Connections\Pbk`, the all-users `%ProgramData%\…\Pbk` (a VPN added, changed or
//! removed in Settings) and WinVPN's own `ras` folder. A folder that does not exist yet is watched through its
//! nearest existing parent. Each wake is "reload now"; the manager's poll stays the source of truth.

use super::system;
use macvpn_core::ras::names;
use macvpn_platform_api::{SystemVpnWatch, WINVPN};
use macvpn_winsys::ras::Watcher;
use std::io;
use std::path::{Path, PathBuf};

/// `Microsoft\Network\Connections\Pbk` under `%APPDATA%` and `%ProgramData%`.
fn pbk(root: &Path) -> PathBuf {
    root.join("Microsoft").join("Network").join("Connections").join("Pbk")
}

/// The folders of Windows' default phonebooks and WinVPN's private one (those whose known folder can be read).
pub(crate) fn folders() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.extend(system::roaming_app_data().map(|r| pbk(&r)));
    dirs.extend(macvpn_winsys::known::program_data().ok().map(|r| pbk(&r)));
    dirs.extend(system::local_app_data().map(|l| WINVPN.data_dir(&l).join(names::PHONEBOOK_DIR)));
    dirs
}

/// The watch over `dirs` (production: [`folders`]).
pub(crate) struct RasWatch {
    pub(crate) dirs: Vec<PathBuf>,
}

impl SystemVpnWatch for RasWatch {
    /// The watcher runs until the returned guard is dropped; `on_change` runs on its thread.
    fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        let watcher = Watcher::start(&self.dirs, on_change).map_err(io::Error::from)?;
        Ok(Box::new(watcher))
    }
}
