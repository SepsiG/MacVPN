//! The package upgrade from outside the app (`sudo apt-get install ./linvpn_*.deb`, the Software app, unattended
//! upgrades): the `.deb`'s `postinst` (`configure`) writes the installed version to [`MARKER`] (one line, `X.Y.Z`;
//! `/run` is cleared at boot, so a fresh boot has none until the next upgrade). The installed LinVPN polls it
//! (`lin::package_watch`) and, once it names another version than the running one (a downgrade too), restarts into
//! the new binary the way the in-app updater does (`ok <version>`, `linvpn --after-update`, quit without the quit
//! questions; the tunnels stay up).
//!
//! A marker that already differed when the watch began is not acted on until it changes (a package whose binary
//! does not report the package's version would otherwise restart LinVPN over and over).

use macvpn_core::deb_update;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// The installed package's version, written by the `.deb`'s `postinst` (0644 in a 0755 root-owned folder).
pub const MARKER: &str = "/run/linvpn/package-version";
/// The largest marker read.
const MAX_MARKER: u64 = 256;
/// How often the marker is read.
pub const POLL: Duration = Duration::from_secs(3);

/// The marker's text as a version: one plain `X.Y.Z` line (a trailing newline allowed); anything else is no version.
pub fn parse_marker(text: &str) -> Option<String> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    deb_update::is_newer(line, None).then(|| line.to_string())
}

/// The version in the marker at `path`: a regular file (not a link) of at most 256 bytes; `None` when it is missing
/// or anything else.
pub fn read_marker(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_MARKER {
        return None;
    }
    let mut text = String::new();
    fs::File::open(path).ok()?.take(MAX_MARKER).read_to_string(&mut text).ok()?;
    parse_marker(&text)
}

/// The version to restart into: the marker's `now`, when it names another version than `running` and differs from
/// what the marker held when the watch began (`at_start`). `None`: keep running.
pub fn upgraded_to(running: &str, at_start: Option<&str>, now: Option<&str>) -> Option<String> {
    let now = now?;
    (now != running && Some(now) != at_start).then(|| now.to_string())
}
