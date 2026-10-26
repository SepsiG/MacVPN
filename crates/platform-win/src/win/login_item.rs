//! Launch at login: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinVPN` = `"<exe>"`, and the Startup apps
//! switch of Settings (`…\Explorer\StartupApproved\Run\WinVPN`).

use super::{registry, shell};
use crate::pure::{run_key, texts};
use macvpn_platform_api::{LoginItemView, LoginItems, PlatformError};
use std::path::PathBuf;

pub(crate) const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub(crate) const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// The value's name (a storage identifier, never derived from `Product`).
pub(crate) const VALUE: &str = "WinVPN";

pub(crate) struct RunKeyItem {
    pub(crate) exe: PathBuf,
    /// [`VALUE`]; tests use their own name.
    pub(crate) value: String,
}

fn failed(e: std::io::Error) -> PlatformError {
    PlatformError::Failed(e.to_string())
}

impl RunKeyItem {
    pub(crate) fn new(exe: PathBuf) -> RunKeyItem {
        RunKeyItem { exe, value: VALUE.to_owned() }
    }

    /// Our command under our name (another command under the name is not ours, so it shows as off).
    fn registered(&self) -> bool {
        registry::read_string(RUN, &self.value).is_some_and(|v| v.eq_ignore_ascii_case(&run_key::command(&self.exe)))
    }

    fn disabled(&self) -> bool {
        registry::read_binary(APPROVED, &self.value).is_some_and(|b| run_key::disabled_in_settings(&b))
    }

    /// The value and its Settings switch go (a missing one is fine).
    fn remove(&self) -> Result<(), PlatformError> {
        registry::delete_value(RUN, &self.value).map_err(failed)?;
        registry::delete_value(APPROVED, &self.value).map_err(failed)
    }
}

impl LoginItems for RunKeyItem {
    fn state(&self) -> LoginItemView {
        let (registered, disabled) = (self.registered(), self.disabled());
        LoginItemView {
            is_on: registered && !disabled,
            can_toggle: true,
            note: (registered && disabled).then(texts::startup_disabled),
            shows_open_settings: registered && disabled,
        }
    }

    /// On: the Run value (the quoted path; a relative or quoted path is refused), and the Settings switch back on
    /// (the user asked for it here). Off: the value goes.
    fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError> {
        if !on {
            return self.remove();
        }
        if !run_key::usable(&self.exe) {
            return Err(PlatformError::Failed("not an absolute executable path".into()));
        }
        registry::write_string(RUN, &self.value, &run_key::command(&self.exe)).map_err(failed)?;
        registry::delete_value(APPROVED, &self.value).map_err(failed)
    }

    /// Any value under our name goes (the uninstaller's cleanup).
    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError> {
        if registry::read_string(RUN, &self.value).is_none() {
            return Ok(false);
        }
        self.remove()?;
        Ok(true)
    }

    fn open_settings(&self) {
        shell::open_settings("ms-settings:startupapps");
    }

    fn remove_stale_entries(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
