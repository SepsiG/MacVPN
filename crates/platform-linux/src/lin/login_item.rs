//! "Launch at Login" through `$XDG_CONFIG_HOME/autostart/linvpn.desktop` (`pure::autostart`). Only the installed
//! LinVPN (`/usr/bin/linvpn`) can toggle it; a development build shows why. GNOME has no settings page for it.

use crate::pure::autostart::{self, State};
use macvpn_core::l10n;
use macvpn_platform_api::{LoginItemView, LoginItems, PlatformError};
use std::path::PathBuf;

const NOT_INSTALLED: &str = "Launch at login is available when LinVPN is installed from its package.";

pub struct AutostartItem {
    pub file: PathBuf,
    pub installed: bool,
}

fn failed(e: impl ToString) -> PlatformError {
    PlatformError::Failed(e.to_string())
}

impl LoginItems for AutostartItem {
    fn state(&self) -> LoginItemView {
        if !self.installed {
            return LoginItemView {
                is_on: false,
                can_toggle: false,
                note: Some(l10n::tr(NOT_INSTALLED, &[])),
                shows_open_settings: false,
            };
        }
        let text = std::fs::read_to_string(&self.file).ok();
        let state = autostart::state_of(text.as_deref());
        LoginItemView {
            is_on: state == State::On,
            can_toggle: true,
            note: (state == State::TurnedOffElsewhere).then(|| l10n::tr("Turned off by another app.", &[])),
            shows_open_settings: false,
        }
    }

    /// On: the whole file is (re)written, which also turns on a file another tool turned off.
    fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError> {
        if !self.installed {
            return Err(PlatformError::Failed(l10n::tr(NOT_INSTALLED, &[])));
        }
        if on {
            let dir = self.file.parent().ok_or_else(|| failed("no autostart folder"))?;
            std::fs::create_dir_all(dir).map_err(failed)?;
            macvpn_core::fsx::atomic_write(
                &self.file,
                autostart::desktop_file().as_bytes(),
                macvpn_core::fsx::Access::Shared,
            )
            .map_err(failed)
        } else {
            self.unregister_if_registered().map(|_| ())
        }
    }

    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError> {
        match std::fs::remove_file(&self.file) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(failed(e)),
        }
    }

    /// GNOME has no settings page for autostart entries.
    fn open_settings(&self) {}

    fn remove_stale_entries(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
