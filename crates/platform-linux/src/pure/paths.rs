//! The XDG base directories LinVPN uses (spec 3.2): data `$XDG_DATA_HOME/LinVPN` (default `~/.local/share`),
//! settings `$XDG_CONFIG_HOME/LinVPN` (default `~/.config`), the update cache `$XDG_CACHE_HOME/LinVPN/updates`
//! (default `~/.cache`), run files `$XDG_RUNTIME_DIR/linvpn`. A variable counts only when it is set, non-empty and
//! absolute (the XDG Base Directory spec: a relative value is invalid and ignored). The sandbox keeps all of them
//! under its home, with `<sandbox>/run` as the runtime dir. The data dir's name comes from `Product::data_dir`; the
//! other names are storage identifiers (literals).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xdg {
    pub home: PathBuf,
    pub data_home: PathBuf,
    pub config_home: PathBuf,
    pub cache_home: PathBuf,
    /// `None`: unset or invalid (no control socket then: fail closed).
    pub runtime_dir: Option<PathBuf>,
}

fn absolute(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|p| p.is_absolute())
}

impl Xdg {
    /// The real user's directories from `var` (the process environment in production).
    pub fn from_env(home: &Path, var: impl Fn(&str) -> Option<OsString>) -> Xdg {
        Xdg {
            home: home.to_path_buf(),
            data_home: absolute(var("XDG_DATA_HOME")).unwrap_or_else(|| home.join(".local/share")),
            config_home: absolute(var("XDG_CONFIG_HOME")).unwrap_or_else(|| home.join(".config")),
            cache_home: absolute(var("XDG_CACHE_HOME")).unwrap_or_else(|| home.join(".cache")),
            runtime_dir: absolute(var("XDG_RUNTIME_DIR")),
        }
    }

    /// The sandbox's directories, all under `root` (the environment is never read).
    pub fn sandbox(root: &Path) -> Xdg {
        Xdg {
            home: root.to_path_buf(),
            data_home: root.join(".local/share"),
            config_home: root.join(".config"),
            cache_home: root.join(".cache"),
            runtime_dir: Some(root.join("run")),
        }
    }

    /// `$XDG_CONFIG_HOME/LinVPN/preferences.json`.
    pub fn preferences_file(&self) -> PathBuf {
        self.config_home.join("LinVPN").join("preferences.json")
    }

    /// `$XDG_CACHE_HOME/LinVPN/updates` (private, 0700).
    pub fn updates_dir(&self) -> PathBuf {
        self.cache_home.join("LinVPN").join("updates")
    }

    /// `$XDG_CONFIG_HOME/autostart/linvpn.desktop`.
    pub fn autostart_file(&self) -> PathBuf {
        self.config_home.join("autostart").join("linvpn.desktop")
    }

    /// `$XDG_RUNTIME_DIR/linvpn`.
    pub fn runtime(&self) -> Option<PathBuf> {
        self.runtime_dir.as_ref().map(|r| r.join("linvpn"))
    }

    /// `$XDG_RUNTIME_DIR/linvpn/control/linvpn.sock`.
    pub fn control_socket(&self) -> Option<PathBuf> {
        self.runtime().map(|r| r.join("control").join("linvpn.sock"))
    }
}
