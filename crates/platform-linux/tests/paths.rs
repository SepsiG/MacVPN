use macvpn_platform_linux::pure::paths::Xdg;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
    move |k| map.get(k).cloned()
}

#[test]
fn defaults_under_home() {
    let x = Xdg::from_env(Path::new("/home/ann"), env(&[]));
    assert_eq!(x.data_home, PathBuf::from("/home/ann/.local/share"));
    assert_eq!(x.config_home, PathBuf::from("/home/ann/.config"));
    assert_eq!(x.cache_home, PathBuf::from("/home/ann/.cache"));
    assert_eq!(x.runtime_dir, None);
    assert_eq!(x.preferences_file(), PathBuf::from("/home/ann/.config/LinVPN/preferences.json"));
    assert_eq!(x.updates_dir(), PathBuf::from("/home/ann/.cache/LinVPN/updates"));
    assert_eq!(x.autostart_file(), PathBuf::from("/home/ann/.config/autostart/linvpn.desktop"));
    assert_eq!(x.control_socket(), None);
}

#[test]
fn absolute_variables_win_relative_and_empty_ones_are_ignored() {
    let x = Xdg::from_env(
        Path::new("/home/ann"),
        env(&[
            ("XDG_DATA_HOME", "/data"),
            ("XDG_CONFIG_HOME", "relative/config"),
            ("XDG_CACHE_HOME", ""),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ]),
    );
    assert_eq!(x.data_home, PathBuf::from("/data"));
    assert_eq!(x.config_home, PathBuf::from("/home/ann/.config"));
    assert_eq!(x.cache_home, PathBuf::from("/home/ann/.cache"));
    assert_eq!(x.runtime(), Some(PathBuf::from("/run/user/1000/linvpn")));
    assert_eq!(x.control_socket(), Some(PathBuf::from("/run/user/1000/linvpn/control/linvpn.sock")));
    assert_eq!(Xdg::from_env(Path::new("/h"), env(&[("XDG_RUNTIME_DIR", "run")])).runtime_dir, None);
}

#[test]
fn the_sandbox_keeps_everything_under_its_home() {
    let x = Xdg::sandbox(Path::new("/tmp/sb"));
    assert_eq!(x.data_home, PathBuf::from("/tmp/sb/.local/share"));
    assert_eq!(x.config_home, PathBuf::from("/tmp/sb/.config"));
    assert_eq!(x.cache_home, PathBuf::from("/tmp/sb/.cache"));
    assert_eq!(x.runtime(), Some(PathBuf::from("/tmp/sb/run/linvpn")));
}
