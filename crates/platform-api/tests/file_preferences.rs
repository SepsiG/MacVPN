//! FilePreferences: the JSON preference file in the private data directory (WinVPN).

use macvpn_core::date::Date;
use macvpn_platform_api::{FilePreferences, PreferenceStore};
use std::fs;
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("file-prefs-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn values_survive_a_new_store_and_keep_their_types() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    let prefs = FilePreferences::new(path.clone());
    prefs.set_bool("autoUpdate", true);
    prefs.set_string("language", "hu");
    prefs.set_date("lastCheck", Date::from_time_interval_since_1970(1_790_000_000.5));
    let again = FilePreferences::new(path.clone());
    assert_eq!(again.bool("autoUpdate"), Some(true));
    assert_eq!(again.string("language").as_deref(), Some("hu"));
    assert_eq!(again.date("lastCheck").map(|d| d.time_interval_since_1970()), Some(1_790_000_000.5));
    assert_eq!(again.bool("language"), None, "a string is not a bool");
    assert_eq!(again.string("missing"), None);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_file_is_private_and_remove_all_empties_it() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    let prefs = FilePreferences::new(path.clone());
    prefs.set_bool("x", true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
    }
    #[cfg(windows)]
    {
        use macvpn_core::fsx::{self, Access, Follow};
        assert!(fsx::has_access(&fsx::stat_path(&path, Follow::No).unwrap(), Access::Private));
    }
    prefs.remove_all();
    assert_eq!(FilePreferences::new(path).bool("x"), None);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_corrupt_or_missing_file_reads_as_empty_and_is_replaced_on_write() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    assert_eq!(FilePreferences::new(path.clone()).bool("x"), None);
    fs::write(&path, b"{not json").unwrap();
    let prefs = FilePreferences::new(path.clone());
    assert_eq!(prefs.bool("x"), None);
    prefs.set_bool("x", false);
    assert_eq!(FilePreferences::new(path).bool("x"), Some(false));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_file_has_the_documented_format() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    let prefs = FilePreferences::new(path.clone());
    prefs.set_string("language", "hu");
    prefs.set_bool("autoUpdate", false);
    prefs.set_date("lastCheck", Date::from_time_interval_since_1970(10.5));
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"version": 1, "values": {
            "autoUpdate": {"bool": false},
            "language": {"string": "hu"},
            "lastCheck": {"date": 10.5},
        }})
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn another_version_or_an_oversized_file_reads_as_empty_and_a_missing_directory_is_created_private() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    fs::write(&path, br#"{"version":2,"values":{"x":{"bool":true}}}"#).unwrap();
    assert_eq!(FilePreferences::new(path.clone()).bool("x"), None);
    let mut big = br#"{"version":1,"values":{"x":{"bool":true}}}"#.to_vec();
    big.resize(1024 * 1024 + 1, b' ');
    fs::write(&path, &big).unwrap();
    assert_eq!(FilePreferences::new(path).bool("x"), None);

    let nested = dir.join("WinVPN").join("preferences.json");
    FilePreferences::new(nested.clone()).set_bool("x", true);
    assert_eq!(FilePreferences::new(nested).bool("x"), Some(true));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(dir.join("WinVPN")).unwrap().permissions().mode() & 0o7777, 0o700);
    }
    #[cfg(windows)]
    {
        use macvpn_core::fsx::{self, Access, Follow};
        assert!(fsx::has_access(&fsx::stat_path(&dir.join("WinVPN"), Follow::No).unwrap(), Access::Private));
    }
    fs::remove_dir_all(dir).unwrap();
}
