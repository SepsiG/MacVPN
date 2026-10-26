//! `macvpn_winsys::msi` against the real Windows Installer database API, as a standard user: a small MSI database
//! made here (nothing is installed), and optionally OpenVPN's real MSI (`WINVPN_TEST_OPENVPN_MSI`, downloaded by
//! hand).

#![cfg(windows)]

use macvpn_winsys::msi;
use std::path::PathBuf;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winsys-msi-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_property_table_is_read_back_as_written() {
    let dir = temp("rows");
    let path = dir.join("t.msi");
    let long = "x".repeat(1000);
    let rows = [
        ("ProductName", "OpenVPN"),
        ("ProductVersion", "2.7.801"),
        ("UpgradeCode", "{461BDF86-D389-4471-BF36-99806B64C127}"),
        ("Manufacturer", "OpenVPN, Inc."),
        ("Long", long.as_str()),
        ("Unicode", "árvíztűrő tükörfúrógép"),
    ];
    // The Hungarian letters are all in code page 1250 (Central European); the machine's own code page (1252 on
    // GitHub's runners) does not matter.
    msi::create_for_tests(&path, 1250, &rows).unwrap();
    let mut read = msi::properties(&path).unwrap();
    read.sort();
    let mut want: Vec<(String, String)> = rows.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    want.sort();
    assert_eq!(read, want);
    // Read-only: the file is unchanged and can be read again.
    assert_eq!(msi::properties(&path).unwrap().len(), rows.len());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_file_that_is_no_msi_database_is_an_error() {
    let dir = temp("bad");
    let path = dir.join("x.msi");
    std::fs::write(&path, b"MZ not an MSI").unwrap();
    assert!(msi::properties(&path).is_err());
    assert!(msi::properties(&dir.join("missing.msi")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn openvpns_real_msi_names_itself() {
    let Some(path) = std::env::var_os("WINVPN_TEST_OPENVPN_MSI") else {
        eprintln!("WINVPN_TEST_OPENVPN_MSI not set: skipped");
        return;
    };
    let props = msi::properties(std::path::Path::new(&path)).unwrap();
    let get = |k: &str| props.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("ProductName"), Some("OpenVPN"));
    assert_eq!(get("Manufacturer"), Some("OpenVPN, Inc."));
    assert_eq!(get("ProductVersion"), Some("2.7.801"));
    assert!(get("UpgradeCode").is_some_and(|c| c.starts_with('{') && c.len() == 38));
}
