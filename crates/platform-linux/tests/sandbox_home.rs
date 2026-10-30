//! The sandbox's NetworkManager engine keeps its files under the sandbox home (`MACVPN_SANDBOX_HOME`), never under
//! the real user's `~/.local/share/LinVPN`: a smoke run's managed L2TP save writes its plan record there. A test
//! binary of its own: it sets the process environment.
#![cfg(target_os = "linux")]

use macvpn_core::date::Date;
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use macvpn_platform_api::Platform;
use macvpn_platform_linux::LinPlatform;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use uuid::Uuid;

#[test]
fn the_sandbox_engine_writes_its_plan_records_under_the_sandbox_home() {
    let home = std::env::temp_dir().join(format!("linvpn-sandbox-home.{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: this test binary has one test and no other thread reads the environment.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("MACVPN_SANDBOX_HOME", &home)
    };

    let p = LinPlatform::new(true);
    let id = Uuid::new_v4();
    let mut c = Connection::with_id(id, "Sandbox L2TP", VPNKind::L2tp, Date::now());
    c.native = Some(NativeSettings {
        server: "l2tp.example.com".into(),
        account: "erin".into(),
        group_name: String::new(),
        send_all_traffic: true,
    });
    let profiles = p.native_profiles(Path::new("/nonexistent"), false);
    let profile = profiles.build(&c, "").unwrap();
    profiles.install(&id, &profile.data, &profile.file_name, false).unwrap();

    let record = home.join(".local/share/LinVPN/nm").join(format!("{}.json", id.hyphenated()));
    let written = record.is_file();
    profiles.remove(&id);
    let removed = !record.exists();
    let _ = std::fs::remove_dir_all(&home);
    assert!(written, "the plan record is under the sandbox home: {}", record.display());
    assert!(removed, "remove deletes it there");
}
