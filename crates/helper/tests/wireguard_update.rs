//! wireguard-nt updates through the console service (2b plan, "As built (fix4)"), as a standard user and offline:
//! the console serves the listing and the zip from a fixtures directory (`--wireguard-updates`), never the network.
//! The real signed DLL is the only wireguard-nt there is to test with, so the success path lowers the version a
//! download must be above (`--wireguard-floor 1.0`, debug console only) and has no bundled DLL.
#![cfg(all(windows, debug_assertions))]

mod common;

use common::console::{Console, spawn, test_pipe, wireguard_dll};
use macvpn_core::service_proto::{self as proto, EngineFacts, EngineUpdate};
use std::path::{Path, PathBuf};

/// The listing of download.wireguard.com/wireguard-nt/ captured 2026-10-24 (1.1).
const LISTING: &str = include_str!("fixtures/wireguard-nt-listing-2026-10-24.html");

/// The pinned SDK zip as `scripts/fetch-wireguard-nt.sh` leaves it.
fn sdk_zip() -> Vec<u8> {
    let p = wireguard_dll().parent().unwrap().join(r"..\..\..\wireguard-nt.zip");
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e} (run scripts/fetch-wireguard-nt.sh first)", p.display()))
}

/// A fixtures directory: `listing.html` and the given zips.
fn fixtures(listing: &str, zips: &[(&str, &[u8])]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winvpn-wg-fixtures-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("listing.html"), listing).unwrap();
    for (name, bytes) in zips {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    dir
}

fn facts(c: &Console) -> EngineFacts {
    EngineFacts::parse(&c.call(&["engine"], b"").stdout).unwrap()
}

fn text(r: &proto::Response) -> String {
    String::from_utf8_lossy(&r.stderr).trim().to_string()
}

fn engine_files(data: &Path) -> Vec<String> {
    let dir = data.join(r"engines\wireguard-nt");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|it| it.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn the_console_never_goes_online() {
    let dll = wireguard_dll();
    let c = Console::start_with(&["--wireguard-dll", dll.to_str().unwrap()]);
    let r = c.call(&["wireguard-check", "--lang", "en"], b"");
    assert_eq!((r.code, text(&r).as_str()), (1, "wireguard-nt could not be checked for updates."));
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!(r.code, 1);
    assert_eq!(facts(&c).wireguard.dll_version.as_deref(), Some("1.1.0"));
}

#[test]
fn the_bundled_version_is_the_newest_so_nothing_is_offered() {
    let dll = wireguard_dll();
    let fx = fixtures(LISTING, &[("wireguard-nt-1.1.zip", &sdk_zip())]);
    let c =
        Console::start_with(&["--wireguard-dll", dll.to_str().unwrap(), "--wireguard-updates", fx.to_str().unwrap()]);
    let r = c.call(&["wireguard-check"], b"");
    assert_eq!(r.code, 0, "{}", text(&r));
    assert_eq!(EngineUpdate::parse(&r.stdout), Some(EngineUpdate { installed: Some("1.1.0".into()), available: None }));
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!((r.code, text(&r).as_str()), (1, "No newer wireguard-nt is available."));
    assert!(engine_files(&c.data).is_empty(), "{:?}", engine_files(&c.data));
    drop(c);
    std::fs::remove_dir_all(&fx).unwrap();
}

#[test]
fn a_download_that_is_not_newer_than_it_claims_is_refused_and_leaves_nothing() {
    // The listing claims 1.2; its zip holds the real 1.1 DLL (signed, this machine's): refused by its version.
    let dll = wireguard_dll();
    let listing = LISTING.replace("wireguard-nt-1.1.zip", "wireguard-nt-1.2.zip");
    let fx = fixtures(&listing, &[("wireguard-nt-1.2.zip", &sdk_zip())]);
    let c =
        Console::start_with(&["--wireguard-dll", dll.to_str().unwrap(), "--wireguard-updates", fx.to_str().unwrap()]);
    let r = c.call(&["wireguard-check"], b"");
    assert_eq!(
        EngineUpdate::parse(&r.stdout),
        Some(EngineUpdate { installed: Some("1.1.0".into()), available: Some("1.2.0".into()) })
    );
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!(r.code, 1);
    assert!(text(&r).starts_with("The downloaded wireguard-nt did not pass its checks"), "{}", text(&r));
    assert!(engine_files(&c.data).is_empty(), "{:?}", engine_files(&c.data));
    assert_eq!(facts(&c).wireguard.dll_version.as_deref(), Some("1.1.0"), "the bundled DLL stays");
    // A zip that is not a zip, and a missing zip: refused the same way, nothing left.
    std::fs::write(fx.join("wireguard-nt-1.2.zip"), b"not a zip").unwrap();
    assert_eq!(c.call(&["wireguard-update"], b"").code, 1);
    std::fs::remove_file(fx.join("wireguard-nt-1.2.zip")).unwrap();
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!((r.code, text(&r).as_str()), (1, "The newest wireguard-nt could not be downloaded."));
    assert!(engine_files(&c.data).is_empty(), "{:?}", engine_files(&c.data));
    drop(c);
    std::fs::remove_dir_all(&fx).unwrap();
}

#[test]
fn an_update_is_checked_kept_and_loaded_again_at_the_next_start() {
    // No bundled DLL (none next to the console's exe) and a floor of 1.0: the real 1.1 DLL stands for a newer one.
    let fx = fixtures(LISTING, &[("wireguard-nt-1.1.zip", &sdk_zip())]);
    let args = ["--wireguard-updates", fx.to_str().unwrap(), "--wireguard-floor", "1.0"];
    let c = Console::start_with(&args);
    assert!(facts(&c).wireguard.problem.is_some_and(|p| p.contains("Repair WinVPN")));
    let r = c.call(&["wireguard-check"], b"");
    assert_eq!(EngineUpdate::parse(&r.stdout), Some(EngineUpdate { installed: None, available: Some("1.1.0".into()) }));
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!(r.code, 0, "{}", text(&r));
    assert_eq!(EngineUpdate::parse(&r.stdout), Some(EngineUpdate { installed: Some("1.1.0".into()), available: None }));
    let f = facts(&c);
    assert_eq!((f.wireguard.dll_version.as_deref(), f.wireguard.problem), (Some("1.1.0"), None));
    // Only the checked DLL is kept; the listing, the zip and the temporary DLL are gone.
    assert_eq!(engine_files(&c.data), ["wireguard.dll"]);
    // Nothing newer now (the check's cache was cleared by the update).
    let r = c.call(&["wireguard-check"], b"");
    assert_eq!(EngineUpdate::parse(&r.stdout), Some(EngineUpdate { installed: Some("1.1.0".into()), available: None }));
    let r = c.call(&["wireguard-update", "--lang", "en"], b"");
    assert_eq!((r.code, text(&r).as_str()), (1, "No newer wireguard-nt is available."));
    // A new start over the same data directory loads the download again (its signer checked again).
    let data = c.data.to_str().unwrap().to_owned();
    let pipe = test_pipe();
    let child = spawn(&["--pipe", &pipe, "--data", &data, "--existing-data", "--wireguard-floor", "1.0"]);
    // Its own drop must not remove the shared data directory (the first console's does).
    let unused = std::env::temp_dir().join(format!("winvpn-console-unused-{}", uuid::Uuid::new_v4()));
    let again = Console { child, pipe, data: unused };
    assert_eq!(facts(&again).wireguard.dll_version.as_deref(), Some("1.1.0"));
    drop(again);
    drop(c);
    std::fs::remove_dir_all(&fx).unwrap();
}
