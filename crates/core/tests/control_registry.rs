//! The control API's paired-client registry: tokens, pinning, the allowlist, persistence and the pairing rate
//! limit.

mod common;

use common::TempDir;
#[cfg(unix)]
use common::mode;
use macvpn_core::control::protocol::{ErrorCode, is_token_shaped};
use macvpn_core::control::registry::*;
use macvpn_core::date::Date;
use std::fs;
use uuid::Uuid;

const APP: &str = "/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop";
const KEY_A: &str = "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5B";
const KEY_B: &str = "6A1C1E0B-9F57-4D16-9E2A-7C0B3B6F4E21";

fn at(seconds: f64) -> Date {
    Date::from_time_interval_since_1970(1_790_000_000.0 + seconds)
}

fn client(entropy: u8, executable: &str, allowed: &[&str]) -> (PairedClient, String) {
    let token = new_token([entropy; 32]);
    let c = PairedClient::new(
        Uuid::new_v4(),
        "Remote Desktop".into(),
        &token,
        executable.into(),
        allowed.iter().map(|s| s.to_string()).collect(),
        at(0.0),
    );
    (c, token)
}

fn registry() -> (Registry, Uuid, String, Uuid, String) {
    let mut r = Registry::new();
    let (a, token_a) = client(1, APP, &[KEY_A]);
    let (b, token_b) = client(2, "/Users/me/dev/target/debug/rd", &[KEY_A, KEY_B]);
    let (id_a, id_b) = (a.id, b.id);
    r.add(a);
    r.add(b);
    (r, id_a, token_a, id_b, token_b)
}

// MARK: Tokens

#[test]
fn token_is_43_base64url_chars_and_depends_on_entropy() {
    let a = new_token([0; 32]);
    let b = new_token([1; 32]);
    assert_eq!(a.len(), 43);
    assert_eq!(b.len(), 43);
    assert_ne!(a, b);
    assert!(is_token_shaped(&a) && is_token_shaped(&b));
    assert_eq!(a, "A".repeat(43));
    // The URL-safe alphabet, no padding.
    let mut entropy = [0u8; 32];
    for chunk in entropy[..30].chunks_mut(3) {
        chunk.copy_from_slice(&[0xFB, 0xEF, 0xBE]);
    }
    entropy[30] = 0xFF;
    entropy[31] = 0xFF;
    assert_eq!(new_token(entropy), format!("{}__8", "-".repeat(40)));
}

#[test]
fn only_the_hash_is_stored() {
    let (c, token) = client(7, APP, &[KEY_A]);
    assert_eq!(c.token_sha256, token_sha256(&token));
    assert_eq!(token_sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert!(!format!("{c:?}").contains(&token));
    assert!(!format!("{c:?}").contains(&c.token_sha256));
}

// MARK: Authentication

#[test]
fn authenticate_with_right_token_and_path() {
    let (r, id_a, token_a, id_b, token_b) = registry();
    assert_eq!(r.authenticate(&token_a, APP).unwrap().id, id_a);
    assert_eq!(r.authenticate(&token_b, "/Users/me/dev/target/debug/rd").unwrap().id, id_b);
}

#[test]
fn wrong_token_is_unauthorized() {
    let (r, _, token_a, _, _) = registry();
    assert_eq!(r.authenticate(&new_token([9; 32]), APP).unwrap_err(), ErrorCode::Unauthorized);
    let mut flipped = token_a.into_bytes();
    flipped[42] = if flipped[42] == b'A' { b'B' } else { b'A' };
    assert_eq!(r.authenticate(&String::from_utf8(flipped).unwrap(), APP).unwrap_err(), ErrorCode::Unauthorized);
    assert_eq!(r.authenticate("", APP).unwrap_err(), ErrorCode::Unauthorized);
    assert_eq!(Registry::new().authenticate(&new_token([1; 32]), APP).unwrap_err(), ErrorCode::Unauthorized);
}

#[test]
fn wrong_path_is_unauthorized() {
    let (r, _, token_a, _, token_b) = registry();
    for path in ["", "/Applications/Remote Desktop.app", &format!("{APP} "), &format!("{APP}/"), "/tmp/rd"] {
        assert_eq!(r.authenticate(&token_a, path).unwrap_err(), ErrorCode::Unauthorized, "{path}");
    }
    // Client B's token from client A's path.
    assert_eq!(r.authenticate(&token_b, APP).unwrap_err(), ErrorCode::Unauthorized);
}

#[test]
fn identify_finds_the_token_whatever_the_path() {
    let (mut r, id_a, token_a, id_b, token_b) = registry();
    assert_eq!(r.identify(&token_a), Some(id_a));
    assert_eq!(r.identify(&token_b), Some(id_b));
    assert_eq!(r.identify(&new_token([9; 32])), None);
    assert_eq!(r.identify(""), None);
    r.revoke(id_a);
    assert_eq!(r.identify(&token_a), None);
}

#[test]
fn revoked_client_is_unauthorized() {
    let (mut r, id_a, token_a, id_b, token_b) = registry();
    assert!(r.revoke(id_a));
    assert!(!r.revoke(id_a));
    assert_eq!(r.authenticate(&token_a, APP).unwrap_err(), ErrorCode::Unauthorized);
    assert!(r.get(id_a).is_none());
    assert_eq!(r.authenticate(&token_b, "/Users/me/dev/target/debug/rd").unwrap().id, id_b);
    assert_eq!(r.clients().len(), 1);
}

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq(&[0; 32], &[0; 32]));
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = 1;
        assert!(!constant_time_eq(&[0; 32], &b), "{i}");
        b[i] = 0;
    }
}

// MARK: Allowlist and bookkeeping

#[test]
fn allowlist_is_enforced() {
    let (mut r, id_a, token_a, _, _) = registry();
    let a = r.authenticate(&token_a, APP).unwrap();
    assert!(Registry::is_allowed(a, KEY_A));
    assert!(!Registry::is_allowed(a, KEY_B));
    assert!(!Registry::is_allowed(a, &KEY_A.to_lowercase()));
    assert!(!Registry::is_allowed(a, ""));

    assert!(r.set_allowed(id_a, vec![KEY_B.into()]));
    let a = r.get(id_a).unwrap();
    assert!(!Registry::is_allowed(a, KEY_A));
    assert!(Registry::is_allowed(a, KEY_B));
    assert!(!r.set_allowed(Uuid::new_v4(), vec![KEY_A.into()]));
}

#[test]
fn touch_sets_last_used() {
    let (mut r, id_a, _, _, _) = registry();
    assert_eq!(r.get(id_a).unwrap().last_used, None);
    assert!(r.touch(id_a, at(60.0)));
    assert_eq!(r.get(id_a).unwrap().last_used, Some(at(60.0)));
    assert!(!r.touch(Uuid::new_v4(), at(60.0)));
}

#[test]
fn add_replaces_the_same_id() {
    let (mut r, id_a, _, _, _) = registry();
    let (mut again, token) = client(3, "/Applications/Other.app/Contents/MacOS/Other", &[]);
    again.id = id_a;
    r.add(again);
    assert_eq!(r.clients().len(), 2);
    assert_eq!(r.authenticate(&token, "/Applications/Other.app/Contents/MacOS/Other").unwrap().id, id_a);
}

// MARK: Persistence

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn save_then_load_round_trips() {
    let tmp = TempDir::new();
    let (mut r, id_a, token_a, _, _) = registry();
    r.touch(id_a, at(3600.0));
    r.save(tmp.path()).unwrap();
    let loaded = Registry::load(tmp.path()).unwrap();
    assert_eq!(loaded.clients(), r.clients());
    assert_eq!(loaded.authenticate(&token_a, APP).unwrap().id, id_a);
    // The token itself is never written.
    let text = fs::read_to_string(Registry::path(tmp.path())).unwrap();
    assert!(!text.contains(&token_a));
    assert!(text.contains(&token_sha256(&token_a)));
}

#[test]
fn client_values_round_trip_and_refuse_bad_entries() {
    let (mut r, id_a, token_a, _, _) = registry();
    r.touch(id_a, at(3600.0));
    let values = r.client_values();
    assert_eq!(values.len(), 2);
    let back = Registry::from_client_values(&values).unwrap();
    assert_eq!(back.clients(), r.clients());
    assert_eq!(back.authenticate(&token_a, APP).unwrap().id, id_a);
    // A repeated id or a malformed entry: nothing (never an incomplete registry).
    assert!(Registry::from_client_values(&[values[0].clone(), values[0].clone()]).is_none());
    assert!(Registry::from_client_values(&[values[0].clone(), serde_json::json!({"id": 1})]).is_none());
    assert!(Registry::from_client_values(&[]).unwrap().clients().is_empty());
}

#[test]
fn missing_file_is_empty_registry() {
    let tmp = TempDir::new();
    assert!(Registry::load(tmp.path()).unwrap().clients().is_empty());
    assert!(Registry::load(&tmp.path().join("nope")).unwrap().clients().is_empty());
}

#[cfg(unix)]
#[test]
fn file_mode_is_0600_and_dir_0700() {
    let tmp = TempDir::new();
    let dir = tmp.path().join("MacVPN");
    let (r, ..) = registry();
    r.save(&dir).unwrap();
    assert_eq!(Registry::path(&dir), dir.join("control-clients.json"));
    assert_eq!(mode(&Registry::path(&dir)), 0o600);
    assert_eq!(mode(&dir), 0o700);
    // An existing wider file is replaced, not rewritten in place.
    fs::set_permissions(Registry::path(&dir), std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    r.save(&dir).unwrap();
    assert_eq!(mode(&Registry::path(&dir)), 0o600);
    // No temp files left behind.
    let names: Vec<String> =
        fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, ["control-clients.json"]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn corrupt_file_is_empty_registry_and_renamed_to_bad() {
    let (r, ..) = registry();
    let good = {
        let tmp = TempDir::new();
        r.save(tmp.path()).unwrap();
        fs::read_to_string(Registry::path(tmp.path())).unwrap()
    };
    let bad_hash = good.replacen("tokenSha256\" : \"", "tokenSha256\" : \"x", 1);
    assert_ne!(bad_hash, good);
    let cases: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        b"".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        br#"{"clients":[{}]}"#.to_vec(),
        bad_hash.into_bytes(),
        good.replacen("\"id\" : \"", "\"id\" : \"x", 1).into_bytes(),
        vec![0xFF, 0xFE],
    ];
    for data in cases {
        let tmp = TempDir::new();
        let path = Registry::path(tmp.path());
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(&path, &data).unwrap();
        let loaded = Registry::load(tmp.path()).unwrap();
        assert!(loaded.clients().is_empty(), "{:?}", String::from_utf8_lossy(&data));
        assert!(!path.exists());
        assert_eq!(fs::read(tmp.path().join("control-clients.json.bad")).unwrap(), data);
        // The next save starts a fresh file.
        loaded.save(tmp.path()).unwrap();
        assert!(Registry::load(tmp.path()).unwrap().clients().is_empty());
    }
}

// MARK: Pairing rate limit

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn pairing_rate_limit_with_fake_clock() {
    let mut r = Registry::new();
    assert!(!r.pairing_blocked(at(0.0)));
    r.record_rejection(at(0.0));
    r.record_rejection(at(60.0));
    assert!(!r.pairing_blocked(at(60.0)), "two rejections do not block");
    r.record_rejection(at(120.0));
    assert!(r.pairing_blocked(at(120.0)));
    assert!(r.pairing_blocked(at(719.0)));
    assert!(!r.pairing_blocked(at(720.0)), "10 min after the newest");
    assert!(!r.pairing_blocked(at(5000.0)));

    // Three rejections that do not fall inside 10 minutes.
    let mut r = Registry::new();
    r.record_rejection(at(0.0));
    r.record_rejection(at(400.0));
    r.record_rejection(at(700.0));
    assert!(!r.pairing_blocked(at(700.0)));
    // Only the last three count: 400, 700, 800.
    r.record_rejection(at(800.0));
    assert!(r.pairing_blocked(at(800.0)));
    assert!(r.pairing_blocked(at(1399.0)));
    assert!(!r.pairing_blocked(at(1400.0)));

    // Memory only: a loaded registry starts unblocked.
    let tmp = TempDir::new();
    r.save(tmp.path()).unwrap();
    assert!(!Registry::load(tmp.path()).unwrap().pairing_blocked(at(800.0)));
}

#[test]
fn clock_jumping_back_does_not_block_for_long() {
    let mut r = Registry::new();
    r.record_rejection(at(0.0));
    r.record_rejection(at(60.0));
    r.record_rejection(at(120.0));
    // A little back in time still counts as inside the block.
    assert!(r.pairing_blocked(at(100.0)));
    assert!(r.pairing_blocked(at(-480.0)));
    // More than 10 minutes before the newest rejection: the clock jumped, unblock.
    assert!(!r.pairing_blocked(at(-481.0)));
    assert!(!r.pairing_blocked(at(-100_000.0)));
}

#[test]
fn load_fails_when_the_file_is_a_directory() {
    let tmp = TempDir::new();
    let path = Registry::path(tmp.path());
    fs::create_dir_all(&path).unwrap();
    assert!(Registry::load(tmp.path()).is_err());
    // Nothing is renamed: the caller must not save over it.
    assert!(path.is_dir());
    assert!(!tmp.path().join("control-clients.json.bad").exists());
}

#[test]
fn existing_bad_file_is_replaced() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let bad = tmp.path().join("control-clients.json.bad");
    fs::write(&bad, b"older").unwrap();
    fs::write(Registry::path(tmp.path()), b"newer").unwrap();
    assert!(Registry::load(tmp.path()).unwrap().clients().is_empty());
    assert_eq!(fs::read(&bad).unwrap(), b"newer");
    assert!(!Registry::path(tmp.path()).exists());
}

#[test]
fn forget_keys_prunes_every_allowlist() {
    let (mut r, id_a, _, id_b, _) = registry();
    assert!(r.forget_keys(&[KEY_A.to_string(), "00000000-0000-0000-0000-00000000000F".into()]));
    assert!(r.get(id_a).unwrap().allowed.is_empty());
    assert_eq!(r.get(id_b).unwrap().allowed, [KEY_B]);
    assert!(!r.forget_keys(&[KEY_A.to_string()]), "nothing left to forget");
}
