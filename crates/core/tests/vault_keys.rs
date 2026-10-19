//! The vault key hierarchy (`vault.keys`) and the recovery key (spec 2.2, plan B Task 4).
//!
//! Every test uses the cheap [`KdfParams::insecure_for_tests`] so the suite stays fast; the one test with the real
//! [`KdfParams::DEFAULT`] is `#[ignore]`d.

mod common;

use common::{TempDir, mode};
use macvpn_core::vault::{
    AAD_PASSWORD, AAD_RECOVERY, Dek, Entropy, FixedEntropy, KEYS_FILE, KdfParams, KeyError, KeyFile, RecoveryKey,
    RecoveryKeyError, check_password_rules, derive_kek,
};
use std::fs;

const PASSWORD: &str = "correct horse battery";

fn kdf() -> KdfParams {
    KdfParams::insecure_for_tests()
}

fn fixture(seed: u64) -> (Dek, RecoveryKey, KeyFile) {
    let e = FixedEntropy::new(seed);
    let dek = Dek::generate(&e).unwrap();
    let rk = RecoveryKey::generate(&e).unwrap();
    let file = KeyFile::create(&dek, PASSWORD, &rk, kdf(), &e).unwrap();
    (dek, rk, file)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- Parameters and constants -----------------------------------------------------------------------------------

#[test]
fn constants_match_the_spec_and_the_spike() {
    assert_eq!(KEYS_FILE, "vault.keys");
    assert_eq!(AAD_PASSWORD, b"macvpn-vault-v1|pw");
    assert_eq!(AAD_RECOVERY, b"macvpn-vault-v1|rc");
    assert_eq!(KdfParams::DEFAULT, KdfParams { m_kib: 65536, t: 32, p: 1 });
    assert_eq!(KdfParams::insecure_for_tests(), KdfParams { m_kib: 64, t: 1, p: 1 });
}

// --- Entropy ------------------------------------------------------------------------------------------------------

#[test]
fn fixed_entropy_is_deterministic_and_not_constant() {
    let (mut a, mut b, mut c) = ([0u8; 100], [0u8; 100], [0u8; 100]);
    FixedEntropy::new(1).fill(&mut a).unwrap();
    FixedEntropy::new(1).fill(&mut b).unwrap();
    FixedEntropy::new(2).fill(&mut c).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    let e = FixedEntropy::new(1);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    e.fill(&mut x).unwrap();
    e.fill(&mut y).unwrap();
    assert_ne!(x, y, "the stream continues between fills");
}

// --- Known-answer vectors ---------------------------------------------------------------------------------------

/// Argon2id with the test parameters: catches a dependency upgrade that changes the KDF output.
#[test]
fn derive_kek_known_answer() {
    let kek = derive_kek(b"password", &[0x11; 16], kdf()).unwrap();
    assert_eq!(hex(&kek[..]), KAT_KEK);
}

/// Fixed seed, password and DEK: the exact wrapped bytes (XChaCha20-Poly1305 with the slot's AAD).
#[test]
fn wrap_known_answer() {
    let e = FixedEntropy::new(7);
    let dek = Dek::from_bytes(&[0x42; 32]).unwrap();
    let rk = RecoveryKey::parse("0000-0000-0000-0000-0000-0000").unwrap();
    let file = KeyFile::create(&dek, "password123", &rk, kdf(), &e).unwrap();
    assert_eq!(hex(&file.password.salt), KAT_PW_SALT);
    assert_eq!(hex(&file.password.nonce), KAT_PW_NONCE);
    assert_eq!(hex(&file.password.wrapped), KAT_PW_WRAPPED);
    assert_eq!(hex(&file.recovery.wrapped), KAT_RC_WRAPPED);
    assert_eq!(file.unlock_password("password123").unwrap().as_bytes(), &[0x42; 32]);
}

// Argon2id: equals the reference C implementation (`argon2 <salt> -id -k 64 -t 1 -p 1 -l 32`). The password
// slot's wrap was recomputed independently (that KEK, HChaCha20 + IETF ChaCha20-Poly1305 with the slot's AAD).
const KAT_KEK: &str = "0b46d021009599322d5a1a5aac7fc3fe3abca03cd05d98f51281febf7a6f5ca0";
const KAT_PW_SALT: &str = "e8dd943d366caae7beb706c6ae668eff";
const KAT_PW_NONCE: &str = "0a257fc56edc27d7b2fa1c31bdf2eec14ff190b4c2c573ec";
const KAT_PW_WRAPPED: &str =
    "0f56285c4fdd51c584435a1770d4af3fdaeca72d20dac28da6a43327ffc195de6f6ad3f50a72427c82a4ee5b49f295a4";
const KAT_RC_WRAPPED: &str =
    "93f8ecf6df48b570c5a1178da4c41bb9a29a45ba86aa46e588967a12d6cbdd42a3c2156b710a94cd0e8a01519c874d9b";

// --- Unwrap -----------------------------------------------------------------------------------------------------

#[test]
fn unwrap_with_the_password_or_the_recovery_key_gives_the_same_dek() {
    let (dek, rk, file) = fixture(1);
    assert_eq!(file.unlock_password(PASSWORD).unwrap().as_bytes(), dek.as_bytes());
    assert_eq!(file.unlock_recovery(&rk).unwrap().as_bytes(), dek.as_bytes());
    // The recovery key typed differently (lower case, spaces) still unlocks.
    let typed = RecoveryKey::parse(&rk.as_str().to_lowercase().replace('-', " ")).unwrap();
    assert_eq!(file.unlock_recovery(&typed).unwrap().as_bytes(), dek.as_bytes());
}

#[test]
fn wrong_password_and_wrong_recovery_key_are_both_wrong() {
    let (_, _, file) = fixture(1);
    assert!(matches!(file.unlock_password("not the password"), Err(KeyError::Wrong)));
    let other = RecoveryKey::generate(&FixedEntropy::new(99)).unwrap();
    assert!(matches!(file.unlock_recovery(&other), Err(KeyError::Wrong)));
    // The password typed as a recovery key and the other way round.
    assert!(matches!(file.unlock_password(other.as_str()), Err(KeyError::Wrong)));
}

/// Swapping the slots makes the AAD wrong: still `Wrong`, never something that tells which part failed.
#[test]
fn swapped_slots_are_wrong() {
    let (_, rk, mut file) = fixture(1);
    std::mem::swap(&mut file.password, &mut file.recovery);
    assert!(matches!(file.unlock_password(PASSWORD), Err(KeyError::Wrong)));
    assert!(matches!(file.unlock_recovery(&rk), Err(KeyError::Wrong)));
}

#[test]
fn flipped_bytes_are_wrong() {
    let (_, rk, file) = fixture(1);
    for i in 0..48 {
        let mut f = file.clone();
        f.password.wrapped[i] ^= 0x01;
        assert!(matches!(f.unlock_password(PASSWORD), Err(KeyError::Wrong)), "wrapped[{i}]");
    }
    for i in 0..24 {
        let mut f = file.clone();
        f.recovery.nonce[i] ^= 0x80;
        assert!(matches!(f.unlock_recovery(&rk), Err(KeyError::Wrong)), "nonce[{i}]");
    }
    for i in 0..16 {
        let mut f = file.clone();
        f.password.salt[i] ^= 0x01;
        assert!(matches!(f.unlock_password(PASSWORD), Err(KeyError::Wrong)), "salt[{i}]");
    }
}

#[test]
fn different_kdf_parameters_are_wrong() {
    let (_, _, mut file) = fixture(1);
    file.password.kdf = KdfParams { m_kib: 128, t: 1, p: 1 };
    assert!(matches!(file.unlock_password(PASSWORD), Err(KeyError::Wrong)));
}

// --- Rewrapping -------------------------------------------------------------------------------------------------

#[test]
fn set_password_rewraps_only_the_password_slot() {
    let (dek, rk, mut file) = fixture(2);
    let recovery_before = file.recovery.clone();
    file.set_password(&dek, "a brand new password", &FixedEntropy::new(3)).unwrap();
    assert!(matches!(file.unlock_password(PASSWORD), Err(KeyError::Wrong)));
    assert_eq!(file.unlock_password("a brand new password").unwrap().as_bytes(), dek.as_bytes());
    assert_eq!(file.recovery, recovery_before);
    assert_eq!(file.unlock_recovery(&rk).unwrap().as_bytes(), dek.as_bytes());
}

#[test]
fn set_recovery_invalidates_the_old_key() {
    let (dek, old, mut file) = fixture(2);
    let e = FixedEntropy::new(4);
    let new = RecoveryKey::generate(&e).unwrap();
    let password_before = file.password.clone();
    file.set_recovery(&dek, &new, &e).unwrap();
    assert!(matches!(file.unlock_recovery(&old), Err(KeyError::Wrong)));
    assert_eq!(file.unlock_recovery(&new).unwrap().as_bytes(), dek.as_bytes());
    assert_eq!(file.password, password_before);
}

#[test]
fn every_wrap_uses_fresh_salt_and_nonce() {
    let (dek, rk, file) = fixture(5);
    assert_ne!(file.password.salt, file.recovery.salt);
    assert_ne!(file.password.nonce, file.recovery.nonce);
    let mut again = file.clone();
    again.set_password(&dek, PASSWORD, &FixedEntropy::new(6)).unwrap();
    assert_ne!(again.password.nonce, file.password.nonce);
    assert_ne!(again.password.salt, file.password.salt);
    assert_eq!(again.unlock_recovery(&rk).unwrap().as_bytes(), dek.as_bytes());
}

// --- Recovery key format ----------------------------------------------------------------------------------------

const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[test]
fn recovery_key_is_six_groups_of_four_crockford_symbols() {
    for seed in 0..50 {
        let rk = RecoveryKey::generate(&FixedEntropy::new(seed)).unwrap();
        let s = rk.as_str();
        assert_eq!(s.len(), 29, "{seed}");
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 6);
        for (i, g) in groups.iter().enumerate() {
            assert_eq!(g.len(), 4);
            assert!(g.chars().all(|c| ALPHABET.contains(c)), "{g}");
            assert_eq!(rk.group(i), *g);
        }
    }
}

#[test]
fn two_generations_differ() {
    let e = FixedEntropy::new(8);
    let a = RecoveryKey::generate(&e).unwrap();
    let b = RecoveryKey::generate(&e).unwrap();
    assert_ne!(a.as_str(), b.as_str());
}

#[test]
fn recovery_key_encoding_is_big_endian_base32() {
    // 15 bytes of 0xFF → 120 one bits → 24 × 'Z'.
    let rk = RecoveryKey::parse("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ").unwrap();
    assert_eq!(&rk.secret_bytes()[..], &[0xFF; 15]);
    // 0x08 0x42 … : the first symbols are 00001 00001 00001 …
    let rk = RecoveryKey::parse("1111-1111-1111-1111-1111-1111").unwrap();
    assert_eq!(&rk.secret_bytes()[..5], &[0x08, 0x42, 0x10, 0x84, 0x21]);
}

#[test]
fn parse_is_lenient_about_case_separators_and_look_alikes() {
    let rk = RecoveryKey::generate(&FixedEntropy::new(10)).unwrap();
    let canonical = rk.as_str().to_string();
    let variants = [
        canonical.to_lowercase(),
        canonical.replace('-', " "),
        canonical.replace('-', ""),
        format!("  {}  ", canonical.replace('-', " - ")),
    ];
    for v in variants {
        assert_eq!(RecoveryKey::parse(&v).unwrap().as_str(), canonical, "{v}");
    }
    assert_eq!(RecoveryKey::parse("OoIi-Ll00-0000-0000-0000-0000").unwrap().as_str(), "0011-1100-0000-0000-0000-0000");
}

#[test]
fn parse_rejects_wrong_length_and_foreign_symbols() {
    assert!(matches!(RecoveryKey::parse("0000-0000-0000-0000-0000-000"), Err(RecoveryKeyError::WrongLength)));
    assert!(matches!(RecoveryKey::parse("0000-0000-0000-0000-0000-00000"), Err(RecoveryKeyError::WrongLength)));
    assert!(matches!(RecoveryKey::parse(""), Err(RecoveryKeyError::WrongLength)));
    assert!(matches!(RecoveryKey::parse("U000-0000-0000-0000-0000-0000"), Err(RecoveryKeyError::InvalidCharacter)));
    assert!(matches!(RecoveryKey::parse("0000_0000-0000-0000-0000-0000"), Err(RecoveryKeyError::InvalidCharacter)));
    assert!(matches!(RecoveryKey::parse("ÁÁÁÁ-0000-0000-0000-0000-0000"), Err(RecoveryKeyError::InvalidCharacter)));
}

// --- vault.keys -------------------------------------------------------------------------------------------------

#[test]
fn save_and_load_round_trip_with_mode_0600() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let (dek, _, file) = fixture(11);
    file.save(tmp.path()).unwrap();
    let path = tmp.path().join(KEYS_FILE);
    assert_eq!(mode(&path), 0o600);
    let loaded = KeyFile::load(tmp.path()).unwrap();
    assert_eq!(loaded, file);
    assert_eq!(loaded.unlock_password(PASSWORD).unwrap().as_bytes(), dek.as_bytes());
    // Saving again replaces the file atomically (no temp file left behind).
    file.save(tmp.path()).unwrap();
    let names: Vec<_> = fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from(KEYS_FILE)]);
}

#[test]
fn the_file_format_is_the_documented_json() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let (_, _, file) = fixture(12);
    file.save(tmp.path()).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&fs::read(tmp.path().join(KEYS_FILE)).unwrap()).unwrap();
    assert_eq!(json["version"], 1);
    assert!(json.get("kdf").is_none(), "the KDF parameters are per slot");
    for slot in ["password", "recovery"] {
        let keys: Vec<_> = json[slot].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["kdf", "nonce", "salt", "wrapped"]);
        assert_eq!(json[slot]["kdf"], serde_json::json!({"m_kib": 64, "t": 1, "p": 1}));
        assert!(json[slot]["salt"].is_string());
    }
}

#[test]
fn load_rejects_newer_versions_and_garbage() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let (_, _, file) = fixture(13);
    file.save(tmp.path()).unwrap();
    let path = tmp.path().join(KEYS_FILE);
    let good: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

    let write = |v: &serde_json::Value| fs::write(&path, serde_json::to_vec(v).unwrap()).unwrap();
    let mut v2 = good.clone();
    v2["version"] = 2.into();
    write(&v2);
    assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::UnsupportedVersion(2))));

    let corrupt = |v: serde_json::Value| {
        write(&v);
        assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Corrupt)), "{v}");
    };
    let mut bad = good.clone();
    bad["version"] = 0.into();
    corrupt(bad);
    let mut bad = good.clone();
    bad["password"]["salt"] = "AAAA".into(); // 3 bytes
    corrupt(bad);
    let mut bad = good.clone();
    bad["recovery"]["nonce"] = "not base64!".into();
    corrupt(bad);
    let mut bad = good.clone();
    bad["password"]["wrapped"] = "AAAA".into();
    corrupt(bad);
    let mut bad = good.clone();
    bad["password"]["kdf"]["t"] = 0.into();
    corrupt(bad);
    let mut bad = good.clone();
    bad["recovery"]["kdf"]["m_kib"] = 4.into();
    corrupt(bad);
    let mut bad = good.clone();
    bad["password"]["kdf"]["m_kib"] = u64::from(u32::MAX).into();
    corrupt(bad);
    let mut bad = good.clone();
    bad.as_object_mut().unwrap().remove("recovery");
    corrupt(bad);

    fs::write(&path, b"\x00\x01garbage").unwrap();
    assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Corrupt)));
    fs::write(&path, vec![b' '; 1024 * 1024]).unwrap();
    assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Corrupt)));
    fs::remove_file(&path).unwrap();
    assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Io(_))));
}

/// `vault.keys` is opened with `O_NOFOLLOW` (security review L4).
#[test]
fn load_refuses_a_symlinked_key_file() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let (_, _, file) = fixture(14);
    file.save(tmp.path()).unwrap();
    let real = tmp.path().join("elsewhere.keys");
    fs::rename(tmp.path().join(KEYS_FILE), &real).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join(KEYS_FILE)).unwrap();
    assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Io(_))));
}

// --- KDF floor and ceiling (security review M1) ------------------------------------------------------------------

/// Saves a key file and rewrites one slot's KDF parameters in the JSON.
fn file_with_slot_kdf(tmp: &TempDir, slot: &str, kdf: serde_json::Value) -> std::path::PathBuf {
    fs::create_dir_all(tmp.path()).unwrap();
    let (_, _, file) = fixture(20);
    file.save(tmp.path()).unwrap();
    let path = tmp.path().join(KEYS_FILE);
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    json[slot]["kdf"] = kdf;
    fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    path
}

#[test]
fn parameters_below_the_floor_are_corrupt() {
    for (slot, kdf) in [
        ("password", serde_json::json!({"m_kib": 65536, "t": 2, "p": 1})),
        ("recovery", serde_json::json!({"m_kib": 32768, "t": 32, "p": 1})),
        ("password", serde_json::json!({"m_kib": 64, "t": 2, "p": 1})),
        ("recovery", serde_json::json!({"m_kib": 65536, "t": 32, "p": 0})),
    ] {
        let tmp = TempDir::new();
        file_with_slot_kdf(&tmp, slot, kdf.clone());
        assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Corrupt)), "{slot} {kdf}");
    }
    // The floor itself (64 MiB, t = 3) and the default are accepted.
    for kdf in
        [serde_json::json!({"m_kib": 65536, "t": 3, "p": 1}), serde_json::json!({"m_kib": 65536, "t": 32, "p": 1})]
    {
        let tmp = TempDir::new();
        file_with_slot_kdf(&tmp, "password", kdf.clone());
        assert!(KeyFile::load(tmp.path()).is_ok(), "{kdf}");
    }
    // derive_kek refuses them too.
    assert!(matches!(derive_kek(b"x", &[0; 16], KdfParams { m_kib: 65536, t: 2, p: 1 }), Err(KeyError::Corrupt)));
    assert!(matches!(derive_kek(b"x", &[0; 16], KdfParams { m_kib: 128, t: 1, p: 1 }), Err(KeyError::Corrupt)));
}

#[test]
fn parameters_above_the_ceiling_are_corrupt() {
    for kdf in [
        serde_json::json!({"m_kib": 1024 * 1024 + 1, "t": 32, "p": 1}),
        serde_json::json!({"m_kib": 65536, "t": 257, "p": 1}),
        serde_json::json!({"m_kib": 65536, "t": 32, "p": 17}),
    ] {
        let tmp = TempDir::new();
        file_with_slot_kdf(&tmp, "recovery", kdf.clone());
        assert!(matches!(KeyFile::load(tmp.path()), Err(KeyError::Corrupt)), "{kdf}");
    }
    let tmp = TempDir::new();
    file_with_slot_kdf(&tmp, "recovery", serde_json::json!({"m_kib": 1024 * 1024, "t": 256, "p": 16}));
    assert!(KeyFile::load(tmp.path()).is_ok(), "the ceiling itself is accepted");
}

#[test]
fn create_refuses_parameters_below_the_floor() {
    let e = FixedEntropy::new(21);
    let dek = Dek::generate(&e).unwrap();
    let rk = RecoveryKey::generate(&e).unwrap();
    for kdf in [KdfParams { m_kib: 65536, t: 2, p: 1 }, KdfParams { m_kib: 128, t: 1, p: 1 }] {
        assert!(KeyFile::create(&dek, PASSWORD, &rk, kdf, &e).is_err(), "{kdf:?}");
    }
}

/// A rewrap never keeps weaker parameters than the default: each slot is raised on its own.
#[test]
fn a_rewrap_raises_weak_parameters_to_the_default() {
    let tmp = TempDir::new();
    file_with_slot_kdf(&tmp, "password", serde_json::json!({"m_kib": 65536, "t": 3, "p": 1}));
    let mut file = KeyFile::load(tmp.path()).unwrap();
    assert_eq!(file.password.kdf, KdfParams { m_kib: 65536, t: 3, p: 1 });
    let recovery_before = file.recovery.clone();
    let dek = Dek::from_bytes(&[3; 32]).unwrap();
    file.set_password(&dek, "a new password!", &FixedEntropy::new(22)).unwrap();
    assert_eq!(file.password.kdf, KdfParams::DEFAULT);
    assert_eq!(file.recovery, recovery_before, "the other slot is untouched");
    // Stronger-than-default parameters are kept (only raised, never lowered).
    assert_eq!(KdfParams { m_kib: 131072, t: 8, p: 2 }.strengthened(), KdfParams { m_kib: 131072, t: 32, p: 2 });
    assert_eq!(KdfParams { m_kib: 65536, t: 3, p: 1 }.strengthened(), KdfParams::DEFAULT);
}

// --- Password rules ---------------------------------------------------------------------------------------------

#[test]
fn password_rules_count_graphemes() {
    assert!(check_password_rules("123456789").is_err());
    assert!(check_password_rules("1234567890").is_ok());
    assert!(check_password_rules("").is_err());
    // Ten family emoji are ten characters (grapheme clusters), many more code points and bytes.
    assert!(check_password_rules(&"👨‍👩‍👧".repeat(10)).is_ok());
    assert!(check_password_rules(&"👨‍👩‍👧".repeat(9)).is_err());
    assert!(check_password_rules("árvíztűrő!").is_ok());
}

// --- Debug output ---------------------------------------------------------------------------------------------

#[test]
fn debug_shows_no_key_material() {
    let dek = Dek::from_bytes(&[0xAB; 32]).unwrap();
    let rk = RecoveryKey::parse("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ").unwrap();
    let file = KeyFile::create(&dek, PASSWORD, &rk, kdf(), &FixedEntropy::new(1)).unwrap();
    let all = format!("{dek:?} {rk:?} {file:?} {:?} {:?}", file.password, file.recovery);
    for needle in ["ab", "AB", "171", "ZZZZ", PASSWORD] {
        assert!(!all.contains(needle), "{needle} in {all}");
    }
    for bytes in [&file.password.wrapped[..], &file.password.salt[..], &file.recovery.nonce[..]] {
        assert!(!all.contains(&hex(&bytes[..4])), "{all}");
    }
}

#[test]
fn dek_from_bytes_requires_32_bytes_and_hex_is_lower_case() {
    assert!(Dek::from_bytes(&[0; 31]).is_none());
    assert!(Dek::from_bytes(&[0; 33]).is_none());
    let dek = Dek::from_bytes(&[0xAB; 32]).unwrap();
    assert_eq!(dek.hex().as_str(), "ab".repeat(32));
}

// --- Real cost ------------------------------------------------------------------------------------------------

/// The production parameters (spike report C: about 0.66 s on an M5 in a release build).
#[test]
#[ignore = "slow: Argon2id with the production parameters"]
fn default_parameters_timing() {
    let start = std::time::Instant::now();
    let kek = derive_kek(PASSWORD.as_bytes(), &[7; 16], KdfParams::DEFAULT).unwrap();
    println!("Argon2id {:?}: {:?}", KdfParams::DEFAULT, start.elapsed());
    assert_eq!(kek.len(), 32);
}
