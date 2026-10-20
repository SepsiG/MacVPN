//! Team catalog keys (spec 3 and 7, plan Task 2): the team key text, the admin signing key, the publisher key and
//! its fingerprint. The known-answer vectors were computed independently (Python `hashlib` for the
//! `FixedEntropy` stream, the Crockford text and the fingerprint; the public key with OpenSSL 3 in the spike).

use macvpn_core::catalog::keys::{
    AdminKey, Fingerprint, FingerprintError, KEY_FINGERPRINT_DOMAIN, PublisherKey, TEAM_KEY_PREFIX, TeamKey,
    TeamKeyError,
};
use macvpn_core::vault::{Entropy, FixedEntropy};
use regex::Regex;

const KAT_TEAM_KEY: &str = "TEAM-F0W2-B0HA-DYF6-5PH1-J3M2-HS69-T9BP-WPBQ-WEGB-6RGB-14PZ-Q7MS-JVX0-BGF6";
const KAT_ADMIN_SEED: &str = "e8dd943d366caae7beb706c6ae668eff0a257fc56edc27d7b2fa1c31bdf2eec1";
const KAT_ADMIN_PUBLIC: &str = "95e19a2555f7f773e488bb22e8b9e1e9d92bc9caeefff8ec996e323e7bfed68e";
const KAT_FINGERPRINT: &str = "993F-0ECA-76C5-C969-D41D-C78A-4969-1B78";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn team_key(seed: u64) -> TeamKey {
    TeamKey::generate(&FixedEntropy::new(seed)).unwrap()
}

fn admin_key(seed: u64) -> AdminKey {
    AdminKey::generate(&FixedEntropy::new(seed)).unwrap()
}

/// The text without the prefix and separators, as symbols.
fn symbols(text: &str) -> Vec<char> {
    text.strip_prefix(TEAM_KEY_PREFIX).unwrap().chars().filter(|c| *c != '-').collect()
}

// MARK: - team key

#[test]
fn team_key_round_trips_through_its_text() {
    let key = team_key(1);
    let text = key.to_text();
    let parsed = TeamKey::parse(&text).unwrap();
    assert_eq!(parsed.as_bytes(), key.as_bytes());
    assert_eq!(&*parsed.to_text(), &*text);
}

#[test]
fn team_key_text_has_the_documented_shape() {
    let shape = Regex::new("^TEAM(-[0-9A-HJKMNP-TV-Z]{4}){14}$").unwrap();
    for seed in 0..50 {
        let text = team_key(seed).to_text();
        assert!(shape.is_match(&text), "{}", text.len());
    }
}

#[test]
fn team_key_known_answer() {
    let key = team_key(1);
    assert_eq!(&*key.to_text(), KAT_TEAM_KEY);
    // The same stream gives the same bytes.
    let mut bytes = [0u8; 32];
    FixedEntropy::new(1).fill(&mut bytes).unwrap();
    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn team_key_parse_is_forgiving_about_case_spaces_prefix_and_look_alikes() {
    let key = team_key(1);
    let text = key.to_text().to_string();
    let lower = text.to_lowercase();
    let spaced = text.replace('-', " ");
    let without_prefix = text.strip_prefix(TEAM_KEY_PREFIX).unwrap().to_string();
    let prefix_without_dash = format!("team {without_prefix}");
    let multiline = format!("  {}\n{}  ", &text[..30], &text[30..]);
    let look_alikes = text.replace('0', "O").replace('1', "l");
    for input in [lower, spaced, without_prefix, prefix_without_dash, multiline, look_alikes] {
        assert_eq!(TeamKey::parse(&input).unwrap().as_bytes(), key.as_bytes(), "{input}");
    }
    let i_for_one = text.replace('1', "I");
    assert_eq!(TeamKey::parse(&i_for_one).unwrap().as_bytes(), key.as_bytes());
}

#[test]
fn a_key_whose_first_group_reads_team_still_parses_without_a_prefix() {
    // T, E, A, M = 26, 14, 10, 20 = 11010 01110 01010 10100: the bytes D3 95 4…
    let mut bytes = [0x5au8; 32];
    bytes[..3].copy_from_slice(&[0xd3, 0x95, 0x40]);
    let key = TeamKey::from_bytes(&bytes).unwrap();
    let text = key.to_text();
    assert!(text.starts_with("TEAM-TEAM-"), "{}", &text[..10]);
    let bare: String = symbols(&text).iter().collect();
    assert_eq!(TeamKey::parse(&bare).unwrap().as_bytes(), &bytes);
    assert_eq!(TeamKey::parse(&text).unwrap().as_bytes(), &bytes);
    assert_eq!(TeamKey::parse(&text[5..]).unwrap().as_bytes(), &bytes);
}

#[test]
fn team_key_wrong_lengths() {
    let s = symbols(&team_key(1).to_text());
    let short: String = s[..55].iter().collect();
    let long: String = s.iter().chain(['0'].iter()).collect();
    assert_eq!(TeamKey::parse(&short).err(), Some(TeamKeyError::WrongLength));
    assert_eq!(TeamKey::parse(&long).err(), Some(TeamKeyError::WrongLength));
    assert_eq!(TeamKey::parse("").err(), Some(TeamKeyError::WrongLength));
    assert_eq!(TeamKey::parse("TEAM-").err(), Some(TeamKeyError::WrongLength));
}

#[test]
fn a_changed_symbol_is_a_typo() {
    let text = team_key(1).to_text().to_string();
    let s = symbols(&text);
    // Change each key symbol in turn (the last key symbol carries padding bits, so change it to a value with zero
    // padding).
    for i in 0..52 {
        let mut t = s.clone();
        t[i] = if i == 51 {
            if t[i] == '0' { 'G' } else { '0' }
        } else if t[i] == '2' {
            '3'
        } else {
            '2'
        };
        let input: String = t.iter().collect();
        assert_eq!(TeamKey::parse(&input).err(), Some(TeamKeyError::Typo), "symbol {i}");
    }
    // A changed check symbol too.
    let mut t = s.clone();
    t[55] = if t[55] == '2' { '3' } else { '2' };
    assert_eq!(TeamKey::parse(&t.iter().collect::<String>()).err(), Some(TeamKeyError::Typo));
}

#[test]
fn invalid_characters() {
    let text = team_key(1).to_text().to_string();
    let u = format!("{}U{}", &text[..10], &text[11..]);
    assert_eq!(TeamKey::parse(&u).err(), Some(TeamKeyError::InvalidCharacter));
    let unicode = format!("{}é{}", &text[..10], &text[11..]);
    assert_eq!(TeamKey::parse(&unicode).err(), Some(TeamKeyError::InvalidCharacter));
    let underscore = text.replace('-', "_");
    assert_eq!(TeamKey::parse(&underscore).err(), Some(TeamKeyError::InvalidCharacter));
}

#[test]
fn non_zero_padding_bits_are_an_invalid_character() {
    let s = symbols(&team_key(1).to_text());
    // The 52nd symbol holds 1 key bit and 4 padding bits: any value with one of the low 4 bits set is not
    // canonical.
    let mut t = s.clone();
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let value = alphabet.find(t[51]).unwrap();
    t[51] = alphabet.chars().nth(value | 1).unwrap();
    assert_ne!(t[51], s[51]);
    assert_eq!(TeamKey::parse(&t.iter().collect::<String>()).err(), Some(TeamKeyError::InvalidCharacter));
}

#[test]
fn two_generations_differ() {
    let e = FixedEntropy::new(3);
    let a = TeamKey::generate(&e).unwrap();
    let b = TeamKey::generate(&e).unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(&*a.to_text(), &*b.to_text());
}

#[test]
fn groups_for_the_retype_check() {
    let key = team_key(1);
    let text = key.to_text();
    let groups: Vec<&str> = text.strip_prefix(TEAM_KEY_PREFIX).unwrap().split('-').collect();
    assert_eq!(groups.len(), 14);
    for (i, g) in groups.iter().enumerate() {
        assert_eq!(&*key.group(i), *g);
    }
    assert_eq!(&*key.group(14), "");
}

#[test]
fn team_key_from_bytes() {
    let key = team_key(1);
    let copy = TeamKey::from_bytes(key.as_bytes()).unwrap();
    assert_eq!(copy.as_bytes(), key.as_bytes());
    assert!(TeamKey::from_bytes(&[0u8; 31]).is_none());
    assert!(TeamKey::from_bytes(&[0u8; 33]).is_none());
}

#[test]
fn debug_output_shows_no_key_material() {
    let key = team_key(1);
    let debug = format!("{key:?}");
    assert!(!debug.contains(&key.to_text()[5..9]));
    assert!(!debug.contains(&hex(key.as_bytes())[..8]));
    assert_eq!(debug, "TeamKey(..)");

    let admin = admin_key(7);
    let debug = format!("{admin:?}");
    assert!(!debug.contains(&KAT_ADMIN_SEED[..8]));
    assert!(!debug.to_lowercase().contains(&hex(&admin.seed()[..])[..8]));
    // The public half may be shown, as its fingerprint.
    assert!(debug.contains(KAT_FINGERPRINT), "{debug}");
}

// MARK: - admin key

#[test]
fn admin_key_known_answer() {
    let admin = admin_key(7);
    assert_eq!(hex(&admin.seed()[..]), KAT_ADMIN_SEED);
    assert_eq!(hex(admin.public().as_bytes()), KAT_ADMIN_PUBLIC);
    assert_eq!(admin.public().fingerprint().to_text(), KAT_FINGERPRINT);
}

#[test]
fn admin_key_from_seed() {
    let admin = admin_key(7);
    let again = AdminKey::from_seed(&admin.seed()[..]).unwrap();
    assert_eq!(again.public(), admin.public());
    assert!(AdminKey::from_seed(&[1u8; 31]).is_none());
    assert!(AdminKey::from_seed(&[1u8; 33]).is_none());
}

#[test]
fn signatures_verify_and_tampering_fails() {
    let admin = admin_key(7);
    let other = admin_key(8);
    let message = b"macvpn-catalog-v1\nthe signed bytes";
    let signature = admin.sign(message);
    let public = admin.public();
    assert!(public.verify(message, &signature));
    // Ed25519 is deterministic.
    assert_eq!(admin.sign(message), signature);

    for i in 0..message.len() {
        let mut m = message.to_vec();
        m[i] ^= 0x01;
        assert!(!public.verify(&m, &signature), "message byte {i}");
    }
    for i in 0..64 {
        let mut s = signature;
        s[i] ^= 0x01;
        assert!(!public.verify(message, &s), "signature byte {i}");
    }
    assert!(!other.public().verify(message, &signature));
    assert!(other.public().verify(message, &other.sign(message)));
}

#[test]
fn small_order_and_invalid_public_keys_are_refused() {
    // The identity point and the other small-order encodings (spike C.3: dalek's from_bytes accepts them).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(PublisherKey::from_bytes(&identity).is_none());
    assert!(PublisherKey::from_bytes(&[0u8; 32]).is_none());
    // Order 2: the point (0, -1).
    let mut order2 = [0xffu8; 32];
    order2[0] = 0xec;
    order2[31] = 0x7f;
    assert!(PublisherKey::from_bytes(&order2).is_none());
    // Wrong lengths.
    assert!(PublisherKey::from_bytes(&[9u8; 31]).is_none());
    assert!(PublisherKey::from_bytes(&[9u8; 33]).is_none());
    // A real key is accepted and round-trips.
    let public = admin_key(7).public();
    assert_eq!(PublisherKey::from_bytes(public.as_bytes()), Some(public));
}

// MARK: - fingerprint

#[test]
fn fingerprint_is_the_domain_separated_hash() {
    use sha2::{Digest, Sha256};
    let public = admin_key(7).public();
    let mut h = Sha256::new();
    h.update(KEY_FINGERPRINT_DOMAIN);
    h.update(public.as_bytes());
    let digest = h.finalize();
    let expected: String = hex(&digest[..16]).to_uppercase();
    assert_eq!(public.fingerprint().to_text().replace('-', ""), expected);
}

#[test]
fn fingerprint_text_format_and_parse() {
    let shape = Regex::new("^[0-9A-F]{4}(-[0-9A-F]{4}){7}$").unwrap();
    let fp = admin_key(7).public().fingerprint();
    let text = fp.to_text();
    assert!(shape.is_match(&text));
    assert_eq!(Fingerprint::parse(&text), Ok(fp));
    assert_eq!(Fingerprint::parse(&text.to_lowercase()), Ok(fp));
    assert_eq!(Fingerprint::parse(&text.replace('-', " ")), Ok(fp));
    assert_eq!(Fingerprint::parse(&format!("  {}  ", text.replace('-', ""))), Ok(fp));
    assert_ne!(admin_key(8).public().fingerprint(), fp);
}

#[test]
fn fingerprint_parse_errors() {
    let digits = admin_key(7).public().fingerprint().to_text().replace('-', "");
    assert_eq!(Fingerprint::parse(&digits[..31]), Err(FingerprintError::WrongLength));
    assert_eq!(Fingerprint::parse(&format!("{digits}0")), Err(FingerprintError::WrongLength));
    assert_eq!(Fingerprint::parse(""), Err(FingerprintError::WrongLength));
    assert_eq!(Fingerprint::parse(&format!("{}G", &digits[..31])), Err(FingerprintError::InvalidCharacter));
    assert_eq!(Fingerprint::parse(&format!("{}_", &digits[..31])), Err(FingerprintError::InvalidCharacter));
}
