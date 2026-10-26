//! The subscription string `macvpn-sub:<base64url JSON>` (spec 5, plan Task 5).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use macvpn_core::catalog::keys::{AdminKey, TeamKey, TeamKeyError};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl, SourceError};
use macvpn_core::catalog::subscription::{
    MAX_SUBSCRIPTION_CHARS, SUBSCRIPTION_PREFIX, SubscriptionError, SubscriptionString, format_subscription,
    parse_subscription,
};
use macvpn_core::vault::FixedEntropy;
use std::path::PathBuf;

fn https_subscription() -> SubscriptionString {
    let e = FixedEntropy::new(5);
    SubscriptionString {
        source: CatalogSource::Https(
            HttpsUrl::parse("https://catalog.example.com/team.macvpncatalog?sig=abc").unwrap(),
        ),
        team_key: TeamKey::generate(&e).unwrap(),
        fingerprint: AdminKey::generate(&e).unwrap().public().fingerprint(),
        catalog_id: None,
        min_version: None,
    }
}

/// A file source: an absolute path of this OS (`/Volumes/…` is drive-relative on Windows, so refused there), and the
/// same path as a JSON string's content.
const FILE: &str =
    if cfg!(windows) { r"\\fileserver\Team\team.macvpncatalog" } else { "/Volumes/Team/team.macvpncatalog" };
const FILE_JSON: &str =
    if cfg!(windows) { r"\\\\fileserver\\Team\\team.macvpncatalog" } else { "/Volumes/Team/team.macvpncatalog" };

fn encoded(json: &str) -> String {
    format!("{SUBSCRIPTION_PREFIX}{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

fn json_of(s: &str) -> String {
    let body = s.strip_prefix(SUBSCRIPTION_PREFIX).unwrap();
    String::from_utf8(URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap()
}

fn same(a: &SubscriptionString, b: &SubscriptionString) {
    assert_eq!(a.source, b.source);
    assert_eq!(a.team_key.as_bytes(), b.team_key.as_bytes());
    assert_eq!(a.fingerprint, b.fingerprint);
    assert_eq!(a.catalog_id, b.catalog_id);
    assert_eq!(a.min_version, b.min_version);
}

#[test]
fn round_trip_https_and_file() {
    let s = https_subscription();
    let text = format_subscription(&s);
    assert!(text.starts_with(SUBSCRIPTION_PREFIX));
    same(&parse_subscription(&text).unwrap(), &s);

    let file = SubscriptionString {
        source: CatalogSource::File(PathBuf::from(FILE)),
        team_key: TeamKey::generate(&FixedEntropy::new(6)).unwrap(),
        fingerprint: s.fingerprint,
        catalog_id: None,
        min_version: None,
    };
    same(&parse_subscription(&format_subscription(&file)).unwrap(), &file);
}

#[test]
fn the_json_shape() {
    let s = https_subscription();
    let json = json_of(&format_subscription(&s));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["source"]["https"], "https://catalog.example.com/team.macvpncatalog?sig=abc");
    assert_eq!(v["teamKey"].as_str().unwrap(), &*s.team_key.to_text());
    assert_eq!(v["fingerprint"].as_str().unwrap(), s.fingerprint.to_text());
    assert_eq!(v.as_object().unwrap().len(), 4);
}

#[test]
fn outer_white_space_is_trimmed_but_nothing_else() {
    let s = https_subscription();
    let text = format_subscription(&s).to_string();
    same(&parse_subscription(&format!("  \n{text}\t \n")).unwrap(), &s);
    // A line break inside the base64 (copied from mail) is refused: the UI strips only the outer white space.
    let (head, tail) = text.split_at(40);
    assert_eq!(parse_subscription(&format!("{head}\n{tail}")).err(), Some(SubscriptionError::Malformed));
    assert_eq!(parse_subscription(&format!("{head} {tail}")).err(), Some(SubscriptionError::Malformed));
    assert_eq!(parse_subscription(&format!("Here it is: {text}")).err(), Some(SubscriptionError::NotASubscription));
    assert_eq!(parse_subscription(&format!("{text} thanks")).err(), Some(SubscriptionError::Malformed));
}

#[test]
fn wrong_prefix_and_length() {
    let text = format_subscription(&https_subscription()).to_string();
    let body = text.strip_prefix(SUBSCRIPTION_PREFIX).unwrap();
    assert_eq!(parse_subscription(&format!("macvpn-subs:{body}")).err(), Some(SubscriptionError::NotASubscription));
    assert_eq!(parse_subscription(body).err(), Some(SubscriptionError::NotASubscription));
    assert_eq!(parse_subscription("").err(), Some(SubscriptionError::NotASubscription));
    let long = format!("{SUBSCRIPTION_PREFIX}{}", "A".repeat(MAX_SUBSCRIPTION_CHARS + 1 - SUBSCRIPTION_PREFIX.len()));
    assert_eq!(long.chars().count(), MAX_SUBSCRIPTION_CHARS + 1);
    assert_eq!(parse_subscription(&long).err(), Some(SubscriptionError::TooLong));
}

#[test]
fn json_rules() {
    let s = https_subscription();
    let key = s.team_key.to_text().to_string();
    let fp = s.fingerprint.to_text();
    assert_eq!(serde_json::to_string(FILE).unwrap(), format!("\"{FILE_JSON}\""));
    let good = format!(r#"{{"v":1,"source":{{"file":"{FILE_JSON}"}},"teamKey":"{key}","fingerprint":"{fp}"}}"#);
    assert_eq!(parse_subscription(&encoded(&good)).unwrap().source, CatalogSource::File(PathBuf::from(FILE)));

    let newer = good.replace("\"v\":1", "\"v\":2");
    assert_eq!(parse_subscription(&encoded(&newer)).err(), Some(SubscriptionError::NewerVersion(2)));
    let zero = good.replace("\"v\":1", "\"v\":0");
    assert_eq!(parse_subscription(&encoded(&zero)).err(), Some(SubscriptionError::Malformed));
    let duplicate = good.replace("\"v\":1", "\"v\":1,\"v\":1");
    assert_eq!(parse_subscription(&encoded(&duplicate)).err(), Some(SubscriptionError::Malformed));
    let unknown = good.replace("\"v\":1", "\"v\":1,\"bearer\":\"t\"");
    assert_eq!(parse_subscription(&encoded(&unknown)).err(), Some(SubscriptionError::Malformed));
    let two_sources = good.replace(FILE_JSON, &format!(r#"{FILE_JSON}","https":"https://a.example/"#));
    assert_eq!(parse_subscription(&encoded(&two_sources)).err(), Some(SubscriptionError::Malformed));
    let missing = good.replace(&format!(",\"fingerprint\":\"{fp}\""), "");
    assert_eq!(parse_subscription(&encoded(&missing)).err(), Some(SubscriptionError::Malformed));
    assert_eq!(parse_subscription(&encoded("not json")).err(), Some(SubscriptionError::Malformed));
    assert_eq!(parse_subscription(&format!("{SUBSCRIPTION_PREFIX}***")).err(), Some(SubscriptionError::Malformed));
    // Padding is not part of the format.
    assert_eq!(parse_subscription(&format!("{}=", encoded(&good))).err(), Some(SubscriptionError::Malformed));

    let http = good.replace(&format!(r#"{{"file":"{FILE_JSON}"}}"#), r#"{"https":"http://a.example/"}"#);
    assert_eq!(parse_subscription(&encoded(&http)).err(), Some(SubscriptionError::Source(SourceError::NotHttps)));
    let relative = good.replace(FILE_JSON, "t.macvpncatalog");
    assert_eq!(
        parse_subscription(&encoded(&relative)).err(),
        Some(SubscriptionError::Source(SourceError::NotAbsolute))
    );
    let bad_fp = good.replace(&fp, &fp[..fp.len() - 1]);
    assert!(matches!(parse_subscription(&encoded(&bad_fp)).err(), Some(SubscriptionError::Fingerprint(_))));
}

#[test]
fn a_mistyped_team_key_is_a_typo() {
    let s = https_subscription();
    let key = s.team_key.to_text().to_string();
    let fp = s.fingerprint.to_text();
    let last = key.chars().last().unwrap();
    let typo = format!("{}{}", &key[..key.len() - 1], if last == '2' { '3' } else { '2' });
    let json = format!(r#"{{"v":1,"source":{{"file":"{FILE_JSON}"}},"teamKey":"{typo}","fingerprint":"{fp}"}}"#);
    assert_eq!(parse_subscription(&encoded(&json)).err(), Some(SubscriptionError::TeamKey(TeamKeyError::Typo)));
}

#[test]
fn debug_shows_the_source_and_fingerprint_only() {
    let s = https_subscription();
    let debug = format!("{s:?}");
    assert!(debug.contains("catalog.example.com"), "{debug}");
    assert!(debug.contains(&s.fingerprint.to_text()));
    assert!(!debug.contains(&s.team_key.to_text()[5..9]));
    assert!(!debug.contains("sig=abc"));
}

/// Review L6: the optional catalog id and minimum version bind the first download.
#[test]
fn catalog_id_and_min_version_round_trip_and_are_checked() {
    let id = uuid::Uuid::from_u128(0x1000_0000_0000_4000_8000_0000_0000_00AB);
    let mut s = https_subscription();
    s.catalog_id = Some(id);
    s.min_version = Some(7);
    let text = format_subscription(&s);
    let back = parse_subscription(&text).unwrap();
    same(&back, &s);
    let v: serde_json::Value = serde_json::from_str(&json_of(&text)).unwrap();
    assert_eq!(v["catalogId"], "10000000-0000-4000-8000-0000000000AB");
    assert_eq!(v["minVersion"], 7);

    // Absent: None (the strings of 1.3.0 without them still parse).
    let plain = parse_subscription(&format_subscription(&https_subscription())).unwrap();
    assert_eq!((plain.catalog_id, plain.min_version), (None, None));

    let json = json_of(&text);
    for (from, to) in [
        ("10000000-0000-4000-8000-0000000000AB", "10000000-0000-4000-8000-0000000000ab"),
        ("10000000-0000-4000-8000-0000000000AB", "not-a-uuid"),
        ("\"minVersion\":7", "\"minVersion\":0"),
        ("\"minVersion\":7", "\"minVersion\":\"7\""),
        ("\"minVersion\":7", "\"minVersion\":-1"),
    ] {
        let bad = json.replace(from, to);
        assert_ne!(bad, json);
        assert_eq!(parse_subscription(&encoded(&bad)).err(), Some(SubscriptionError::Malformed), "{to}");
    }
}
