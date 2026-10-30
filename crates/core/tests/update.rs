//! Port of `UpdateTests.swift` (SemVerTests, UpdateCheckerTests, the pure UpdateInstallerTests: checksum file,
//! SHA-256, helper log) and `UpdateSignatureTests.swift`. Downloading, mounting and installing are platform-mac
//! (Task 1.5).

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::swift_base64;
use macvpn_core::update::*;
use std::process::Command;

const REPO_ID: i64 = 1_422_472_799;
const REPO: &str = "SepsiG/MacVPN";

/// MacVPN's release asset (`Product::update_asset` of MacVPN; core does not know the product).
fn macvpn_asset(version: &str) -> Option<String> {
    Some(format!("MacVPN-{version}.dmg"))
}

// MARK: SemVer

fn v(s: &str) -> SemVer {
    SemVer::parse(s).unwrap()
}

#[test]
fn semver_ordering() {
    assert!(v("0.1.10") > v("0.1.9"));
    assert!(v("1.0.0") > v("0.99.99"));
    assert!(v("0.2") < v("0.2.1"));
}

#[test]
fn semver_prefix_and_prerelease() {
    assert_eq!(SemVer::parse("v1.0.0"), SemVer::parse("1.0.0"));
    assert_eq!(SemVer::parse("1.2.3-beta.1"), SemVer::parse("1.2.3"));
    assert_eq!(SemVer::parse("v1.2.3+build5"), SemVer::parse("1.2.3"));
    assert_eq!(v("V2").to_string(), "2.0.0");
}

#[test]
fn semver_invalid() {
    for s in ["", "abc", "1..2", "1.2.3.4", "1.٣.0", "99999999999999999999"] {
        assert_eq!(SemVer::parse(s), None, "{s}");
    }
}

// MARK: UpdateChecker

struct ReleaseJson {
    tag: String,
    dmg_url: String,
    sum_url: String,
    sig_url: Option<String>,
    version: String,
    html_url: Option<String>,
    published_at: Option<String>,
}

impl Default for ReleaseJson {
    fn default() -> Self {
        ReleaseJson {
            tag: "v0.2.0".into(),
            dmg_url: "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg".into(),
            sum_url: "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256".into(),
            sig_url: Some("https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig".into()),
            version: "0.2.0".into(),
            html_url: None,
            published_at: Some("2026-10-01T12:00:00Z".into()),
        }
    }
}

impl ReleaseJson {
    fn data(&self) -> Vec<u8> {
        let mut assets = vec![
            serde_json::json!({"name": format!("MacVPN-{}.dmg.sha256", self.version), "browser_download_url": self.sum_url}),
            serde_json::json!({"name": "Source.zip", "browser_download_url": "https://github.com/x.zip"}),
            serde_json::json!({"name": format!("MacVPN-{}.dmg", self.version), "browser_download_url": self.dmg_url}),
        ];
        if let Some(sig) = &self.sig_url {
            assets.push(
                serde_json::json!({"name": format!("MacVPN-{}.dmg.sig", self.version), "browser_download_url": sig}),
            );
        }
        let mut json = serde_json::json!({
            "tag_name": self.tag,
            "body": "## Újdonságok\n- frissítés az appból",
            "html_url": self.html_url.clone().unwrap_or_else(|| format!("https://github.com/SepsiG/MacVPN/releases/tag/{}", self.tag)),
            "draft": false, "prerelease": false,
            "assets": assets,
        });
        if let Some(p) = &self.published_at {
            json["published_at"] = serde_json::Value::String(p.clone());
        }
        serde_json::to_vec(&json).unwrap()
    }
}

fn parse(r: ReleaseJson) -> Result<Release, UpdateError> {
    UpdateChecker::parse_release(&r.data(), REPO, &macvpn_asset)
}

fn published() -> Date {
    Date::parse_iso8601("2026-10-01T12:00:00Z").unwrap()
}

/// The query uses the immutable numeric repo ID, not the (takeable) name.
#[test]
fn latest_release_url_uses_immutable_repo_id() {
    let url = UpdateChecker::latest_release_url(REPO_ID);
    assert_eq!(url, "https://api.github.com/repositories/1422472799/releases/latest");
    assert!(!url.contains("SepsiG"));
    assert!(UpdateChecker::validate_source(0, REPO).is_err());
    assert!(UpdateChecker::validate_source(-5, REPO).is_err());
    assert!(UpdateChecker::validate_source(REPO_ID, REPO).is_ok());
}

fn info(entries: &[(&str, InfoValue)]) -> Info {
    entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn id_of(value: InfoValue) -> Option<i64> {
    UpdateChecker::repo_id_from_info(Some(&info(&[("MacVPNUpdateRepoID", value)])))
}

#[test]
fn repo_id_key() {
    assert_eq!(UpdateChecker::REPO_ID_INFO_PLIST_KEY, "MacVPNUpdateRepoID");
    assert_eq!(id_of(InfoValue::String("1422472799".into())), Some(REPO_ID));
    assert_eq!(id_of(InfoValue::String(" 1422472799 ".into())), Some(REPO_ID));
    assert_eq!(id_of(InfoValue::Integer(REPO_ID)), Some(REPO_ID));
    // A missing or invalid ID: no update (no fallback to the name).
    assert_eq!(UpdateChecker::repo_id_from_info(None), None);
    assert_eq!(UpdateChecker::repo_id_from_info(Some(&info(&[]))), None);
    assert_eq!(
        UpdateChecker::repo_id_from_info(Some(&info(&[("MacVPNUpdateRepo", InfoValue::String(REPO.into()))]))),
        None
    );
    for bad in ["", "0", "-1", "abc", "12a", "1e9", "+12", "0x10", "١٢", "99999999999999999999", "12/34", "1 2"] {
        assert_eq!(id_of(InfoValue::String(bad.into())), None, "{bad}");
    }
    assert_eq!(id_of(InfoValue::Integer(0)), None);
    assert_eq!(id_of(InfoValue::Integer(-3)), None);
    assert_eq!(id_of(InfoValue::Real(1.5)), None);
    assert_eq!(id_of(InfoValue::Boolean(true)), None);
}

#[test]
fn source_from_info() {
    let full = info(&[
        ("MacVPNUpdateRepo", InfoValue::String(REPO.into())),
        ("MacVPNUpdateRepoID", InfoValue::String("1422472799".into())),
    ]);
    assert_eq!(UpdateChecker::source_from_info(Some(&full)), Some((REPO_ID, REPO.to_string())));
    assert_eq!(
        UpdateChecker::source_from_info(Some(&info(&[("MacVPNUpdateRepo", InfoValue::String(REPO.into()))]))),
        None
    );
    assert_eq!(
        UpdateChecker::source_from_info(Some(&info(&[("MacVPNUpdateRepoID", InfoValue::String("1422472799".into()))]))),
        None
    );
    assert_eq!(
        UpdateChecker::source_from_info(Some(&info(&[
            ("MacVPNUpdateRepo", InfoValue::String(REPO.into())),
            ("MacVPNUpdateRepoID", InfoValue::String("x".into()))
        ]))),
        None
    );
}

/// The bundled Info.plist pins the ID (`app/src-tauri/Info.plist`, merged into the bundle's by the Tauri bundler;
/// `scripts/build-dmg.sh` checks the result).
#[test]
fn bundled_info_plist_pins_repo_id() {
    let plist = plist::Value::from_file(repo_root().join("app/src-tauri/Info.plist")).unwrap();
    let dict = plist.as_dictionary().unwrap();
    let mut bundled = Info::new();
    for (k, v) in dict {
        let value = match v {
            plist::Value::String(s) => InfoValue::String(s.clone()),
            plist::Value::Integer(i) => InfoValue::Integer(i.as_signed().unwrap()),
            plist::Value::Real(r) => InfoValue::Real(*r),
            plist::Value::Boolean(b) => InfoValue::Boolean(*b),
            _ => continue,
        };
        bundled.insert(k.clone(), value);
    }
    assert_eq!(bundled.get("MacVPNUpdateRepoID"), Some(&InfoValue::String("1422472799".into())));
    assert_eq!(UpdateChecker::source_from_info(Some(&bundled)), Some((REPO_ID, REPO.to_string())));
}

#[test]
fn latest_release_parses_assets() {
    let r = UpdateChecker::release_from_response(200, &ReleaseJson::default().data(), REPO, &macvpn_asset).unwrap();
    assert_eq!(r.tag, "v0.2.0");
    assert_eq!(r.version, "0.2.0");
    assert_eq!(r.notes, "## Újdonságok\n- frissítés az appból");
    assert_eq!(r.package.name, "MacVPN-0.2.0.dmg");
    assert_eq!(r.checksum.name, "MacVPN-0.2.0.dmg.sha256");
    assert_eq!(r.checksum.url, "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256");
    assert_eq!(r.signature.as_ref().unwrap().name, "MacVPN-0.2.0.dmg.sig");
    assert_eq!(
        r.signature.as_ref().unwrap().url,
        "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig"
    );
    assert_eq!(r.page_url.as_deref(), Some("https://github.com/SepsiG/MacVPN/releases/tag/v0.2.0"));
    assert_eq!(r.published_at, Some(published()));
    assert!(r.is_newer("0.1.0"));
    assert!(!r.is_newer("0.2.0"));
    assert!(!r.is_newer("0.10.0"));
}

#[test]
fn http_errors() {
    assert_eq!(UpdateChecker::release_from_response(404, b"", REPO, &macvpn_asset), Err(UpdateError::Http(404)));
    assert_eq!(
        UpdateChecker::release_from_response(200, b"nem json", REPO, &macvpn_asset),
        Err(UpdateError::InvalidResponse)
    );
}

#[test]
fn rejects_untrusted_asset_urls() {
    for bad in [
        "http://github.com/a/MacVPN-0.2.0.dmg",
        "https://evil.example.com/MacVPN-0.2.0.dmg",
        "https://github.com.evil.example/MacVPN-0.2.0.dmg",
        "https://user@github.com/MacVPN-0.2.0.dmg",
        "https://github.com:8443/MacVPN-0.2.0.dmg",
        "https://objects.githubusercontent.com/github-production-release-asset/1/MacVPN-0.2.0.dmg",
    ] {
        assert_eq!(
            parse(ReleaseJson { dmg_url: bad.into(), ..Default::default() }),
            Err(UpdateError::UntrustedUrl(bad.into())),
            "{bad}"
        );
    }
}

/// The asset path is exactly `/<owner>/<repo>/releases/download/<tag>/<name>` (owner/repo case-insensitively).
#[test]
fn asset_path_must_match_repo_tag_and_name() {
    let base = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/";
    let bad = [
        "https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg".to_string(),
        "https://github.com/SepsiG/Other/releases/download/v0.2.0/MacVPN-0.2.0.dmg".to_string(),
        "https://github.com/SepsiG/MacVPN/releases/download/v0.1.0/MacVPN-0.2.0.dmg".to_string(),
        format!("{base}Other.dmg"),
        format!("{base}MacVPN-0.2.0.dmg/x"),
        format!("{base}MacVPN-0.2.0.dmg?x=1"),
        format!("{base}MacVPN-0.2.0.dmg#frag"),
        "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/../v0.2.0/MacVPN-0.2.0.dmg".to_string(),
        "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0%2FMacVPN-0.2.0.dmg".to_string(),
        "https://github.com/SepsiG%2FMacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg".to_string(),
        "https://github.com//SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg".to_string(),
        "https://github.com/SepsiG/MacVPN/releases/v0.2.0/MacVPN-0.2.0.dmg".to_string(),
    ];
    for b in bad {
        assert_eq!(
            parse(ReleaseJson { dmg_url: b.clone(), ..Default::default() }),
            Err(UpdateError::UntrustedUrl(b.clone())),
            "{b}"
        );
    }
    // The same applies to the checksum asset.
    let bad_sum = "https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256";
    assert_eq!(
        parse(ReleaseJson { sum_url: bad_sum.into(), ..Default::default() }),
        Err(UpdateError::UntrustedUrl(bad_sum.into()))
    );
    // And to the `.sig` asset.
    for bad_sig in [
        "https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig",
        "https://evil.example/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig",
        "https://github.com/SepsiG/MacVPN/releases/download/v0.1.0/MacVPN-0.2.0.dmg.sig",
        "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig?x=1",
    ] {
        assert_eq!(
            parse(ReleaseJson { sig_url: Some(bad_sig.into()), ..Default::default() }),
            Err(UpdateError::UntrustedUrl(bad_sig.into())),
            "{bad_sig}"
        );
    }
    // Owner/repo case-insensitively; the host too.
    assert!(
        parse(ReleaseJson {
            dmg_url: "https://GitHub.com/sepsig/macvpn/releases/download/v0.2.0/MacVPN-0.2.0.dmg".into(),
            ..Default::default()
        })
        .is_ok()
    );
    assert!(UpdateChecker::parse_release(&ReleaseJson::default().data(), "sepsig/MACVPN", &macvpn_asset).is_ok());
    // An app set to another (valid) repo does not accept SepsiG's assets.
    assert!(UpdateChecker::parse_release(&ReleaseJson::default().data(), "Other/MacVPN", &macvpn_asset).is_err());
}

#[test]
fn asset_url_path_check_is_pure() {
    let ok = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg";
    assert!(UpdateURLPolicy::is_expected_asset(ok, REPO, "v0.2.0", "MacVPN-0.2.0.dmg"));
    assert!(!UpdateURLPolicy::is_expected_asset(ok, REPO, "v0.2.0", "MacVPN-0.2.0.DMG"));
    assert!(!UpdateURLPolicy::is_expected_asset(ok, REPO, "V0.2.0", "MacVPN-0.2.0.dmg"));
    assert!(!UpdateURLPolicy::is_expected_asset(ok, "SepsiG/MacVPNx", "v0.2.0", "MacVPN-0.2.0.dmg"));
    // Foundation decodes a percent-encoded host (`github%2Ecom` is github.com), as Swift does.
    assert!(UpdateURLPolicy::is_expected_asset(
        "https://github%2Ecom/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
        REPO,
        "v0.2.0",
        "MacVPN-0.2.0.dmg"
    ));
}

/// The release page link may only be `https://github.com/<owner>/<repo>/releases/…`; otherwise no link.
#[test]
fn html_url_host_and_prefix() {
    assert_eq!(
        parse(ReleaseJson::default()).unwrap().page_url.as_deref(),
        Some("https://github.com/SepsiG/MacVPN/releases/tag/v0.2.0")
    );
    for bad in [
        "https://evil.example/SepsiG/MacVPN/releases/tag/v0.2.0",
        "http://github.com/SepsiG/MacVPN/releases/tag/v0.2.0",
        "https://github.com/Evil/MacVPN/releases/tag/v0.2.0",
        "https://github.com/SepsiG/MacVPN/issues/1",
        "https://github.com/SepsiG/MacVPNx/releases/tag/v0.2.0",
        "https://github.com/SepsiG/MacVPN/releases/../../../Evil/x",
        "https://objects.githubusercontent.com/SepsiG/MacVPN/releases/tag/v0.2.0",
    ] {
        assert_eq!(
            parse(ReleaseJson { html_url: Some(bad.into()), ..Default::default() }).unwrap().page_url,
            None,
            "{bad}"
        );
    }
}

#[test]
fn missing_assets_and_bad_tags() {
    assert_eq!(
        parse(ReleaseJson { version: "0.1.9".into(), ..Default::default() }),
        Err(UpdateError::MissingAsset("MacVPN-0.2.0.dmg".into()))
    );
    assert!(parse(ReleaseJson { tag: "v0.2.0/../x".into(), ..Default::default() }).is_err());
    assert!(parse(ReleaseJson { tag: "nightly".into(), ..Default::default() }).is_err());
}

/// The asset name is the caller's (the product's): the same release JSON with another product's asset names, and
/// no asset for this machine.
#[test]
fn package_asset_is_a_parameter() {
    let base = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/";
    let assets = ["WinVPN-0.2.0-arm64.msi", "WinVPN-0.2.0-arm64.msi.sha256", "WinVPN-0.2.0-arm64.msi.sig"]
        .map(|n| serde_json::json!({"name": n, "browser_download_url": format!("{base}{n}")}));
    let json = serde_json::json!({"tag_name": "v0.2.0", "assets": assets});
    let data = serde_json::to_vec(&json).unwrap();
    let msi = |v: &str| Some(format!("WinVPN-{v}-arm64.msi"));
    let r = UpdateChecker::parse_release(&data, REPO, &msi).unwrap();
    assert_eq!(r.package.name, "WinVPN-0.2.0-arm64.msi");
    assert_eq!(r.checksum.name, "WinVPN-0.2.0-arm64.msi.sha256");
    assert_eq!(r.signature.unwrap().name, "WinVPN-0.2.0-arm64.msi.sig");
    assert_eq!(
        UpdateChecker::parse_release(&data, REPO, &macvpn_asset),
        Err(UpdateError::MissingAsset("MacVPN-0.2.0.dmg".into()))
    );
    // No asset for this architecture: the release has nothing to install here.
    assert_eq!(UpdateChecker::parse_release(&data, REPO, &|_| None), Err(UpdateError::MissingAsset("v0.2.0".into())));
    assert_eq!(
        UpdateChecker::release_from_response(200, &data, REPO, &|_| None),
        Err(UpdateError::MissingAsset("v0.2.0".into()))
    );
}

/// The optional delay: only a release published at least 24 hours ago is offered.
#[test]
fn minimum_age() {
    let r = parse(ReleaseJson::default()).unwrap();
    let age = UpdateChecker::MINIMUM_RELEASE_AGE;
    assert_eq!(age, 24.0 * 60.0 * 60.0);
    assert!(!r.is_old_enough(age, published()));
    assert!(!r.is_old_enough(age, published().adding(23.0 * 3600.0 + 3599.0)));
    assert!(r.is_old_enough(age, published().adding(24.0 * 3600.0)));
    assert!(r.is_old_enough(0.0, published().adding(-60.0)));
    // Without (or with a bad) publication time, nothing is offered with the delay on.
    let undated = parse(ReleaseJson { published_at: None, ..Default::default() }).unwrap();
    assert_eq!(undated.published_at, None);
    assert!(!undated.is_old_enough(age, published().adding(1e7)));
    assert!(undated.is_old_enough(0.0, published()));
    assert_eq!(
        parse(ReleaseJson { published_at: Some("tegnap".into()), ..Default::default() }).unwrap().published_at,
        None
    );
}

/// What the app offers: a newer version, and with the delay on, at least 24 hours old.
#[test]
fn offer_decision() {
    let r = parse(ReleaseJson::default()).unwrap();
    assert_eq!(UpdateChecker::offer(&r, "0.1.0", false, published()), Offer::Offer);
    assert_eq!(UpdateChecker::offer(&r, "0.2.0", false, published()), Offer::UpToDate);
    assert_eq!(UpdateChecker::offer(&r, "0.1.0", true, published().adding(3600.0)), Offer::TooRecent);
    assert_eq!(UpdateChecker::offer(&r, "0.1.0", true, published().adding(86400.0)), Offer::Offer);
    assert_eq!(UpdateChecker::offer(&r, "0.2.0", true, published()), Offer::UpToDate);
}

/// A release without a `.sig` asset (not signed yet) is not offered; an older unsigned release is "up to date".
#[test]
fn release_without_signature_asset_is_not_offered() {
    let r = parse(ReleaseJson { sig_url: None, ..Default::default() }).unwrap();
    assert_eq!(r.signature, None);
    assert_eq!(UpdateChecker::offer(&r, "0.1.0", false, published()), Offer::AwaitingSignature);
    assert_eq!(UpdateChecker::offer(&r, "0.1.0", true, published().adding(86400.0)), Offer::AwaitingSignature);
    assert_eq!(UpdateChecker::offer(&r, "0.2.0", false, published()), Offer::UpToDate);
    lang(AppLanguage::En);
    assert_eq!(UpdateError::UnsignedUpdate.message(), "The update is not signed by the MacVPN maintainer");
    assert_eq!(
        l10n::tr_in(AppLanguage::Hu, "The update is not signed by the MacVPN maintainer", &[]),
        "A frissítést nem a MacVPN fejlesztője írta alá"
    );
}

#[test]
fn repo_key() {
    let repo =
        |v: &str| UpdateChecker::repo_from_info(Some(&info(&[("MacVPNUpdateRepo", InfoValue::String(v.into()))])));
    assert_eq!(repo(REPO).as_deref(), Some(REPO));
    assert_eq!(UpdateChecker::repo_from_info(None), None);
    assert_eq!(UpdateChecker::repo_from_info(Some(&info(&[]))), None);
    for bad in ["", "a/b/c", "a/..", "a b/c"] {
        assert_eq!(repo(bad), None, "{bad}");
    }
    assert!(UpdateChecker::validate_source(REPO_ID, "x?y=1/z").is_err());
}

#[test]
fn url_policy() {
    assert!(UpdateURLPolicy::is_allowed_redirect("https://release-assets.githubusercontent.com/x"));
    assert!(UpdateURLPolicy::is_allowed_redirect("https://objects.githubusercontent.com/x"));
    assert!(UpdateURLPolicy::is_allowed_redirect("https://api.github.com/repositories/1/releases/latest"));
    assert!(!UpdateURLPolicy::is_allowed_download("https://release-assets.githubusercontent.com/x"));
    assert!(!UpdateURLPolicy::is_allowed_download("https://objects.githubusercontent.com/x"));
    assert!(UpdateURLPolicy::is_allowed_download("https://github.com/x"));
    assert!(!UpdateURLPolicy::is_allowed_redirect("http://objects.githubusercontent.com/x"));
    assert!(!UpdateURLPolicy::is_allowed_redirect("https://example.com/x"));
}

#[test]
fn user_guide_url() {
    assert_eq!(
        UserGuide::url(Some(REPO), REPO, "user-guide", &["hu-HU", "en-US"]),
        "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.hu.md"
    );
    assert_eq!(
        UserGuide::url(Some(REPO), REPO, "user-guide", &["en-US", "hu-HU"]),
        "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.en.md"
    );
    assert_eq!(
        UserGuide::url(None, REPO, "user-guide", &["hu"]),
        "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.hu.md"
    );
    // An invalid repo falls back to the caller's; the stem is the product's.
    assert_eq!(
        UserGuide::url(Some("evil.com/x?y"), REPO, "winvpn-user-guide", &["en"]),
        "https://github.com/SepsiG/MacVPN/blob/main/docs/winvpn-user-guide.en.md"
    );
    assert_eq!(UserGuide::language::<&str>(&[]), "en");
    assert_eq!(UserGuide::language(&["hr-HR"]), "en");
}

/// `ISO8601DateFormatter` (the release's `published_at`) is lenient; values printed by Foundation on macOS 27.
#[test]
fn published_at_like_iso8601_date_formatter() {
    let p = |s: &str| Date::parse_iso8601_formatter(s).map(Date::time_interval_since_1970);
    for (s, expected) in [
        ("2026-10-01T12:00:00Z", Some(1_790_856_000.0)),
        ("2026-10-01T2:00:00Z", Some(1_790_820_000.0)),
        ("2026-1-1T1:2:3Z", Some(1_767_229_323.0)),
        ("2026-1\r\n01T12:00:00Z", Some(1_767_268_800.0)),
        ("02026-10-01T12:00:00Z", Some(1_790_856_000.0)),
        ("2026-10-01T12:00:00+0100", Some(1_790_852_400.0)),
        ("2026-10-01T12:00:00 Z", Some(1_790_856_000.0)),
        (" 2026-10-01T12:00:00Z", Some(1_790_856_000.0)),
        ("2026-10-01T12:00:00Zjunk", Some(1_790_856_000.0)),
        ("2026-10-011T12:00:00Z", Some(1_791_720_000.0)),
        ("2026-10-01T12:000:00Z", Some(1_790_856_000.0)),
        ("2026-10-01T12:00:00GMT", Some(1_790_856_000.0)),
        ("2026-10-01T12:00:00UTC", Some(1_790_856_000.0)),
        ("2026-10-01T12:00:00+1", Some(1_790_852_400.0)),
        ("2026-10-01T12:00:00+01:00:00", Some(1_790_852_400.0)),
        ("2026-1001T12:00:00Z", None),
        ("2026x10x01T12:00:00Z", None),
        ("2026-10-01T12:00:00", None),
        ("2026-10-01T12:00:00.123Z", None),
        ("2026-10-01 T12:00:00Z", None),
        ("2026--10-01T12:00:00Z", None),
        ("2026-100-01T12:00:00Z", None),
        ("2026-10-01t12:00:00z", None),
        ("2026-10-01T12:00:00EST", None),
        ("2026-10-32T12:00:00Z", None),
        ("2026-10-01T12:00:00 ", None),
    ] {
        assert_eq!(p(s), expected, "{s:?}");
    }
}

// MARK: Checksum, SHA-256, helper log (UpdateInstallerTests)

#[test]
fn checksum_parsing() {
    let h = "ab".repeat(32);
    assert_eq!(parse_checksum(&format!("{h}  MacVPN-0.2.0.dmg\n"), "MacVPN-0.2.0.dmg"), Ok(h.clone()));
    assert_eq!(parse_checksum(&format!("{} *MacVPN-0.2.0.dmg", h.to_uppercase()), "MacVPN-0.2.0.dmg"), Ok(h.clone()));
    assert_eq!(parse_checksum(&format!("{h}  Other.dmg"), "MacVPN-0.2.0.dmg"), Err(UpdateError::InvalidChecksumFile));
    assert!(parse_checksum("abc  MacVPN-0.2.0.dmg", "MacVPN-0.2.0.dmg").is_err());
    assert!(parse_checksum("", "MacVPN-0.2.0.dmg").is_err());
}

#[test]
fn sha256_of_file_and_data() {
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.dmg");
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    assert_eq!(sha256_of_file(&path).unwrap(), sha256_hex(&data));
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn helper_log_outcome() {
    let ok = "=== 2026-10-01 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===\nthe app did not quit within 30 s, update cancelled\n=== 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===\nHDIUTIL detach\ndone\n\n";
    assert_eq!(
        last_helper_outcome(ok),
        Some((
            "=== 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===".into(),
            HelperOutcome::Succeeded
        ))
    );
    let timeout = "=== 2026-10-02 10:00:00 update: a -> b ===\ndone\n=== 2026-10-03 11:00:00 update: a -> b ===\nthe app did not quit within 30 s, update cancelled";
    assert_eq!(
        last_helper_outcome(timeout),
        Some(("=== 2026-10-03 11:00:00 update: a -> b ===".into(), HelperOutcome::TimedOut))
    );
    for line in [
        "copy (ditto) failed",
        "cannot rename the old app",
        "cannot move the new app into place, restoring",
        "the target still exists after the rename, update cancelled",
    ] {
        let failed = format!("=== 2026-10-03 11:00:00 update: a -> b ===\nsome output\n{line}\nold app restored\n");
        assert_eq!(last_helper_outcome(&failed).map(|o| o.1), Some(HelperOutcome::Failed(line.into())), "{line}");
    }
    // A still running (or old, "done"-after-opening) script: no error marker, no error.
    assert_eq!(
        last_helper_outcome("=== 2026-10-03 11:00:00 update: a -> b ===\nHDIUTIL detach\n").map(|o| o.1),
        Some(HelperOutcome::Unknown)
    );
    assert_eq!(last_helper_outcome(""), None);
    assert_eq!(last_helper_outcome("random\n"), None);
}

// MARK: UpdateSignatureTests (throwaway keys only)

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keys() -> Vec<[u8; 32]> {
    vec![key(1).verifying_key().to_bytes(), key(2).verifying_key().to_bytes()]
}

fn sign(k: &SigningKey, version: &str, digest: &str) -> String {
    let message = UpdateSignature::message(version, digest).unwrap();
    swift_base64::encode(&k.sign(&message).to_bytes()) + "\n"
}

fn verify(sig: &str, version: &str, digest: &str) -> bool {
    UpdateSignature::verify(version, digest, sig, &keys())
}

#[test]
fn message_format_is_exact() {
    assert_eq!(
        UpdateSignature::message("0.2.2", DIGEST),
        Some(format!("macvpn-update-v1\n0.2.2\n{DIGEST}\n").into_bytes())
    );
    assert_eq!(UpdateSignature::message("v0.2.2", DIGEST), None);
    assert_eq!(UpdateSignature::message("0.2", DIGEST), None);
    assert_eq!(UpdateSignature::message("0.2.2\n", DIGEST), None);
    assert_eq!(UpdateSignature::message("0.2.2", &DIGEST.to_uppercase()), None);
    assert_eq!(UpdateSignature::message("0.2.2", &DIGEST[..63]), None);
    assert_eq!(UpdateSignature::message("0.2.2", &format!("{}g", &DIGEST[..63])), None);
}

const X64: &str = "WinVPN-0.2.2-x64.msi";
const ARM64: &str = "WinVPN-0.2.2-arm64.msi";

fn sign_for(k: &SigningKey, domain: SignatureDomain, asset: &str, version: &str, digest: &str) -> String {
    let message = UpdateSignature::message_for(domain, asset, version, digest).unwrap();
    swift_base64::encode(&k.sign(&message).to_bytes()) + "\n"
}

#[test]
fn macvpn_message_is_unchanged_whatever_the_asset() {
    let expected = format!("macvpn-update-v1\n0.2.2\n{DIGEST}\n").into_bytes();
    assert_eq!(UpdateSignature::message("0.2.2", DIGEST), Some(expected.clone()));
    for asset in ["MacVPN-0.2.2.dmg", "", X64] {
        assert_eq!(
            UpdateSignature::message_for(SignatureDomain::MacVpnV1, asset, "0.2.2", DIGEST),
            Some(expected.clone())
        );
    }
}

#[test]
fn winvpn_message_names_the_asset() {
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST),
        Some(format!("winvpn-update-v1\n{X64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST),
        Some(format!("winvpn-update-v1\n{ARM64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
}

#[test]
fn winvpn_message_refuses_any_other_asset_name() {
    for asset in [
        "",
        "MacVPN-0.2.2.dmg",
        "WinVPN-0.2.3-x64.msi",
        "WinVPN-0.2.2-x86.msi",
        "winvpn-0.2.2-x64.msi",
        "WinVPN-0.2.2-x64.msi\n",
        "WinVPN-0.2.2-x64.MSI",
        "../WinVPN-0.2.2-x64.msi",
    ] {
        assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, asset, "0.2.2", DIGEST), None, "{asset:?}");
    }
    assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2", DIGEST), None);
    assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2.2", &DIGEST[..63]), None);
}

#[test]
fn macvpn_rejects_a_winvpn_signature() {
    let sig = sign_for(&key(1), SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST);
    assert!(!UpdateSignature::verify("0.2.2", DIGEST, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(
        SignatureDomain::MacVpnV1,
        "MacVPN-0.2.2.dmg",
        "0.2.2",
        DIGEST,
        &sig,
        &keys()
    ));
}

#[test]
fn winvpn_rejects_a_macvpn_signature() {
    let sig = sign(&key(1), "0.2.2", DIGEST);
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST, &sig, &keys()));
}

#[test]
fn winvpn_rejects_the_x64_signature_for_the_arm64_asset() {
    let sig = sign_for(&key(1), SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST, &sig, &keys()));
}

#[test]
fn winvpn_signature_is_bound_to_version_and_hash() {
    let sig = sign_for(&key(2), SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST, &sig, &keys()));
    let other = format!("{}0", &DIGEST[..63]);
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", &other, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(
        SignatureDomain::WinVpnV1,
        "WinVPN-0.2.3-arm64.msi",
        "0.2.3",
        DIGEST,
        &sig,
        &keys()
    ));
}

const AMD64: &str = "linvpn_0.2.2_amd64.deb";
const DEB_ARM64: &str = "linvpn_0.2.2_arm64.deb";

#[test]
fn linvpn_message_names_the_asset() {
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST),
        Some(format!("linvpn-update-v1\n{AMD64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::LinVpnV1, DEB_ARM64, "0.2.2", DIGEST),
        Some(format!("linvpn-update-v1\n{DEB_ARM64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
}

#[test]
fn linvpn_message_refuses_any_other_asset_name() {
    for asset in [
        "",
        "MacVPN-0.2.2.dmg",
        X64,
        "linvpn_0.2.3_amd64.deb",
        "linvpn_0.2.2_i386.deb",
        "LinVPN_0.2.2_amd64.deb",
        "linvpn-0.2.2-amd64.deb",
        "linvpn_0.2.2_amd64.deb\n",
        "linvpn_0.2.2_amd64.DEB",
        "../linvpn_0.2.2_amd64.deb",
    ] {
        assert_eq!(UpdateSignature::message_for(SignatureDomain::LinVpnV1, asset, "0.2.2", DIGEST), None, "{asset:?}");
    }
    assert_eq!(UpdateSignature::message_for(SignatureDomain::LinVpnV1, AMD64, "0.2", DIGEST), None);
    assert_eq!(UpdateSignature::message_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", &DIGEST[..63]), None);
}

#[test]
fn no_product_accepts_another_products_signature() {
    let lin = sign_for(&key(1), SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST, &lin, &keys()));
    assert!(!UpdateSignature::verify("0.2.2", DIGEST, &lin, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST, &lin, &keys()));
    let win = sign_for(&key(1), SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST);
    let mac = sign(&key(1), "0.2.2", DIGEST);
    for sig in [&win, &mac] {
        assert!(!UpdateSignature::verify_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST, sig, &keys()));
    }
}

#[test]
fn linvpn_rejects_the_amd64_signature_for_the_arm64_asset() {
    let sig = sign_for(&key(2), SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", DIGEST, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::LinVpnV1, DEB_ARM64, "0.2.2", DIGEST, &sig, &keys()));
    let other = format!("{}0", &DIGEST[..63]);
    assert!(!UpdateSignature::verify_for(SignatureDomain::LinVpnV1, AMD64, "0.2.2", &other, &sig, &keys()));
}

/// Signatures of released MacVPN versions (public release assets `MacVPN-<v>.dmg.sig`, the hash from
/// `MacVPN-<v>.dmg.sha256`), made with the maintainer's real key: they still verify with the embedded keys exactly
/// as the updaters in the field check them, and never in WinVPN's domain.
#[test]
fn released_macvpn_signatures_still_verify() {
    let released = [
        (
            "1.0.0",
            "1ac353e1be03e03d6ec914ae3c804d6be0e632ae3b30f663310a1104dc8ca793",
            "9GavlM5gncZKRsJ2U6vFESMfB2JqYHAHoeQNGWFiHxFmrNlQNiUKtz4gFAGC+QyBor+LJqA2cZY8yINsGrLdAg==\n",
        ),
        (
            "1.5.0",
            "53893b777ecfa24b2d2a132f867ea062a7eb19fb8a66e5533d28372e356bb976",
            "sUn0EpYzjMSSikB1dber+BsVT13fFN9PB8tRS8Ip1j0Ob+kQ4Yr629XRVnc8QnfVGuIuLuoYFw4PuwtxAqi0AA==\n",
        ),
    ];
    for (version, digest, sig) in released {
        assert!(UpdateSignature::verify_trusted(version, digest, sig), "{version}");
        let dmg = format!("MacVPN-{version}.dmg");
        assert!(
            UpdateSignature::verify_trusted_for(SignatureDomain::MacVpnV1, &dmg, version, digest, sig),
            "{version}"
        );
        for arch in ["x64", "arm64"] {
            let msi = format!("WinVPN-{version}-{arch}.msi");
            assert!(
                !UpdateSignature::verify_trusted_for(SignatureDomain::WinVpnV1, &msi, version, digest, sig),
                "{version} {arch}"
            );
        }
        for arch in ["amd64", "arm64"] {
            let deb = format!("linvpn_{version}_{arch}.deb");
            assert!(
                !UpdateSignature::verify_trusted_for(SignatureDomain::LinVpnV1, &deb, version, digest, sig),
                "{version} {arch}"
            );
        }
        // Bound to its own version.
        assert!(!UpdateSignature::verify_trusted("1.5.1", digest, sig), "{version}");
    }
}

#[test]
fn signature_valid() {
    assert!(verify(&sign(&key(1), "0.2.2", DIGEST), "0.2.2", DIGEST));
    // Without the trailing newline too (the file format is one line + newline, the line is what counts).
    assert!(verify(sign(&key(1), "0.2.2", DIGEST).trim_end(), "0.2.2", DIGEST));
}

#[test]
fn backup_key_also_works() {
    assert!(verify(&sign(&key(2), "0.2.2", DIGEST), "0.2.2", DIGEST));
    assert!(UpdateSignature::verify(
        "0.2.2",
        DIGEST,
        &sign(&key(2), "0.2.2", DIGEST),
        &[key(2).verifying_key().to_bytes()]
    ));
}

#[test]
fn wrong_version() {
    assert!(!verify(&sign(&key(1), "0.2.1", DIGEST), "0.2.2", DIGEST));
    assert!(!verify(&sign(&key(1), "0.2.2", DIGEST), "0.2.3", DIGEST));
    assert!(!verify(&sign(&key(1), "0.2.2", DIGEST), "v0.2.2", DIGEST));
}

#[test]
fn wrong_hash() {
    let other = "f".repeat(64);
    assert!(!verify(&sign(&key(1), "0.2.2", &other), "0.2.2", DIGEST));
    assert!(!verify(&sign(&key(1), "0.2.2", DIGEST), "0.2.2", &other));
    assert!(!verify(&sign(&key(1), "0.2.2", DIGEST), "0.2.2", &DIGEST.to_uppercase()));
    assert!(!verify(&sign(&key(1), "0.2.2", DIGEST), "0.2.2", ""));
}

#[test]
fn wrong_key() {
    let good = sign(&key(1), "0.2.2", DIGEST);
    assert!(!verify(&sign(&key(9), "0.2.2", DIGEST), "0.2.2", DIGEST));
    assert!(!UpdateSignature::verify("0.2.2", DIGEST, &good, &[key(2).verifying_key().to_bytes()]));
    assert!(!UpdateSignature::verify("0.2.2", DIGEST, &good, &[]));
    // The embedded (real) keys do not accept the throwaway key's signature.
    assert!(!UpdateSignature::verify_trusted("0.2.2", DIGEST, &good));
}

#[test]
fn malformed_base64() {
    let good = sign(&key(1), "0.2.2", DIGEST).trim_end().to_string();
    let (head, tail) = good.split_at(44);
    let mut cases = vec![
        String::new(),
        "\n".into(),
        "not base64!".into(),
        "====".into(),
        good[..good.len() - 4].to_string(),
        format!("{good}AAAA"),
        swift_base64::encode(&[1; 63]),
        swift_base64::encode(&[1; 65]),
        format!("{head}\n{tail}"),
        format!("{head} {tail}"),
        format!("{good}\n{good}"),
    ];
    // s + L (scalar malleability) is rejected.
    let mut bytes = swift_base64::decode(&good).unwrap();
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(bytes[32 + i]) + u16::from(l[i]) + carry;
        bytes[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    cases.push(swift_base64::encode(&bytes));
    for bad in cases {
        assert!(!verify(&bad, "0.2.2", DIGEST), "{bad:?}");
    }
}

#[test]
fn oversize_input() {
    let good = sign(&key(1), "0.2.2", DIGEST);
    let pad = UpdateSignature::MAX_SIGNATURE_FILE_SIZE - good.len();
    assert!(verify(&format!("{good}{}", "\n".repeat(pad)), "0.2.2", DIGEST));
    assert!(!verify(&format!("{good}{}", "\n".repeat(pad + 1)), "0.2.2", DIGEST));
    assert!(!verify(&"A".repeat(1 << 20), "0.2.2", DIGEST));
    assert_eq!(UpdateSignature::MAX_SIGNATURE_FILE_SIZE, 1024);
}

/// The primary and the backup public key are valid, 32 bytes, and different.
#[test]
fn embedded_public_keys_decode_to_32_bytes() {
    assert_eq!(UpdateSignature::PRIMARY_PUBLIC_KEY_BASE64, "KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk=");
    assert_eq!(UpdateSignature::BACKUP_PUBLIC_KEY_BASE64, "QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI=");
    let trusted = UpdateSignature::trusted_keys();
    assert_eq!(
        trusted.iter().map(|k| swift_base64::encode(k)).collect::<Vec<_>>(),
        [UpdateSignature::PRIMARY_PUBLIC_KEY_BASE64, UpdateSignature::BACKUP_PUBLIC_KEY_BASE64]
    );
    assert_ne!(trusted[0], trusted[1]);
}

// MARK: OpenSSL interop and sign-release.sh

const OPENSSL: &str = "/opt/homebrew/opt/openssl@3/bin/openssl";

fn openssl3() -> Option<&'static str> {
    let out = Command::new(OPENSSL).arg("version").output().ok()?;
    (out.status.success() && String::from_utf8_lossy(&out.stdout).starts_with("OpenSSL 3.")).then_some(OPENSSL)
}

/// A throwaway OpenSSL Ed25519 key: (PEM path, raw public key).
fn openssl_key(openssl: &str, dir: &std::path::Path) -> (std::path::PathBuf, [u8; 32]) {
    let pem = dir.join("throwaway.pem");
    let der = dir.join("throwaway.pub.der");
    assert!(
        Command::new(openssl).args(["genpkey", "-algorithm", "ed25519", "-out"]).arg(&pem).status().unwrap().success()
    );
    assert!(
        Command::new(openssl)
            .args(["pkey", "-in"])
            .arg(&pem)
            .args(["-pubout", "-outform", "DER", "-out"])
            .arg(&der)
            .status()
            .unwrap()
            .success()
    );
    let spki = std::fs::read(&der).unwrap();
    assert_eq!(spki.len(), 44);
    (pem, spki[12..].try_into().unwrap())
}

/// OpenSSL's `pkeyutl -sign -rawin` (plain Ed25519) signature is accepted.
#[test]
fn openssl_rawin_signature_verifies() {
    let Some(openssl) = openssl3() else {
        eprintln!("skipped: OpenSSL 3 not installed");
        return;
    };
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let (pem, public) = openssl_key(openssl, tmp.path());
    let message = tmp.path().join("message");
    let sig = tmp.path().join("sig.bin");
    std::fs::write(&message, UpdateSignature::message("0.2.2", DIGEST).unwrap()).unwrap();
    assert!(
        Command::new(openssl)
            .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(&pem)
            .arg("-in")
            .arg(&message)
            .arg("-out")
            .arg(&sig)
            .status()
            .unwrap()
            .success()
    );
    let b64 = swift_base64::encode(&std::fs::read(&sig).unwrap()) + "\n";
    assert!(UpdateSignature::verify("0.2.2", DIGEST, &b64, &[public]));
    assert!(!UpdateSignature::verify("0.2.3", DIGEST, &b64, &[public]));
    assert!(!UpdateSignature::verify_trusted("0.2.2", DIGEST, &b64));
}

/// `scripts/sign-release.sh --dry-run` with a throwaway key: its signature verifies against the locally computed
/// hash (the script and the app build the same message). No network, no Keychain.
#[test]
fn sign_release_dry_run_matches_app() {
    let Some(openssl) = openssl3() else {
        eprintln!("skipped: OpenSSL 3 not installed");
        return;
    };
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let (pem, public) = openssl_key(openssl, tmp.path());
    let dmg = tmp.path().join("MacVPN-0.2.2.dmg");
    std::fs::write(&dmg, (0..5000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>()).unwrap();
    let out = Command::new("/bin/bash")
        .arg(repo_root().join("scripts/sign-release.sh"))
        .args(["--dry-run", "--dmg"])
        .arg(&dmg)
        .arg("--backup-key")
        .arg(&pem)
        .arg("v0.2.2")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    let line = stdout.lines().find(|l| l.starts_with("signature: ")).unwrap();
    let sig = format!("{}\n", &line["signature: ".len()..]);
    let local = sha256_of_file(&dmg).unwrap();
    assert!(stdout.contains(&local));
    assert!(UpdateSignature::verify("0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify_trusted("0.2.2", &local, &sig));
    assert!(stdout.contains("not an embedded key"));
}

/// `scripts/sign-release.sh --dry-run --msi FILE --arch x64` with a throwaway key: the signature verifies in WinVPN's
/// domain for the x64 asset only, never for the arm64 asset or as a MacVPN signature.
#[test]
fn sign_release_dry_run_msi_matches_app() {
    let Some(openssl) = openssl3() else {
        eprintln!("skipped: OpenSSL 3 not installed");
        return;
    };
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let (pem, public) = openssl_key(openssl, tmp.path());
    let msi = tmp.path().join("built.msi");
    std::fs::write(&msi, (0..7000u32).map(|i| (i % 241) as u8).collect::<Vec<_>>()).unwrap();
    let out = Command::new("/bin/bash")
        .arg(repo_root().join("scripts/sign-release.sh"))
        .args(["--dry-run", "--msi"])
        .arg(&msi)
        .args(["--arch", "x64", "--backup-key"])
        .arg(&pem)
        .arg("v0.2.2")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    let line = stdout.lines().find(|l| l.starts_with("signature: ")).unwrap();
    let sig = format!("{}\n", &line["signature: ".len()..]);
    let local = sha256_of_file(&msi).unwrap();
    assert!(stdout.contains(&local));
    let win = SignatureDomain::WinVpnV1;
    assert!(UpdateSignature::verify_for(win, "WinVPN-0.2.2-x64.msi", "0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify_for(win, "WinVPN-0.2.2-arm64.msi", "0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify("0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify_trusted_for(win, "WinVPN-0.2.2-x64.msi", "0.2.2", &local, &sig));
}

/// `scripts/sign-release.sh --dry-run --deb FILE --arch arm64` with a throwaway key: the signature verifies in
/// LinVPN's domain for the arm64 package only.
#[cfg(unix)]
#[test]
fn sign_release_dry_run_deb_matches_app() {
    let Some(openssl) = openssl3() else {
        eprintln!("skipped: OpenSSL 3 not installed");
        return;
    };
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let (pem, public) = openssl_key(openssl, tmp.path());
    let deb = tmp.path().join("built.deb");
    std::fs::write(&deb, (0..7000u32).map(|i| (i % 239) as u8).collect::<Vec<_>>()).unwrap();
    let out = Command::new("/bin/bash")
        .arg(repo_root().join("scripts/sign-release.sh"))
        .args(["--dry-run", "--deb"])
        .arg(&deb)
        .args(["--arch", "arm64", "--backup-key"])
        .arg(&pem)
        .arg("v0.2.2")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    let line = stdout.lines().find(|l| l.starts_with("signature: ")).unwrap();
    let sig = format!("{}\n", &line["signature: ".len()..]);
    let local = sha256_of_file(&deb).unwrap();
    let lin = SignatureDomain::LinVpnV1;
    assert!(UpdateSignature::verify_for(lin, "linvpn_0.2.2_arm64.deb", "0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify_for(lin, "linvpn_0.2.2_amd64.deb", "0.2.2", &local, &sig, &[public]));
    assert!(!UpdateSignature::verify("0.2.2", &local, &sig, &[public]));
}

/// The script reads the embedded keys from this crate's source (`UpdateSignature`): it gets the same as the app.
// Unix only: the script runs under /bin/bash (a macOS release tool).
#[cfg(unix)]
#[test]
fn sign_release_uses_the_embedded_keys() {
    let out = Command::new("/bin/bash")
        .arg(repo_root().join("scripts/sign-release.sh"))
        .arg("--print-public-keys")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!(
            "primary {}\nbackup {}\n",
            UpdateSignature::PRIMARY_PUBLIC_KEY_BASE64,
            UpdateSignature::BACKUP_PUBLIC_KEY_BASE64
        )
    );
}

// MARK: Hardening from the parity review

/// `verify_strict` still accepts a valid signature (and the OpenSSL-made ones above).
#[test]
fn strict_verification_accepts_valid_signatures() {
    for seed in [1u8, 2, 3, 42, 255] {
        let k = key(seed);
        let sig = sign(&k, "1.0.0", DIGEST);
        assert!(UpdateSignature::verify("1.0.0", DIGEST, &sig, &[k.verifying_key().to_bytes()]), "{seed}");
    }
    // A small-order (identity) public key is rejected even with a signature that would satisfy plain verify.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut forged = vec![0u8; 64];
    forged[0] = 1;
    assert!(!UpdateSignature::verify("1.0.0", DIGEST, &swift_base64::encode(&forged), &[identity]));
}

#[test]
fn canonical_download_url() {
    let path = "/SepsiG/MacVPN/releases/download/v1.0.0/MacVPN-1.0.0.dmg";
    let canonical = format!("https://github.com{path}");
    // Accepted hosts come back in the canonical form.
    for host in [
        "github.com",
        "GitHub.com",
        "GITHUB.COM",
        "github%2Ecom",
        "Github%2ECOM",
        "ＧＩＴＨＵＢ.com",
        "gi\u{ad}thub.com",
        "github.com:443",
        "github.com:0443",
    ] {
        assert_eq!(
            UpdateURLPolicy::canonical_download_url(&format!("https://{host}{path}")).as_deref(),
            Some(canonical.as_str()),
            "{host}"
        );
    }
    assert_eq!(
        UpdateURLPolicy::canonical_download_url(&format!("HTTPS://github.com{path}")).as_deref(),
        Some(canonical.as_str())
    );
    // Everything the policy rejects, and URLs with a query or fragment, are rejected.
    for bad in [
        format!("http://github.com{path}"),
        format!("https://evil.example{path}"),
        format!("https://github.com.evil.example{path}"),
        format!("https://user@github.com{path}"),
        format!("https://github.com:8443{path}"),
        format!("https://git\u{200d}hub.com{path}"),
        format!("https://objects.githubusercontent.com{path}"),
        format!("https://github.com{path}?x=1"),
        format!("https://github.com{path}#f"),
        "not a url".to_string(),
    ] {
        assert_eq!(UpdateURLPolicy::canonical_download_url(&bad), None, "{bad}");
    }
    // The path is Foundation's percent-encoded path (invalid characters encoded).
    assert_eq!(
        UpdateURLPolicy::canonical_download_url("https://github.com/a b/c").as_deref(),
        Some("https://github.com/a%20b/c")
    );
}
