//! The core hooks (CoreFoundation collation, preferred languages), the user database, the curl HTTP client's
//! redirect policy (with a recorded curl), and the text-table coverage of this crate's messages.

use macvpn_core::collation;
use macvpn_core::l10n;
use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::http::{CurlHttpClient, HttpClient, HttpError};
use macvpn_platform_mac::testing::Call;
use macvpn_platform_mac::{install_core_hooks, system};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[test]
fn core_hooks_install_corefoundation_collation() {
    install_core_hooks();
    // Case-insensitive, accent-aware, numbers as text (as Swift's localizedCaseInsensitiveCompare).
    assert_eq!(collation::localized_case_insensitive_compare("Office", "office"), Ordering::Equal);
    assert_eq!(collation::localized_case_insensitive_compare("alpha", "Beta"), Ordering::Less);
    assert_eq!(collation::localized_case_insensitive_compare("Zeta", "alpha"), Ordering::Greater);
    assert_eq!(collation::localized_case_insensitive_compare("10", "9"), Ordering::Less);
    // Canonically equivalent forms compare equal (NFC é vs NFD e + U+0301).
    assert_eq!(collation::localized_case_insensitive_compare("caf\u{e9}", "cafe\u{301}"), Ordering::Equal);
    assert!(!l10n::table().is_empty());
}

#[test]
fn user_database() {
    let home = system::home_directory().expect("home from getpwuid");
    assert!(home.is_absolute());
    assert!(home.exists());
    assert!(!system::user_name().expect("user name").is_empty());
    // The owner of a file this process creates is the real user.
    let dir = std::env::temp_dir().join(format!("macvpn-uid-{}", uuid::Uuid::new_v4()));
    std::fs::write(&dir, b"x").unwrap();
    let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    std::fs::remove_file(&dir).unwrap();
    assert_eq!(system::user_id(), owner);
}

/// url → (status, redirect, body)
type Answers = Arc<Mutex<HashMap<String, (i64, String, Vec<u8>)>>>;

/// Records curl invocations and answers with scripted `--write-out` output, writing the body to `--output`.
#[derive(Clone, Default)]
struct FakeCurl {
    calls: Arc<Mutex<Vec<Call>>>,
    answers: Answers,
}

impl CommandRunner for FakeCurl {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.calls.lock().unwrap().push(Call {
            executable: executable.into(),
            arguments: arguments.to_vec(),
            stdin: stdin.map(str::to_string),
        });
        let url = arguments.last().unwrap().clone();
        let output = arguments.iter().position(|a| a == "--output").map(|i| arguments[i + 1].clone()).unwrap();
        match self.answers.lock().unwrap().get(&url).cloned() {
            Some((status, redirect, body)) => {
                // Like curl: an empty body may leave no file at all.
                if !body.is_empty() {
                    std::fs::write(&output, body).unwrap();
                }
                Ok(CommandResult::stdout(&format!("{status} {redirect}")))
            }
            None => Ok(CommandResult::new(6, "000 ", "curl: (6) Could not resolve host")),
        }
    }
}

const API: &str = "https://api.github.com/repositories/1/releases/latest";
const DMG: &str = "https://github.com/o/r/releases/download/v1/MacVPN-1.dmg";
const ASSETS: &str = "https://release-assets.githubusercontent.com/x/MacVPN-1.dmg";

#[test]
fn curl_client_follows_allowed_redirects_only() {
    let curl = FakeCurl::default();
    curl.answers.lock().unwrap().insert(DMG.into(), (302, ASSETS.into(), b"redirecting".to_vec()));
    curl.answers.lock().unwrap().insert(ASSETS.into(), (200, String::new(), b"dmg bytes".to_vec()));
    curl.answers.lock().unwrap().insert(API.into(), (200, String::new(), "{\"tag_name\":\"v1\"}".as_bytes().to_vec()));
    let client = CurlHttpClient::new(Box::new(curl.clone()));

    let (file, status) = client.download(DMG).unwrap();
    assert_eq!(status, 200);
    assert_eq!(std::fs::read(&file).unwrap(), b"dmg bytes");
    std::fs::remove_file(&file).unwrap();

    let response = client.get(API).unwrap();
    assert_eq!((response.status, response.data.as_slice()), (200, "{\"tag_name\":\"v1\"}".as_bytes()));

    let calls = curl.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    for call in &calls {
        assert_eq!(call.executable, "/usr/bin/curl");
        let args = &call.arguments;
        let has = |pair: [&str; 2]| args.windows(2).any(|w| w[0] == pair[0] && w[1] == pair[1]);
        assert!(has(["--proto", "=https"]) && has(["--max-redirs", "0"]) && has(["--user-agent", "MacVPN-Updater"]));
        assert_eq!(args[0], "-q", "no ~/.curlrc");
        assert_eq!(args[args.len() - 2], "--", "the URL is never an option");
        assert!(args.iter().any(|a| a == "--globoff"), "a URL's [] and {{}} are never globbed");
    }
    assert!(calls[2].arguments.windows(2).any(|w| w[0] == "--header" && w[1] == "Accept: application/vnd.github+json"));
}

#[test]
fn curl_client_stops_at_disallowed_redirect() {
    let curl = FakeCurl::default();
    curl.answers.lock().unwrap().insert(DMG.into(), (302, "https://evil.example.com/x.dmg".into(), b"".to_vec()));
    let client = CurlHttpClient::new(Box::new(curl.clone()));
    let (file, status) = client.download(DMG).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert_eq!(status, 302, "the 3xx comes back as the result");
    assert_eq!(curl.calls.lock().unwrap().len(), 1, "the disallowed target is never requested");
    // http:// is not followed either.
    curl.answers.lock().unwrap().insert(DMG.into(), (301, "http://github.com/x".into(), b"".to_vec()));
    let (file, status) = client.download(DMG).unwrap();
    std::fs::remove_file(&file).unwrap();
    assert_eq!(status, 301);
}

#[test]
fn curl_client_refuses_untrusted_urls_and_reports_transport_errors() {
    let curl = FakeCurl::default();
    let client = CurlHttpClient::new(Box::new(curl.clone()));
    assert!(matches!(client.download("https://evil.example.com/x.dmg"), Err(HttpError::Update(_))));
    assert!(matches!(client.get("http://api.github.com/x"), Err(HttpError::Update(_))));
    assert!(curl.calls.lock().unwrap().is_empty());
    let e = client.get(API).unwrap_err();
    assert!(matches!(e, HttpError::Transport(6, _)), "{e}");
    assert_eq!(e.to_string(), "curl: (6) Could not resolve host");
    // A redirect loop ends.
    curl.answers.lock().unwrap().insert(DMG.into(), (302, DMG.into(), Vec::new()));
    assert!(matches!(client.download(DMG), Err(HttpError::Transport(47, _))));
}

#[test]
fn trailer_parsing() {
    assert_eq!(CurlHttpClient::parse_trailer("200 "), Some((200, String::new())));
    assert_eq!(CurlHttpClient::parse_trailer("302 https://x/y"), Some((302, "https://x/y".into())));
    assert_eq!(CurlHttpClient::parse_trailer("garbage"), None);
}

/// Every `l10n::tr` key used in this crate has a Hungarian entry (so no message falls back to English).
#[test]
fn every_message_is_in_the_text_table() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let re = regex::Regex::new(r#"(?s)(?:l10n::tr|tr1)\(\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let mut keys = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for m in re.captures_iter(&text) {
            keys.push(m[1].replace("\\\"", "\"").replace("\\n", "\n"));
        }
    }
    // Keys passed through variables (the login item notes) are checked in their own tests.
    assert!(keys.len() > 40, "{}", keys.len());
    let missing: Vec<&String> = keys.iter().filter(|k| l10n::hungarian(k).is_none()).collect();
    assert!(missing.is_empty(), "{missing:?}");
}

/// curl never sees the app's environment: only PATH, HOME and LANG=C.
#[test]
fn curl_environment_is_minimal() {
    let env = CurlHttpClient::environment();
    assert_eq!(env.keys().cloned().collect::<Vec<_>>(), ["HOME", "LANG", "PATH"]);
    assert_eq!(env["PATH"], "/usr/bin:/bin");
    assert_eq!(env["LANG"], "C");
    assert_eq!(std::path::PathBuf::from(&env["HOME"]), system::home_directory().unwrap());
    // The production runner applies it: a child sees nothing else (SSLKEYLOGFILE, *_PROXY, CURL_CA_BUNDLE …).
    let r = CurlHttpClient::runner().run("/usr/bin/env", &[], None).unwrap();
    let mut keys: Vec<&str> = r.stdout.lines().filter_map(|l| l.split('=').next()).collect();
    keys.sort();
    assert_eq!(keys, ["HOME", "LANG", "PATH"]);
}

/// A redirect hop's body is never returned as data: the file is deleted before each hop, and a final 3xx has
/// no data.
#[test]
fn curl_redirect_bodies_are_never_data() {
    let curl = FakeCurl::default();
    // 302 with a body, then 200 with an empty body (curl writes no file).
    curl.answers.lock().unwrap().insert(DMG.into(), (302, ASSETS.into(), b"redirect page".to_vec()));
    curl.answers.lock().unwrap().insert(ASSETS.into(), (200, String::new(), Vec::new()));
    let client = CurlHttpClient::new(Box::new(curl.clone()));
    let (file, status) = client.download(DMG).unwrap();
    assert_eq!(status, 200);
    assert_eq!(std::fs::read(&file).unwrap(), b"");
    std::fs::remove_file(&file).unwrap();
    // A disallowed redirect: its 3xx body is dropped too.
    curl.answers.lock().unwrap().insert(DMG.into(), (302, "https://evil.example.com/x".into(), b"page".to_vec()));
    let (file, status) = client.download(DMG).unwrap();
    assert_eq!((status, std::fs::read(&file).unwrap()), (302, Vec::new()));
    std::fs::remove_file(&file).unwrap();
    curl.answers.lock().unwrap().insert(API.into(), (301, "http://x/".into(), b"moved".to_vec()));
    assert_eq!(client.get(API).unwrap().data, b"");
}

/// curl gets the canonical github.com URL, whatever form the release JSON used; redirect targets go with a
/// lower-case ASCII host, and a percent-encoded or non-ASCII host in a Location is never followed.
#[test]
fn curl_gets_canonical_urls() {
    let curl = FakeCurl::default();
    curl.answers.lock().unwrap().insert(DMG.into(), (200, String::new(), b"x".to_vec()));
    let client = CurlHttpClient::new(Box::new(curl.clone()));
    for raw in [
        DMG.replace("github.com", "github%2Ecom"),
        DMG.replace("github.com", "\u{FF47}\u{FF49}\u{FF54}\u{FF48}\u{FF55}\u{FF42}.com"),
        DMG.replace("https://github.com", "HTTPS://GitHub.com:443"),
    ] {
        let (file, status) = client.download(&raw).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(status, 200, "{raw}");
    }
    let urls: Vec<String> = curl.calls.lock().unwrap().iter().map(|c| c.arguments.last().unwrap().clone()).collect();
    assert_eq!(urls, [DMG, DMG, DMG]);

    // Disallowed hosts never reach curl.
    curl.calls.lock().unwrap().clear();
    for bad in [
        "https://evil.example.com/x.dmg",
        "https://github.com.evil.com/x",
        "https://github.com/x?y=1",
        "http://github.com/x",
    ] {
        assert!(matches!(client.download(bad), Err(HttpError::Update(_))), "{bad}");
    }
    assert!(matches!(client.get("https://api.github%2Ecom.evil.com/x"), Err(HttpError::Update(_))));
    assert!(curl.calls.lock().unwrap().is_empty());

    // Redirect targets: re-serialised with a lower-case host, the query kept; encoded hosts are not followed.
    let signed = "https://release-assets.githubusercontent.com/github-production/x?sp=r&sig=a%2Bb";
    curl.answers.lock().unwrap().insert(
        DMG.into(),
        (302, signed.replace("release-assets.githubusercontent", "Release-Assets.GitHubUserContent"), Vec::new()),
    );
    curl.answers.lock().unwrap().insert(signed.into(), (200, String::new(), b"dmg".to_vec()));
    let (file, status) = client.download(DMG).unwrap();
    assert_eq!((status, std::fs::read(&file).unwrap()), (200, b"dmg".to_vec()));
    std::fs::remove_file(&file).unwrap();
    assert_eq!(curl.calls.lock().unwrap().last().unwrap().arguments.last().unwrap(), signed);
    for location in [
        "https://release-assets.githubusercontent%2Ecom/x",
        "https://release-assets.githubuserconten\u{FF54}.com/x",
        "https://release-assets.githubusercontent.com:8443/x",
    ] {
        curl.calls.lock().unwrap().clear();
        curl.answers.lock().unwrap().insert(DMG.into(), (302, location.into(), Vec::new()));
        let (file, status) = client.download(DMG).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(status, 302, "{location}");
        assert_eq!(curl.calls.lock().unwrap().len(), 1, "{location} was followed");
    }
    use macvpn_platform_mac::http::canonical_redirect_url;
    assert_eq!(
        canonical_redirect_url("https://API.GitHub.com/repositories/1/releases/latest#x").as_deref(),
        Some("https://api.github.com/repositories/1/releases/latest")
    );
    // The path goes percent-encoded (as Foundation's `percentEncodedPath`).
    assert_eq!(
        canonical_redirect_url("https://objects.githubusercontent.com/a b").as_deref(),
        Some("https://objects.githubusercontent.com/a%20b")
    );
    assert_eq!(canonical_redirect_url("https://user@objects.githubusercontent.com/x"), None);
}
