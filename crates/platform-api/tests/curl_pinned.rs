//! `CurlHttpClient::download_pinned` (2b plan, Task 17: the OpenVPN Community MSI): HTTPS only, redirects to
//! HTTPS targets only (at most 5), `--max-filesize`, and the file is kept only when its SHA-256 is the pin.
//! Portable: a recording runner plays curl, nothing is started.

use macvpn_core::update::{UpdateError, sha256_hex};
use macvpn_platform_api::curl::http::{CurlHttpClient, HttpError};
use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner, Curl};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Answers each request with the next scripted `(status, redirect, body)` (the last one repeats), writing the body
/// to the `--output` path, and records each argv.
struct Server {
    answers: Vec<(i64, &'static str, Vec<u8>)>,
    calls: Mutex<Vec<Vec<String>>>,
}

struct Runner(Arc<Server>);

impl CommandRunner for Runner {
    fn run(&self, _exe: &str, args: &[String], _stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        let mut calls = self.0.calls.lock().unwrap();
        let (status, redirect, body) = &self.0.answers[calls.len().min(self.0.answers.len() - 1)];
        calls.push(args.to_vec());
        let out = args.iter().position(|a| a == "--output").map(|i| args[i + 1].clone()).unwrap();
        std::fs::write(out, body).unwrap();
        Ok(CommandResult::stdout(&format!("{status} {redirect}")))
    }
}

fn server(answers: Vec<(i64, &'static str, Vec<u8>)>) -> Arc<Server> {
    Arc::new(Server { answers, calls: Mutex::default() })
}

fn private_dir(prefix: &str) -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("{prefix}.{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

thread_local! {
    /// This test's own download base (each test runs on its own thread), so one test never sees another's files.
    static BASE: PathBuf = private_dir("macvpn-pinned-base").unwrap();
}

fn client(server: &Arc<Server>) -> CurlHttpClient {
    let curl = Curl {
        executable: "curl".into(),
        extra_args: vec![],
        private_dir,
        temp_base: || Ok(BASE.with(PathBuf::clone)),
    };
    CurlHttpClient::with_curl(Box::new(Runner(server.clone())), curl)
}

/// Every file in this test's download base (what a failed download must not leave behind).
fn files_in_base() -> Vec<PathBuf> {
    BASE.with(|b| std::fs::read_dir(b).unwrap().map(|e| e.unwrap().path()).collect())
}

const URL: &str = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.8-I001-amd64.msi";

#[test]
fn a_pinned_download_is_kept_only_with_the_right_hash() {
    let s = server(vec![(200, "", b"payload".to_vec())]);
    let path = client(&s).download_pinned(URL, &sha256_hex(b"payload"), 1024).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    std::fs::remove_file(&path).unwrap();
    let args = &s.calls.lock().unwrap()[0];
    assert!(args.windows(2).any(|w| w == ["--max-filesize", "1024"]));
    assert!(args.windows(2).any(|w| w == ["--proto", "=https"]));
    assert_eq!(args.last().unwrap(), URL);
    assert_eq!(args[args.len() - 2], "--");

    let s = server(vec![(200, "", b"payload".to_vec())]);
    let before = files_in_base();
    let wrong = client(&s).download_pinned(URL, &"0".repeat(64), 1024);
    assert!(matches!(wrong, Err(HttpError::Update(UpdateError::ChecksumMismatch))), "{wrong:?}");
    assert_eq!(files_in_base(), before, "the wrong file is deleted");
}

#[test]
fn only_https_is_downloaded() {
    let s = server(vec![(200, "", vec![])]);
    for url in ["http://swupdate.openvpn.org/x.msi", "https://user@swupdate.openvpn.org/x.msi", "ftp://x/y"] {
        let r = client(&s).download_pinned(url, &"0".repeat(64), 1024);
        assert!(matches!(r, Err(HttpError::Update(UpdateError::UntrustedUrl(_)))), "{url}: {r:?}");
    }
    assert!(s.calls.lock().unwrap().is_empty());
}

#[test]
fn a_malformed_pin_is_refused_before_any_request() {
    let s = server(vec![(200, "", vec![])]);
    for pin in ["", "abc", &"G".repeat(64), &"A".repeat(64)] {
        let r = client(&s).download_pinned(URL, pin, 1024);
        assert!(matches!(r, Err(HttpError::Update(UpdateError::ChecksumMismatch))), "{pin}: {r:?}");
    }
    assert!(s.calls.lock().unwrap().is_empty());
}

#[test]
fn https_redirects_are_followed_and_others_end_the_download() {
    // swupdate.openvpn.org answers 301 to swupdate.openvpn.net (the pins file's note).
    let target = "https://swupdate.openvpn.net/community/releases/OpenVPN-2.7.8-I001-amd64.msi";
    let s = server(vec![(301, target, b"<html>moved</html>".to_vec()), (200, "", b"msi".to_vec())]);
    let path = client(&s).download_pinned(URL, &sha256_hex(b"msi"), 1024).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"msi");
    std::fs::remove_file(&path).unwrap();
    let calls = s.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].last().unwrap(), target);
    assert!(calls[1].windows(2).any(|w| w == ["--max-filesize", "1024"]));
    drop(calls);

    // A redirect to plain HTTP is not followed: the 3xx is the answer.
    let s = server(vec![(302, "http://swupdate.openvpn.net/x.msi", vec![])]);
    let r = client(&s).download_pinned(URL, &sha256_hex(b""), 1024);
    assert!(matches!(r, Err(HttpError::Update(UpdateError::Http(302)))), "{r:?}");
    assert_eq!(s.calls.lock().unwrap().len(), 1);

    // An endless chain stops after 5 redirects.
    let s = server(vec![(301, target, vec![])]);
    let r = client(&s).download_pinned(URL, &sha256_hex(b""), 1024);
    assert!(matches!(r, Err(HttpError::Transport(..))), "{r:?}");
    assert_eq!(s.calls.lock().unwrap().len(), 6);
}

#[test]
fn an_error_status_is_no_download() {
    let s = server(vec![(404, "", b"not found".to_vec())]);
    let before = files_in_base();
    let r = client(&s).download_pinned(URL, &sha256_hex(b"not found"), 1024);
    assert!(matches!(r, Err(HttpError::Update(UpdateError::Http(404)))), "{r:?}");
    assert_eq!(files_in_base(), before);
}
