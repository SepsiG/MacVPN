//! Golden argv of every curl call MacVPN makes (written before the curl layer moved to platform-api; it must stay
//! green unchanged after the move).
#![cfg(target_os = "macos")]

use macvpn_core::catalog::fetch::{CatalogFetcher, FetchRequest};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::vault::SourceValidators;
use macvpn_platform_mac::catalog_http::CurlCatalogFetcher;
use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::http::{CurlHttpClient, HttpClient};
use std::sync::{Arc, Mutex};

type Call = (String, Vec<String>, Option<String>);

/// Records every call and answers each with the next scripted `--write-out` trailer (`200 ` once they run out).
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<Call>>,
    answers: Mutex<Vec<&'static str>>,
}

struct Runner(Arc<Recorder>);

impl CommandRunner for Runner {
    fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.0.calls.lock().unwrap().push((exe.to_string(), args.to_vec(), stdin.map(String::from)));
        let mut answers = self.0.answers.lock().unwrap();
        let answer = if answers.is_empty() { "200 " } else { answers.remove(0) };
        Ok(CommandResult::stdout(answer))
    }
}

fn recorder(answers: &[&'static str]) -> Arc<Recorder> {
    let rec = Arc::new(Recorder::default());
    *rec.answers.lock().unwrap() = answers.to_vec();
    rec
}

/// The private directory's files are fresh each time: compare them by shape only (the file name is kept).
fn normalize(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    for flag in ["--output", "--dump-header"] {
        if let Some(i) = out.iter().position(|a| a == flag) {
            let name = std::path::Path::new(&out[i + 1]).file_name().unwrap().to_string_lossy().into_owned();
            out[i + 1] = format!("<DIR>/{name}");
        }
    }
    out
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_release_query_argv_is_pinned() {
    let rec = recorder(&[]);
    let client = CurlHttpClient::new(Box::new(Runner(rec.clone())));
    let _ = client.get("https://api.github.com/repositories/1/releases/latest");
    let seen = rec.calls.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "/usr/bin/curl");
    assert_eq!(
        normalize(&seen[0].1),
        strings(&[
            "-q",
            "--globoff",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            "--globoff",
            "--connect-timeout",
            "30",
            "--max-time",
            "30",
            "--user-agent",
            "MacVPN-Updater",
            "--header",
            "Accept: application/vnd.github+json",
            "--write-out",
            "%{http_code} %{redirect_url}",
            "--output",
            "<DIR>/response",
            "--",
            "https://api.github.com/repositories/1/releases/latest",
        ])
    );
    assert_eq!(seen[0].2, None);
}

#[test]
fn the_download_argv_with_a_redirect_is_pinned() {
    let asset = "https://github.com/acme/macvpn/releases/download/v9.9.9/MacVPN-9.9.9.dmg";
    let cdn = "https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=ab%2Fc";
    let rec = recorder(&[Box::leak(format!("302 {cdn}").into_boxed_str())]);
    let client = CurlHttpClient::new(Box::new(Runner(rec.clone())));
    let (file, status) = client.download(asset).unwrap();
    let _ = std::fs::remove_file(&file);
    assert_eq!(status, 200);
    let seen = rec.calls.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for (i, url) in [asset, cdn].iter().enumerate() {
        assert_eq!(seen[i].0, "/usr/bin/curl");
        assert_eq!(
            normalize(&seen[i].1),
            strings(&[
                "-q",
                "--globoff",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--max-redirs",
                "0",
                "--globoff",
                "--connect-timeout",
                "30",
                "--max-time",
                "600",
                "--user-agent",
                "MacVPN-Updater",
                "--write-out",
                "%{http_code} %{redirect_url}",
                "--output",
                "<DIR>/download",
                "--",
                url,
            ]),
            "hop {i}"
        );
        assert_eq!(seen[i].2, None);
    }
}

#[test]
fn the_catalog_argv_and_stdin_are_pinned_across_origins() {
    let cat = "https://vpn.example.com/team/acme.macvpncatalog";
    let other = "https://cdn.example.org/acme.macvpncatalog";
    let rec = recorder(&[Box::leak(format!("302 {other}").into_boxed_str())]);
    let fetcher = CurlCatalogFetcher::new(Box::new(Runner(rec.clone())));
    let previous = SourceValidators {
        etag: Some("\"v1\"".into()),
        last_modified: Some("Mon, 19 Oct 2026 08:00:00 GMT".into()),
        content_hash: None,
    };
    let source = CatalogSource::Https(HttpsUrl::parse(cat).unwrap());
    fetcher.fetch(&FetchRequest { source: &source, bearer: Some("tok.EN"), previous: &previous }).unwrap();
    let seen = rec.calls.lock().unwrap();
    assert_eq!(seen.len(), 2);
    let ua = format!("MacVPN-Catalog/{}", env!("CARGO_PKG_VERSION"));
    let head = [
        "-q",
        "--globoff",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--globoff",
        "--connect-timeout",
        "30",
        "--max-time",
        "60",
        "--user-agent",
        ua.as_str(),
    ];
    let mut first = strings(&head);
    first.extend(strings(&[
        "--config",
        "-",
        "--max-filesize",
        "8388608",
        "--dump-header",
        "<DIR>/headers",
        "--write-out",
        "%{http_code} %{redirect_url}",
        "--output",
        "<DIR>/body",
        "--header",
        "If-None-Match: \"v1\"",
        "--header",
        "If-Modified-Since: Mon, 19 Oct 2026 08:00:00 GMT",
        "--",
        cat,
    ]));
    assert_eq!(seen[0].0, "/usr/bin/curl");
    assert_eq!(normalize(&seen[0].1), first);
    assert_eq!(seen[0].2.as_deref(), Some("header = \"Authorization: Bearer tok.EN\"\n"));
    // Another origin: neither the token nor the validators.
    let mut second = strings(&head);
    second.extend(strings(&[
        "--max-filesize",
        "8388608",
        "--dump-header",
        "<DIR>/headers",
        "--write-out",
        "%{http_code} %{redirect_url}",
        "--output",
        "<DIR>/body",
        "--",
        other,
    ]));
    assert_eq!(seen[1].0, "/usr/bin/curl");
    assert_eq!(normalize(&seen[1].1), second);
    assert_eq!(seen[1].2, None);
}

#[test]
fn the_environment_is_pinned() {
    let env = CurlHttpClient::environment();
    assert_eq!(env.keys().cloned().collect::<Vec<_>>(), ["HOME", "LANG", "PATH"]);
    assert_eq!(env["PATH"], "/usr/bin:/bin");
    assert_eq!(env["LANG"], "C");
    assert_eq!(std::path::Path::new(&env["HOME"]), macvpn_platform_mac::system::home_directory().unwrap());
    // The production runner's limit: the 600 s download plus a 30 s margin.
    assert_eq!(CurlHttpClient::runner().timeout, 630.0);
}
