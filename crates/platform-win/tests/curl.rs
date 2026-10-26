//! The curl layer on Windows (System32's `curl.exe`): the installed curl knows every flag the layer uses, the
//! catalog fetcher runs it with the shared arguments and the bearer token on stdin only, and the Windows runner
//! (minimal environment, no console window, a time limit) hands curl its stdin. Only loopback servers of the test;
//! nothing on the internet.

#![cfg(windows)]

use macvpn_core::catalog::fetch::FetchRequest;
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::vault::SourceValidators;
use macvpn_platform_api::curl::CommandError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn https(url: &str) -> CatalogSource {
    CatalogSource::Https(HttpsUrl::parse(url).unwrap())
}

#[test]
fn windows_curl_supports_every_flag_the_curl_layer_uses() {
    let curl = macvpn_platform_win::windows_curl_for_tests();
    let out = std::process::Command::new(&curl.executable).args(["--help", "all"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--globoff",
        "--silent",
        "--show-error",
        "--proto",
        "--max-redirs",
        "--connect-timeout",
        "--max-time",
        "--user-agent",
        "--header",
        "--write-out",
        "--output",
        "--dump-header",
        "--max-filesize",
        "--config",
        "--cacert",
        "--ssl-revoke-best-effort",
    ] {
        assert!(help.contains(flag), "{} lacks {flag}", curl.executable);
    }
    assert!(curl.executable.to_ascii_lowercase().ends_with(r"\system32\curl.exe"), "{}", curl.executable);
    assert_eq!(curl.extra_args, ["--ssl-revoke-best-effort"]);
}

#[test]
fn the_catalog_fetcher_runs_windows_curl_with_the_shared_arguments() {
    let (fetcher, seen) = macvpn_platform_win::catalog_fetcher_recording_for_tests();
    let source = https("https://catalog.example.com/team.macvpncatalog");
    let previous = SourceValidators::default();
    let _ = fetcher.fetch(&FetchRequest { source: &source, bearer: Some("abc.DEF-123"), previous: &previous });
    let calls = seen.lock().unwrap();
    let (exe, args, stdin) = &calls[0];
    assert!(exe.to_ascii_lowercase().ends_with(r"\system32\curl.exe"), "{exe}");
    // The flavour's argument right after `--max-time <n>`, then WinVPN's user agent.
    let i = args.iter().position(|a| a == "--max-time").unwrap();
    assert_eq!(args[i + 2], "--ssl-revoke-best-effort");
    assert_eq!(
        args[i + 3..i + 5],
        ["--user-agent".to_string(), format!("WinVPN-Catalog/{}", env!("CARGO_PKG_VERSION"))]
    );
    assert!(args.windows(2).any(|w| w == ["--config", "-"]));
    assert!(!args.iter().any(|a| a.contains("abc.DEF-123")), "the token in the argv: {args:?}");
    assert_eq!(stdin.as_deref(), Some("header = \"Authorization: Bearer abc.DEF-123\"\n"));
    // The private directory is under the user's temp folder and gone afterwards.
    let out = &args[args.iter().position(|a| a == "--output").unwrap() + 1];
    let dir = std::path::Path::new(out).parent().unwrap();
    assert!(dir.starts_with(std::env::temp_dir()), "{out}");
    assert!(!dir.exists(), "{} was left behind", dir.display());
}

#[test]
fn the_runner_hands_curl_its_config_on_stdin_and_nothing_of_the_apps_environment() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "the request ended early");
            request.extend_from_slice(&buf[..n]);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });
    let curl = macvpn_platform_win::windows_curl_for_tests();
    let runner = macvpn_platform_win::curl_runner_for_tests(30.0);
    // Plain HTTP on loopback only here (the layer itself is `--proto =https`): the request shows what curl sent.
    let args: Vec<String> =
        ["-q", "--silent", "--config", "-", "--max-time", "20", "--", &format!("http://127.0.0.1:{port}/probe")]
            .iter()
            .map(|s| s.to_string())
            .collect();
    let result = runner.run(&curl.executable, &args, Some("header = \"Authorization: Bearer abc.DEF-123\"\n")).unwrap();
    let request = server.join().unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(result.stdout, "ok");
    assert!(request.contains("Authorization: Bearer abc.DEF-123\r\n"), "{request}");

    // The child's environment: `SystemRoot` and `PATH` (System32) only.
    let system32 = std::path::Path::new(&curl.executable).parent().unwrap().to_path_buf();
    let cmd = system32.join("cmd.exe").to_string_lossy().into_owned();
    let env = runner.run(&cmd, &["/d".to_string(), "/c".to_string(), "set".to_string()], None).unwrap();
    let names: Vec<String> = env
        .stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(name, _)| name.to_ascii_uppercase())
        .filter(|name| !name.is_empty())
        .collect();
    assert!(names.contains(&"SYSTEMROOT".to_string()), "{names:?}");
    assert!(names.contains(&"PATH".to_string()), "{names:?}");
    for leaked in ["USERPROFILE", "TEMP", "TMP", "APPDATA", "HTTPS_PROXY", "CURL_HOME"] {
        assert!(!names.contains(&leaked.to_string()), "{leaked} reached the child: {names:?}");
    }
    let path_line = env.stdout.lines().find(|l| l.to_ascii_uppercase().starts_with("PATH=")).unwrap();
    assert!(path_line[5..].eq_ignore_ascii_case(&system32.to_string_lossy()), "{path_line}");
}

#[test]
fn the_runner_stops_curl_at_its_time_limit() {
    // A server that accepts and never answers (TLS never starts): only the runner's limit ends the run.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _server = std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    let curl = macvpn_platform_win::windows_curl_for_tests();
    let runner = macvpn_platform_win::curl_runner_for_tests(2.0);
    let args: Vec<String> = ["-q", "--silent", "--max-time", "60", "--", &format!("https://127.0.0.1:{port}/")]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let started = Instant::now();
    let result = runner.run(&curl.executable, &args, None);
    assert!(matches!(&result, Err(CommandError::TimedOut(exe)) if *exe == curl.executable), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(15), "{:?}", started.elapsed());
}

#[test]
fn the_runner_refuses_a_relative_executable() {
    let runner = macvpn_platform_win::curl_runner_for_tests(5.0);
    assert!(matches!(runner.run("curl.exe", &[], None), Err(CommandError::Io(_))));
}

#[test]
fn a_closed_port_is_unavailable_through_the_real_curl() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let fetcher = macvpn_platform_win::catalog_fetcher_for_tests();
    let source = https(&format!("https://127.0.0.1:{port}/team.macvpncatalog"));
    let previous = SourceValidators::default();
    let result = fetcher.fetch(&FetchRequest { source: &source, bearer: Some("abc.DEF-123"), previous: &previous });
    assert!(matches!(&result, Err(CatalogError::Unavailable(host)) if host == "127.0.0.1"), "{result:?}");
}
