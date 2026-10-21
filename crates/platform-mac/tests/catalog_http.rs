//! The HTTPS catalog fetcher (plan Task 9): a fake `CommandRunner` that plays curl (it reads the argument list
//! and writes the header dump, the body and the `--write-out` trailer as curl would), and a local HTTPS server on
//! 127.0.0.1 with a throwaway CA passed through `--cacert` (the `test-support` hook only), as in the spike. No
//! external host is contacted; the one live test is `#[ignore]` and needs `MACVPN_CATALOG_TEST_URL`.
#![cfg(target_os = "macos")]

mod common;

use common::Scratch;
use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::format::{CatalogError, MAX_CATALOG_BYTES};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::vault::SourceValidators;
use macvpn_platform_mac::catalog_http::{CurlCatalogFetcher, MAX_REDIRECTS};
use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::http::CurlHttpClient;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

const TOKEN: &str = "s3cr3t.TOKEN~abc+/==";

// MARK: - fake curl

#[derive(Clone, Default)]
struct Hop {
    exit: i32,
    status: i64,
    redirect: String,
    headers: Vec<(String, String)>,
    /// `None`: no output file (a 304 or an aborted transfer).
    body: Option<Vec<u8>>,
}

impl Hop {
    fn status(status: i64) -> Hop {
        Hop { status, body: Some(Vec::new()), ..Hop::default() }
    }

    fn ok(body: &[u8], headers: &[(&str, &str)]) -> Hop {
        Hop {
            status: 200,
            body: Some(body.to_vec()),
            headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            ..Hop::default()
        }
    }

    fn redirect(status: i64, to: &str) -> Hop {
        Hop { status, redirect: to.to_string(), body: Some(Vec::new()), ..Hop::default() }
    }

    fn exit(code: i32) -> Hop {
        Hop { exit: code, status: 0, ..Hop::default() }
    }
}

#[derive(Debug, Clone)]
struct Seen {
    args: Vec<String>,
    stdin: Option<String>,
    url: String,
    dir: PathBuf,
}

#[derive(Default)]
struct FakeCurl {
    hops: Mutex<HashMap<String, Hop>>,
    seen: Mutex<Vec<Seen>>,
}

impl FakeCurl {
    fn new(hops: &[(&str, Hop)]) -> Arc<FakeCurl> {
        let fake = FakeCurl::default();
        for (url, hop) in hops {
            fake.hops.lock().unwrap().insert(url.to_string(), hop.clone());
        }
        Arc::new(fake)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn value_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).map(|i| args[i + 1].as_str())
}

struct Runner(Arc<FakeCurl>);

impl CommandRunner for Runner {
    fn run(&self, executable: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.0.play(executable, args, stdin)
    }
}

impl FakeCurl {
    fn play(&self, executable: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        assert_eq!(executable, "/usr/bin/curl");
        let url = args.last().unwrap().clone();
        assert_eq!(args[args.len() - 2], "--", "the URL comes right after --");
        let headers = PathBuf::from(value_after(args, "--dump-header").unwrap());
        let output = PathBuf::from(value_after(args, "--output").unwrap());
        assert_eq!(headers.parent(), output.parent());
        let dir = output.parent().unwrap().to_path_buf();
        assert!(dir.is_dir(), "the private directory exists during the request");
        self.seen.lock().unwrap().push(Seen {
            args: args.to_vec(),
            stdin: stdin.map(str::to_string),
            url: url.clone(),
            dir: dir.clone(),
        });
        let hop = self.hops.lock().unwrap().get(&url).cloned().unwrap_or_else(|| Hop::status(404));
        if hop.exit == 0 || hop.status != 0 {
            let mut dump = format!("HTTP/1.1 {} X\r\n", hop.status);
            for (n, v) in &hop.headers {
                dump.push_str(&format!("{n}: {v}\r\n"));
            }
            dump.push_str("\r\n");
            std::fs::write(&headers, dump).unwrap();
        }
        if let Some(body) = &hop.body {
            std::fs::write(&output, body).unwrap();
        }
        Ok(CommandResult {
            exit_code: hop.exit,
            stdout: format!("{} {}", hop.status, hop.redirect),
            stderr: if hop.exit == 0 { String::new() } else { format!("curl: ({}) failed", hop.exit) },
        })
    }
}

fn fetcher(fake: &Arc<FakeCurl>) -> CurlCatalogFetcher {
    CurlCatalogFetcher::new(Box::new(Runner(fake.clone())))
}

fn url(s: &str) -> CatalogSource {
    CatalogSource::Https(HttpsUrl::parse(s).unwrap())
}

fn fetch(
    f: &CurlCatalogFetcher,
    source: &CatalogSource,
    bearer: Option<&str>,
    previous: &SourceValidators,
) -> Result<FetchOutcome, CatalogError> {
    f.fetch(&FetchRequest { source, bearer, previous })
}

fn assert_dirs_gone(fake: &FakeCurl) {
    let seen = fake.seen();
    assert!(!seen.is_empty());
    for s in seen {
        assert!(!s.dir.exists(), "the private directory is removed: {}", s.dir.display());
    }
}

const CAT: &str = "https://vpn.example.com/team/acme.macvpncatalog";

// MARK: - arguments and the token

#[test]
fn the_argument_list_is_pinned_and_the_token_goes_only_on_stdin() {
    let fake = FakeCurl::new(&[(CAT, Hop::ok(b"MVPNCAT1-bytes", &[]))]);
    let previous = SourceValidators {
        etag: Some("\"v1\"".into()),
        last_modified: Some("Mon, 19 Oct 2026 08:00:00 GMT".into()),
        content_hash: None,
    };
    fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &previous).unwrap();
    let seen = fake.seen();
    assert_eq!(seen.len(), 1);
    let args = &seen[0].args;
    assert_eq!(args[0], "-q", "-q must be the first argument");
    assert!(args.windows(2).any(|w| w == ["--proto", "=https"]));
    assert!(args.windows(2).any(|w| w == ["--max-redirs", "0"]));
    assert!(args.windows(2).any(|w| w == ["--max-time", "60"]));
    assert!(args.windows(2).any(|w| w == ["--max-filesize", "8388608"]));
    assert!(args.windows(2).any(|w| w == ["--config", "-"]));
    assert!(args.windows(2).any(|w| w == ["--header", "If-None-Match: \"v1\""]));
    assert!(args.windows(2).any(|w| w == ["--header", "If-Modified-Since: Mon, 19 Oct 2026 08:00:00 GMT"]));
    assert!(args.windows(2).any(|w| w == ["--write-out", "%{http_code} %{redirect_url}"]));
    let ua = value_after(args, "--user-agent").unwrap();
    assert!(ua.starts_with("MacVPN-Catalog/"), "{ua}");
    assert!(!args.iter().any(|a| a == "--cacert"), "production never passes a CA");
    assert_eq!(args[args.len() - 2..], ["--".to_string(), CAT.to_string()]);
    assert!(!args.iter().any(|a| a.contains(TOKEN) || a.contains("Bearer")), "no token in argv");
    assert_eq!(seen[0].stdin.as_deref(), Some(format!("header = \"Authorization: Bearer {TOKEN}\"\n").as_str()));
    // The process environment is the fixed one: nothing of the app's, so no token either.
    let env = CurlHttpClient::environment();
    assert!(env.keys().all(|k| ["PATH", "HOME", "LANG"].contains(&k.as_str())));
    assert!(!env.values().any(|v| v.contains(TOKEN)));
}

#[test]
fn without_a_token_there_is_no_config_on_stdin_and_bad_validators_are_not_sent() {
    let fake = FakeCurl::new(&[(CAT, Hop::ok(b"x", &[]))]);
    let previous = SourceValidators {
        etag: Some("\"v1\"\r\nX-Evil: 1".into()),
        last_modified: Some("é".into()),
        content_hash: None,
    };
    fetch(&fetcher(&fake), &url(CAT), None, &previous).unwrap();
    let seen = fake.seen();
    assert_eq!(seen[0].stdin, None);
    assert!(!seen[0].args.iter().any(|a| a == "--config"));
    assert!(!seen[0].args.iter().any(|a| a.starts_with("If-")), "{:?}", seen[0].args);
}

#[test]
fn a_token_that_is_not_a_bearer_token_is_refused_before_any_request() {
    let fake = FakeCurl::new(&[(CAT, Hop::ok(b"x", &[]))]);
    let err =
        fetch(&fetcher(&fake), &url(CAT), Some("bad\"token\nurl = \"http://evil\""), &SourceValidators::default())
            .unwrap_err();
    assert!(matches!(err, CatalogError::Io(_)), "{err:?}");
    assert!(fake.seen().is_empty());
}

#[test]
fn a_file_source_is_not_this_fetchers() {
    let fake = FakeCurl::new(&[]);
    let source = CatalogSource::File(PathBuf::from("/Volumes/Share/acme.macvpncatalog"));
    assert!(matches!(fetch(&fetcher(&fake), &source, None, &SourceValidators::default()), Err(CatalogError::Io(_))));
    assert!(fake.seen().is_empty());
}

// MARK: - responses

#[test]
fn a_200_gives_the_bytes_and_the_validators_from_mixed_case_headers() {
    let fake = FakeCurl::new(&[(
        CAT,
        Hop::ok(b"MVPNCAT1 body", &[("eTaG", "\"cat-v1\""), ("last-MODIFIED", "Mon, 19 Oct 2026 08:00:00 GMT")]),
    )]);
    let outcome = fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()).unwrap();
    let FetchOutcome::Fetched { bytes, validators } = outcome else { panic!("fetched expected") };
    assert_eq!(bytes, b"MVPNCAT1 body");
    assert_eq!(validators.etag.as_deref(), Some("\"cat-v1\""));
    assert_eq!(validators.last_modified.as_deref(), Some("Mon, 19 Oct 2026 08:00:00 GMT"));
    assert_dirs_gone(&fake);
}

#[test]
fn a_304_without_an_output_file_is_not_modified() {
    let fake = FakeCurl::new(&[(CAT, Hop { status: 304, body: None, ..Hop::default() })]);
    let previous = SourceValidators { etag: Some("\"cat-v1\"".into()), ..SourceValidators::default() };
    assert_eq!(fetch(&fetcher(&fake), &url(CAT), None, &previous).unwrap(), FetchOutcome::NotModified);
    assert_dirs_gone(&fake);
}

#[test]
fn a_200_without_an_output_file_reads_as_empty() {
    let fake = FakeCurl::new(&[(CAT, Hop { status: 200, body: None, ..Hop::default() })]);
    let FetchOutcome::Fetched { bytes, .. } =
        fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()).unwrap()
    else {
        panic!()
    };
    assert!(bytes.is_empty());
}

#[test]
fn errors_map_to_their_catalog_errors_and_the_directory_is_always_removed() {
    type Check = fn(&CatalogError) -> bool;
    let cases: Vec<(Hop, Check)> = vec![
        (Hop::status(401), |e| matches!(e, CatalogError::Io(m) if m.contains("access denied"))),
        (Hop::status(403), |e| matches!(e, CatalogError::Io(m) if m.contains("access denied"))),
        (Hop::status(500), |e| matches!(e, CatalogError::Io(m) if m == "HTTP 500")),
        (Hop::status(404), |e| matches!(e, CatalogError::Io(m) if m == "HTTP 404")),
        (Hop::exit(6), |e| *e == CatalogError::Unavailable("vpn.example.com".into())),
        (Hop::exit(7), |e| matches!(e, CatalogError::Unavailable(_))),
        (Hop::exit(28), |e| matches!(e, CatalogError::Unavailable(_))),
        (Hop::exit(35), |e| matches!(e, CatalogError::Unavailable(_))),
        (Hop::exit(60), |e| matches!(e, CatalogError::Io(m) if m.contains("certificate"))),
        (Hop::exit(63), |e| *e == CatalogError::TooLarge),
    ];
    for (hop, check) in cases {
        let fake = FakeCurl::new(&[(CAT, hop)]);
        let err = fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap_err();
        assert!(check(&err), "{err:?}");
        assert!(!err.to_string().contains(TOKEN));
        assert_dirs_gone(&fake);
    }
}

#[test]
fn a_body_over_the_cap_is_too_large_even_if_curl_let_it_through() {
    let fake = FakeCurl::new(&[(CAT, Hop::ok(&vec![b'x'; MAX_CATALOG_BYTES + 1], &[]))]);
    assert_eq!(fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()), Err(CatalogError::TooLarge));
    assert_dirs_gone(&fake);
    // Exactly at the cap is fine.
    let fake = FakeCurl::new(&[(CAT, Hop::ok(&vec![b'x'; MAX_CATALOG_BYTES], &[]))]);
    assert!(matches!(
        fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()),
        Ok(FetchOutcome::Fetched { .. })
    ));
}

// MARK: - redirects

#[test]
fn a_same_origin_redirect_keeps_the_token_and_another_origin_drops_it() {
    let same = "https://vpn.example.com/current.macvpncatalog";
    let other = "https://cdn.example.net/acme.macvpncatalog";
    let other_port = "https://vpn.example.com:8443/acme.macvpncatalog";
    let fake = FakeCurl::new(&[
        (CAT, Hop::redirect(302, same)),
        (same, Hop::redirect(301, other)),
        (other, Hop::redirect(307, other_port)),
        (other_port, Hop::ok(b"body", &[("ETag", "\"e\"")])),
    ]);
    let outcome = fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap();
    assert!(matches!(outcome, FetchOutcome::Fetched { ref bytes, .. } if bytes == b"body"));
    let seen = fake.seen();
    let urls: Vec<&str> = seen.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(urls, [CAT, same, other, other_port]);
    let with_token: Vec<bool> = seen.iter().map(|s| s.stdin.is_some()).collect();
    assert_eq!(with_token, [true, true, false, false], "a different host or port never gets the token");
    for s in &seen[2..] {
        assert!(!s.args.iter().any(|a| a == "--config"));
    }
    assert_dirs_gone(&fake);
}

#[test]
fn a_relative_redirect_is_resolved_against_the_current_url() {
    let target = "https://vpn.example.com/team/v2/acme.macvpncatalog";
    let fake = FakeCurl::new(&[(CAT, Hop::redirect(302, "v2/acme.macvpncatalog")), (target, Hop::ok(b"b", &[]))]);
    fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap();
    assert_eq!(fake.seen()[1].url, target);
    assert!(fake.seen()[1].stdin.is_some());
}

#[test]
fn a_redirect_to_http_is_refused_without_requesting_it() {
    let fake = FakeCurl::new(&[(CAT, Hop::redirect(301, "http://vpn.example.com/acme.macvpncatalog"))]);
    let err = fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap_err();
    assert_eq!(err, CatalogError::Io("redirect to a non-HTTPS address".into()));
    assert_eq!(fake.seen().len(), 1, "the http:// target is never requested");
    assert_dirs_gone(&fake);
}

#[test]
fn at_most_five_redirects_are_followed() {
    assert_eq!(MAX_REDIRECTS, 5);
    let hop = |i: usize| format!("https://vpn.example.com/r{i}");
    let mut hops: Vec<(String, Hop)> = vec![(CAT.to_string(), Hop::redirect(302, &hop(1)))];
    for i in 1..=4 {
        hops.push((hop(i), Hop::redirect(302, &hop(i + 1))));
    }
    // Five redirects, then the catalog: fine.
    hops.push((hop(5), Hop::ok(b"b", &[])));
    let refs: Vec<(&str, Hop)> = hops.iter().map(|(u, h)| (u.as_str(), h.clone())).collect();
    let fake = FakeCurl::new(&refs);
    assert!(fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()).is_ok());
    assert_eq!(fake.seen().len(), 6);
    // A sixth redirect: refused, and its target never requested.
    hops.pop();
    hops.push((hop(5), Hop::redirect(302, &hop(6))));
    hops.push((hop(6), Hop::ok(b"b", &[])));
    let refs: Vec<(&str, Hop)> = hops.iter().map(|(u, h)| (u.as_str(), h.clone())).collect();
    let fake = FakeCurl::new(&refs);
    let err = fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()).unwrap_err();
    assert_eq!(err, CatalogError::Io("too many redirects".into()));
    assert_eq!(fake.seen().len(), 6);
    assert_dirs_gone(&fake);
}

#[test]
fn a_304_after_a_redirect_is_not_modified_and_the_conditional_headers_go_to_every_hop() {
    let target = "https://vpn.example.com/current.macvpncatalog";
    let fake = FakeCurl::new(&[(CAT, Hop::redirect(302, target)), (target, Hop { status: 304, ..Hop::default() })]);
    let previous = SourceValidators { etag: Some("\"e\"".into()), ..SourceValidators::default() };
    assert_eq!(fetch(&fetcher(&fake), &url(CAT), None, &previous).unwrap(), FetchOutcome::NotModified);
    for s in fake.seen() {
        assert!(s.args.iter().any(|a| a == "If-None-Match: \"e\""));
    }
}

// MARK: - a local HTTPS server (127.0.0.1, throwaway CA)

const SERVER: &str = r#"
import http.server, ssl, sys
CERTS, LOG = sys.argv[1], sys.argv[2]
ETAG = '"cat-v1"'
LAST_MOD = "Mon, 19 Oct 2026 08:00:00 GMT"
BODY = b"MVPNCAT1" + b"x" * 1000

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def send(self, status, headers=(), body=b""):
        self.send_response(status)
        for n, v in headers:
            self.send_header(n, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        with open(LOG, "a") as f:
            f.write(self.path + "\t" + (self.headers.get("Authorization") or "-") + "\n")
        p = self.path
        if p == "/cat":
            if self.headers.get("If-None-Match") == ETAG:
                self.send_response(304)
                self.send_header("ETag", ETAG)
                self.end_headers()
                return
            self.send(200, [("eTaG", ETAG), ("last-modified", LAST_MOD)], BODY)
        elif p == "/big":
            self.send(200, [], b"y" * (8 * 1024 * 1024 + 1))
        elif p == "/redir-http":
            self.send(301, [("Location", "http://127.0.0.1:%d/cat" % PORT)])
        elif p == "/redir-https":
            self.send(302, [("Location", "/cat")])
        else:
            self.send(404)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERTS + "/server.pem", CERTS + "/server.key")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
PORT = srv.server_address[1]
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(PORT, flush=True)
srv.serve_forever()
"#;

struct LocalServer {
    child: Child,
    port: u16,
    ca: PathBuf,
    log: PathBuf,
    _dir: Scratch,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_ok(dir: &Path, program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A throwaway CA and a 127.0.0.1 server certificate (`/usr/bin/openssl`), and the Python server above.
/// `None` (the test is skipped with a note) without `python3` or `openssl`.
fn local_server() -> Option<LocalServer> {
    let dir = Scratch::new("macvpn-catalog-https");
    let d = dir.path();
    std::fs::write(
        d.join("ext.cnf"),
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    let steps: [&[&str]; 3] = [
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "2",
            "-subj",
            "/CN=MacVPN catalog test CA",
        ],
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=127.0.0.1",
        ],
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "2",
            "-extfile",
            "ext.cnf",
        ],
    ];
    for step in steps {
        if !run_ok(d, "/usr/bin/openssl", step) {
            eprintln!("skipped: /usr/bin/openssl could not make the test certificates");
            return None;
        }
    }
    std::fs::write(d.join("server.py"), SERVER).unwrap();
    let log = d.join("requests.log");
    let mut child = match Command::new("python3")
        .arg("-I")
        .arg(d.join("server.py"))
        .arg(d)
        .arg(&log)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("skipped: no python3 for the local HTTPS server");
            return None;
        }
    };
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).ok()?;
    let Ok(port) = line.trim().parse() else {
        let _ = child.kill();
        eprintln!("skipped: the local HTTPS server did not start");
        return None;
    };
    Some(LocalServer { child, port, ca: d.join("ca.pem"), log, _dir: dir })
}

fn auth_log(server: &LocalServer) -> Vec<(String, Option<String>)> {
    std::fs::read_to_string(&server.log)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let (path, auth) = l.split_once('\t').unwrap();
            (path.to_string(), (auth != "-").then(|| auth.to_string()))
        })
        .collect()
}

#[test]
fn against_a_local_https_server_conditional_get_the_token_and_the_limits_work() {
    let Some(server) = local_server() else { return };
    let base = format!("https://127.0.0.1:{}", server.port);
    let f = CurlCatalogFetcher::default().with_test_ca(server.ca.clone());

    // 200 with the validators, the token sent to the same origin.
    let source = url(&format!("{base}/cat"));
    let outcome = fetch(&f, &source, Some(TOKEN), &SourceValidators::default()).unwrap();
    let FetchOutcome::Fetched { bytes, validators } = outcome else { panic!("fetched expected") };
    assert_eq!(bytes.len(), 1008);
    assert_eq!(validators.etag.as_deref(), Some("\"cat-v1\""));
    assert_eq!(validators.last_modified.as_deref(), Some("Mon, 19 Oct 2026 08:00:00 GMT"));
    // The same validators: 304.
    assert_eq!(fetch(&f, &source, Some(TOKEN), &validators).unwrap(), FetchOutcome::NotModified);
    // A relative same-origin redirect.
    let outcome = fetch(&f, &url(&format!("{base}/redir-https")), Some(TOKEN), &SourceValidators::default()).unwrap();
    assert!(matches!(outcome, FetchOutcome::Fetched { .. }));
    let expected = Some(format!("Bearer {TOKEN}"));
    assert_eq!(
        auth_log(&server),
        vec![
            ("/cat".to_string(), expected.clone()),
            ("/cat".to_string(), expected.clone()),
            ("/redir-https".to_string(), expected.clone()),
            ("/cat".to_string(), expected),
        ]
    );
    // A redirect to http://: refused, the http target never requested.
    let err = fetch(&f, &url(&format!("{base}/redir-http")), None, &SourceValidators::default()).unwrap_err();
    assert_eq!(err, CatalogError::Io("redirect to a non-HTTPS address".into()));
    assert_eq!(auth_log(&server).len(), 5);
    // Over the cap: curl stops it (exit 63).
    assert_eq!(
        fetch(&f, &url(&format!("{base}/big")), None, &SourceValidators::default()),
        Err(CatalogError::TooLarge)
    );
    // A 404.
    assert_eq!(
        fetch(&f, &url(&format!("{base}/none")), None, &SourceValidators::default()),
        Err(CatalogError::Io("HTTP 404".into()))
    );
    // Without the test CA, the system trust store refuses the throwaway certificate.
    let err = fetch(&CurlCatalogFetcher::default(), &source, None, &SourceValidators::default()).unwrap_err();
    assert_eq!(err, CatalogError::Io("certificate not trusted".into()));
}

#[test]
fn a_closed_port_on_127_0_0_1_is_unavailable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let err = fetch(
        &CurlCatalogFetcher::default(),
        &url(&format!("https://127.0.0.1:{port}/cat")),
        None,
        &SourceValidators::default(),
    )
    .unwrap_err();
    assert_eq!(err, CatalogError::Unavailable("127.0.0.1".into()));
}

/// Run by hand (documented in the spike report): `MACVPN_CATALOG_TEST_URL=https://… cargo test -p
/// macvpn-platform-mac --test catalog_http -- --ignored`.
#[test]
#[ignore]
fn live_fetch_of_macvpn_catalog_test_url() {
    let Ok(target) = std::env::var("MACVPN_CATALOG_TEST_URL") else { return };
    let outcome = fetch(&CurlCatalogFetcher::default(), &url(&target), None, &SourceValidators::default()).unwrap();
    let FetchOutcome::Fetched { validators, .. } = outcome else { panic!("fetched expected") };
    if validators.etag.is_some() || validators.last_modified.is_some() {
        let again = fetch(&CurlCatalogFetcher::default(), &url(&target), None, &validators).unwrap();
        assert_eq!(again, FetchOutcome::NotModified);
    }
}

#[test]
fn url_globbing_is_off_and_a_bracketed_query_still_works() {
    let encoded = "https://vpn.example.com/team/acme.macvpncatalog?filter%5Bx%5D=1";
    let fake = FakeCurl::new(&[(encoded, Hop::ok(b"body", &[]))]);
    let source = url("https://vpn.example.com/team/acme.macvpncatalog?filter[x]=1");
    let outcome = fetch(&fetcher(&fake), &source, None, &SourceValidators::default()).unwrap();
    assert!(matches!(outcome, FetchOutcome::Fetched { ref bytes, .. } if bytes == b"body"));
    let seen = fake.seen();
    assert!(seen[0].args.iter().any(|a| a == "--globoff"), "{:?}", seen[0].args);
    assert_eq!(seen[0].url, encoded);
    // The updater's requests too.
    assert!(CurlHttpClient::base_arguments(None, 30.0, "MacVPN-Updater").iter().any(|a| a == "--globoff"));
    assert_eq!(CurlHttpClient::base_arguments(None, 30.0, "MacVPN-Updater")[0], "-q");
}

#[test]
fn a_glob_redirect_is_requested_as_one_encoded_url() {
    let target = "https://vpn.example.com/x%5B1-100000000%5D";
    let fake = FakeCurl::new(&[
        (CAT, Hop::redirect(302, "https://vpn.example.com/x[1-100000000]")),
        (target, Hop::ok(b"b", &[])),
    ]);
    fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap();
    let seen = fake.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].url, target);
    assert!(seen[1].args.iter().any(|a| a == "--globoff"));
}

#[test]
fn the_conditional_headers_never_go_to_another_origin() {
    let other = "https://cdn.example.net/acme.macvpncatalog";
    let fake = FakeCurl::new(&[(CAT, Hop::redirect(302, other)), (other, Hop::ok(b"b", &[]))]);
    let previous = SourceValidators {
        etag: Some("\"e\"".into()),
        last_modified: Some("Mon, 19 Oct 2026 08:00:00 GMT".into()),
        content_hash: None,
    };
    fetch(&fetcher(&fake), &url(CAT), None, &previous).unwrap();
    let seen = fake.seen();
    assert!(seen[0].args.iter().any(|a| a.starts_with("If-None-Match")));
    assert!(!seen[1].args.iter().any(|a| a.starts_with("If-")), "{:?}", seen[1].args);
}

/// The details a user reads in the subscription's status are translated (here: Hungarian).
#[test]
fn the_error_details_are_localized() {
    use macvpn_core::l10n::{AppLanguage, with_language};
    with_language(AppLanguage::Hu, || {
        let fake = FakeCurl::new(&[(CAT, Hop::status(401))]);
        let err = fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap_err();
        assert_eq!(err, CatalogError::Io("hozzáférés megtagadva (ellenőrizd a hozzáférési tokent)".into()));
        let fake = FakeCurl::new(&[(CAT, Hop::redirect(301, "http://vpn.example.com/acme.macvpncatalog"))]);
        let err = fetch(&fetcher(&fake), &url(CAT), Some(TOKEN), &SourceValidators::default()).unwrap_err();
        assert_eq!(err, CatalogError::Io("átirányítás nem HTTPS-címre".into()));
        let fake = FakeCurl::new(&[(CAT, Hop::exit(60))]);
        let err = fetch(&fetcher(&fake), &url(CAT), None, &SourceValidators::default()).unwrap_err();
        assert_eq!(err, CatalogError::Io("a tanúsítvány nem megbízható".into()));
    });
}
