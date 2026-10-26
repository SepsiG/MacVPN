//! The shared curl layer with a non-macOS flavour (as Windows will use it): the flavour's executable is the one run,
//! its extra arguments come right after `--max-time <n>`, and the private directory is removed afterwards. Portable:
//! a recording runner plays curl, nothing is started.

use macvpn_core::catalog::fetch::{CatalogFetcher, FetchRequest};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::vault::SourceValidators;
use macvpn_platform_api::curl::catalog::CurlCatalogFetcher;
use macvpn_platform_api::curl::http::{CurlHttpClient, HttpClient};
use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner, Curl};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const EXE: &str = r"C:\Windows\System32\curl.exe";

type Call = (String, Vec<String>, Option<String>);

#[derive(Default)]
struct Recorder(Mutex<Vec<Call>>);

struct Runner(Arc<Recorder>);

impl CommandRunner for Runner {
    fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.0.0.lock().unwrap().push((exe.to_string(), args.to_vec(), stdin.map(String::from)));
        Ok(CommandResult::stdout("200 "))
    }
}

fn private_dir(prefix: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("{prefix}.{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn flavour() -> Curl {
    Curl {
        executable: EXE.to_string(),
        extra_args: vec!["--ssl-revoke-best-effort"],
        private_dir,
        temp_base: || Ok(std::env::temp_dir()),
    }
}

fn after_max_time(args: &[String]) -> &[String] {
    let i = args.iter().position(|a| a == "--max-time").unwrap();
    &args[i + 2..]
}

#[test]
fn base_arguments_put_the_extra_arguments_right_after_max_time() {
    let plain = CurlHttpClient::base_arguments(None, 30.0, "UA", &[]);
    let extra = CurlHttpClient::base_arguments(None, 30.0, "UA", &["--ssl-revoke-best-effort"]);
    let i = plain.iter().position(|a| a == "--max-time").unwrap();
    let mut expected = plain.clone();
    expected.insert(i + 2, "--ssl-revoke-best-effort".to_string());
    assert_eq!(extra, expected);
    assert_eq!(extra[0], "-q");
}

#[test]
fn the_http_client_runs_the_flavours_curl_with_its_extra_arguments() {
    let rec = Arc::new(Recorder::default());
    let client = CurlHttpClient::with_curl(Box::new(Runner(rec.clone())), flavour());
    let response = client.get("https://api.github.com/repositories/1/releases/latest").unwrap();
    assert_eq!(response.status, 200);
    let seen = rec.0.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, EXE);
    assert_eq!(after_max_time(&seen[0].1)[0], "--ssl-revoke-best-effort");
    let output = PathBuf::from(&seen[0].1[seen[0].1.iter().position(|a| a == "--output").unwrap() + 1]);
    assert!(!output.parent().unwrap().exists(), "the private directory is removed");
}

#[test]
fn the_http_client_sends_its_user_agent() {
    let agent = |client: CurlHttpClient, rec: &Recorder| {
        client.get("https://api.github.com/repositories/1/releases/latest").unwrap();
        let seen = rec.0.lock().unwrap();
        let args = &seen.last().unwrap().1;
        args[args.iter().position(|a| a == "--user-agent").unwrap() + 1].clone()
    };
    let rec = Arc::new(Recorder::default());
    assert_eq!(agent(CurlHttpClient::with_curl(Box::new(Runner(rec.clone())), flavour()), &rec), "MacVPN-Updater");
    let rec = Arc::new(Recorder::default());
    let client = CurlHttpClient::new_with(Box::new(Runner(rec.clone())), flavour(), "WinVPN-Updater/9.9.9".into());
    assert_eq!(agent(client, &rec), "WinVPN-Updater/9.9.9");
}

#[test]
fn the_download_lands_in_the_flavours_temp_base() {
    let rec = Arc::new(Recorder::default());
    let client = CurlHttpClient::with_curl(Box::new(Runner(rec.clone())), flavour());
    let (file, status) =
        client.download("https://github.com/acme/macvpn/releases/download/v1/WinVPN-1-x64.msi").unwrap();
    assert_eq!(status, 200);
    assert_eq!(file.parent().unwrap(), std::env::temp_dir());
    std::fs::remove_file(&file).unwrap();
    assert_eq!(rec.0.lock().unwrap()[0].0, EXE);
}

#[test]
fn the_catalog_fetcher_runs_the_flavours_curl_with_its_extra_arguments() {
    let rec = Arc::new(Recorder::default());
    let fetcher = CurlCatalogFetcher::with_curl(Box::new(Runner(rec.clone())), flavour());
    let source = CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/acme.macvpncatalog").unwrap());
    let previous = SourceValidators::default();
    fetcher.fetch(&FetchRequest { source: &source, bearer: Some("tok"), previous: &previous }).unwrap();
    let seen = rec.0.lock().unwrap();
    assert_eq!(seen[0].0, EXE);
    assert_eq!(after_max_time(&seen[0].1)[0], "--ssl-revoke-best-effort");
    assert!(!seen[0].1.iter().any(|a| a.contains("tok")), "the token never in argv");
    assert_eq!(seen[0].2.as_deref(), Some("header = \"Authorization: Bearer tok\"\n"));
}
