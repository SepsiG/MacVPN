//! The file source of team catalogs (plan Task 10): `read_catalog_file`'s rules on a worker thread with the 20 s
//! timeout, change detection by the SHA-256 of the content (spike decision B1), and "unavailable" for a missing
//! share.

mod common;

use common::TempDir;
use macvpn_app_core::catalog_file::{FILE_READ_TIMEOUT, FileCatalogFetcher};
use macvpn_app_core::deps::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::fetch::content_hash;
use macvpn_core::catalog::format::CatalogError;
#[cfg(unix)]
use macvpn_core::catalog::format::MAX_CATALOG_BYTES;
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::vault::SourceValidators;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn fetch(f: &FileCatalogFetcher, path: &Path, previous: &SourceValidators) -> Result<FetchOutcome, CatalogError> {
    let source = CatalogSource::File(path.to_path_buf());
    f.fetch(&FetchRequest { source: &source, bearer: None, previous })
}

fn fetched(outcome: Result<FetchOutcome, CatalogError>) -> (Vec<u8>, SourceValidators) {
    match outcome {
        Ok(FetchOutcome::Fetched { bytes, validators }) => (bytes, validators),
        other => panic!("fetched expected, got {other:?}"),
    }
}

#[test]
fn the_timeout_is_20_seconds() {
    assert_eq!(FILE_READ_TIMEOUT, Duration::from_secs(20));
}

#[test]
fn a_regular_file_is_fetched_with_its_hash_and_the_same_content_is_not_modified() {
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("acme.macvpncatalog");
    std::fs::write(&path, b"MVPNCAT1 v1").unwrap();
    let f = FileCatalogFetcher::new();
    let (bytes, validators) = fetched(fetch(&f, &path, &SourceValidators::default()));
    assert_eq!(bytes, b"MVPNCAT1 v1");
    assert_eq!(validators, SourceValidators { content_hash: Some(content_hash(b"MVPNCAT1 v1")), ..Default::default() });
    assert_eq!(fetch(&f, &path, &validators).unwrap(), FetchOutcome::NotModified);
    // Replaced (an atomic rename, as the publisher writes it) with new content.
    let next = tmp.path().join("next");
    std::fs::write(&next, b"MVPNCAT1 v2").unwrap();
    std::fs::rename(&next, &path).unwrap();
    let (bytes, v2) = fetched(fetch(&f, &path, &validators));
    assert_eq!(bytes, b"MVPNCAT1 v2");
    assert_ne!(v2.content_hash, validators.content_hash);
    // Same size, changed in place: still seen (no fstat shortcut).
    std::fs::write(&path, b"MVPNCAT1 v3").unwrap();
    assert!(matches!(fetch(&f, &path, &v2), Ok(FetchOutcome::Fetched { .. })));
}

#[cfg(unix)]
#[test]
fn a_symlink_a_fifo_and_an_oversized_file_are_refused() {
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let target = tmp.path().join("real.macvpncatalog");
    std::fs::write(&target, b"MVPNCAT1").unwrap();
    let link = tmp.path().join("link.macvpncatalog");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let f = FileCatalogFetcher::new();
    assert_eq!(fetch(&f, &link, &SourceValidators::default()), Err(CatalogError::Io("not a regular file".into())));

    let fifo = tmp.path().join("fifo.macvpncatalog");
    assert!(std::process::Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap().success());
    let started = Instant::now();
    assert_eq!(fetch(&f, &fifo, &SourceValidators::default()), Err(CatalogError::Io("not a regular file".into())));
    assert!(started.elapsed() < Duration::from_secs(2), "a FIFO never blocks");

    let big = tmp.path().join("big.macvpncatalog");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(MAX_CATALOG_BYTES as u64 + 1).unwrap();
    assert_eq!(fetch(&f, &big, &SourceValidators::default()), Err(CatalogError::TooLarge));
}

#[test]
fn a_path_under_a_missing_directory_is_unavailable_by_file_name() {
    let f = FileCatalogFetcher::new();
    let path = PathBuf::from("/Volumes/MacVPN-no-such-share/team/acme.macvpncatalog");
    assert_eq!(
        fetch(&f, &path, &SourceValidators::default()),
        Err(CatalogError::Unavailable("acme.macvpncatalog".into()))
    );
}

#[test]
fn an_https_source_is_not_this_fetchers() {
    let f = FileCatalogFetcher::new();
    let source = CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/a.macvpncatalog").unwrap());
    let previous = SourceValidators::default();
    assert!(matches!(
        f.fetch(&FetchRequest { source: &source, bearer: None, previous: &previous }),
        Err(CatalogError::Io(_))
    ));
}

#[test]
fn a_read_that_hangs_is_unavailable_after_the_timeout_and_never_starts_a_second_thread() {
    let (release, wait) = mpsc::channel::<()>();
    let wait = Arc::new(Mutex::new(wait));
    let calls = Arc::new(Mutex::new(0usize));
    let counting = calls.clone();
    let f = FileCatalogFetcher::with_reader(Duration::from_millis(200), move |path: &Path| {
        *counting.lock().unwrap() += 1;
        if path.ends_with("slow.macvpncatalog") {
            let _ = wait.lock().unwrap().recv();
        }
        Ok(b"MVPNCAT1".to_vec())
    });
    let slow = PathBuf::from("/Volumes/Share/slow.macvpncatalog");
    let started = Instant::now();
    assert_eq!(
        fetch(&f, &slow, &SourceValidators::default()),
        Err(CatalogError::Unavailable("slow.macvpncatalog".into()))
    );
    assert!(started.elapsed() >= Duration::from_millis(200));
    assert_eq!(f.hung_reads(), 1);
    // While it hangs: at once, without another thread.
    let started = Instant::now();
    assert_eq!(
        fetch(&f, &slow, &SourceValidators::default()),
        Err(CatalogError::Unavailable("slow.macvpncatalog".into()))
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(*calls.lock().unwrap(), 1);
    // Another path is not held up.
    assert!(matches!(
        fetch(&f, Path::new("/Volumes/Share/other.macvpncatalog"), &SourceValidators::default()),
        Ok(FetchOutcome::Fetched { .. })
    ));
    // The hung read finishes: the next fetch reads again.
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while f.hung_reads() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.hung_reads(), 0);
    release.send(()).unwrap();
    assert!(matches!(fetch(&f, &slow, &SourceValidators::default()), Ok(FetchOutcome::Fetched { .. })));
    assert_eq!(*calls.lock().unwrap(), 3);
}

#[test]
fn a_reader_that_panics_frees_its_path_for_the_next_fetch() {
    let calls = Arc::new(Mutex::new(0usize));
    let counting = calls.clone();
    let f = FileCatalogFetcher::with_reader(Duration::from_secs(5), move |_: &Path| {
        let n = {
            let mut c = counting.lock().unwrap();
            *c += 1;
            *c
        };
        if n == 1 {
            panic!("reader failure (expected by the test)");
        }
        Ok(b"MVPNCAT1".to_vec())
    });
    let path = PathBuf::from("/Volumes/Share/acme.macvpncatalog");
    let started = Instant::now();
    assert!(matches!(fetch(&f, &path, &SourceValidators::default()), Err(CatalogError::Io(_))));
    assert!(started.elapsed() < Duration::from_secs(4), "no wait for the timeout");
    assert_eq!(f.hung_reads(), 0);
    assert!(matches!(fetch(&f, &path, &SourceValidators::default()), Ok(FetchOutcome::Fetched { .. })));
    assert_eq!(*calls.lock().unwrap(), 2);
}
