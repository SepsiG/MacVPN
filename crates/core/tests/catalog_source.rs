//! Catalog sources (spec 4, plan Task 5): the HTTPS URL rules and the file source reader.

mod common;

use common::TempDir;
use macvpn_core::catalog::format::{CatalogError, MAX_CATALOG_BYTES};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl, SourceError, parse_file_source, read_catalog_file};
use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::{Duration, Instant};

fn url(s: &str) -> HttpsUrl {
    HttpsUrl::parse(s).unwrap_or_else(|e| panic!("{s}: {e:?}"))
}

// MARK: - HTTPS URL

#[test]
fn accepted_urls_and_their_canonical_form() {
    let cases = [
        ("https://catalog.example.com/team.macvpncatalog", "https://catalog.example.com/team.macvpncatalog"),
        ("https://Catalog.EXAMPLE.com/Team.macvpncatalog", "https://catalog.example.com/Team.macvpncatalog"),
        ("HTTPS://catalog.example.com/x", "https://catalog.example.com/x"),
        ("https://catalog.example.com", "https://catalog.example.com/"),
        ("https://catalog.example.com:443/x", "https://catalog.example.com/x"),
        ("https://catalog.example.com:8443/x", "https://catalog.example.com:8443/x"),
        ("https://192.0.2.10/x", "https://192.0.2.10/x"),
        ("https://[::1]/x", "https://[::1]/x"),
        ("https://[2001:DB8::1]:8443/x", "https://[2001:db8::1]:8443/x"),
        ("https://bücher.example/katalog", "https://xn--bcher-kva.example/katalog"),
        ("https://catalog.example.com/x?sig=abc&exp=1", "https://catalog.example.com/x?sig=abc&exp=1"),
        ("https://catalog.example.com/a%20b", "https://catalog.example.com/a%20b"),
    ];
    for (input, canonical) in cases {
        assert_eq!(url(input).as_str(), canonical, "{input}");
    }
}

#[test]
fn origin_and_redaction() {
    let u = url("https://Catalog.example.com/x/y?token=secret");
    assert_eq!(u.origin(), ("catalog.example.com".to_string(), 443));
    assert_eq!(u.redacted(), "https://catalog.example.com/x/y");
    let u = url("https://[::1]:8443/x");
    assert_eq!(u.origin(), ("[::1]".to_string(), 8443));
    assert!(!format!("{u:?}").contains("token"));
    let u = url("https://catalog.example.com/x?token=secret");
    assert!(!format!("{u:?}").contains("secret"));
    assert!(!format!("{:?}", CatalogSource::Https(u)).contains("secret"));
}

#[test]
fn refused_urls() {
    let cases: [(&str, SourceError); 18] = [
        ("http://catalog.example.com/x", SourceError::NotHttps),
        ("ftp://catalog.example.com/x", SourceError::NotHttps),
        ("file:///etc/passwd", SourceError::NotHttps),
        ("https://user:pw@catalog.example.com/x", SourceError::UserInfo),
        ("https://user@catalog.example.com/x", SourceError::UserInfo),
        ("https://catalog.example.com/x#part", SourceError::Fragment),
        ("https://catalog.example.com/a b", SourceError::BadUrl),
        ("https://catalog.example.com/a\u{7}b", SourceError::BadUrl),
        ("https://catalog.example.com/a\nb", SourceError::BadUrl),
        ("https://catalog.example.com/ü", SourceError::BadUrl),
        ("https:///x", SourceError::BadUrl),
        ("https://", SourceError::BadUrl),
        ("https://catalog.example.com:0/x", SourceError::BadUrl),
        ("https://catalog.example.com:65536/x", SourceError::BadUrl),
        ("https://catalog.example.com:/x", SourceError::BadUrl),
        ("https://cat_alog.example.com/x", SourceError::BadUrl),
        ("https://[::1/x", SourceError::BadUrl),
        ("catalog.example.com/x", SourceError::BadUrl),
    ];
    for (input, error) in cases {
        assert_eq!(HttpsUrl::parse(input).err(), Some(error), "{input:?}");
    }
    assert_eq!(HttpsUrl::parse("https://999.1.1.1/x").err(), Some(SourceError::BadUrl));
    assert_eq!(HttpsUrl::parse("https://-bad.example.com/x").err(), Some(SourceError::BadUrl));
    assert_eq!(HttpsUrl::parse("").err(), Some(SourceError::BadUrl));
}

#[test]
fn the_length_limit() {
    let base = "https://catalog.example.com/";
    let ok = format!("{base}{}", "a".repeat(2048 - base.len()));
    assert_eq!(ok.len(), 2048);
    assert!(HttpsUrl::parse(&ok).is_ok());
    let long = format!("{ok}a");
    assert_eq!(HttpsUrl::parse(&long).err(), Some(SourceError::TooLong));
}

#[test]
fn redirect_targets() {
    let base = url("https://catalog.example.com/teams/a/team.macvpncatalog?x=1");
    let cases = [
        ("/x", "https://catalog.example.com/x"),
        ("x", "https://catalog.example.com/teams/a/x"),
        ("../x", "https://catalog.example.com/teams/x"),
        ("../../../../x", "https://catalog.example.com/x"),
        ("./b/./c", "https://catalog.example.com/teams/a/b/c"),
        ("?y=2", "https://catalog.example.com/teams/a/team.macvpncatalog?y=2"),
        ("/x?q=1#frag", "https://catalog.example.com/x?q=1"),
        ("https://cdn.example.net/f", "https://cdn.example.net/f"),
        ("//cdn.example.net/f", "https://cdn.example.net/f"),
        ("HTTPS://CDN.example.net:8443/f", "https://cdn.example.net:8443/f"),
    ];
    for (location, expected) in cases {
        assert_eq!(base.redirect_target(location).map(|u| u.as_str().to_string()), Ok(expected.into()), "{location}");
    }
    assert_eq!(base.redirect_target("http://catalog.example.com/x").err(), Some(SourceError::NotHttps));
    assert_eq!(base.redirect_target("ftp://catalog.example.com/x").err(), Some(SourceError::NotHttps));
    assert_eq!(base.redirect_target("https://u@cdn.example.net/").err(), Some(SourceError::UserInfo));
    assert_eq!(base.redirect_target("/a b").err(), Some(SourceError::BadUrl));
    assert_eq!(base.redirect_target("").err(), Some(SourceError::BadUrl));
}

// MARK: - file source

#[test]
fn file_source_paths() {
    assert_eq!(parse_file_source("team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source("~/team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source("").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source("/a\0b").err(), Some(SourceError::BadPath));
    assert_eq!(parse_file_source("/a\nb").err(), Some(SourceError::BadPath));
}

/// macOS (and Linux): an absolute path starts with `/`.
#[cfg(unix)]
#[test]
fn file_source_paths_on_unix() {
    assert_eq!(
        parse_file_source("/Volumes/Team/team.macvpncatalog"),
        Ok(PathBuf::from("/Volumes/Team/team.macvpncatalog"))
    );
    assert_eq!(parse_file_source(r"C:\Team\team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source(&format!("/{}", "a".repeat(1024))).err(), Some(SourceError::TooLong));
    assert!(parse_file_source(&format!("/{}", "a".repeat(1023))).is_ok());
}

/// Windows: a drive path or a UNC share; a path relative to a drive or to the current drive's root is not absolute.
/// Found by the Windows smoke run (every file source was refused: the check wanted a leading `/`).
#[cfg(windows)]
#[test]
fn file_source_paths_on_windows() {
    assert_eq!(parse_file_source(r"C:\Team\team.macvpncatalog"), Ok(PathBuf::from(r"C:\Team\team.macvpncatalog")));
    assert!(parse_file_source(r"\\fileserver\team\team.macvpncatalog").is_ok());
    assert_eq!(parse_file_source(r"C:team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source(r"\Team\team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    assert_eq!(parse_file_source("/Volumes/Team/team.macvpncatalog").err(), Some(SourceError::NotAbsolute));
    // Device and verbatim paths (a pipe, a raw volume) are never a catalog file.
    for device in
        [r"\\.\pipe\x", r"\\?\C:\team.macvpncatalog", "//./pipe/x", r"\\?\UNC\fileserver\team\t.macvpncatalog"]
    {
        assert_eq!(parse_file_source(device).err(), Some(SourceError::BadPath), "{device}");
    }
    assert_eq!(parse_file_source(&format!(r"C:\{}", "a".repeat(1022))).err(), Some(SourceError::TooLong));
    assert!(parse_file_source(&format!(r"C:\{}", "a".repeat(1021))).is_ok());
}

#[test]
fn read_catalog_file_reads_a_regular_file() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("team.macvpncatalog");
    fs::write(&file, b"MVPNCAT1 contents").unwrap();
    assert_eq!(read_catalog_file(&file).unwrap(), b"MVPNCAT1 contents");
}

#[cfg(unix)]
#[test]
fn read_catalog_file_refuses_symlinks_directories_and_fifos() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("team.macvpncatalog");
    fs::write(&file, b"x").unwrap();
    let link = tmp.path().join("link.macvpncatalog");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_eq!(read_catalog_file(&link).err(), Some(CatalogError::Io("not a regular file".into())));
    assert_eq!(read_catalog_file(tmp.path()).err(), Some(CatalogError::Io("not a regular file".into())));

    let fifo = tmp.path().join("fifo.macvpncatalog");
    assert!(std::process::Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap().success());
    // On a worker thread with a 2 s guard: a blocking open would hang the test otherwise.
    let (tx, rx) = std::sync::mpsc::channel();
    let path = fifo.clone();
    let started = Instant::now();
    std::thread::spawn(move || tx.send(read_catalog_file(&path)).unwrap());
    let result = rx.recv_timeout(Duration::from_secs(2)).expect("the FIFO must not block");
    assert_eq!(result.err(), Some(CatalogError::Io("not a regular file".into())));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn read_catalog_file_caps_the_size() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let big = tmp.path().join("big.macvpncatalog");
    fs::File::create(&big).unwrap().set_len(MAX_CATALOG_BYTES as u64 + 1).unwrap();
    assert_eq!(read_catalog_file(&big).err(), Some(CatalogError::TooLarge));
    let exact = tmp.path().join("exact.macvpncatalog");
    fs::File::create(&exact).unwrap().set_len(MAX_CATALOG_BYTES as u64).unwrap();
    assert_eq!(read_catalog_file(&exact).unwrap().len(), MAX_CATALOG_BYTES);
}

#[test]
fn a_missing_file_or_share_is_unavailable() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let missing = tmp.path().join("missing.macvpncatalog");
    assert_eq!(read_catalog_file(&missing).err(), Some(CatalogError::Unavailable("missing.macvpncatalog".into())));
    let under_missing_dir = tmp.path().join("gone/team.macvpncatalog");
    assert_eq!(
        read_catalog_file(&under_missing_dir).err(),
        Some(CatalogError::Unavailable("team.macvpncatalog".into()))
    );
    let share = PathBuf::from("/Volumes/macvpn-test-no-such-share/team.macvpncatalog");
    assert_eq!(read_catalog_file(&share).err(), Some(CatalogError::Unavailable("team.macvpncatalog".into())));
    // A regular file used as a directory: ENOTDIR.
    let file = tmp.path().join("plain");
    fs::write(&file, b"x").unwrap();
    assert_eq!(
        read_catalog_file(&file.join("team.macvpncatalog")).err(),
        Some(CatalogError::Unavailable("team.macvpncatalog".into()))
    );
}

#[test]
fn source_redaction_for_logs() {
    let https = CatalogSource::Https(url("https://catalog.example.com/x?token=secret"));
    assert_eq!(https.redacted(), "https://catalog.example.com/x");
    let file = CatalogSource::File(PathBuf::from("/Users/someone/Shared/team.macvpncatalog"));
    assert_eq!(file.redacted(), "team.macvpncatalog");
}

// MARK: - review L7, L8

#[test]
fn a_host_that_ends_in_a_number_is_refused() {
    for bad in [
        "https://example.123/c",
        "https://vpn.example.0x1f/c",
        "https://1.2.3.0x4/c",
        "https://0x7f000001/c",
        "https://vpn.0X10/c",
    ] {
        assert_eq!(HttpsUrl::parse(bad).err(), Some(SourceError::BadUrl), "{bad}");
    }
    // Digits elsewhere are fine, and so is a real IPv4 literal.
    assert_eq!(url("https://vpn1.example.com/c").as_str(), "https://vpn1.example.com/c");
    assert_eq!(url("https://123.example.com/c").as_str(), "https://123.example.com/c");
    assert_eq!(url("https://10.0.0.1/c").as_str(), "https://10.0.0.1/c");
}

#[test]
fn dot_segments_of_the_initial_path_are_resolved() {
    assert_eq!(
        url("https://vpn.example.com/a/./b/../c.macvpncatalog").as_str(),
        "https://vpn.example.com/a/c.macvpncatalog"
    );
    assert_eq!(url("https://vpn.example.com/../../x?q=1").as_str(), "https://vpn.example.com/x?q=1");
    assert_eq!(url("https://vpn.example.com/a/..").as_str(), "https://vpn.example.com/");
    // The same form a redirect to it gets.
    let base = url("https://vpn.example.com/team/c.macvpncatalog");
    assert_eq!(base.redirect_target("https://vpn.example.com/a/./b/../c").unwrap(), url("https://vpn.example.com/a/c"));
}

#[test]
fn read_catalog_file_reads_a_whole_large_file() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("big.macvpncatalog");
    let bytes: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    fs::write(&file, &bytes).unwrap();
    assert_eq!(read_catalog_file(&file).unwrap(), bytes);
}

#[test]
fn glob_characters_are_percent_encoded_in_the_canonical_text() {
    // curl's URL globbing must never see `[ ] { }` (it also runs with --globoff).
    assert_eq!(
        url("https://vpn.example.com/c.macvpncatalog?filter[x]=1&a={b}").as_str(),
        "https://vpn.example.com/c.macvpncatalog?filter%5Bx%5D=1&a=%7Bb%7D"
    );
    assert_eq!(url("https://vpn.example.com/x[1-100000000]").as_str(), "https://vpn.example.com/x%5B1-100000000%5D");
    // Idempotent, and an IPv6 host keeps its brackets.
    let once = url("https://[::1]:8443/a{1,2}");
    assert_eq!(once.as_str(), "https://[::1]:8443/a%7B1,2%7D");
    assert_eq!(url(once.as_str()), once);
    let base = url("https://vpn.example.com/team/c.macvpncatalog");
    assert_eq!(
        base.redirect_target("https://victim.example.net/x[1-100000000]").unwrap().as_str(),
        "https://victim.example.net/x%5B1-100000000%5D"
    );
    assert_eq!(
        base.redirect_target("v{1,2}?q=[0]").unwrap().as_str(),
        "https://vpn.example.com/team/v%7B1,2%7D?q=%5B0%5D"
    );
}
