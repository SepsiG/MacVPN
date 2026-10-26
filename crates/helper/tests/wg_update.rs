//! wireguard-nt updates at runtime, the pure parts (2b plan, "As built (fix4)"): the listing, versions, the zip's
//! one member and its refusals, the PE checks, which DLL is loaded, the curl argv and the check cache. Every OS.

use macvpn_helper::windows::wg_update::{self as wu, CheckCache, Listed, NtVersion, ZipError};

/// The listing of `https://download.wireguard.com/wireguard-nt/`, captured 2026-10-24 (1.1 only).
const LISTING: &str = include_str!("fixtures/wireguard-nt-listing-2026-10-24.html");
const MEMBER: &str = "wireguard-nt/bin/amd64/wireguard.dll";

fn v(s: &str) -> NtVersion {
    NtVersion::parse(s).unwrap()
}

fn inflate(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(data, limit).ok()
}

/// A minimal zip writer for the tests: (name, data, deflate) entries; `patch` may change the bytes afterwards.
fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflate) in entries {
        let packed = if *deflate { miniz_oxide::deflate::compress_to_vec(data, 6) } else { data.to_vec() };
        let method: u16 = if *deflate { 8 } else { 0 };
        let crc = wu::crc32(data);
        let local = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&local.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn the_listing_names_the_newest_zip() {
    let l = wu::parse_listing(LISTING).unwrap();
    assert_eq!(l, Listed { text: "1.1".into(), version: v("1.1") });
    assert_eq!(wu::zip_url(&l).unwrap(), "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip");
    // Several links: the highest version, numerically (0.10.1 < 0.11 < 1.1 < 1.10).
    let html = r#"<a href="wireguard-nt-0.10.1.zip">x</a><a href="wireguard-nt-1.10.zip">y</a><a href="wireguard-nt-1.1.zip">z</a><a href="wireguard-nt-0.11.zip">"#;
    assert_eq!(wu::parse_listing(html).unwrap().text, "1.10");
    // Only that exact link form; anything else in the version is no version.
    for bad in [
        "",
        "<p>wireguard-nt-9.9.zip</p>",
        r#"<a href="https://evil.example/wireguard-nt-9.9.zip">"#,
        r#"<a href="wireguard-nt-9.9/../x.zip">"#,
        r#"<a href="wireguard-nt-9.9a.zip">"#,
        r#"<a href="wireguard-nt-1.2.3.4.5.zip">"#,
        r#"<a href="wireguard-nt-99999999.zip">"#,
        r#"<a href="wireguard-nt-.zip">"#,
        r#"<a href="wireguard-nt-1..2.zip">"#,
    ] {
        assert_eq!(wu::parse_listing(bad), None, "{bad}");
    }
    // A bad link next to a good one leaves the good one.
    assert_eq!(wu::parse_listing(r#"href="wireguard-nt-x.zip" href="wireguard-nt-1.2.zip""#).unwrap().text, "1.2");
}

#[test]
fn versions_compare_numerically_with_missing_parts_as_zero() {
    assert_eq!(v("1.1"), NtVersion([1, 1, 0, 0]));
    assert_eq!(v("1.1"), NtVersion::from_file_version((1, 1, 0, 0)));
    assert!(v("1.1.1") > v("1.1") && v("1.10") > v("1.9") && v("0.10.1") < v("0.11"));
    assert_eq!(v("1.1").to_string(), "1.1.0");
    assert_eq!(v("1.2.3.4").to_string(), "1.2.3.4");
    for bad in ["", "1.", ".1", "1.2.3.4.5", "1.x", "65536", "-1", "1 .2", "１.2"] {
        assert_eq!(NtVersion::parse(bad), None, "{bad}");
    }
    let listed = Listed { text: "1.2".into(), version: v("1.2") };
    assert!(wu::matches_listed(v("1.2.0.0"), &listed));
    assert!(wu::matches_listed(v("1.2.3.1"), &listed));
    assert!(!wu::matches_listed(v("1.1.0.0"), &listed));
    assert!(!wu::matches_listed(v("1.3"), &listed));
}

#[test]
fn the_downloaded_dll_is_used_only_when_it_is_newer_than_the_bundled_one() {
    assert!(wu::use_downloaded(v("1.1"), Some(v("1.2"))));
    assert!(!wu::use_downloaded(v("1.1"), Some(v("1.1"))));
    assert!(!wu::use_downloaded(v("1.2"), Some(v("1.1"))), "a WinVPN update brought a newer one");
    assert!(!wu::use_downloaded(v("1.1"), None));
    assert!(wu::is_newer(v("1.2"), &[v("1.1"), v("1.1.1")]));
    assert!(!wu::is_newer(v("1.2"), &[v("1.1"), v("1.2")]), "never the same version again");
    assert!(!wu::is_newer(v("1.0"), &[v("1.1")]), "never a downgrade");
    assert!(wu::is_newer(v("1.0"), &[]));
}

#[test]
fn the_member_is_read_by_its_exact_name() {
    let dll = b"MZ the dll bytes, repeated repeated repeated repeated".repeat(50);
    for deflate in [false, true] {
        let z = zip(&[
            ("wireguard-nt/README.md", b"readme", deflate),
            ("wireguard-nt/bin/arm64/wireguard.dll", b"arm", deflate),
            (MEMBER, &dll, deflate),
        ]);
        assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate).unwrap(), dll);
        assert_eq!(wu::extract(&z, "wireguard-nt/bin/arm64/wireguard.dll", 1 << 20, inflate).unwrap(), b"arm");
    }
    assert_eq!(wu::dll_member("x86_64"), Some(MEMBER));
    assert_eq!(wu::dll_member("aarch64"), Some("wireguard-nt/bin/arm64/wireguard.dll"));
    assert_eq!(wu::dll_member("x86"), None);
}

#[test]
fn a_zip_out_of_shape_is_refused() {
    let dll = b"MZ dll".to_vec();
    let good = zip(&[(MEMBER, &dll, true)]);
    // Missing, other spellings and traversal names are not the member (names never become paths).
    for other in ["wireguard-nt/bin/amd64/../amd64/wireguard.dll", "WIREGUARD-NT/bin/amd64/wireguard.dll", "/x"] {
        let z = zip(&[(other, &dll, false)]);
        assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Missing), "{other}");
    }
    // Twice the same name.
    assert_eq!(
        wu::extract(&zip(&[(MEMBER, &dll, false), (MEMBER, b"MZ other", false)]), MEMBER, 1 << 20, inflate),
        Err(ZipError::Duplicate)
    );
    // Too large for the limit.
    assert_eq!(wu::extract(&good, MEMBER, 3, inflate), Err(ZipError::TooLarge));
    // Not a zip, truncated, empty.
    assert_eq!(wu::extract(b"", MEMBER, 1 << 20, inflate), Err(ZipError::Malformed));
    assert_eq!(wu::extract(&good[..good.len() - 1], MEMBER, 1 << 20, inflate), Err(ZipError::Malformed));
    assert_eq!(wu::extract(&good[10..], MEMBER, 1 << 20, inflate), Err(ZipError::Malformed));
    // The central directory's offset of the local header (offset 42 of the central record).
    let cd = good.len() - 22 - (46 + MEMBER.len());
    // Encrypted (flag bit 0 in the central directory).
    let mut z = good.clone();
    z[cd + 8] |= 1;
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Unsupported));
    // Another method (e.g. 12, bzip2).
    let mut z = good.clone();
    z[cd + 10] = 12;
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Unsupported));
    // The local header names another file (same length).
    let mut z = good.clone();
    z[30] = b'W';
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Inconsistent));
    // Sizes that disagree between the local header and the central directory.
    let mut z = good.clone();
    z[22] ^= 1;
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Inconsistent));
    // A flipped data byte: the CRC-32 (or the inflater) refuses it.
    let stored = zip(&[(MEMBER, &dll, false)]);
    let mut z = stored.clone();
    z[30 + MEMBER.len()] ^= 0xFF;
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Corrupt));
    // A central directory that points past its end, and a multi-disk archive.
    let mut z = good.clone();
    let n = z.len();
    z[n - 6..n - 2].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Malformed));
    let mut z = good.clone();
    z[n - 18] = 1;
    assert_eq!(wu::extract(&z, MEMBER, 1 << 20, inflate), Err(ZipError::Malformed));
    // An inflater that fails.
    assert_eq!(wu::extract(&good, MEMBER, 1 << 20, |_, _| None), Err(ZipError::Corrupt));
}

#[test]
fn crc32_is_zips() {
    assert_eq!(wu::crc32(b""), 0);
    assert_eq!(wu::crc32(b"123456789"), 0xCBF4_3926);
}

/// A PE header: `MZ`, `e_lfanew` at 0x3C, `PE\0\0`, the machine and the characteristics.
fn pe(machine: u16, characteristics: u16) -> Vec<u8> {
    let mut b = vec![0u8; 0x80 + 24];
    b[..2].copy_from_slice(b"MZ");
    b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    b[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());
    b
}

#[test]
fn the_dll_machine_is_read_from_its_pe_header() {
    assert_eq!(wu::pe_dll_machine(&pe(0x8664, 0x2022)), Some(0x8664));
    assert_eq!(wu::pe_dll_machine(&pe(0xAA64, 0x2022)), Some(0xAA64));
    assert_eq!(wu::pe_dll_machine(&pe(0x8664, 0x0022)), None, "an EXE is no DLL");
    assert_eq!(wu::pe_dll_machine(b"MZ"), None);
    assert_eq!(wu::pe_dll_machine(&pe(0x8664, 0x2022)[..0x90]), None, "truncated");
    let mut not_pe = pe(0x8664, 0x2022);
    not_pe[0x80] = b'X';
    assert_eq!(wu::pe_dll_machine(&not_pe), None);
    let mut far = pe(0x8664, 0x2022);
    far[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(wu::pe_dll_machine(&far), None);
    assert_eq!(wu::machine_of("x86_64"), Some(0x8664));
    assert_eq!(wu::machine_of("aarch64"), Some(0xAA64));
    assert_eq!(wu::machine_of("x86"), None);
}

#[test]
fn curl_gets_a_fixed_https_only_argv() {
    let a = wu::curl_args(wu::LISTING_URL, r"C:\ProgramData\WinVPN\engines\wireguard-nt\listing.tmp", 262_144, 30);
    let pairs: Vec<(&str, &str)> = a.windows(2).map(|w| (w[0].as_str(), w[1].as_str())).collect();
    for want in [
        ("--proto", "=https"),
        ("--max-redirs", "0"),
        ("--max-time", "30"),
        ("--max-filesize", "262144"),
        ("--write-out", "%{http_code}"),
        ("--output", r"C:\ProgramData\WinVPN\engines\wireguard-nt\listing.tmp"),
        ("--", wu::LISTING_URL),
    ] {
        assert!(pairs.contains(&want), "{want:?} in {a:?}");
    }
    assert_eq!(a[0], "-q", "no .curlrc");
    assert!(a.contains(&"--tlsv1.2".to_string()) && a.contains(&"--ssl-revoke-best-effort".to_string()));
    assert!(!a.iter().any(|x| x == "-L" || x == "--location" || x == "-k" || x == "--insecure"));
    assert_eq!(a.last().unwrap(), wu::LISTING_URL, "the URL is last, after --");
}

#[test]
fn a_check_is_reused_for_a_minute() {
    let c = Some(CheckCache { at: 1000, answer: 7 });
    assert_eq!(CheckCache::fresh(&c, 1000), Some(7));
    assert_eq!(CheckCache::fresh(&c, 1000 + wu::CHECK_CACHE_SECS - 1), Some(7));
    assert_eq!(CheckCache::fresh(&c, 1000 + wu::CHECK_CACHE_SECS), None);
    assert_eq!(CheckCache::fresh(&c, 999), None, "a clock that went back");
    assert_eq!(CheckCache::<i32>::fresh(&None, 1000), None);
}
