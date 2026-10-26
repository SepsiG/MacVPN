//! Authenticode, file versions, admin-only paths and DLL loading, on files every Windows machine (and Git for
//! Windows, which the test machine and CI have) carries. Runs as a standard user.
//!
//! Which signature each test file has (Windows 11, build 26300, checked with `Get-AuthenticodeSignature`):
//! embedded: `git.exe` (Johannes Schindelin), `System32\kernel32.dll` (Microsoft Windows); catalog only (no
//! embedded signature): `System32\cmd.exe`, `System32\notepad.exe`, `System32\msiexec.exe`.

#![cfg(windows)]

use macvpn_winsys::cert_store::{self, Location, Presence};
use macvpn_winsys::{acl_check, dll, file, trust, version};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

fn git_exe() -> PathBuf {
    // Embedded Authenticode signature (Git for Windows' binaries are signed by their maintainer).
    PathBuf::from(r"C:\Program Files\Git\cmd\git.exe")
}

/// A fresh directory under the user's temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "winsys-trust-{}-{nanos}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn copy_of(&self, src: &Path) -> PathBuf {
        let to = self.0.join(src.file_name().unwrap());
        fs::copy(src, &to).unwrap();
        to
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_signed_binary_names_its_signer() {
    assert_eq!(trust::verify_signature(&git_exe()).unwrap().subject, "Johannes Schindelin");
    let kernel32 = trust::verify_signature(Path::new(r"C:\Windows\System32\kernel32.dll")).unwrap();
    assert_eq!(kernel32.subject, "Microsoft Windows");
}

/// The pinned wireguard-nt 1.1 DLLs as `scripts/fetch-wireguard-nt.sh` leaves them (run it first).
fn wireguard_nt_dll(arch: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(r"..\..\target\wireguard-nt\bin\{arch}\wireguard.dll"));
    let p = fs::canonicalize(&p)
        .unwrap_or_else(|e| panic!("{}: {e} (run scripts/fetch-wireguard-nt.sh first)", p.display()));
    PathBuf::from(p.to_str().unwrap().strip_prefix(r"\\?\").unwrap().to_owned())
}

/// wireguard-nt 1.1's chain (`openssl pkcs7 -print_certs` of the PE signature, each key's
/// `openssl pkey -pubin -outform der | sha256`): the leaf `WireGuard LLC` (valid 2026-03-30 to 2027-03-30) under
/// `Sectigo Public Code Signing CA EV R36`, under `Sectigo Public Code Signing Root R46`.
const WG_LEAF_SPKI: &str = "97d260d874a49220032a702875d9bc59f445f5192682d5acb9538df584ed4087";
const WG_CA_SPKI: &str = "4c2655992d5a342a1082d3c3f0ba8ade37dfb425d15d3f4a3c091609af60c112";

/// M-1 of the 2.0.0 security review: the signer's chain is read, each certificate's key as its SPKI SHA-256, and a
/// signer is only pinned when its name matches and a CA above it in the chain has a pinned key.
#[test]
fn the_signing_chain_of_the_pinned_wireguard_nt_dll_is_read() {
    for arch in ["amd64", "arm64"] {
        let signer = trust::verify_signature(&wireguard_nt_dll(arch)).unwrap();
        assert_eq!(signer.subject, "WireGuard LLC");
        assert_eq!(signer.chain_spki_sha256.first().map(String::as_str), Some(WG_LEAF_SPKI), "{arch}");
        assert_eq!(signer.chain_spki_sha256.get(1).map(String::as_str), Some(WG_CA_SPKI), "{arch}");
        assert!(signer.chain_spki_sha256.len() >= 3, "up to a root: {:?}", signer.chain_spki_sha256);
        assert!(signer.is_pinned("WireGuard LLC", &[WG_CA_SPKI]));
        assert!(signer.is_pinned("WireGuard LLC", &["00".repeat(32).as_str(), WG_CA_SPKI]));
        // The name and a CA key are both needed; the leaf's own key is not a CA.
        assert!(!signer.is_pinned("OpenVPN Inc.", &[WG_CA_SPKI]));
        assert!(!signer.is_pinned("WireGuard LLC", &[WG_LEAF_SPKI]));
        assert!(!signer.is_pinned("WireGuard LLC", &[]));
        assert!(!signer.is_pinned("WireGuard LLC", &[&WG_CA_SPKI.to_uppercase()]));
    }
    // Another publisher's chain (Git for Windows): read too, every key a SHA-256 in lower-case hex, not pinned.
    let git = trust::verify_signature(&git_exe()).unwrap();
    assert!(git.chain_spki_sha256.len() >= 2, "{:?}", git.chain_spki_sha256);
    assert!(
        git.chain_spki_sha256
            .iter()
            .all(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    );
    assert!(!git.is_pinned("Johannes Schindelin", &[WG_CA_SPKI]));
}

#[test]
fn an_unmodified_copy_keeps_its_signature() {
    let scratch = Scratch::new();
    let copy = scratch.copy_of(&git_exe());
    assert_eq!(trust::verify_signature(&copy).unwrap().subject, "Johannes Schindelin");
}

#[test]
fn a_modified_copy_is_not_trusted() {
    let scratch = Scratch::new();
    let copy = scratch.copy_of(&git_exe());
    let mut bytes = fs::read(&copy).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    fs::write(&copy, &bytes).unwrap();
    assert!(trust::verify_signature(&copy).is_err());
}

#[test]
fn an_unsigned_file_is_not_trusted() {
    let scratch = Scratch::new();
    let f = scratch.0.join("plain.exe");
    fs::write(&f, b"MZ not really").unwrap();
    assert!(trust::verify_signature(&f).is_err());
    assert!(trust::verify_signature(&scratch.0.join("missing.exe")).is_err());
    assert!(trust::verify_signature(Path::new("git.exe")).is_err());
}

#[test]
fn a_catalog_signed_file_is_not_trusted() {
    // Signed only through a catalog in CatRoot, which an embedded-signature check does not consult.
    assert!(trust::verify_signature(Path::new(r"C:\Windows\System32\cmd.exe")).is_err());
}

#[test]
fn file_versions_are_read() {
    // Windows' own files report 6.2 instead of 10.0 to a process without a Windows 10 compatibility manifest (the
    // test binary has none: an application compatibility shim); the build number is the real one.
    let v = version::file_version(Path::new(r"C:\Windows\System32\kernel32.dll")).unwrap();
    assert!(v.0 >= 6 && v.2 >= 10240, "{v:?}");
    // Other files are read as they are (Git 2.x).
    let git = version::file_version(&git_exe()).unwrap();
    assert!(git.0 >= 2, "{git:?}");
    assert!(version::file_version(Path::new(r"C:\does-not-exist.exe")).is_err());
    assert!(version::file_version(Path::new("kernel32.dll")).is_err());
    // A file without a version resource.
    let scratch = Scratch::new();
    let f = scratch.0.join("plain.dll");
    fs::write(&f, b"MZ not really").unwrap();
    assert!(version::file_version(&f).is_err());
}

#[test]
fn system32_and_program_files_are_admin_only_and_a_temp_dir_is_not() {
    assert!(acl_check::is_admin_only(Path::new(r"C:\Windows\System32\kernel32.dll")).unwrap());
    assert!(acl_check::is_admin_only(&git_exe()).unwrap());
    let scratch = Scratch::new();
    let copy = scratch.copy_of(&git_exe());
    assert!(!acl_check::is_admin_only(&copy).unwrap());
    assert!(acl_check::is_admin_only(Path::new("relative.exe")).is_err());
    assert!(acl_check::is_admin_only(Path::new(r"C:\Windows\System32\..\System32\kernel32.dll")).is_err());
    assert!(acl_check::is_admin_only(Path::new(r"\\localhost\C$\Windows\System32\kernel32.dll")).is_err());
    assert!(acl_check::is_admin_only(Path::new(r"C:\Windows\System32\no-such-file.dll")).is_err());
}

#[test]
fn a_junction_in_the_path_is_not_admin_only() {
    let scratch = Scratch::new();
    let link = scratch.0.join("link");
    fs::create_dir(&link).unwrap();
    file::make_junction_for_tests(&link, r"\??\C:\Windows\System32").unwrap();
    // Through the junction: never admin-only (Windows 11 may already refuse to traverse a junction a standard user
    // made, ERROR_UNTRUSTED_MOUNT_POINT: an error, which callers treat as "not admin-only").
    assert!(!matches!(acl_check::is_admin_only(&link.join("kernel32.dll")), Ok(true)));
    // The junction itself is opened, not followed, and refused.
    assert!(!acl_check::is_admin_only(&link).unwrap());
}

#[test]
fn dlls_load_only_by_absolute_path() {
    dll::harden_process_search();
    let lib = dll::Library::load(Path::new(r"C:\Windows\System32\version.dll")).unwrap();
    assert!(lib.symbol(c"GetFileVersionInfoSizeW").is_ok());
    assert!(lib.symbol(c"NoSuchExport").is_err());
    assert!(dll::Library::load(Path::new("version.dll")).is_err());
    assert!(dll::Library::load(Path::new(r"C:\Windows\System32\no-such.dll")).is_err());
}

/// WinVPN 2c Task 12: the read-only check of the computer's Trusted Root store (a standard user may read it).
#[test]
fn the_machine_root_store_answers_by_thumbprint() {
    // Microsoft Root Certificate Authority 2011: in the Trusted Root store of every Windows 10 and 11.
    let microsoft: [u8; 20] = [
        0x8F, 0x43, 0x28, 0x8A, 0xD2, 0x72, 0xF3, 0x10, 0x3B, 0x6F, 0xB1, 0x42, 0x84, 0x85, 0xEA, 0x30, 0x14, 0xC0,
        0xBC, 0xFE,
    ];
    assert!(cert_store::local_machine_contains("Root", &microsoft).unwrap());
    assert!(!cert_store::local_machine_contains("Root", &[0x5A; 20]).unwrap());
    assert!(cert_store::local_machine_contains("WinVPN-no-such-store", &microsoft).is_err());
}

/// The test CA of `crates/platform-win/tests/fixtures/ca/ca.pem` (DER; SHA-1 53cdc417ceda8000a2fcfd50eb98f4d80c9cde2f).
const TEST_CA_DER: &[u8] = include_bytes!("fixtures/test-ca.der");
const TEST_CA_SHA1: [u8; 20] = [
    0x53, 0xcd, 0xc4, 0x17, 0xce, 0xda, 0x80, 0x00, 0xa2, 0xfc, 0xfd, 0x50, 0xeb, 0x98, 0xf4, 0xd8, 0x0c, 0x9c, 0xde,
    0x2f,
];
/// `SEQUENCE { serverAuth, clientAuth }` (RFC 5280 ExtKeyUsageSyntax).
const TLS_ONLY: &[u8] = &[
    0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x03, 0x02,
];

/// M-1: a certificate is added with its enhanced key usage property set in the same step, read back, and removed.
/// As the standard user, in the user's own `My` store (the machine's `Root` store needs an administrator:
/// `cert_store_admin.rs`).
#[test]
fn a_certificate_is_added_with_a_usage_property_and_removed() {
    let (at, store) = (Location::CurrentUser, "My");
    let _ = cert_store::remove(at, store, &TEST_CA_SHA1);
    assert_eq!(cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(), Presence::Absent);
    assert_eq!(cert_store::add_with_usage(at, store, TEST_CA_DER, TLS_ONLY).unwrap(), cert_store::Added::New);
    assert_eq!(
        cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(),
        Presence::Present { usage: Some(TLS_ONLY.to_vec()) }
    );
    // Already there: left as it is.
    assert_eq!(
        cert_store::add_with_usage(at, store, TEST_CA_DER, &TLS_ONLY[..2]).unwrap(),
        cert_store::Added::AlreadyThere
    );
    assert_eq!(
        cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(),
        Presence::Present { usage: Some(TLS_ONLY.to_vec()) }
    );
    assert!(cert_store::remove(at, store, &TEST_CA_SHA1).unwrap());
    assert!(!cert_store::remove(at, store, &TEST_CA_SHA1).unwrap());
    assert_eq!(cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(), Presence::Absent);
    // Not a certificate; a missing store.
    assert!(cert_store::add_with_usage(at, store, b"\x30\x03\x02\x01\x00", TLS_ONLY).is_err());
    assert!(cert_store::presence(Location::LocalMachine, "WinVPN-no-such-store", &TEST_CA_SHA1).is_err());
    // A machine store is readable by everyone: Microsoft's root there has no usage property set by WinVPN.
    assert!(matches!(cert_store::presence(Location::LocalMachine, "Root", &TEST_CA_SHA1).unwrap(), Presence::Absent));
}
