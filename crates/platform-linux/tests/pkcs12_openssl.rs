#![cfg(target_os = "linux")]
//! The PKCS#12 conversion with the system's real `/usr/bin/openssl` (OpenSSL 3): files made here with openssl, a
//! modern (AES) and a legacy (RC2 / 3DES) one, converted to the PEM form; a wrong password is its own error.
use macvpn_core::client_cert::{ClientCert, Form};
use macvpn_platform_linux::convert_pkcs12;
use std::path::{Path, PathBuf};
use std::process::Command;

const OPENSSL: &str = "/usr/bin/openssl";

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new(OPENSSL).current_dir(dir).args(args).output().is_ok_and(|o| o.status.success())
}

/// A key, its self-signed client certificate and a CA, in `dir`.
fn credentials() -> Dir {
    let dir = Dir(std::env::temp_dir().join(format!("linvpn-p12-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir_all(&dir.0).unwrap();
    assert!(openssl(
        &dir.0,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            "client.key",
            "-out",
            "client.crt",
            "-days",
            "30",
            "-subj",
            "/CN=client.example.com",
        ]
    ));
    dir
}

fn p12(dir: &Path, name: &str, password: &str, legacy: bool) -> Option<Vec<u8>> {
    let pass = format!("pass:{password}");
    let mut args =
        vec!["pkcs12", "-export", "-inkey", "client.key", "-in", "client.crt", "-out", name, "-passout", &pass];
    if legacy {
        args.extend(["-legacy", "-certpbe", "PBE-SHA1-RC2-40", "-keypbe", "PBE-SHA1-3DES"]);
    }
    openssl(dir, &args).then(|| std::fs::read(dir.join(name)).unwrap())
}

fn der_of(dir: &Path) -> Vec<u8> {
    let out =
        Command::new(OPENSSL).current_dir(dir).args(["x509", "-in", "client.crt", "-outform", "DER"]).output().unwrap();
    out.stdout
}

#[test]
fn a_modern_pkcs12_becomes_the_pem_form_with_its_key_still_encrypted() {
    let dir = credentials();
    let file = p12(&dir.0, "client.p12", "s3cret pass", false).expect("openssl pkcs12 -export");
    let imported = convert_pkcs12(&file, "s3cret pass").unwrap();
    assert_eq!(imported.cert.form(), Form::Pem);
    let ClientCert::Pem { cert, key, encrypted } = &imported.cert else { panic!() };
    assert_eq!(cert, &der_of(&dir.0));
    assert!(*encrypted && key.contains("ENCRYPTED PRIVATE KEY"));
    // The key opens with the same password (as charon-nm will open it).
    std::fs::write(dir.0.join("out.key"), key.as_bytes()).unwrap();
    assert!(openssl(&dir.0, &["pkey", "-in", "out.key", "-passin", "pass:s3cret pass", "-noout"]));
    // The stored form reads back.
    assert!(ClientCert::from_stored(&imported.cert.stored()).is_some());
}

#[test]
fn a_wrong_password_is_its_own_error() {
    let dir = credentials();
    let file = p12(&dir.0, "client.p12", "right", false).unwrap();
    let err = convert_pkcs12(&file, "wrong").unwrap_err();
    assert_eq!(err, "The PKCS#12 password is wrong.");
    assert_eq!(convert_pkcs12(b"not a pkcs12 file", "x").unwrap_err(), "openssl could not read the PKCS#12 file.");
}

#[test]
fn a_legacy_pkcs12_is_converted_with_the_legacy_provider() {
    let dir = credentials();
    let Some(file) = p12(&dir.0, "legacy.p12", "old-pass", true) else {
        eprintln!("skip: this openssl cannot write a legacy PKCS#12 file");
        return;
    };
    let imported = convert_pkcs12(&file, "old-pass").unwrap();
    let ClientCert::Pem { cert, encrypted, .. } = &imported.cert else { panic!() };
    assert_eq!(cert, &der_of(&dir.0));
    assert!(*encrypted);
    assert_eq!(convert_pkcs12(&file, "wrong").unwrap_err(), "The PKCS#12 password is wrong.");
}

#[test]
fn an_empty_password_gives_an_unencrypted_key() {
    let dir = credentials();
    let file = p12(&dir.0, "open.p12", "", false).unwrap();
    let imported = convert_pkcs12(&file, "").unwrap();
    let ClientCert::Pem { encrypted, key, .. } = &imported.cert else { panic!() };
    assert!(!*encrypted && key.contains("PRIVATE KEY"));
}
