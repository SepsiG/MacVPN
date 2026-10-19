//! Port of `ConfigImporterTests.swift`, `PKCS12ImportTests` (OpenVPNTierTests.swift), the importer parts of
//! `MikroTikImportTests` and `SecurityReviewTests` (L5), and the SSTP import cases of `SSTPTests.swift`.

mod common;

use common::*;
use macvpn_core::importer::{self, ConfigImportError, MAX_INLINE_FILE_SIZE};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{ConfigValidator, OpenVPNValidator, StrongSwanValidator};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n";
const STATIC_KEY: &str = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\nabcdef\n-----END OpenVPN Static key V1-----\n";
const V2_KEY: &str =
    "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nabc\n-----END OpenVPN tls-crypt-v2 client key-----\n";
const DH: &str = "-----BEGIN DH PARAMETERS-----\nMIIBfake\n-----END DH PARAMETERS-----\n";

/// `root/vpn` (the config's folder) under a fresh temp dir; realpath'd like the Swift tests' expectations.
struct Env {
    _tmp: TempDir,
    root: PathBuf,
    dir: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = TempDir::new();
        let dir = tmp.path().join("vpn");
        fs::create_dir_all(&dir).unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let dir = root.join("vpn");
        Env { _tmp: tmp, root, dir }
    }

    fn put(&self, name: &str, content: &str) {
        fs::write(self.dir.join(name), content).unwrap();
    }

    fn put_in(&self, base: &Path, name: &str, content: &str) {
        fs::write(base.join(name), content).unwrap();
    }

    fn inline(&self, text: &str) -> Result<importer::InlineResult, ConfigImportError> {
        importer::inline_openvpn_files(text, &self.dir)
    }

    #[track_caller]
    fn rejected(&self, line: &str, expected: ConfigImportError) {
        assert_eq!(self.inline(&format!("{line}\n")).unwrap_err(), expected, "{line}");
    }

    fn openssl(&self, args: &[&str]) -> bool {
        Command::new("/usr/bin/openssl")
            .args(args)
            .current_dir(&self.dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

#[test]
fn detect_kind() {
    assert_eq!(importer::detect_kind("a.ovpn", ""), Some(VPNKind::Openvpn));
    assert_eq!(importer::detect_kind("wg0.conf", "[Interface]\nPrivateKey = x\n"), Some(VPNKind::Wireguard));
    assert_eq!(importer::detect_kind("s.conf", "connections {\n}\n"), Some(VPNKind::Strongswan));
    assert_eq!(importer::detect_kind("c.conf", "client\nremote a 1194\n"), Some(VPNKind::Openvpn));
    assert_eq!(importer::detect_kind("x.txt", "hello"), None);
}

#[test]
fn mobileconfig_is_rejected_with_finder_hint() {
    assert_eq!(
        importer::kind("Office.mobileconfig", "<?xml version=\"1.0\"?><plist/>"),
        Err(ConfigImportError::NativeProfile)
    );
    assert_eq!(importer::kind("x.txt", "hello"), Err(ConfigImportError::UnknownType));
    assert_eq!(importer::kind("a.ovpn", ""), Ok(VPNKind::Openvpn));
    lang(AppLanguage::En);
    assert_eq!(
        ConfigImportError::NativeProfile.message(),
        "A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles)."
    );
    lang(AppLanguage::Hu);
    assert_eq!(
        ConfigImportError::NativeProfile.message(),
        "A .mobileconfig profil nem importálható a MacVPN-be. Kattints rá duplán a Finderben: a macOS profilként telepíti, utána a Rendszerbeállítások → Általános → Eszközkezelés (Profilok) alatt hagyd jóvá."
    );
}

#[test]
fn path_extension_like_nsstring() {
    for (name, ext) in [
        ("a.ovpn", "ovpn"),
        ("a.OVPN", "OVPN"),
        (".mobileconfig", ""),
        ("a.mobileconfig/", "mobileconfig"),
        ("dir/x.mobileconfig", "mobileconfig"),
        ("a.", ""),
        ("a.b.c", "c"),
        ("a b.mobileconfig", "mobileconfig"),
        ("a/.b", ""),
        ("..mobileconfig", ""),
        ("a..ovpn", "ovpn"),
        ("....x", "x"),
        ("...<", ""),
        ("a. b", ""),
        ("a.b\tc", "b\tc"),
        ("a.x\u{2066}", ""),
    ] {
        assert_eq!(importer::path_extension(name), ext, "{name}");
    }
}

#[test]
fn inlines_referenced_files() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    env.put("ta.key", STATIC_KEY);
    let out = env.inline("remote a 1\nca \"ca.crt\"\ntls-auth ta.key 1\nauth-user-pass creds.txt\n").unwrap();
    assert_eq!(
        out.config,
        format!(
            "remote a 1\n<ca>\n{}\n</ca>\n<tls-auth>\n{}\n</tls-auth>\nkey-direction 1\nauth-user-pass\n",
            &CERT[..CERT.len() - 1],
            &STATIC_KEY[..STATIC_KEY.len() - 1]
        )
    );
    assert_eq!(out.inlined_files, ["ca.crt", "ta.key"]);
    assert_eq!(OpenVPNValidator.validate(&out.config), []);
}

#[test]
fn inlines_every_directive_with_its_format() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    env.put("c.crt", CERT);
    env.put("c.key", KEY);
    env.put("tc.key", STATIC_KEY);
    env.put("v2.key", V2_KEY);
    env.put("dh.pem", DH);
    env.put("rsa.key", "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n");
    fs::create_dir_all(env.dir.join("sub")).unwrap();
    env.put("sub/extra.crt", CERT);
    let input = "remote a 1\nca ca.crt\ncert c.crt\nkey c.key\ntls-crypt tc.key\ntls-crypt-v2 v2.key\ndh dh.pem\nextra-certs sub/extra.crt\nsecret tc.key\n";
    let out = env.inline(input).unwrap();
    assert_eq!(
        out.inlined_files,
        ["ca.crt", "c.crt", "c.key", "tc.key", "v2.key", "dh.pem", "sub/extra.crt", "tc.key"]
    );
    assert!(out.config.contains("<tls-crypt-v2>\n-----BEGIN OpenVPN tls-crypt-v2 client key-----"));
    assert_eq!(env.inline("key rsa.key\n").unwrap().inlined_files, ["rsa.key"]);
    assert_eq!(env.inline("dh none\n").unwrap().config, "dh none\n");
}

#[test]
fn absolute_path_inside_base_is_allowed() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    let path = format!("{}/ca.crt", env.dir.display());
    assert_eq!(env.inline(&format!("ca {path}\n")).unwrap().inlined_files, [path]);
}

#[test]
fn parent_directory_escape_is_rejected() {
    let env = Env::new();
    let ssh = env.root.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    env.put_in(&ssh, "id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n");
    env.rejected("key ../.ssh/id_ed25519", ConfigImportError::OutsideBaseDirectory("../.ssh/id_ed25519".into()));
    env.rejected(
        "ca sub/../../.ssh/id_ed25519",
        ConfigImportError::OutsideBaseDirectory("sub/../../.ssh/id_ed25519".into()),
    );
}

#[test]
fn absolute_path_outside_base_is_rejected() {
    let env = Env::new();
    env.rejected("ca /etc/hosts", ConfigImportError::OutsideBaseDirectory("/etc/hosts".into()));
}

#[test]
fn symlink_escaping_base_is_rejected() {
    let env = Env::new();
    env.put_in(&env.root, "outside.crt", CERT);
    std::os::unix::fs::symlink(env.root.join("outside.crt"), env.dir.join("ca.crt")).unwrap();
    env.rejected("ca ca.crt", ConfigImportError::OutsideBaseDirectory("ca.crt".into()));
    // A directory symlink too.
    std::os::unix::fs::symlink(&env.root, env.dir.join("up")).unwrap();
    env.rejected("ca up/outside.crt", ConfigImportError::OutsideBaseDirectory("up/outside.crt".into()));
}

fn wrong(directive: &str, file: &str) -> ConfigImportError {
    ConfigImportError::WrongFormat { directive: directive.into(), file: file.into() }
}

#[test]
fn wrong_format_is_rejected() {
    let env = Env::new();
    env.put("hosts", "127.0.0.1 localhost\n");
    env.put("ca.crt", CERT);
    env.put("c.key", KEY);
    env.rejected("ca hosts", wrong("ca", "hosts"));
    env.rejected("key ca.crt", wrong("key", "ca.crt"));
    env.rejected("ca c.key", wrong("ca", "c.key"));
    env.rejected("tls-auth c.key", wrong("tls-auth", "c.key"));
    env.rejected("tls-crypt-v2 ca.crt", wrong("tls-crypt-v2", "ca.crt"));
    env.rejected("dh ca.crt", wrong("dh", "ca.crt"));
    // The file's content cannot close the block (directive smuggling).
    env.put("evil.crt", &format!("{CERT}</ca>\nup /tmp/x\n<ca>\n"));
    env.rejected("ca evil.crt", wrong("ca", "evil.crt"));
}

/// Foundation behaviours kept on purpose (differential tests against Swift): a CRLF PEM file does not match the
/// format check (`\r\n` is one Character for Swift's `\r?\n`), a leading BOM is dropped when reading, and a NUL ends
/// the path given to realpath.
#[test]
fn foundation_reading_rules() {
    let env = Env::new();
    env.put("crlf.crt", &CERT.replace('\n', "\r\n"));
    env.rejected("ca crlf.crt", wrong("ca", "crlf.crt"));
    env.put("bom.crt", &format!("\u{FEFF}{CERT}"));
    let out = env.inline("ca bom.crt\n").unwrap();
    assert!(out.config.starts_with("<ca>\n-----BEGIN CERTIFICATE-----"));
    env.put("auth.cfg", "\u{FEFF}bob\npass\n");
    let prepared = importer::prepare("x.ovpn", "remote a 1\nauth-user-pass auth.cfg\n", &env.dir).unwrap();
    assert_eq!(prepared.credentials.username.as_deref(), Some("bob"));
    env.rejected("ca \u{0}x.crt", ConfigImportError::OutsideBaseDirectory("\u{0}x.crt".into()));
}

#[test]
fn oversize_file_is_rejected() {
    let env = Env::new();
    env.put("big.crt", &format!("{CERT}{}", "#".repeat(MAX_INLINE_FILE_SIZE)));
    env.rejected("ca big.crt", ConfigImportError::FileTooLarge("big.crt".into()));
}

#[test]
fn directory_and_missing_file_are_rejected() {
    let env = Env::new();
    fs::create_dir_all(env.dir.join("d")).unwrap();
    env.rejected("ca d", ConfigImportError::MissingFile("d".into()));
    env.rejected("ca nope.crt", ConfigImportError::MissingFile("nope.crt".into()));
}

#[test]
fn prepare_validates_but_keeps_the_config() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    let ok = importer::prepare("a.ovpn", "client\nremote a 1194\nca ca.crt\n", &env.dir).unwrap();
    assert_eq!(ok.kind, VPNKind::Openvpn);
    assert_eq!(ok.inlined_files, ["ca.crt"]);
    assert_eq!(ok.issues, []);
    let bad = importer::prepare("b.ovpn", "client\nremote a 1194\nup /tmp/x\n", &env.dir).unwrap();
    assert_eq!(bad.config, "client\nremote a 1194\nup /tmp/x\n");
    assert_eq!(lines(&bad.issues), [3]);
    let wg = importer::prepare("wg.conf", "[Interface]\nPrivateKey = x\nPostUp = rm -rf /\n", &env.dir).unwrap();
    assert_eq!(wg.kind, VPNKind::Wireguard);
    assert!(!wg.issues.is_empty());
    assert!(wg.inlined_files.is_empty());
}

#[test]
fn import_errors_are_localized() {
    lang(AppLanguage::Hu);
    assert_eq!(
        ConfigImportError::OutsideBaseDirectory("../x".into()).message(),
        "A hivatkozott fájl a config mappáján kívül van: ../x"
    );
    assert_eq!(ConfigImportError::FileTooLarge("x".into()).message(), "A hivatkozott fájl nagyobb 1 MB-nál: x");
    assert_eq!(wrong("ca", "x").message(), "A(z) ca direktíva fájlja (x) nem a várt formátumú");
}

#[test]
fn templates_for_text_kinds_are_valid_shape() {
    assert!(!importer::template(VPNKind::Openvpn).is_empty());
    assert!(StrongSwanValidator::names(&importer::template(VPNKind::Strongswan)).is_some());
    assert_eq!(importer::template(VPNKind::L2tp), "");
    assert_eq!(StrongSwanValidator.validate(&importer::template(VPNKind::Strongswan)), []);
}

// MARK: PKCS#12 (OpenVPNTierTests.swift)

fn make_p12(env: &Env, name: &str, password: &str) -> Vec<u8> {
    assert!(env.openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "k.pem",
        "-out",
        "c.pem",
        "-subj",
        "/CN=macvpn-test",
        "-days",
        "1",
    ]));
    let pass = format!("pass:{password}");
    assert!(env.openssl(&["pkcs12", "-export", "-in", "c.pem", "-inkey", "k.pem", "-out", name, "-passout", &pass]));
    fs::read(env.dir.join(name)).unwrap()
}

fn check_p12(env: &Env, p12: &[u8], name: &str) {
    assert!(importer::is_pkcs12(p12));
    let input = format!("client\ndev tun\nremote a 1194\npkcs12 {name}\n");
    let prepared = importer::prepare("x.ovpn", &input, &env.dir).unwrap();
    assert_eq!(prepared.inlined_files, [name]);
    assert_eq!(prepared.issues, []);
    assert_eq!(prepared.risky, []);
    let lines: Vec<&str> = prepared.config.split('\n').collect();
    let start = lines.iter().position(|l| *l == "<pkcs12>").unwrap();
    let end = lines.iter().position(|l| *l == "</pkcs12>").unwrap();
    let body = &lines[start + 1..end];
    assert!(body.iter().all(|l| l.len() <= 64 && !l.is_empty()));
    assert!(body[..body.len() - 1].iter().all(|l| l.len() == 64));
    assert_eq!(macvpn_core::swift_base64::decode(&body.concat()).unwrap(), p12);
    assert!(!prepared.config.contains(&format!("pkcs12 {name}")));
    // Export: <pkcs12> is key material, it can be stripped.
    assert_eq!(macvpn_core::exporter::secret_material(&prepared.config, VPNKind::Openvpn), ["<pkcs12>"]);
    assert!(!macvpn_core::exporter::strip_secrets(&prepared.config, VPNKind::Openvpn).contains("pkcs12"));
}

#[test]
fn imports_pkcs12_without_password() {
    let env = Env::new();
    let p12 = make_p12(&env, "nopass.p12", "");
    check_p12(&env, &p12, "nopass.p12");
}

#[test]
fn imports_pkcs12_with_password() {
    let env = Env::new();
    let p12 = make_p12(&env, "client.p12", "s3cret");
    check_p12(&env, &p12, "client.p12");
}

#[test]
fn rejects_non_pkcs12_and_escapes() {
    let env = Env::new();
    env.put("fake.p12", "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n");
    let p = |c: &str| importer::prepare("x.ovpn", c, &env.dir).unwrap_err();
    assert_eq!(p("remote a\npkcs12 fake.p12\n"), wrong("pkcs12", "fake.p12"));
    assert_eq!(p("remote a\npkcs12 ../out.p12\n"), ConfigImportError::OutsideBaseDirectory("../out.p12".into()));
    assert_eq!(p("remote a\npkcs12 missing.p12\n"), ConfigImportError::MissingFile("missing.p12".into()));
    let mut not_p12 = vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x02];
    not_p12.extend([0u8; 40]);
    assert!(!importer::is_pkcs12(&not_p12));
    assert!(!importer::is_pkcs12(&[0x31, 0x82]));
}

#[test]
fn encrypted_pem_keys_are_inlined() {
    let env = Env::new();
    assert!(env.openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "k.pem",
        "-out",
        "c.pem",
        "-subj",
        "/CN=macvpn-test",
        "-days",
        "1",
    ]));
    assert!(env.openssl(&["rsa", "-in", "k.pem", "-aes256", "-passout", "pass:x", "-out", "legacy.key"]));
    assert!(env.openssl(&["pkcs8", "-topk8", "-in", "k.pem", "-passout", "pass:x", "-out", "pkcs8.key"]));
    for name in ["legacy.key", "pkcs8.key"] {
        let prepared = importer::prepare("x.ovpn", &format!("remote a\nkey {name}\n"), &env.dir).unwrap();
        assert_eq!(prepared.inlined_files, [name], "{name}");
        assert!(prepared.config.contains("ENCRYPTED"), "{name}");
        assert_eq!(prepared.issues, [], "{name}");
    }
}

// MARK: MikroTik (importer part of MikroTikImportTests)

fn mikrotik(name: &str) -> String {
    fs::read_to_string(repo_root().join("Tests/Fixtures/mikrotik").join(name)).unwrap()
}

#[test]
fn routeros_exports_import_unchanged() {
    lang(AppLanguage::En);
    let env = Env::new();
    for name in [
        "routeros-v7-export-udp.ovpn",
        "routeros-v7-export-tcp.ovpn",
        "routeros-v7-export-tls-crypt.ovpn",
        "routeros-wiki-extras.ovpn",
        "routeros-v6-imported.ovpn",
    ] {
        let text = mikrotik(name);
        let prepared = importer::prepare(name, &text, &env.dir).unwrap();
        assert_eq!(prepared.issues, [], "{name}");
        assert_eq!(prepared.risky, [], "{name}");
        assert_eq!(prepared.config, text, "{name}");
    }
    assert!(importer::contains_encrypted_key(&mikrotik("routeros-v7-export-udp.ovpn")));
    assert!(importer::contains_encrypted_key(&mikrotik("routeros-v6-imported.ovpn")));
}

/// A real CA + client certificate and a password-encrypted key like the MikroTik export, in both forms.
fn make_router_files(env: &Env, legacy_key: bool) {
    assert!(env.openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-subj",
        "/CN=router-ca",
        "-days",
        "1",
    ]));
    assert!(env.openssl(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "plain.key",
        "-out",
        "client.csr",
        "-subj",
        "/CN=client1",
    ]));
    assert!(env.openssl(&[
        "x509",
        "-req",
        "-in",
        "client.csr",
        "-CA",
        "ca.crt",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "client.crt",
        "-days",
        "1",
    ]));
    if legacy_key {
        assert!(env.openssl(&[
            "rsa",
            "-in",
            "plain.key",
            "-aes256",
            "-passout",
            "pass:exportpass",
            "-out",
            "client.key"
        ]));
    } else {
        assert!(env.openssl(&[
            "pkcs8",
            "-topk8",
            "-in",
            "plain.key",
            "-v2",
            "aes-256-cbc",
            "-passout",
            "pass:exportpass",
            "-out",
            "client.key",
        ]));
    }
}

#[test]
fn routeros_v6_wiki_with_files_imports_cleanly() {
    lang(AppLanguage::En);
    for legacy in [false, true] {
        let env = Env::new();
        make_router_files(&env, legacy);
        env.put("auth.cfg", "vpnuser\nS3cret pass\n");
        let prepared = importer::prepare("router.ovpn", &mikrotik("routeros-v6-wiki.ovpn"), &env.dir).unwrap();
        assert_eq!(prepared.issues, [], "legacy: {legacy}");
        assert_eq!(prepared.risky, [], "legacy: {legacy}");
        assert_eq!(prepared.inlined_files, ["ca.crt", "client.crt", "client.key"]);
        assert!(prepared.has_encrypted_key);
        assert!(prepared.config.contains(if legacy {
            "Proc-Type: 4,ENCRYPTED"
        } else {
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        }));
        let c = &prepared.credentials;
        assert_eq!(c.username.as_deref(), Some("vpnuser"));
        assert_eq!(c.password.as_deref(), Some("S3cret pass"));
        assert_eq!(c.credentials_file.as_deref(), Some("auth.cfg"));
        assert!(c.unread_files.is_empty());
        assert!(!prepared.config.contains("S3cret"));
        assert!(!prepared.config.contains("auth.cfg"));
        assert!(prepared.config.contains("\nauth-user-pass\n"));
        assert_eq!(OpenVPNValidator.validate(&prepared.config), []);
    }
}

#[test]
fn credentials_file_rules() {
    let env = Env::new();
    let creds = |file: &str| {
        importer::prepare("x.ovpn", &format!("client\nremote a 1194\nauth-user-pass {file}\n"), &env.dir)
            .unwrap()
            .credentials
    };
    env.put("crlf.txt", "user\r\npass\r\n");
    assert_eq!(creds("crlf.txt").password.as_deref(), Some("pass"));
    env.put("three.txt", "a\nb\nc\n");
    env.put("one.txt", "a\n");
    env.put("big.txt", &format!("u\n{}\n", "p".repeat(2000)));
    env.put("ctrl.txt", "u\u{01}\np\n");
    for name in ["three.txt", "one.txt", "big.txt", "ctrl.txt", "missing.txt", "../outside.txt", "/etc/hosts"] {
        let c = creds(name);
        assert_eq!(c.username, None, "{name}");
        assert_eq!(c.unread_files, [name], "{name}");
    }
    let outside = env.root.join("outside.txt");
    fs::write(&outside, "u\np\n").unwrap();
    std::os::unix::fs::symlink(&outside, env.dir.join("link.txt")).unwrap();
    assert_eq!(creds("link.txt").unread_files, ["link.txt"]);
}

#[test]
fn askpass_file_goes_to_keychain_field() {
    let env = Env::new();
    env.put("pass.txt", "exportpass\n");
    let prepared = importer::prepare("x.ovpn", "client\nremote a 1194\naskpass pass.txt\n", &env.dir).unwrap();
    assert_eq!(prepared.credentials.key_password.as_deref(), Some("exportpass"));
    assert_eq!(prepared.credentials.key_password_file.as_deref(), Some("pass.txt"));
    assert!(prepared.config.contains("\naskpass\n"));
    assert!(!prepared.config.contains("pass.txt"));
    assert_eq!(prepared.issues, []);
}

/// SecurityReviewTests L5: the import is a pure function: it only returns candidates (the file names for the
/// confirmation), it stores nothing.
#[test]
fn credential_files_are_only_candidates() {
    let env = Env::new();
    env.put("auth.cfg", "u\np\n");
    env.put("pass.txt", "k\n");
    let prepared =
        importer::prepare("x.ovpn", "client\nremote a 1194\nauth-user-pass auth.cfg\naskpass pass.txt\n", &env.dir)
            .unwrap();
    assert_eq!(prepared.credentials.candidate_files(), ["auth.cfg", "pass.txt"]);
    assert_eq!(prepared.credentials.username.as_deref(), Some("u"));
    assert_eq!(prepared.credentials.key_password.as_deref(), Some("k"));
    assert!(importer::ImportedCredentials::default().candidate_files().is_empty());
}

// MARK: SSTP (SSTPTests.swift)

#[test]
fn sstp_import_detection() {
    let good = "# office\nserver=vpn.example.com\nport=4443\nuser=alice@corp.example\ncert=ca\nroute_all=no\npeer_dns=yes\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2E+/=\n-----END CERTIFICATE-----\n</ca>\n\n";
    assert_eq!(importer::kind("x.sstp", ""), Ok(VPNKind::Sstp));
    assert_eq!(importer::detect_kind("x.txt", good), Some(VPNKind::Sstp));
    assert_eq!(importer::detect_kind("x.txt", "server=a\nuser=b\n"), Some(VPNKind::Sstp));
    assert_eq!(importer::detect_kind("x.txt", "server = a\n"), None);
}
