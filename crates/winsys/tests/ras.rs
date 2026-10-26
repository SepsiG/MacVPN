//! `macvpn_winsys::ras` against the real RAS API (Windows only), as a standard user. Every test works in its own
//! private phonebook in a fresh temp folder, with throwaway `WinVPN-test-<uuid>` entries it deletes again; the
//! user's own phonebooks are only read. Dials go to 192.0.2.1 (TEST-NET-1, never answers) with dummy secrets.
//!
//! Dial / hang-up tests need the interactive desktop session (in a network logon, as over SSH, a process cannot
//! see or release its own RAS connection: the RAS spike, Task 2): they are `#[ignore = "desktop: …"]` and run at
//! the desktop (`cargo test -p macvpn-winsys --test ras -- --ignored`, e.g. from a one-shot scheduled task).

#![cfg(windows)]

use macvpn_winsys::ras::{
    self, Auth, AuthTransform, CipherTransform, DhGroup, DialEvent, DialParams, Encryption, Entry, Integrity,
    IpsecPolicy, PfsGroup, Phonebook, Strategy, Watcher,
};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ras");
const UNREACHABLE: &str = "192.0.2.1";
const DUMMY_PSK: &str = "winsys-test-psk-not-secret";

/// A fresh folder under the temp folder with the phonebook `t.pbk` in it. On drop every entry left in it is
/// cleared (PSK) and deleted, then the folder is removed.
struct TempBook {
    dir: PathBuf,
    book: Phonebook,
}

impl TempBook {
    fn new() -> TempBook {
        let dir = std::env::temp_dir().join(format!("winsys-ras-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let book = Phonebook::at(dir.join("t.pbk")).unwrap();
        TempBook { dir, book }
    }

    fn file(&self) -> PathBuf {
        self.dir.join("t.pbk")
    }

    /// The phonebook file as text (Windows writes it in ANSI; the tests' values are ASCII).
    fn text(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(self.file()).unwrap()).into_owned()
    }
}

impl Drop for TempBook {
    fn drop(&mut self) {
        for name in self.book.names().unwrap_or_default() {
            let _ = ras::clear_psk(&self.book, &name);
            let _ = self.book.delete(&name);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn test_name() -> String {
    format!("WinVPN-test-{}", uuid::Uuid::new_v4().to_string().to_uppercase())
}

fn entry(strategy: Strategy, auth: Auth, server: &str, full_tunnel: bool) -> Entry {
    Entry {
        name: test_name(),
        strategy,
        server: server.into(),
        auth,
        default_gateway_v4: full_tunnel,
        default_gateway_v6: full_tunnel,
        ..Entry::default()
    }
}

fn policy(d: [u32; 6]) -> IpsecPolicy {
    IpsecPolicy::from_dwords(d).unwrap()
}

/// The keys that differ between two entries of the same choices (the spike's list): the instance keys, and the
/// dialler-UI keys `Add-VpnConnection` sets and WinVPN leaves off.
const INSTANCE_KEYS: &[&str] = &[
    "Guid",
    "DialParamsUID",
    "LowDateTime",
    "HighDateTime",
    "PreviewUserPw",
    "PreviewDomain",
    "ShowDialingProgress",
    "ShowMonitorIconInTaskBar",
    "PowershellCreatedProfile",
];

/// The lines of the section `[name]` in a phonebook text (the first section when `name` is `None`), without blank
/// lines, the instance keys' values replaced by `*`, sorted (Windows appends keys written with
/// `WritePrivateProfileStringW` at the end of the section; the position does not matter).
fn section(text: &str, name: Option<&str>) -> Vec<String> {
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    let header = lines
        .by_ref()
        .find(|l| l.starts_with('[') && name.is_none_or(|n| *l == format!("[{n}]")))
        .unwrap_or_else(|| panic!("no section {name:?}"));
    assert!(header.ends_with(']'));
    let mut out: Vec<String> = lines
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_once('=') {
            Some((k, _)) if INSTANCE_KEYS.contains(&k) => format!("{k}=*"),
            _ => l.to_string(),
        })
        .collect();
    out.sort();
    out
}

/// Windows Server (`InstallationType` `Server` or `Server Core`; GitHub's runners), not a client edition.
fn windows_server() -> bool {
    static SERVER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SERVER.get_or_init(read_windows_server)
}

fn read_windows_server() -> bool {
    let out = std::process::Command::new(r"C:\Windows\System32\reg.exe")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "/v", "InstallationType"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let value = text.lines().find_map(|l| l.split("REG_SZ").nth(1)).expect("InstallationType").trim().to_string();
    value.starts_with("Server")
}

/// [`section`] of an entry WinVPN wrote, compared with a reference of Windows 11 (the spike's machine). One key is
/// the edition's default, not WinVPN's: `IpDnsFlags` ("Register this connection's addresses in DNS"). WinVPN never
/// sets `RASEO2_RegisterIpWithDNS` (as the references leave it off); Windows 11 then writes `IpDnsFlags=0`, Windows
/// Server writes `IpDnsFlags=1` (seen on GitHub's windows-latest, Server 2025 build 26100: the only difference from
/// the references). It decides only whether Windows registers the VPN address in DNS (no authentication,
/// encryption, PSK or IPsec policy key), so on Server the edition's value is taken as the reference's; on a client
/// edition every key must match.
fn written_section(text: &str, name: &str) -> Vec<String> {
    let mut lines = section(text, Some(name));
    if windows_server() {
        for l in &mut lines {
            if l == "IpDnsFlags=1" {
                *l = "IpDnsFlags=0".to_string();
            }
        }
    }
    lines
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURES).join(format!("{name}.pbk"))).unwrap()
}

/// The choices of each reference entry (`docs/superpowers/spikes/2026-10-25-winvpn-ras.md`, section 1).
fn reference_cases() -> Vec<(&'static str, Entry)> {
    let srv = "vpn.example.com";
    let l2tp = Auth::MsChapV2 { psk: true };
    let ppp = Auth::MsChapV2 { psk: false };
    let with_policy = |d| Entry { policy: Some(policy(d)), ..entry(Strategy::Ikev2, Auth::EapMsChapV2, srv, true) };
    vec![
        ("l2tp_psk", entry(Strategy::L2tp, l2tp, srv, true)),
        ("l2tp_psk_split", entry(Strategy::L2tp, l2tp, srv, false)),
        ("sstp", entry(Strategy::Sstp, ppp, srv, true)),
        ("sstp_split", entry(Strategy::Sstp, ppp, srv, false)),
        ("sstp_port", entry(Strategy::Sstp, ppp, "vpn.example.com:8443", true)),
        ("ikev2_eap", entry(Strategy::Ikev2, Auth::EapMsChapV2, srv, true)),
        ("ikev2_eap_split", entry(Strategy::Ikev2, Auth::EapMsChapV2, srv, false)),
        ("ikev2_machinecert", entry(Strategy::Ikev2, Auth::MachineCertificate, srv, true)),
        ("ikev2_policy", with_policy([2, 4, 3, 5, 2, 0])),
        ("ikev2_policy_gcm", with_policy([3, 6, 5, 8, 5, 5])),
        ("ikev2_policy_3des", with_policy([1, 1, 2, 2, 1, 3])),
    ]
}

#[test]
fn an_entry_is_written_read_back_and_deleted() {
    let t = TempBook::new();
    assert_eq!(t.book.names().unwrap(), Vec::<String>::new(), "no file yet: no entries");
    let e = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, "vpn.example.com", true);
    t.book.write(&e).unwrap();
    let back = t.book.read(&e.name).unwrap();
    assert!(back.guid.is_some());
    assert_eq!(Entry { guid: None, ..back.clone() }, e);
    assert_eq!(t.book.names().unwrap(), vec![e.name.clone()]);
    let listed = t.book.entries().unwrap();
    assert!(listed[0].phonebook.to_string_lossy().eq_ignore_ascii_case(&t.file().to_string_lossy()), "{listed:?}");

    // A rewrite keeps the entry's GUID.
    let split = Entry { default_gateway_v4: false, default_gateway_v6: false, ..e.clone() };
    t.book.write(&split).unwrap();
    let again = t.book.read(&e.name).unwrap();
    assert_eq!(again.guid, back.guid);
    assert!(!again.default_gateway_v4 && !again.default_gateway_v6);

    // Every field read back as written, for each kind.
    for (_, mut e) in reference_cases() {
        e.ts_as_routes = e.strategy == Strategy::Ikev2 && !e.default_gateway_v4;
        e.ike_fragmentation = e.strategy != Strategy::Ikev2;
        e.interface_metric = (e.strategy == Strategy::Sstp).then_some(9000);
        t.book.write(&e).unwrap();
        assert_eq!(Entry { guid: None, ..t.book.read(&e.name).unwrap() }, e);
    }

    for name in t.book.names().unwrap() {
        t.book.delete(&name).unwrap();
    }
    assert_eq!(t.book.read(&e.name).unwrap_err().code(), Some(ras::ERROR_CANNOT_FIND_PHONEBOOK_ENTRY));
    // Windows deletes the phonebook file with its last entry.
    assert!(!t.file().exists());
    assert_eq!(t.book.names().unwrap(), Vec::<String>::new());
}

/// Security review L-8: the server becomes the phonebook's `PhoneNumber=` line; a control character (CR/LF would
/// add keys to the section) is refused before RAS sees it, whatever core checked.
#[test]
fn a_server_with_a_control_character_is_never_written() {
    let t = TempBook::new();
    for server in ["vpn.example.com\r\nDevice=evil", "vpn\nx", "vpn\u{1}x", "vpn\u{7f}x", "vpn\u{85}x", "a\u{2028}b"] {
        let e = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, server, true);
        let err = t.book.write(&e).unwrap_err();
        assert!(err.to_string().contains("control character"), "{server:?}: {err}");
        assert!(t.book.read(&e.name).is_err(), "{server:?}");
    }
    assert!(!t.file().exists() || !t.text().contains("evil"));
}

#[test]
fn the_written_sections_match_microsofts_reference() {
    let t = TempBook::new();
    for (name, e) in reference_cases() {
        t.book.write(&e).unwrap();
        assert_eq!(written_section(&t.text(), &e.name), section(&fixture(name), None), "{name}");
    }
}

#[test]
fn a_rewrite_replaces_the_eap_data_and_the_policy_keys() {
    let t = TempBook::new();
    let eap = Entry {
        policy: Some(policy([2, 4, 3, 5, 2, 0])),
        ..entry(Strategy::Ikev2, Auth::EapMsChapV2, "vpn.example.com", true)
    };
    t.book.write(&eap).unwrap();
    assert!(t.text().contains("CustomIPSecPolicies="));
    let cert = Entry { auth: Auth::MachineCertificate, policy: None, ..eap.clone() };
    t.book.write(&cert).unwrap();
    assert_eq!(written_section(&t.text(), &cert.name), section(&fixture("ikev2_machinecert"), None));
    assert_eq!(ras::custom_policy(&t.book, &cert.name).unwrap(), None);
}

#[test]
fn the_policy_keys_are_written_read_back_and_survive_a_rewrite() {
    let t = TempBook::new();
    let e = entry(Strategy::Ikev2, Auth::EapMsChapV2, "vpn.example.com", true);
    t.book.write(&e).unwrap();
    assert_eq!(ras::custom_policy(&t.book, &e.name).unwrap(), None);
    let p = policy([3, 6, 5, 8, 5, 5]);
    ras::set_custom_policy(&t.book, &e.name, Some(&p)).unwrap();
    assert_eq!(ras::custom_policy(&t.book, &e.name).unwrap(), Some(p));
    assert!(t.text().contains("CustomIPSecPolicies=030000000600000005000000080000000500000005000000"));
    // RasSetEntryPropertiesW alone keeps the keys (the spike); `write` sets them from the entry every time.
    t.book.write(&Entry { policy: Some(p), ..e.clone() }).unwrap();
    assert_eq!(t.book.read(&e.name).unwrap().policy, Some(p));
    ras::set_custom_policy(&t.book, &e.name, None).unwrap();
    assert!(t.text().contains("NumCustomPolicy=0"));
    assert!(!t.text().contains("CustomIPSecPolicies"));
    // No stray section for an entry that does not exist.
    assert!(ras::set_custom_policy(&t.book, &test_name(), Some(&p)).is_err());
    assert_eq!(t.book.names().unwrap(), vec![e.name.clone()]);
}

#[test]
fn the_policy_values_are_the_vpnclient_numbers() {
    let cases = [
        (
            "ikev2_policy",
            IpsecPolicy {
                integrity: Integrity::Sha256,
                encryption: Encryption::Aes256,
                dh_group: DhGroup::Group14,
                cipher_transform: CipherTransform::Aes256,
                auth_transform: AuthTransform::Sha256128,
                pfs_group: PfsGroup::None,
            },
        ),
        (
            "ikev2_policy_gcm",
            IpsecPolicy {
                integrity: Integrity::Sha384,
                encryption: Encryption::GcmAes256,
                dh_group: DhGroup::Ecp384,
                cipher_transform: CipherTransform::GcmAes256,
                auth_transform: AuthTransform::GcmAes256,
                pfs_group: PfsGroup::Ecp384,
            },
        ),
        (
            "ikev2_policy_3des",
            IpsecPolicy {
                integrity: Integrity::Sha1,
                encryption: Encryption::Des3,
                dh_group: DhGroup::Group2,
                cipher_transform: CipherTransform::Des3,
                auth_transform: AuthTransform::Sha196,
                pfs_group: PfsGroup::Pfs2048,
            },
        ),
    ];
    for (name, p) in cases {
        let text = fixture(name);
        let hex = text.lines().find_map(|l| l.trim_end().strip_prefix("CustomIPSecPolicies=")).unwrap();
        assert_eq!(p.to_hex(), hex, "{name}");
        assert_eq!(IpsecPolicy::from_hex(hex), Some(p), "{name}");
        assert_eq!(IpsecPolicy::from_hex(&hex.to_lowercase()), Some(p), "{name}");
    }
    assert_eq!(IpsecPolicy::from_hex("02000000"), None);
    assert_eq!(IpsecPolicy::from_dwords([9, 4, 3, 5, 2, 0]), None);
}

#[test]
fn names_are_validated_by_windows() {
    let t = TempBook::new();
    let e = entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "vpn.example.com", true);
    ras::validate_name(&t.book, &e.name).unwrap();
    t.book.write(&e).unwrap();
    // An existing entry's name is a valid name too.
    ras::validate_name(&t.book, &e.name).unwrap();
    assert!(ras::validate_name(&t.book, "").is_err());
    assert!(ras::validate_name(&t.book, "bad\\name").is_err());
    assert!(ras::validate_name(&t.book, "bad]name").is_err());
}

#[test]
fn bad_values_are_refused_before_any_call() {
    let t = TempBook::new();
    let ok = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, "vpn.example.com", true);
    let refused = [
        Entry { name: String::new(), ..ok.clone() },
        Entry { name: "a]b".into(), ..ok.clone() },
        Entry { name: "a\nb".into(), ..ok.clone() },
        Entry { name: "x".repeat(257), ..ok.clone() },
        Entry { server: String::new(), ..ok.clone() },
        Entry { server: "s".repeat(129), ..ok.clone() },
        Entry { server: "a\0b".into(), ..ok.clone() },
        Entry { auth: Auth::EapMsChapV2, ..ok.clone() },
        Entry { strategy: Strategy::Sstp, ..ok.clone() },
        Entry { strategy: Strategy::Ikev2, ..ok.clone() },
        Entry { strategy: Strategy::Other(0), ..ok.clone() },
        Entry { ts_as_routes: true, ..ok.clone() },
        Entry { ike_fragmentation: false, ..ok.clone() },
        Entry { policy: Some(policy([2, 4, 3, 5, 2, 0])), ..ok.clone() },
    ];
    for e in refused {
        assert!(matches!(t.book.write(&e), Err(ras::Error::Invalid(_))), "{e:?}");
    }
    assert!(!t.file().exists(), "nothing was written");
    // The system phonebooks are read-only here.
    let system = Phonebook::system();
    assert!(matches!(system.write(&ok), Err(ras::Error::Invalid(_))));
    assert!(matches!(system.delete(&ok.name), Err(ras::Error::Invalid(_))));
    assert!(matches!(ras::set_psk(&system, &ok.name, DUMMY_PSK), Err(ras::Error::Invalid(_))));
    assert!(matches!(ras::set_custom_policy(&system, &ok.name, None), Err(ras::Error::Invalid(_))));
    assert!(Phonebook::at("relative\\t.pbk").is_err());
    assert!(Phonebook::at("C:/forward/t.pbk").is_err());
}

#[test]
fn a_psk_is_stored_kept_and_cleared() {
    let t = TempBook::new();
    let e = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, "vpn.example.com", true);
    t.book.write(&e).unwrap();
    assert!(!ras::has_psk(&t.book, &e.name).unwrap());
    ras::set_psk(&t.book, &e.name, DUMMY_PSK).unwrap();
    assert!(ras::has_psk(&t.book, &e.name).unwrap());
    // Never in the phonebook file (ANSI or UTF-16).
    let bytes = std::fs::read(t.file()).unwrap();
    let utf16: Vec<u8> = DUMMY_PSK.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!bytes.windows(DUMMY_PSK.len()).any(|w| w == DUMMY_PSK.as_bytes()));
    assert!(!bytes.windows(utf16.len()).any(|w| w == utf16.as_slice()));
    // A rewrite keeps it.
    t.book.write(&e).unwrap();
    assert!(ras::has_psk(&t.book, &e.name).unwrap());
    ras::clear_psk(&t.book, &e.name).unwrap();
    assert!(!ras::has_psk(&t.book, &e.name).unwrap());
    // Delete and re-create the same name: no PSK.
    ras::set_psk(&t.book, &e.name, DUMMY_PSK).unwrap();
    t.book.delete(&e.name).unwrap();
    t.book.write(&e).unwrap();
    assert!(!ras::has_psk(&t.book, &e.name).unwrap());
    assert!(ras::set_psk(&t.book, &e.name, "").is_err());
    assert!(ras::set_psk(&t.book, &e.name, &"k".repeat(257)).is_err());
}

#[test]
fn a_new_entry_has_no_saved_credentials_and_is_not_dialled_without_a_password() {
    let t = TempBook::new();
    let e = entry(Strategy::L2tp, Auth::MsChapV2 { psk: false }, UNREACHABLE, true);
    t.book.write(&e).unwrap();
    let saved = ras::saved_credentials(&t.book, &e.name).unwrap();
    assert_eq!(saved, ras::Saved::default());
    // Nothing saved and no password given: nothing is dialled (also over SSH).
    assert!(ras::dial_saved(&t.book, &e.name, None, |_| {}).unwrap().is_none());
    assert_eq!(
        ras::saved_credentials(&t.book, "WinVPN-test-missing").unwrap_err().code(),
        Some(ras::ERROR_CANNOT_FIND_PHONEBOOK_ENTRY)
    );
    assert!(ras::saved_credentials(&t.book, "bad]name").is_err());
}

#[test]
fn the_watcher_fires_on_a_phonebook_change_and_stops() {
    let t = TempBook::new();
    let later = t.dir.join("later").join("Pbk");
    let (tx, rx) = mpsc::channel();
    let watcher = Watcher::start(&[t.dir.clone(), later.clone()], move || {
        let _ = tx.send(());
    })
    .unwrap();
    let drain = |rx: &mpsc::Receiver<()>| while rx.recv_timeout(Duration::from_millis(300)).is_ok() {};

    t.book.write(&entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "vpn.example.com", true)).unwrap();
    rx.recv_timeout(Duration::from_secs(5)).expect("a call after the phonebook changed");
    drain(&rx);

    // A folder that did not exist is taken over once it does (through its ancestors).
    std::fs::create_dir(t.dir.join("later")).unwrap();
    std::fs::create_dir(&later).unwrap();
    drain(&rx);
    std::fs::write(later.join("rasphone.pbk"), b"").unwrap();
    rx.recv_timeout(Duration::from_secs(5)).expect("a call after a file appeared in the new folder");

    drop(watcher);
    drain(&rx);
    std::fs::write(later.join("other.pbk"), b"").unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_err(), "no call after the watcher stopped");
}

#[test]
fn the_system_phonebooks_do_not_list_private_entries() {
    let t = TempBook::new();
    let e = entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "vpn.example.com", true);
    t.book.write(&e).unwrap();
    let system = ras::system_entries().unwrap();
    assert!(system.iter().all(|s| s.name != e.name), "{system:?}");
    // Each listed entry reads from its own phonebook (only read: the user's entries are never changed).
    for s in system.iter().take(3) {
        Phonebook::at(&s.phonebook).unwrap().read(&s.name).unwrap();
    }
}

#[test]
fn the_connection_list_and_error_texts_answer_without_a_dial() {
    let conns = ras::connections().unwrap();
    assert!(conns.iter().all(|c| !c.entry.starts_with("WinVPN-test-")), "{conns:?}");
    for code in [691u32, 789, 628, 0x8007_274C, 0x8000_4005, 5] {
        let text = ras::error_text(code);
        assert!(!text.is_empty() && !text.contains("os error"), "{code}: {text}");
    }
    assert!(!format!("{:?}", DialParams::user("alice", "not-a-secret")).contains("not-a-secret"));
}

// ---- desktop only: dial and hang up ----

/// One dial at a time (a dial right after another can find the WAN Miniport port still busy: 633).
static DIALS: Mutex<()> = Mutex::new(());

/// Dials `e` and collects its events; `Arc` so the test can also read them while the dial runs.
fn dial(t: &TempBook, e: &Entry) -> (ras::Dial, mpsc::Receiver<DialEvent>) {
    let (tx, rx) = mpsc::channel();
    let tx = Arc::new(Mutex::new(tx));
    let d = ras::dial(&t.book, &e.name, &DialParams::user("winsys-test", "winsys-password-not-secret"), move |ev| {
        let _ = tx.lock().unwrap().send(ev);
    })
    .unwrap();
    (d, rx)
}

fn wait_until_final(rx: &mpsc::Receiver<DialEvent>, timeout: Duration) -> DialEvent {
    let start = Instant::now();
    loop {
        let left = timeout.checked_sub(start.elapsed()).expect("no final dial event in time");
        let ev = rx.recv_timeout(left).expect("no final dial event in time");
        if matches!(ev, DialEvent::Connected | DialEvent::Failed { .. }) {
            return ev;
        }
    }
}

fn settle() {
    std::thread::sleep(Duration::from_secs(2));
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn a_dial_to_test_net_fails_and_releases_its_handle() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempBook::new();
    let e = entry(Strategy::Ikev2, Auth::EapMsChapV2, UNREACHABLE, true);
    t.book.write(&e).unwrap();
    let (d, rx) = dial(&t, &e);
    let last = wait_until_final(&rx, Duration::from_secs(90));
    assert!(matches!(last, DialEvent::Failed { code } if code != 0), "{last:?}");
    d.hang_up_and_wait(Duration::from_secs(10)).unwrap();
    assert_eq!(ras::status(d.handle()).unwrap_err().code(), Some(ras::ERROR_INVALID_HANDLE));
    assert!(ras::connections().unwrap().iter().all(|c| c.entry != e.name));
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn hanging_up_during_a_dial_ends_it() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempBook::new();
    let e = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, UNREACHABLE, true);
    t.book.write(&e).unwrap();
    ras::set_psk(&t.book, &e.name, DUMMY_PSK).unwrap();
    let (d, rx) = dial(&t, &e);
    let first = rx.recv_timeout(Duration::from_secs(10)).expect("a first dial event");
    assert!(matches!(first, DialEvent::State(_)), "{first:?}");
    d.hang_up_and_wait(Duration::from_secs(10)).unwrap();
    assert!(ras::connections().unwrap().iter().all(|c| c.entry != e.name));
    ras::clear_psk(&t.book, &e.name).unwrap();
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn a_dialling_connection_is_listed_with_its_phonebook() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempBook::new();
    let e = entry(Strategy::Ikev2, Auth::MachineCertificate, UNREACHABLE, true);
    t.book.write(&e).unwrap();
    let (d, rx) = dial(&t, &e);
    std::thread::sleep(Duration::from_millis(1500));
    let conns = ras::connections().unwrap();
    let ours = conns.iter().find(|c| c.entry == e.name).unwrap_or_else(|| panic!("not listed: {conns:?}"));
    assert_eq!(ours.handle, d.handle());
    assert!(ours.phonebook.to_string_lossy().eq_ignore_ascii_case(&t.file().to_string_lossy()), "{ours:?}");
    assert_eq!(Some(ours.entry_guid), t.book.read(&e.name).unwrap().guid);
    assert!(ras::status(d.handle()).is_ok());
    assert_eq!(ras::ipv4(d.handle()).ok().flatten(), None);
    d.hang_up_and_wait(Duration::from_secs(10)).unwrap();
    drop(rx);
    settle();
}
