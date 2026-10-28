//! The `RasEngine` against the real RAS API (Windows only), as a standard user (WinVPN 2c Task 8). Every test
//! uses an engine over its own temp data directory (a private phonebook there), connections of its own (entries
//! `WinVPN-<UUID>`), and deletes them; the user's own phonebooks are never written. Dials go to 192.0.2.1
//! (TEST-NET-1, never answers) with dummy secrets.
//!
//! In a network logon (SSH) a process cannot see or release its own RAS connections (the RAS spike, Task 2), so
//! every test that dials is `#[ignore = "desktop: …"]` (listed in `scripts/ignored-everywhere.txt`) and runs at
//! the desktop: `cargo test -p macvpn-platform-win --test ras_engine -- --ignored`.

#![cfg(windows)]

use macvpn_core::models::{Connection, NativeSettings, Secrets, VPNKind};
use macvpn_core::ras::names;
use macvpn_core::ras::policy::{
    DhGroup, EspCipher, EspIntegrity, IkeCipher, IkeIntegrity, WINDOWS_DEFAULT_FOR_STRONGSWAN, WindowsPolicy,
};
use macvpn_platform_api::SystemVpn;
use macvpn_platform_win::{RasEngineForTests, ras_engine_for_tests, ras_engine_without_data_for_tests};
use macvpn_winsys::ras::{self as wras, Phonebook};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

const UNREACHABLE: &str = "192.0.2.1";
const PASSWORD: &str = "ras-engine-password-not-secret";
const PSK: &str = "ras-engine-psk-not-secret";

/// A fresh data directory under the temp folder; on drop every entry of its phonebook is cleared and deleted,
/// then the folder is removed.
struct TempData {
    dir: PathBuf,
}

impl TempData {
    fn new() -> TempData {
        let dir = std::env::temp_dir().join(format!("winvpn-ras-engine-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        TempData { dir }
    }

    fn engine(&self) -> RasEngineForTests {
        ras_engine_for_tests(&self.dir)
    }

    fn book(&self) -> Phonebook {
        Phonebook::at(self.dir.join("ras").join("WinVPN.pbk")).unwrap()
    }

    fn file_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap_or_default()
    }
}

impl Drop for TempData {
    fn drop(&mut self) {
        let book = self.book();
        for name in book.names().unwrap_or_default() {
            let _ = wras::clear_psk(&book, &name);
            let _ = book.delete(&name);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn l2tp(server: &str, all: bool) -> Connection {
    let mut c = Connection::new("Office VPN", VPNKind::L2tp);
    c.native = Some(NativeSettings {
        server: server.into(),
        account: "alice".into(),
        group_name: String::new(),
        send_all_traffic: all,
    });
    c
}

fn install(engine: &RasEngineForTests, c: &Connection) -> Result<(), String> {
    let profile = engine.profiles().build(c, PSK)?;
    engine.profiles().install(&c.id, &profile.data, &profile.file_name, false)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let utf16: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes()) || haystack.windows(utf16.len()).any(|w| w == utf16)
}

fn secrets() -> Secrets {
    Secrets {
        username: Some("alice".into()),
        password: Some(PASSWORD.into()),
        psk: Some(PSK.into()),
        ..Secrets::default()
    }
}

/// `child`: more lines of the child section (after its `remote_ts`).
fn eap_config(child: &str) -> String {
    format!(
        "connections {{\n  office {{\n    remote_addrs = {UNREACHABLE}\n    local {{\n      auth = eap-mschapv2\n      eap_id = alice\n    }}\n    remote {{\n      auth = pubkey\n      id = {UNREACHABLE}\n    }}\n    children {{\n      net {{\n        remote_ts = 10.0.0.0/8\n{child}      }}\n    }}\n  }}\n}}\n"
    )
}

fn sstp_config(cert: &str) -> String {
    format!("server={UNREACHABLE}\nport=443\nuser=alice\ncert={cert}\nroute_all=yes\npeer_dns=yes\n")
}

fn log_text(engine: &RasEngineForTests, id: &Uuid) -> String {
    String::from_utf8_lossy(&TempData::file_bytes(&engine.log_path(id))).into_owned()
}

/// fix 2.0.1: without WinVPN's data folder (no `%LOCALAPPDATA%`, no profile) the engine says so, not that the
/// native VPNs come in a later version.
#[test]
fn without_a_data_folder_the_engine_says_so() {
    let engine = ras_engine_without_data_for_tests();
    macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        let e = install(&engine, &l2tp(UNREACHABLE, true)).unwrap_err();
        assert_eq!(e, macvpn_platform_win::pure::texts::data_folder_missing());
        assert!(e.starts_with("WinVPN's data folder") && !e.contains("later"), "{e}");
        let up = engine.helper().up(
            VPNKind::Sstp,
            &Uuid::new_v4(),
            sstp_config("system").as_bytes(),
            &secrets(),
            false,
            &[],
        );
        assert_eq!(up.unwrap_err(), e);
    });
}

#[test]
fn saving_an_l2tp_connection_writes_its_entry() {
    let t = TempData::new();
    let engine = t.engine();
    let mut c = l2tp("vpn.example.com", true);
    install(&engine, &c).unwrap();
    let name = names::entry_name(&c.id);
    let book = t.book();
    let e = book.read(&name).unwrap();
    assert_eq!(e.strategy, wras::Strategy::L2tp);
    assert_eq!(e.server, "vpn.example.com");
    assert_eq!(e.auth, wras::Auth::MsChapV2 { psk: true });
    assert!(e.default_gateway_v4 && e.default_gateway_v6);
    assert_eq!(engine.phonebook(), t.dir.join("ras").join("WinVPN.pbk"));

    // Saved again with other settings: the entry is rewritten.
    c.native = Some(NativeSettings { server: "vpn2.example.com".into(), send_all_traffic: false, ..c.native.unwrap() });
    install(&engine, &c).unwrap();
    let e = book.read(&name).unwrap();
    assert_eq!(e.server, "vpn2.example.com");
    assert!(!e.default_gateway_v4 && !e.default_gateway_v6);

    // The PSK Windows keeps for it is never in a file WinVPN writes.
    wras::set_psk(&book, &name, PSK).unwrap();
    for file in [engine.phonebook(), t.dir.join("ras").join(format!("{}.ras", c.id.to_string().to_uppercase()))] {
        let bytes = TempData::file_bytes(&file);
        assert!(!bytes.is_empty(), "{}", file.display());
        assert!(!contains(&bytes, PSK) && !contains(&bytes, PASSWORD), "{}", file.display());
    }
}

#[test]
fn remove_deletes_the_entry_and_its_psk() {
    let t = TempData::new();
    let engine = t.engine();
    let c = l2tp("vpn.example.com", true);
    install(&engine, &c).unwrap();
    let name = names::entry_name(&c.id);
    let book = t.book();
    wras::set_psk(&book, &name, PSK).unwrap();
    assert!(wras::has_psk(&book, &name).unwrap());
    assert!(engine.profiles().removes_profiles());

    engine.profiles().remove(&c.id);
    assert!(book.read(&name).is_err());
    assert!(!book.names().unwrap_or_default().contains(&name));
    // Written again under the same name: no PSK survived.
    install(&engine, &c).unwrap();
    assert!(!wras::has_psk(&book, &name).unwrap());
    engine.profiles().remove(&c.id);
    assert!(!t.dir.join("ras").join(format!("{}.ras", c.id.to_string().to_uppercase())).exists());
    // Removing what is not there is fine.
    engine.profiles().remove(&c.id);
}

/// Task 13: the sweep after an unlock removes the `WinVPN-<UUID>` entries of connections the open vault no longer
/// has, with their stored PSK, profile and logs, and the profile/log files left without an entry; every other entry
/// and file of the folder stays. WinVPN installs without an approval step.
#[test]
fn reconcile_removes_only_orphaned_winvpn_entries() {
    let t = TempData::new();
    let engine = t.engine();
    assert!(!engine.profiles().needs_approval());
    let kept = l2tp("vpn.example.com", true);
    let orphan = l2tp("vpn2.example.com", false);
    install(&engine, &kept).unwrap();
    install(&engine, &orphan).unwrap();
    let book = t.book();
    let (kept_name, orphan_name) = (names::entry_name(&kept.id), names::entry_name(&orphan.id));
    wras::set_psk(&book, &kept_name, PSK).unwrap();
    wras::set_psk(&book, &orphan_name, PSK).unwrap();
    // Not WinVPN's names: never touched.
    // (RAS entry names ignore case, so a lower-case twin of a WinVPN name would be the same entry.)
    let similar = format!("WinVPN-{}-old", orphan.id);
    for name in ["Office", similar.as_str()] {
        let foreign = wras::Entry {
            name: name.into(),
            server: "vpn.example.com".into(),
            auth: wras::Auth::MsChapV2 { psk: true },
            ..wras::Entry::default()
        };
        book.write(&foreign).unwrap();
    }
    // A log left by a connection that has no entry any more, and a file of someone else.
    let gone = Uuid::new_v4();
    let gone_log = engine.log_path(&gone);
    std::fs::write(&gone_log, b"old log\n").unwrap();
    let other_file = t.dir.join("ras").join("notes.txt");
    std::fs::write(&other_file, b"keep me\n").unwrap();
    let profile = |c: &Connection| t.dir.join("ras").join(format!("{}.ras", c.id.to_string().to_uppercase()));
    assert!(profile(&orphan).is_file());

    engine.profiles().reconcile(&[kept.id].into());
    assert!(book.read(&orphan_name).is_err(), "the orphan's entry is deleted");
    assert!(!profile(&orphan).exists(), "its profile too");
    assert!(!gone_log.exists(), "a leftover log");
    assert!(book.read(&kept_name).is_ok() && wras::has_psk(&book, &kept_name).unwrap(), "the kept one is untouched");
    assert!(profile(&kept).is_file());
    assert!(book.read("Office").is_ok() && book.read(&similar).is_ok(), "other names stay");
    assert!(other_file.is_file());
    // Written again under the orphan's name: no PSK survived the sweep.
    install(&engine, &orphan).unwrap();
    assert!(!wras::has_psk(&book, &orphan_name).unwrap());

    // An install of an unchanged profile whose entry was deleted (by hand) writes the entry again.
    book.delete(&kept_name).unwrap();
    install(&engine, &kept).unwrap();
    assert_eq!(book.read(&kept_name).unwrap().server, "vpn.example.com");
    for name in ["Office", similar.as_str()] {
        book.delete(name).unwrap();
    }
}

#[test]
fn list_shows_managed_entries_with_their_ids() {
    let t = TempData::new();
    let engine = t.engine();
    assert_eq!(engine.controller().list().unwrap(), Vec::<SystemVpn>::new(), "no phonebook file: no entries");
    let c = l2tp("vpn.example.com", true);
    install(&engine, &c).unwrap();
    // Another name in the same phonebook is not WinVPN's.
    let book = t.book();
    let foreign = wras::Entry {
        name: "Office".into(),
        server: "vpn.example.com".into(),
        auth: wras::Auth::MsChapV2 { psk: true },
        ..wras::Entry::default()
    };
    book.write(&foreign).unwrap();

    let name = names::entry_name(&c.id);
    assert_eq!(engine.controller().list().unwrap(), vec![SystemVpn::new(&name, &name, "L2TP", "Disconnected")]);
    assert_eq!(engine.controller().managed_service_id(&c.id), Some(name.clone()));
    assert_eq!(engine.controller().remote_address(&name).as_deref(), Some("vpn.example.com"));
    assert_eq!(engine.controller().remote_address("Office"), None);
    // Not a `WinVPN-<UUID>` name: the user's own Windows VPNs answer (Task 9), which never list the private
    // phonebook: nothing is hung up or changed there.
    assert!(engine.controller().stop("Office").is_ok());
    assert!(engine.controller().start("Office", None, &Default::default()).unwrap_err().contains("no longer exists"));
    assert!(book.names().unwrap().contains(&"Office".to_string()), "never another entry");
    // Stopping a connection that is not up is fine.
    engine.controller().stop(&name).unwrap();
    book.delete("Office").unwrap();
    engine.profiles().remove(&c.id);
}

#[test]
fn a_cisco_connection_is_saved_but_gets_no_entry() {
    let t = TempData::new();
    let engine = t.engine();
    let mut c = l2tp("vpn.example.com", true);
    c.kind = VPNKind::Cisco;
    let err = install(&engine, &c).unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(engine.support().unsupported_reason(&c, b""), Some(err));
    assert!(t.book().names().unwrap_or_default().is_empty());
}

#[test]
fn an_unsupported_config_is_refused_before_dialling() {
    let t = TempData::new();
    let engine = t.engine();
    let helper = engine.helper();
    let id = Uuid::new_v4();
    let err = helper.up(VPNKind::Sstp, &id, sstp_config("insecure").as_bytes(), &secrets(), false, &[]).unwrap_err();
    let c = Connection::new("S", VPNKind::Sstp);
    assert_eq!(engine.support().unsupported_reason(&c, sstp_config("insecure").as_bytes()), Some(err));
    assert!(t.book().names().unwrap_or_default().is_empty(), "no entry written");
    assert!(!engine.log_path(&id).exists(), "nothing dialled, nothing logged");
    assert!(helper.status().is_err(), "no service and no RAS connection: the service's error as before");
}

#[test]
fn an_ikev2_psk_config_is_refused_before_dialling() {
    let t = TempData::new();
    let engine = t.engine();
    let config = eap_config("").replace("auth = eap-mschapv2", "auth = psk").replace("auth = pubkey", "auth = psk");
    let err = engine.helper().up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &secrets(), false, &[]);
    assert!(err.unwrap_err().contains("local auth = psk"));
    assert!(t.book().names().unwrap_or_default().is_empty());
}

#[test]
fn a_missing_psk_is_refused_before_dialling_and_logged() {
    let t = TempData::new();
    let engine = t.engine();
    let c = l2tp(UNREACHABLE, true);
    install(&engine, &c).unwrap();
    let name = names::entry_name(&c.id);
    let no_psk = Secrets { psk: None, ..secrets() };
    let err = engine.controller().start(&name, None, &no_psk).unwrap_err();
    assert!(err.contains("PSK"), "{err}");
    let log = log_text(&engine, &c.id);
    assert!(
        log.starts_with("═══ ") && log.contains(&format!(" up l2tp {} ═══", c.id.to_string().to_uppercase())),
        "{log}"
    );
    assert!(log.contains(&format!("✗ {err}")), "{log}");
    assert!(!log.contains(PASSWORD));
    // The Log tab reads the same file (G-2).
    let mut source = engine.controller().log_source(&c.id).unwrap();
    assert!(source.read(0, 4096).unwrap().data.starts_with("═══ ".as_bytes()));
    engine.profiles().remove(&c.id);
    assert!(!engine.log_path(&c.id).exists(), "the log goes with the connection");
}

/// "Clear Log…" of a RAS log (no dial holds it): the same file emptied with the note first, `.1` emptied too, through
/// the native controller (L2TP) and the helper (IKEv2 / SSTP read the RAS log when there is one).
#[test]
fn the_ras_log_is_cleared_in_place() {
    let t = TempData::new();
    let engine = t.engine();
    let c = l2tp(UNREACHABLE, true);
    install(&engine, &c).unwrap();
    let no_psk = Secrets { psk: None, ..secrets() };
    assert!(engine.controller().start(&names::entry_name(&c.id), None, &no_psk).is_err());
    let path = engine.log_path(&c.id);
    let rotated = path.with_extension("log.1");
    std::fs::write(&rotated, "older\n").unwrap();
    assert!(log_text(&engine, &c.id).starts_with("═══ "));
    assert_eq!(engine.controller().clear_log(&c.id, "═══ NOTE ═══"), Ok(true));
    assert_eq!(log_text(&engine, &c.id), "═══ NOTE ═══\n");
    assert_eq!(std::fs::read(&rotated).unwrap(), b"");
    assert_eq!(engine.helper().clear_log(&c.id, "═══ NOTE 2 ═══"), Ok(()));
    assert_eq!(log_text(&engine, &c.id), "═══ NOTE 2 ═══\n");
    engine.profiles().remove(&c.id);
}

#[test]
fn a_start_without_a_saved_profile_says_to_save_again() {
    let t = TempData::new();
    let engine = t.engine();
    let name = names::entry_name(&Uuid::new_v4());
    let err = engine.controller().start(&name, None, &secrets()).unwrap_err();
    assert!(err.contains("Windows VPN"), "{err}");
}

#[test]
fn the_ipsec_policy_is_written_as_microsofts_reference() {
    // ikev2_policy.pbk, ikev2_policy_gcm.pbk, ikev2_policy_3des.pbk (the RAS spike).
    assert_eq!(
        RasEngineForTests::policy_hex(&WINDOWS_DEFAULT_FOR_STRONGSWAN),
        "020000000400000003000000050000000200000000000000"
    );
    let gcm = WindowsPolicy {
        ike_cipher: IkeCipher::Aes256Gcm16,
        ike_integrity: IkeIntegrity::Sha384,
        dh_group: DhGroup::Ecp384,
        esp_cipher: EspCipher::Aes256Gcm16,
        esp_integrity: EspIntegrity::Gcm256,
        pfs: Some(DhGroup::Ecp384),
    };
    assert_eq!(RasEngineForTests::policy_hex(&gcm), "030000000600000005000000080000000500000005000000");
    let des = WindowsPolicy {
        ike_cipher: IkeCipher::TripleDes,
        ike_integrity: IkeIntegrity::Sha1,
        dh_group: DhGroup::Group2,
        esp_cipher: EspCipher::TripleDes,
        esp_integrity: EspIntegrity::Sha196,
        pfs: Some(DhGroup::Group14),
    };
    assert_eq!(RasEngineForTests::policy_hex(&des), "010000000100000002000000020000000100000003000000");
}

#[test]
fn an_unsafe_folder_is_refused() {
    let t = TempData::new();
    // A file where the phonebook folder belongs.
    std::fs::write(t.dir.join("ras"), b"not a folder").unwrap();
    let engine = t.engine();
    let err = engine.controller().start(&names::entry_name(&Uuid::new_v4()), None, &secrets()).unwrap_err();
    assert!(err.contains("not a private folder"), "{err}");
    assert_eq!(engine.controller().list().unwrap(), Vec::<SystemVpn>::new());
    std::fs::remove_file(t.dir.join("ras")).unwrap();
}

// ---- desktop only: dial and hang up ----

/// One dial at a time (a dial right after another can find the WAN Miniport port still busy: 633).
static DIALS: Mutex<()> = Mutex::new(());

fn settle() {
    std::thread::sleep(Duration::from_secs(2));
}

/// Polls `f` every 100 ms until it is `Some`, at most `limit`.
fn until<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn root_state(engine: &RasEngineForTests, id: &Uuid) -> Option<String> {
    engine.helper().status().ok()?.into_iter().find(|s| s.id == *id).map(|s| s.state)
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn an_ikev2_up_writes_the_entry_with_its_policy_and_dials() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempData::new();
    let engine = t.engine();
    let id = Uuid::new_v4();
    let config = eap_config("");
    let up = std::thread::scope(|s| {
        let up = s.spawn(|| engine.helper().up(VPNKind::Strongswan, &id, config.as_bytes(), &secrets(), true, &[]));
        let seen = until(Duration::from_secs(4), || root_state(&engine, &id).filter(|s| s == "connecting"));
        assert!(seen.is_some(), "connecting while the dial runs");
        up.join().unwrap()
    });
    let err = up.unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(root_state(&engine, &id).as_deref(), Some("failed"));
    let e = t.book().read(&names::entry_name(&id)).unwrap();
    assert_eq!(e.strategy, wras::Strategy::Ikev2);
    assert_eq!(e.auth, wras::Auth::EapMsChapV2);
    assert_eq!(e.policy.map(|p| p.to_hex()), Some(RasEngineForTests::policy_hex(&WINDOWS_DEFAULT_FOR_STRONGSWAN)));
    let log = log_text(&engine, &id);
    assert!(log.contains("(debug) ═══") && log.contains("✗ Windows error "), "{log}");
    assert!(!log.contains(PASSWORD), "{log}");
    engine.profiles().remove(&id);
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn warnings_are_logged() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempData::new();
    let engine = t.engine();
    let id = Uuid::new_v4();
    let config = eap_config("        dpd_action = restart\n");
    let _ = engine.helper().up(VPNKind::Strongswan, &id, config.as_bytes(), &secrets(), false, &[]);
    assert!(t.book().read(&names::entry_name(&id)).is_ok(), "the connection runs: its entry is written");
    let log = log_text(&engine, &id);
    assert!(log.contains("dpd_action = restart"), "{log}");
    engine.profiles().remove(&id);
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn an_sstp_up_and_down() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempData::new();
    let engine = t.engine();
    let id = Uuid::new_v4();
    let config = sstp_config("system");
    std::thread::scope(|s| {
        let up = s.spawn(|| engine.helper().up(VPNKind::Sstp, &id, config.as_bytes(), &secrets(), false, &[]));
        assert!(until(Duration::from_secs(5), || root_state(&engine, &id).filter(|s| s == "connecting")).is_some());
        std::thread::sleep(Duration::from_millis(500));
        engine.helper().down(VPNKind::Sstp, &id).unwrap();
        assert_eq!(up.join().unwrap(), Ok(()), "a hang-up during the dial is not a failure");
    });
    assert_eq!(root_state(&engine, &id), None, "disconnected");
    assert!(wras::connections().unwrap().iter().all(|c| c.entry != names::entry_name(&id)));
    let log = log_text(&engine, &id);
    assert!(log.trim_end().ends_with("Disconnected"), "{log}");
    engine.profiles().remove(&id);
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn a_relaunch_finds_a_running_dial() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let t = TempData::new();
    let first = t.engine();
    let id = Uuid::new_v4();
    let config = eap_config("");
    std::thread::scope(|s| {
        let up = s.spawn(|| first.helper().up(VPNKind::Strongswan, &id, config.as_bytes(), &secrets(), false, &[]));
        // A second engine over the same folder (the app after a relaunch) finds the dial by phonebook and name.
        let second = t.engine();
        let found = until(Duration::from_secs(4), || root_state(&second, &id).filter(|s| s == "connecting"));
        assert!(found.is_some(), "the relaunched engine sees the dial");
        let _ = up.join().unwrap();
    });
    first.profiles().remove(&id);
    settle();
}

#[test]
#[ignore = "desktop: RAS dials need an interactive logon session"]
fn only_our_phonebook_counts() {
    let _one = DIALS.lock().unwrap_or_else(|e| e.into_inner());
    let ours = TempData::new();
    let other = TempData::new();
    let engine = ours.engine();
    let id = Uuid::new_v4();
    let name = names::entry_name(&id);
    let entry = wras::Entry {
        name: name.clone(),
        strategy: wras::Strategy::Ikev2,
        server: UNREACHABLE.into(),
        auth: wras::Auth::MachineCertificate,
        ..wras::Entry::default()
    };
    // The same name in another phonebook, being dialled: not ours.
    std::fs::create_dir_all(other.dir.join("ras")).unwrap();
    let other_book = other.book();
    other_book.write(&entry).unwrap();
    let dial = wras::dial(&other_book, &name, &wras::DialParams::default(), |_| {}).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(engine.controller().list().unwrap().is_empty());
    assert_eq!(root_state(&engine, &id), None);
    dial.hang_up_and_wait(Duration::from_secs(10)).unwrap();
    settle();

    // Our phonebook dialled through an upper-cased path: ours.
    let _ = engine.controller().list();
    let book = ours.book();
    book.write(&entry).unwrap();
    let upper = Phonebook::at(PathBuf::from(engine.phonebook().to_string_lossy().to_uppercase())).unwrap();
    let dial = wras::dial(&upper, &name, &wras::DialParams::default(), |_| {}).unwrap();
    let listed = until(Duration::from_secs(4), || {
        engine.controller().list().ok()?.into_iter().find(|s| s.id == name && s.status == "Connecting")
    });
    assert!(listed.is_some(), "our own entry, dialled through another spelling of the path");
    engine.hang_up_all();
    assert!(wras::connections().unwrap().iter().all(|c| c.handle != dial.handle()));
    drop(dial);
    settle();
}
