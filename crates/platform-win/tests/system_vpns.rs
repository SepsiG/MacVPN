//! The user's own Windows VPNs as system VPNs and the live list's watch, against the real RAS API, as a standard
//! user. The listing tests use temp phonebooks standing in for Windows' default ones (`system_vpns_for_tests`);
//! nothing writes to the user's phonebooks, except the desktop test, which adds one throwaway entry
//! `WinVPN-test-system-<random>` to the user's default phonebook and always deletes it again.
//!
//! Dials need the interactive desktop session (the RAS spike: a network logon cannot see or hang up its own RAS
//! connection): those tests are `#[ignore = "desktop: …"]` and run at the desktop (`-- --ignored`).

#![cfg(windows)]

use macvpn_core::models::{Secrets, uuid_string};
use macvpn_platform_api::SystemVpn;
use macvpn_winsys::ras::{self, Auth, Entry, Phonebook, Strategy};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../winsys/tests/fixtures/ras/l2tp_psk.pbk");
const UNREACHABLE: &str = "192.0.2.1";

/// A fresh temp folder; on drop every entry of the phonebooks made in it is deleted, then the folder.
struct TempDir {
    dir: PathBuf,
    books: std::cell::RefCell<Vec<PathBuf>>,
}

impl TempDir {
    fn new() -> TempDir {
        let dir = std::env::temp_dir().join(format!("winvpn-sysvpn-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir { dir, books: Default::default() }
    }

    /// The phonebook `file` in `sub` (created).
    fn book(&self, sub: &str, file: &str) -> (PathBuf, Phonebook) {
        let dir = self.dir.join(sub);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(file);
        self.books.borrow_mut().push(path.clone());
        (path.clone(), Phonebook::at(path).unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        for path in self.books.borrow().iter() {
            let Ok(book) = Phonebook::at(path) else { continue };
            for name in book.names().unwrap_or_default() {
                let _ = ras::clear_psk(&book, &name);
                let _ = book.delete(&name);
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn test_name() -> String {
    format!("WinVPN-test-{}", Uuid::new_v4().to_string().to_uppercase())
}

fn entry(strategy: Strategy, auth: Auth, server: &str) -> Entry {
    Entry { name: test_name(), strategy, server: server.into(), auth, ..Entry::default() }
}

/// The ID a system entry must be listed with: its GUID as an upper-case UUID.
fn id_of(book: &Phonebook, name: &str) -> String {
    let guid = book.read(name).unwrap().guid.expect("Windows gives every entry a GUID");
    uuid_string(&Uuid::from_bytes(guid))
}

fn find<'a>(list: &'a [SystemVpn], name: &str) -> &'a SystemVpn {
    list.iter().find(|s| s.name == name).unwrap_or_else(|| panic!("{name} is not listed: {list:?}"))
}

#[test]
fn system_entries_are_listed_with_their_guid_and_label() {
    let t = TempDir::new();
    let (path, book) = t.book("user", "rasphone.pbk");
    let l2tp = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, "vpn.example.com");
    let ikev2 = entry(Strategy::Ikev2, Auth::EapMsChapV2, "ike.example.com");
    let sstp = entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "sstp.example.com:8443");
    for e in [&l2tp, &ikev2, &sstp] {
        book.write(e).unwrap();
    }
    // A PPTP entry (someone else's strategy): Microsoft's L2TP reference section with `VpnStrategy=1` appended to
    // the file as Settings would write it.
    let pptp = test_name();
    let section = std::fs::read_to_string(FIXTURE)
        .unwrap()
        .replace("[WinVPN-spike-1]", &format!("[{pptp}]"))
        .replace("VpnStrategy=3", "VpnStrategy=1")
        .replace("Guid=B43730CF120E33428A48B615EA72ACF0", "Guid=0F1E2D3C4B5A69788796A5B4C3D2E1F0");
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("\r\n");
    text.push_str(&section);
    std::fs::write(&path, text).unwrap();

    let vpns = macvpn_platform_win::system_vpns_for_tests(vec![path.clone()], None);
    let list = vpns.list().unwrap();
    assert_eq!(list.len(), 4, "{list:?}");
    for (e, label) in [(&l2tp.name, "L2TP"), (&ikev2.name, "IKEv2"), (&sstp.name, "SSTP"), (&pptp, "VPN")] {
        let s = find(&list, e);
        assert_eq!(s.type_label, label);
        assert_eq!(s.status, "Disconnected");
        assert_eq!(s.id, id_of(&book, e));
        assert!(s.secret_id().is_some());
    }
    assert!(find(&list, &l2tp.name).supports_stored_secrets());
    assert!(!find(&list, &sstp.name).supports_stored_secrets());
    // The server, as the manager's binding check reads it.
    let id = &find(&list, &sstp.name).id;
    assert_eq!(vpns.remote_address(id).as_deref(), Some("sstp.example.com:8443"));
    // Read-only: listing changed nothing (the file still has exactly these four sections).
    assert_eq!(book.names().unwrap().len(), 4);
}

#[test]
fn the_private_phonebook_is_not_a_system_vpn() {
    let t = TempDir::new();
    let (user_path, user) = t.book("user", "rasphone.pbk");
    let (private_path, private) = t.book("WinVPN-ras", "WinVPN.pbk");
    let own = entry(Strategy::L2tp, Auth::MsChapV2 { psk: false }, "vpn.example.com");
    let ours = Entry { name: format!("WinVPN-{}", uuid_string(&Uuid::new_v4())), ..own.clone() };
    user.write(&own).unwrap();
    private.write(&ours).unwrap();
    // The private path given in another letter case still counts (Windows' file names).
    let upper = PathBuf::from(private_path.to_string_lossy().to_uppercase());
    let vpns = macvpn_platform_win::system_vpns_for_tests(vec![user_path, private_path], Some(upper));
    let list = vpns.list().unwrap();
    assert_eq!(list.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec![own.name.as_str()]);
}

#[test]
fn a_stored_psk_is_written_only_when_windows_has_none() {
    let t = TempDir::new();
    let (path, book) = t.book("user", "rasphone.pbk");
    let l2tp = entry(Strategy::L2tp, Auth::MsChapV2 { psk: true }, "vpn.example.com");
    let sstp = entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "sstp.example.com");
    book.write(&l2tp).unwrap();
    book.write(&sstp).unwrap();
    let provide =
        |name: &str, psk: Option<&str>| macvpn_platform_win::system_vpn_provide_psk_for_tests(&path, name, psk);
    // Not an L2TP PSK entry, or nothing stored in WinVPN: nothing is written.
    assert_eq!(provide(&sstp.name, Some("winvpn-test-psk-a")), Ok(false));
    assert!(!ras::has_psk(&book, &sstp.name).unwrap());
    assert_eq!(provide(&l2tp.name, None), Ok(false));
    assert!(!ras::has_psk(&book, &l2tp.name).unwrap());
    // Windows has none: WinVPN's is stored.
    assert_eq!(provide(&l2tp.name, Some("winvpn-test-psk-a")), Ok(true));
    assert!(ras::has_psk(&book, &l2tp.name).unwrap());
    // Windows has one (the user's own): never overwritten.
    assert_eq!(provide(&l2tp.name, Some("winvpn-test-psk-b")), Ok(false));
    assert!(ras::has_psk(&book, &l2tp.name).unwrap());
    ras::clear_psk(&book, &l2tp.name).unwrap();
}

#[test]
fn the_ras_engine_lists_and_routes_the_users_own_vpns() {
    let t = TempDir::new();
    let (path, book) = t.book("user", "rasphone.pbk");
    let own = entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "sstp.example.com");
    book.write(&own).unwrap();
    let data = t.dir.join("data");
    let engine = macvpn_platform_win::ras_engine_with_system_books_for_tests(&data, vec![path]);
    let native = engine.controller();
    // No managed entry yet: only the user's VPN, with its GUID.
    let list = native.list().unwrap();
    assert_eq!(list, vec![SystemVpn::new(&id_of(&book, &own.name), &own.name, "SSTP", "Disconnected")]);
    // Every ID that is not a `WinVPN-<UUID>` entry name goes to the system VPNs.
    assert_eq!(native.remote_address(&list[0].id).as_deref(), Some("sstp.example.com"));
    assert!(native.stop(&list[0].id).is_ok());
    let gone = native.start(&uuid_string(&Uuid::new_v4()), None, &Secrets::default()).unwrap_err();
    assert!(gone.contains("no longer exists"), "{gone}");
    // A WinVPN connection binds to its own entry, never to a user's VPN by name.
    let c = Uuid::new_v4();
    assert_eq!(native.managed_service_id(&c), Some(format!("WinVPN-{}", uuid_string(&c))));
}

#[test]
fn a_vanished_vpn_is_refused_and_stopping_it_is_fine() {
    let t = TempDir::new();
    let (path, _) = t.book("user", "rasphone.pbk");
    let vpns = macvpn_platform_win::system_vpns_for_tests(vec![path], None);
    let id = uuid_string(&Uuid::new_v4());
    let e = vpns.start(&id, None, &Secrets::default()).unwrap_err();
    assert!(e.contains("no longer exists"), "{e}");
    assert!(vpns.stop(&id).is_ok());
    assert_eq!(vpns.remote_address(&id), None);
    // No phonebook file at all = no entries (Windows deletes it with its last entry).
    assert!(vpns.list().unwrap().is_empty());
}

#[test]
fn the_production_list_reads_windows_default_phonebooks() {
    // Read-only: whatever this user has (often nothing), never an error, never a WinVPN entry.
    let list = macvpn_platform_win::system_vpns_production_for_tests().list().unwrap();
    assert!(list.iter().all(|s| macvpn_core::ras::names::connection_id(&s.name).is_none()), "{list:?}");
    let folders = macvpn_platform_win::system_vpn_watch_folders_for_tests();
    assert_eq!(folders.len(), 3, "{folders:?}");
    assert!(folders.iter().all(|f| f.is_absolute()));
    assert!(folders[0].ends_with(r"Microsoft\Network\Connections\Pbk"));
    assert!(folders[1].ends_with(r"Microsoft\Network\Connections\Pbk"));
    assert!(folders[2].ends_with(r"WinVPN\ras"));
}

fn wait_for(count: &AtomicUsize, above: usize, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if count.load(Ordering::SeqCst) > above {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn the_watch_fires_for_a_new_entry() {
    let t = TempDir::new();
    let (_, user) = t.book("user", "rasphone.pbk");
    // A folder that does not exist yet (as `%ProgramData%\…\Pbk` on most PCs) is watched through its parent.
    let later_dir = t.dir.join("all-users").join("Pbk");
    let watch = macvpn_platform_win::system_vpn_watch_for_tests(vec![t.dir.join("user"), later_dir.clone()]);
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let guard = watch.start(Box::new(move || {
        seen.fetch_add(1, Ordering::SeqCst);
    }));
    let guard = guard.unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let before = count.load(Ordering::SeqCst);
    user.write(&entry(Strategy::Sstp, Auth::MsChapV2 { psk: false }, "vpn.example.com")).unwrap();
    assert!(wait_for(&count, before, Duration::from_secs(5)), "no change reported for a new entry");

    // The folder appears, then an entry in it.
    std::fs::create_dir_all(&later_dir).unwrap();
    let book = Phonebook::at(later_dir.join("rasphone.pbk")).unwrap();
    t.books.borrow_mut().push(later_dir.join("rasphone.pbk"));
    std::thread::sleep(Duration::from_millis(300));
    let before = count.load(Ordering::SeqCst);
    book.write(&entry(Strategy::L2tp, Auth::MsChapV2 { psk: false }, "vpn.example.com")).unwrap();
    assert!(wait_for(&count, before, Duration::from_secs(5)), "no change reported in the new folder");

    // Dropping the guard stops the watch.
    drop(guard);
    let after = count.load(Ordering::SeqCst);
    user.write(&entry(Strategy::L2tp, Auth::MsChapV2 { psk: false }, "vpn2.example.com")).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(count.load(Ordering::SeqCst), after);
}

/// The user's default phonebook (`%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk`).
fn default_phonebook() -> PathBuf {
    let roaming = std::env::var_os("APPDATA").map(PathBuf::from).expect("APPDATA");
    roaming.join("Microsoft").join("Network").join("Connections").join("Pbk").join("rasphone.pbk")
}

/// A throwaway entry in the user's default phonebook, deleted on drop (its file goes with the last entry).
struct ThrowawaySystemEntry {
    book: Phonebook,
    name: String,
}

impl ThrowawaySystemEntry {
    fn new(e: &Entry) -> ThrowawaySystemEntry {
        let path = default_phonebook();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let book = Phonebook::at(&path).unwrap();
        let name = format!("WinVPN-test-system-{}", &Uuid::new_v4().simple().to_string()[..12]);
        assert!(!book.names().unwrap_or_default().contains(&name));
        // The guard first: a failed write still deletes what it created.
        let guard = ThrowawaySystemEntry { book, name };
        let entry = Entry { name: guard.name.clone(), ..e.clone() };
        // Windows reads the default phonebook right after it changes (its file can be busy for a moment: 32).
        let mut tries = 0;
        while let Err(err) = guard.book.write(&entry) {
            tries += 1;
            assert!(err.code() == Some(32) && tries < 20, "{err:?}");
            std::thread::sleep(Duration::from_millis(250));
        }
        guard
    }
}

impl Drop for ThrowawaySystemEntry {
    fn drop(&mut self) {
        let _ = self.book.delete(&self.name);
    }
}

fn wait_status(
    vpns: &dyn macvpn_platform_api::NativeController,
    name: &str,
    want: &[&str],
    timeout: Duration,
) -> String {
    let start = Instant::now();
    loop {
        let list = vpns.list().unwrap();
        let status = list.iter().find(|s| s.name == name).map(|s| s.status.clone()).unwrap_or_default();
        if want.contains(&status.as_str()) || start.elapsed() > timeout {
            return status;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "desktop: RAS connections of an SSH logon cannot be seen or hung up"]
fn a_users_own_vpn_is_listed_dialled_and_hung_up() {
    // An IKEv2 computer-certificate entry needs no credentials (so no Windows window) and is listed at once.
    let e = ThrowawaySystemEntry::new(&entry(Strategy::Ikev2, Auth::MachineCertificate, UNREACHABLE));
    let vpns = macvpn_platform_win::system_vpns_production_for_tests();
    let list = vpns.list().unwrap();
    let s = find(&list, &e.name).clone();
    assert_eq!((s.type_label.as_str(), s.status.as_str()), ("IKEv2", "Disconnected"));
    assert_eq!(s.id, id_of(&e.book, &e.name));
    vpns.start(&s.id, None, &Secrets::default()).unwrap();
    let status = wait_status(vpns.as_ref(), &e.name, &["Connecting", "Connected"], Duration::from_secs(3));
    assert_eq!(status, "Connecting");
    // Found through the connection list (by GUID or name and phonebook), and hung up.
    vpns.stop(&s.id).unwrap();
    assert!(ras::connections().unwrap().iter().all(|c| c.entry != e.name));
    assert_eq!(wait_status(vpns.as_ref(), &e.name, &["Disconnected"], Duration::from_secs(3)), "Disconnected");
    // The entry is unchanged (WinVPN never edits a system VPN).
    let read = e.book.read(&e.name).unwrap();
    assert_eq!(
        (read.strategy, read.auth, read.server.as_str()),
        (Strategy::Ikev2, Auth::MachineCertificate, UNREACHABLE)
    );
    // RAS releases the WAN Miniport port a moment after the hang-up (633 otherwise for the next dial).
    std::thread::sleep(Duration::from_secs(2));
}
