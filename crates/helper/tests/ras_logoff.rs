//! Which RAS connections the WinVPN Service hangs up when a user logs off (crates/helper/src/windows/ras_logoff.rs):
//! pure, every OS.

use macvpn_helper::windows::ras_logoff::{Profile, RasConn, hang_up_line, owned_connections, to_hang_up};
use std::collections::HashSet;

const ALICE: &str = "S-1-5-21-1111-2222-3333-1001";
const BOB: &str = "S-1-5-21-1111-2222-3333-1002";
const ALICE_DIR: &str = r"C:\Users\alice";
const BOB_DIR: &str = r"C:\Users\Bob";
const E1: &str = "WinVPN-0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const E2: &str = "WinVPN-1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

fn conn<'a>(entry: &'a str, phonebook: &'a str) -> RasConn<'a> {
    RasConn { entry, phonebook }
}

#[test]
fn only_the_users_winvpn_phonebook_and_entry_names_are_owned() {
    let conns = [
        // 0: alice's own, as the app dials it.
        conn(E1, r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 1: letter case, `\\?\`, a forward slash and a doubled separator do not matter.
        conn(E2, r"\\?\c:\USERS\Alice\appdata/local\\winvpn\RAS\winvpn.PBK"),
        // 2: the user's own system VPN (default phonebook).
        conn("Work VPN", r"C:\Users\alice\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk"),
        // 3: a WinVPN-named entry in the default phonebook.
        conn(E1, r"C:\Users\alice\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk"),
        // 4: a look-alike file name.
        conn(E1, r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk.bak"),
        // 5: another profile.
        conn(E1, r"C:\Users\Bob\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 6: a profile whose name starts like alice's.
        conn(E1, r"C:\Users\alice2\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 7: `..` never counts, even when it would lead there.
        conn(E1, r"C:\Users\Bob\..\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 8: `.` neither.
        conn(E1, r"C:\Users\alice\.\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 9: not WinVPN's entry name (lower-case UUID, no prefix, a suffix).
        conn("WinVPN-0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        conn("Work VPN", r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        conn("WinVPN-0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0x", r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 12: a deeper folder of the profile.
        conn(E1, r"C:\Users\alice\x\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 13: a relative path.
        conn(E1, r"Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        // 14: an empty path.
        conn(E1, ""),
    ];
    assert_eq!(owned_connections(ALICE_DIR, &conns), vec![0, 1]);
    // The profile path itself is compared the same way.
    assert_eq!(owned_connections(r"\\?\C:\USERS\ALICE\", &conns), vec![0, 1]);
    // A profile path that is not a plain absolute path owns nothing.
    assert!(owned_connections(r"C:\Users\x\..\alice", &conns).is_empty());
    assert!(owned_connections("", &conns).is_empty());
    assert!(owned_connections(r"Users\alice", &conns).is_empty());
}

#[test]
fn non_ascii_profile_names_compare_without_regard_to_case() {
    let conns = [conn(E1, r"C:\Users\ÁRVÍZTŰRŐ\AppData\Local\WinVPN\ras\WinVPN.pbk")];
    assert_eq!(owned_connections(r"C:\Users\árvíztűrő", &conns), vec![0]);
    assert!(owned_connections(r"C:\Users\arvizturo", &conns).is_empty());
}

#[test]
fn only_users_without_a_session_lose_their_connections() {
    let profiles = [
        Profile { sid: ALICE, dir: ALICE_DIR },
        Profile { sid: BOB, dir: BOB_DIR },
        Profile { sid: "S-1-5-18", dir: r"C:\Windows\system32\config\systemprofile" },
    ];
    let conns = [
        conn(E1, r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        conn(E2, r"C:\Users\Bob\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        conn("Bob's VPN", r"C:\Users\Bob\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk"),
    ];
    let present = |sids: &[&str]| sids.iter().map(|s| s.to_string()).collect::<HashSet<String>>();
    // Bob logged off, alice is still there: only Bob's WinVPN connection, never his own system VPN.
    assert_eq!(to_hang_up(&profiles, &present(&[ALICE]), &conns), vec![1]);
    // Both still there (a locked or disconnected session counts): nothing.
    assert!(to_hang_up(&profiles, &present(&[ALICE, BOB]), &conns).is_empty());
    // Nobody left: both WinVPN connections.
    assert_eq!(to_hang_up(&profiles, &present(&[]), &conns), vec![0, 1]);
    // The session list's SIDs compare without regard to letter case.
    assert_eq!(to_hang_up(&profiles, &present(&[&ALICE.to_lowercase()]), &conns), vec![1]);
}

#[test]
fn a_profile_shared_with_a_present_user_is_never_hung_up() {
    // Windows keeps a `<SID>.bak` key next to a repaired profile, with the same path: not a SID, and a path that a
    // present user owns is never anyone else's.
    let profiles = [
        Profile { sid: ALICE, dir: ALICE_DIR },
        Profile { sid: &format!("{ALICE}.bak"), dir: ALICE_DIR },
        Profile { sid: BOB, dir: r"c:\users\ALICE" },
        Profile { sid: "not a sid", dir: BOB_DIR },
        Profile { sid: "S-1-5-21-1111-2222-3333-1003", dir: r"C:\Users\carol" },
    ];
    let conns = [
        conn(E1, r"C:\Users\alice\AppData\Local\WinVPN\ras\WinVPN.pbk"),
        conn(E2, r"C:\Users\Bob\AppData\Local\WinVPN\ras\WinVPN.pbk"),
    ];
    let present: HashSet<String> = HashSet::from([ALICE.to_string()]);
    assert!(to_hang_up(&profiles, &present, &conns).is_empty());
    // A connection two absent profiles own is listed once.
    let profiles =
        [Profile { sid: ALICE, dir: ALICE_DIR }, Profile { sid: "S-1-5-21-1111-2222-3333-1003", dir: ALICE_DIR }];
    assert_eq!(to_hang_up(&profiles, &HashSet::new(), &conns), vec![0]);
}

#[test]
fn the_log_line_names_only_the_entrys_first_eight_hex_digits() {
    assert_eq!(hang_up_line(E1, None), "RAS connection of a logged-off user ended: WinVPN-0F1E2D3C");
    assert_eq!(
        hang_up_line(E1, Some("RasHangUpW failed: 5")),
        "RAS connection of a logged-off user could not be ended: WinVPN-0F1E2D3C (RasHangUpW failed: 5)"
    );
}
