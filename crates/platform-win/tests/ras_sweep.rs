//! The sweep of WinVPN's RAS leftovers (WinVPN 2c Task 13): which entries and files belong to connections that no
//! longer exist. Pure, tested on every OS; the `RasEngine`'s `reconcile` over a real phonebook is in `ras_engine.rs`.

use macvpn_core::models::uuid_string;
use macvpn_platform_win::pure::ras_sweep::{file_connection, orphan_entries, orphan_files};
use std::collections::HashSet;
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xabcd_ef00_0000_4000_8000_0000_0000_0000 + n)
}

#[test]
fn only_winvpn_entries_of_unknown_connections_are_orphans() {
    let known: HashSet<Uuid> = [id(1)].into();
    let kept = format!("WinVPN-{}", uuid_string(&id(1)));
    let orphan = format!("WinVPN-{}", uuid_string(&id(2)));
    let lower = format!("WinVPN-{}", uuid_string(&id(3)).to_lowercase());
    let other_prefix = format!("winvpn-{}", uuid_string(&id(4)));
    let suffixed = format!("WinVPN-{} (2)", uuid_string(&id(5)));
    let names = [
        kept.as_str(),
        orphan.as_str(),
        orphan.as_str(),
        lower.as_str(),
        other_prefix.as_str(),
        suffixed.as_str(),
        "Office VPN",
        "WinVPN-",
        "WinVPN-test",
        "",
    ];
    assert_eq!(orphan_entries(names, &known), [id(2)]);
    // Nothing known (a locked vault must never get here): every WinVPN entry, still nothing else.
    assert_eq!(orphan_entries(names, &HashSet::new()), [id(1), id(2)]);
}

#[test]
fn only_files_winvpn_writes_are_orphans() {
    let up = uuid_string(&id(7));
    assert_eq!(file_connection(&format!("{up}.ras")), Some(id(7)));
    assert_eq!(file_connection(&format!("{up}.log")), Some(id(7)));
    assert_eq!(file_connection(&format!("{up}.log.1")), Some(id(7)));
    for name in [
        format!("{}.ras", up.to_lowercase()),
        format!("{up}.log.2"),
        format!("{up}.pbk"),
        format!("{up}.ras.tmp"),
        format!("x{up}.ras"),
        up.clone(),
        "WinVPN.pbk".to_string(),
        ".ras".to_string(),
    ] {
        assert_eq!(file_connection(&name), None, "{name}");
    }

    let known: HashSet<Uuid> = [id(1)].into();
    let files = [
        format!("{}.ras", uuid_string(&id(1))),
        format!("{}.log", uuid_string(&id(1))),
        format!("{}.ras", uuid_string(&id(2))),
        format!("{}.log", uuid_string(&id(2))),
        format!("{}.log.1", uuid_string(&id(3))),
        "WinVPN.pbk".to_string(),
        "notes.txt".to_string(),
    ];
    assert_eq!(orphan_files(files.iter().map(String::as_str), &known), [id(2), id(3)]);
}
