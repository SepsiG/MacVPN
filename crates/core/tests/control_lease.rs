//! The control API's lease table: who holds which connection up, and when a lease end brings it down.

use macvpn_core::control::lease::*;

const A: &str = "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5B";
const B: &str = "6A1C1E0B-9F57-4D16-9E2A-7C0B3B6F4E21";

#[test]
fn one_holder_up_then_socket_close_disconnects() {
    let mut t = LeaseTable::new();
    assert!(!t.is_leased(A));
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    assert!(t.is_leased(A));
    assert_eq!(t.holders_of(A), [1]);
    assert_eq!(t.release_session(1), [(A.to_string(), LeaseAction::Disconnect)]);
    assert!(!t.is_leased(A));
    assert!(t.holders_of(A).is_empty());
}

#[test]
fn one_holder_down_disconnects() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    assert_eq!(t.release(A, 1), LeaseAction::Disconnect);
    assert!(!t.is_leased(A));
    // Releasing again, or a lease never held, does nothing.
    assert_eq!(t.release(A, 1), LeaseAction::None);
    assert_eq!(t.release(B, 7), LeaseAction::None);
}

#[test]
fn two_holders_disconnect_after_the_last() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    // The second holder finds it active (connecting) but it is ours, not pre-existing.
    assert_eq!(t.acquire(A, 2, true), LeaseAction::None);
    assert_eq!(t.holders_of(A), [1, 2]);
    assert_eq!(t.release(A, 1), LeaseAction::None);
    assert_eq!(t.holders_of(A), [2]);
    assert_eq!(t.release_session(2), [(A.to_string(), LeaseAction::Disconnect)]);
    assert!(!t.is_leased(A));
}

#[test]
fn preexisting_connection_is_never_disconnected() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, true), LeaseAction::None);
    assert_eq!(t.acquire(A, 2, true), LeaseAction::None);
    assert_eq!(t.release(A, 1), LeaseAction::None);
    assert_eq!(t.release(A, 2), LeaseAction::None);
    assert!(!t.is_leased(A));
    // Once the entry is gone, a new lease on a down connection starts it and owns it.
    assert_eq!(t.acquire(A, 3, false), LeaseAction::Connect);
    assert_eq!(t.release(A, 3), LeaseAction::Disconnect);
}

#[test]
fn manual_disconnect_clears_the_entry() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    assert_eq!(t.acquire(A, 2, true), LeaseAction::None);
    assert_eq!(t.acquire(B, 1, false), LeaseAction::Connect);
    assert_eq!(t.on_user_disconnect(A), [1, 2]);
    assert!(!t.is_leased(A));
    // The user won: a later release does not disconnect (again).
    assert_eq!(t.release(A, 1), LeaseAction::None);
    assert!(t.release_session(2).is_empty());
    // Other keys are untouched.
    assert_eq!(t.holders_of(B), [1]);
    assert!(t.on_user_disconnect(A).is_empty());
}

#[test]
fn drop_notifies_holders_and_clears_the_entry() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 5, false), LeaseAction::Connect);
    assert_eq!(t.acquire(A, 3, true), LeaseAction::None);
    assert_eq!(t.on_dropped(A), [3, 5]);
    assert!(!t.is_leased(A));
    assert_eq!(t.release(A, 5), LeaseAction::None);
    assert!(t.on_dropped(A).is_empty());
    assert!(t.on_dropped(B).is_empty());
}

#[test]
fn revoke_releases_all_of_a_sessions_keys() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    assert_eq!(t.acquire(B, 1, true), LeaseAction::None);
    assert_eq!(t.acquire(B, 2, true), LeaseAction::None);
    let mut released = t.release_session(1);
    released.sort();
    assert_eq!(released, [(A.to_string(), LeaseAction::Disconnect), (B.to_string(), LeaseAction::None)]);
    assert!(!t.is_leased(A));
    assert_eq!(t.holders_of(B), [2]);
    assert!(t.release_session(1).is_empty());
}

#[test]
fn same_session_acquiring_twice_is_idempotent() {
    let mut t = LeaseTable::new();
    assert_eq!(t.acquire(A, 1, false), LeaseAction::Connect);
    assert_eq!(t.acquire(A, 1, true), LeaseAction::None);
    assert_eq!(t.holders_of(A), [1]);
    assert_eq!(t.release(A, 1), LeaseAction::Disconnect);
    assert!(!t.is_leased(A));

    // On a pre-existing connection too: the flag is not lost.
    assert_eq!(t.acquire(B, 1, true), LeaseAction::None);
    assert_eq!(t.acquire(B, 1, false), LeaseAction::None);
    assert_eq!(t.release(B, 1), LeaseAction::None);
}
