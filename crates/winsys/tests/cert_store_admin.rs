//! M-1 of the 2.0.0 security review, as an administrator (CI's `windows-admin` job, or the maintainer in an
//! elevated Git Bash; listed in `scripts/ignored-everywhere.txt`): the test CA enters the computer's Trusted Root
//! store with its enhanced key usage limited to server and client authentication, as WinVPN's elevated
//! `--winvpn-trust-ca-step` adds it, and is removed again.

#![cfg(windows)]

use macvpn_winsys::cert_store::{self, Added, Location, Presence};

/// The test CA of `crates/platform-win/tests/fixtures/ca/ca.pem` (DER).
const TEST_CA_DER: &[u8] = include_bytes!("fixtures/test-ca.der");
const TEST_CA_SHA1: [u8; 20] = [
    0x53, 0xcd, 0xc4, 0x17, 0xce, 0xda, 0x80, 0x00, 0xa2, 0xfc, 0xfd, 0x50, 0xeb, 0x98, 0xf4, 0xd8, 0x0c, 0x9c, 0xde,
    0x2f,
];
/// `SEQUENCE { serverAuth, clientAuth }`.
const TLS_ONLY: &[u8] = &[
    0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x03, 0x02,
];

#[test]
#[ignore = "admin: writes the computer's Trusted Root store"]
fn admin_a_ca_enters_the_machine_root_store_for_tls_only() {
    let (at, store) = (Location::LocalMachine, "Root");
    assert_eq!(cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(), Presence::Absent, "remove the test CA first");
    assert_eq!(cert_store::add_with_usage(at, store, TEST_CA_DER, TLS_ONLY).unwrap(), Added::New);
    let after = cert_store::presence(at, store, &TEST_CA_SHA1);
    let removed = cert_store::remove(at, store, &TEST_CA_SHA1);
    assert_eq!(after.unwrap(), Presence::Present { usage: Some(TLS_ONLY.to_vec()) });
    assert!(removed.unwrap());
    assert_eq!(cert_store::presence(at, store, &TEST_CA_SHA1).unwrap(), Presence::Absent);
}
