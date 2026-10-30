#![cfg(unix)]

use macvpn_unixsys::random;

#[test]
fn fills_large_buffers_and_differs() {
    let mut a = vec![0u8; 1000];
    let mut b = vec![0u8; 1000];
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert!(a.iter().any(|&x| x != 0));
    assert_ne!(random::random_32().unwrap(), random::random_32().unwrap());
}
