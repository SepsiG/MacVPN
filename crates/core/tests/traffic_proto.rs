//! The service's `traffic <id>` answer and OpenVPN's `>BYTECOUNT` line.

use macvpn_core::traffic::{
    ByteCount, ChildCount, ChildSums, MAX_BYTES, MAX_CHILDREN, TRAFFIC, encode_children, parse_children,
};

#[test]
fn the_answer_round_trips_and_nothing_else_parses() {
    let b = ByteCount { rx: 12_400_000, tx: 0, run: 1_800_000_000 };
    assert_eq!(b.encode(), "bytes 12400000 0 1800000000\n");
    assert_eq!(ByteCount::parse(b.encode().as_bytes()), Some(b));
    let max = ByteCount { rx: u64::MAX, tx: u64::MAX, run: u64::MAX };
    assert_eq!(ByteCount::parse(max.encode().as_bytes()), Some(max));
    assert_eq!(TRAFFIC, "traffic");
    for bad in [
        "",
        "bytes 1 2 3",
        "bytes 1 2 3\n\n",
        "bytes 1 2\n",
        "bytes 1 2 3 4\n",
        "bytes 01 2 3\n",
        "bytes -1 2 3\n",
        "bytes 1  2 3\n",
        "bytes 18446744073709551616 2 3\n",
        "Usage: up|down …\n",
        "openvpn up\n",
    ] {
        assert_eq!(ByteCount::parse(bad.as_bytes()), None, "{bad:?}");
    }
    assert_eq!(ByteCount::parse(format!("bytes 1 2 {}\n", "9".repeat(MAX_BYTES)).as_bytes()), None);
}

#[test]
fn openvpns_bytecount_line() {
    assert_eq!(ByteCount::from_management(">BYTECOUNT:1024,2048\r", 7), Some(ByteCount { rx: 1024, tx: 2048, run: 7 }));
    assert_eq!(ByteCount::from_management(">BYTECOUNT:0,0", 7), Some(ByteCount { rx: 0, tx: 0, run: 7 }));
    for bad in [">BYTECOUNT:1", ">BYTECOUNT:a,2", ">BYTECOUNT_CLI:1,2,3", ">STATE:1,CONNECTED", ">BYTECOUNT:1,2,3"] {
        assert_eq!(ByteCount::from_management(bad, 7), None, "{bad}");
    }
}

fn c(id: u64, rx: u64, tx: u64) -> ChildCount {
    ChildCount { id, rx, tx }
}

#[test]
fn the_child_sa_answer_round_trips_and_nothing_else_parses() {
    let list = vec![c(3, 1000, 200), c(4, 0, 0)];
    assert_eq!(encode_children(&list), "strongswan 2\nchild 3 1000 200\nchild 4 0 0\n");
    assert_eq!(parse_children(encode_children(&list).as_bytes()), Some(list));
    assert_eq!(parse_children(b"strongswan 0\n"), Some(vec![]));
    let many: Vec<ChildCount> = (0..100).map(|i| c(i, i, i)).collect();
    assert_eq!(parse_children(encode_children(&many).as_bytes()).map(|v| v.len()), Some(MAX_CHILDREN));
    for bad in [
        "",
        "strongswan 1\n",
        "strongswan 1\nchild 1 2 3",
        "strongswan 1\nchild 1 2\n",
        "strongswan 1\nchild 1 2 3\nchild 2 3 4\n",
        "strongswan 65\n",
        "strongswan 1\nchild 01 2 3\n",
        "strongswan 1\nchild 1 2 3 c5d7a1b4\n",
        "wireguard 0\n",
        "bytes 1 2 3\n",
    ] {
        assert_eq!(parse_children(bad.as_bytes()), None, "{bad:?}");
    }
}

#[test]
fn the_sums_over_child_sas_never_go_down() {
    let mut s = ChildSums::default();
    assert_eq!(s.update(&[c(1, 1000, 100)]), (1000, 100));
    assert_eq!(s.update(&[c(1, 1500, 150)]), (1500, 150));
    // A rekey: the new CHILD_SA beside the old one for a moment, then alone.
    assert_eq!(s.update(&[c(1, 1600, 160), c(2, 10, 1)]), (1610, 161));
    assert_eq!(s.update(&[c(2, 50, 5)]), (1650, 165));
    // charon restarted and reused the number 2 with lower counters: counted whole.
    assert_eq!(s.update(&[c(2, 7, 7)]), (1657, 172));
    // Nothing reported (between SAs): the sums stay.
    assert_eq!(s.update(&[]), (1657, 172));
    assert_eq!(s.update(&[c(9, 3, 3)]), (1660, 175));
}
