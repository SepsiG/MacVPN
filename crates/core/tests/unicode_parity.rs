//! Swift `String` semantics in the validators (grapheme clusters, canonical equivalence, Character-based
//! regex matching). Expected results are the Swift validators' output (MacVPN 0.4.0, macOS 27) for the same
//! input; a differential run of 2 million generated configs against the Swift code found no difference.

mod common;

use common::lang;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::validator;

fn display(kind: VPNKind, text: &str) -> Vec<String> {
    validator(kind).unwrap().validate(text).iter().map(|i| i.display()).collect()
}

#[test]
fn validators_match_swift_on_unicode_edge_cases() {
    lang(AppLanguage::En);
    let cases: &[(VPNKind, &str, &[&str])] = &[
        (VPNKind::Openvpn, "remote a 1\n\u{37e}up /x\n", &[]),
        (VPNKind::Openvpn, "remote a 1\n#\u{301} up /x\n", &["Line 2: Invalid directive"]),
        (VPNKind::Openvpn, "remote a 1\n<ca>\n</\u{301}ca>\nup /x\n", &["Line 2: Unclosed inline block: ca"]),
        (VPNKind::Openvpn, "remote a 1\nremote \u{301}x 1194\n", &["Line 2: Invalid directive"]),
        (
            VPNKind::Openvpn,
            "remote a 1\nfuture-option -\u{301}x\n",
            &["Line 2: Risky directive, acknowledgement required: future-option"],
        ),
        (
            VPNKind::Openvpn,
            "remote a 1\nfuture-option a.\u{301}.b\n",
            &["Line 2: Risky directive, acknowledgement required: future-option"],
        ),
        (
            VPNKind::Openvpn,
            "remote a 1\nfuture-option file:\u{301}x\n",
            &["Line 2: Risky directive, acknowledgement required: future-option"],
        ),
        (VPNKind::Openvpn, "remote a 1\ndhcp-option DN\u{17f} 1.1.1.1\n", &["Line 2: Invalid argument: dhcp-option"]),
        (VPNKind::Openvpn, "remote a\u{85} 1\n", &["Line 1: Invalid argument: remote", "Missing remote directive"]),
        (
            VPNKind::Wireguard,
            "[\u{301}Interface]\nPrivateKey = x\n",
            &[
                "Line 1: Invalid line",
                "Line 2: Key not allowed: privatekey",
                "Exactly one [Interface] section is required",
                "At least one [Peer] with a PublicKey is required",
            ],
        ),
        (
            VPNKind::Wireguard,
            "[Interface]\nAddress =\u{301} 10.0.0.1/32\n",
            &["Line 2: Invalid line", "Missing PrivateKey", "At least one [Peer] with a PublicKey is required"],
        ),
        (
            VPNKind::Wireguard,
            "[Interface]\nAddress = 10.0.0.1/32 #\u{301} c\n",
            &[
                "Line 2: Invalid value: address",
                "Missing PrivateKey",
                "At least one [Peer] with a PublicKey is required",
            ],
        ),
        (VPNKind::Strongswan, "connections {\n c {\n  local { id = =\u{301}x }\n  children { n { } }\n }\n}\n", &[]),
        (
            VPNKind::Strongswan,
            "connections {\n c {\n  local { id = file:\u{301}x }\n  children { n { } }\n }\n}\n",
            &[],
        ),
        (VPNKind::Strongswan, "connections {\u{301}\n c {\n  children { n { } }\n }\n}\n", &["Line 1: Invalid line"]),
        (VPNKind::Sstp, "server=a\nuser=b\n#\u{301} x\n", &["Line 3: Invalid line"]),
        (VPNKind::Sstp, "server=a\nuser=b\nport=\u{301}443\n", &["Line 3: Invalid line"]),
        (
            VPNKind::Sstp,
            "server=a\u{600}:b\nuser=b\n",
            &["Line 1: Invalid server: use a host name or an IPv4/IPv6 address, without a port"],
        ),
    ];
    for (kind, text, expected) in cases {
        assert_eq!(display(*kind, text), *expected, "{kind:?} {text:?}");
    }
}
