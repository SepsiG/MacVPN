import XCTest
@testable import MacVPNCore

/// Argumentum- és értékszintű validálás (biztonsági audit, 1. kör): OpenVPN direktíva-argumentumok és
/// `<connection>` blokk, strongSwan default-deny kulcslista, WireGuard értékformátumok.
final class OpenVPNArgumentTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    private func ovpn(_ body: String) -> [ValidationIssue] { OpenVPNValidator().validate("remote a 1\n" + body) }
    private func ok(_ body: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(ovpn(body + "\n"), [], body, file: file, line: line)
    }
    private func bad(_ body: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(ovpn(body + "\n").map(\.line), [2], body, file: file, line: line)
    }

    func testEveryAllowedDirectiveHasAnArgumentSpec() {
        XCTAssertEqual(Set(OpenVPNValidator.argumentSpecs.keys), OpenVPNValidator.allowed)
    }

    func testDevAndDevType() {
        for d in ["dev tun", "dev tap", "dev utun", "dev utun7", "dev tun0", "dev tap3", "dev-type tun", "dev-type tap"] { ok(d) }
        for d in ["dev /dev/disk0", "dev ../../dev/disk0", "dev disk0", "dev -x", "dev tun extra", "dev", "dev \"/dev/rdisk0\"",
                  "dev-type null", "dev-type /dev/x", "setenv opt dev /dev/disk0"] { bad(d) }
    }

    func testRemoteProtoPort() {
        for d in ["remote vpn.example.com", "remote 1.2.3.4 1194", "remote x 443 tcp", "remote x 1194 udp4", "remote fd00::1 1194 udp6",
                  "proto tcp-client", "port 1194", "lport 0", "rport 65535"] { ok(d) }
        for d in ["remote -x 1194", "remote x 99999", "remote x 1194 icmp", "remote x 1194 udp extra", "remote /tmp/x",
                  "proto bogus", "port abc", "lport 70000", "rport"] { bad(d) }
    }

    func testCiphersAndAuth() {
        for d in ["cipher AES-256-GCM", "data-ciphers AES-256-GCM:AES-128-GCM:?CHACHA20-POLY1305", "data-ciphers-fallback AES-256-CBC",
                  "auth SHA512", "auth none", "tls-cipher DEFAULT:@SECLEVEL=0", "tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
                  "tls-groups X25519:secp256r1", "tls-version-min 1.2 or-highest"] { ok(d) }
        for d in ["cipher /etc/passwd", "cipher -x", "auth a b", "data-ciphers", "tls-version-min 1.2 or-lowest"] { bad(d) }
    }

    func testNumericOptions() {
        for d in ["verb 3", "mute 20", "ping 10", "ping-restart 60", "ping-exit 120", "keepalive 10 60", "reneg-sec 0",
                  "tun-mtu 1500", "mssfix 1450", "mssfix", "connect-retry 5 300", "inactive 3600"] { ok(d) }
        for d in ["verb 99", "verb x", "mute -1", "ping x", "keepalive 10", "keepalive a b"] { bad(d) }
    }

    func testRoutesAndRedirect() {
        for d in ["route 10.0.0.0 255.0.0.0", "route 10.0.0.0 255.0.0.0 vpn_gateway 5", "route remote_host 255.255.255.255 net_gateway",
                  "route-ipv6 2000::/3", "route-ipv6 ::/0 default 10", "ifconfig 10.8.0.2 10.8.0.1", "ifconfig-ipv6 fd00::2/64 fd00::1",
                  "redirect-gateway def1 bypass-dhcp", "redirect-gateway ipv6 !ipv4", "redirect-gateway", "route-gateway dhcp"] { ok(d) }
        for d in ["route /etc/x", "route 10.0.0.0 /x", "redirect-gateway /tmp/x", "redirect-gateway evil", "ifconfig a b",
                  "route-ipv6 ../x", "route-gateway /x"] { bad(d) }
    }

    func testQuotedTextArguments() {
        for d in ["verify-x509-name \"C=US, O=Example, CN=vpn\" subject", "verify-x509-name vpn.example.com name",
                  "verify-x509-name 'vpn' name-prefix", "verify-x509-name CN=us1234.nordvpn.com",
                  "pull-filter ignore \"route-ipv6\"", "pull-filter reject \"dhcp-option DNS\"",
                  "static-challenge \"Enter Google Authenticator Code\" 1", "dhcp-option DNS 1.1.1.1", "dhcp-option DOMAIN corp.example",
                  "remote-cert-tls server", "remote-cert-eku \"TLS Web Server Authentication\""] { ok(d) }
        for d in ["verify-x509-name x bogus", "pull-filter allow x", "pull-filter ignore", "static-challenge \"x\" 5",
                  "dhcp-option EVIL x", "dhcp-option DNS /etc/x", "verify-x509-name \"unterminated", "remote-cert-tls both"] { bad(d) }
    }

    func testProxies() {
        for d in ["http-proxy proxy.example 8080", "http-proxy p 8080 auto", "http-proxy p 8080 [inline] basic",
                  "socks-proxy p 1080", "socks-proxy p"] { ok(d) }
        for d in ["http-proxy -p 8080", "http-proxy p port", "http-proxy p 8080 auto bogus", "socks-proxy p x"] { bad(d) }
    }

    func testBackslashCommentsAndExtraArgs() {
        bad("dev tu\\n")
        bad("cipher \"AES\\\"")
        ok("remote b 1194 # backup server")
        ok("remote b 1194 ; backup server")
        bad("persist-key now")
        bad("client yes")
    }

    func testMessagesNameTheDirectiveNotTheValue() {
        let issue = ovpn("dev /dev/SECRET42\n").first
        XCTAssertEqual(issue?.message, "Invalid argument: dev")
        XCTAssertEqual(ovpn("keepalive 10\n").first?.message, "Wrong number of arguments: keepalive")
        XCTAssertFalse(ovpn("verify-x509-name SECRET42 bogus\n").first?.display.contains("SECRET42") ?? true)
    }

    func testRealisticProviderProfiles() {
        let nord = """
        client
        dev tun
        proto udp
        remote 185.1.2.3 1194
        resolv-retry infinite
        remote-random
        nobind
        tun-mtu 1500
        tun-mtu-extra 32
        mssfix 1450
        persist-key
        persist-tun
        ping 15
        ping-restart 0
        ping-timer-rem
        reneg-sec 0
        comp-lzo no
        verify-x509-name CN=us1234.nordvpn.com
        remote-cert-tls server
        auth-user-pass
        verb 3
        pull
        fast-io
        cipher AES-256-CBC
        auth SHA512
        <ca>
        X
        </ca>
        key-direction 1
        <tls-auth>
        X
        </tls-auth>
        """
        let pia = """
        client
        dev tun
        proto udp
        remote us-east.privacy.network 1198
        resolv-retry infinite
        nobind
        persist-key
        persist-tun
        cipher aes-128-cbc
        auth sha1
        tls-client
        remote-cert-tls server
        auth-user-pass
        compress
        verb 1
        reneg-sec 0
        disable-occ
        <crl-verify>
        X
        </crl-verify>
        <ca>
        X
        </ca>
        """
        let pfsense = """
        dev tun
        persist-tun
        persist-key
        data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
        data-ciphers-fallback AES-256-CBC
        auth SHA256
        tls-client
        client
        resolv-retry infinite
        remote 203.0.113.1 1194 udp4
        nobind
        verify-x509-name "pfSense-server-cert" name
        auth-user-pass
        remote-cert-tls server
        explicit-exit-notify
        lport 0
        <ca>
        X
        </ca>
        setenv opt block-outside-dns
        <tls-crypt>
        X
        </tls-crypt>
        """
        let proton = """
        client
        dev tun
        proto udp
        remote 185.159.1.1 80
        remote 185.159.1.1 51820
        remote-random
        resolv-retry infinite
        nobind
        cipher AES-256-GCM
        setenv CLIENT_CERT 0
        tun-mtu 1500
        mssfix 0
        persist-key
        persist-tun
        reneg-sec 0
        remote-cert-tls server
        auth-user-pass
        pull
        fast-io
        <ca>
        X
        </ca>
        <tls-crypt>
        X
        </tls-crypt>
        """
        let accessServer = """
        client
        server-poll-timeout 4
        nobind
        remote vpn.example.com 1194 udp
        remote vpn.example.com 443 tcp
        dev tun
        dev-type tun
        remote-cert-tls server
        tls-version-min 1.2
        reneg-sec 604800
        tun-mtu 1420
        auth-user-pass
        verb 3
        push-peer-info
        static-challenge "Enter Authenticator Code" 1
        setenv opt tls-cipher DEFAULT:@SECLEVEL=0
        ignore-unknown-option block-outside-dns
        block-outside-dns
        <ca>
        X
        </ca>
        key-direction 1
        <tls-auth>
        X
        </tls-auth>
        """
        for (name, profile) in [("nord", nord), ("pia", pia), ("pfsense", pfsense), ("proton", proton), ("access server", accessServer)] {
            XCTAssertEqual(OpenVPNValidator().validate(profile), [], name)
        }
    }

    // MARK: <connection>

    func testConnectionBlockSatisfiesRemote() {
        let text = "client\ndev tun\n<connection>\nremote a 1194 udp\nnobind\n</connection>\n<connection>\nremote b 443 tcp\n</connection>\n"
        XCTAssertEqual(OpenVPNValidator().validate(text), [])
    }

    func testConnectionInnerLinesAreValidated() {
        let text = "client\n<connection>\nremote a 1194\nup /tmp/x\ndev /dev/disk0\nca [inline]\nport x\n# comment\n</connection>\n"
        XCTAssertEqual(OpenVPNValidator().validate(text).map(\.line), [4, 5, 6, 7])
        XCTAssertTrue(OpenVPNValidator().validate(text)[0].message.hasPrefix("Forbidden directive: up"))
        XCTAssertEqual(OpenVPNValidator().validate(text)[2].message, "Directive not allowed in a <connection> block: ca")
    }

    func testConnectionInvalidRemoteDoesNotSatisfy() {
        let issues = OpenVPNValidator().validate("client\n<connection>\nremote -x 1194\n</connection>\n")
        XCTAssertEqual(issues.map(\.line), [3, 0])
    }

    func testConnectionNestedBlocks() {
        // Csak a connection-opcióhoz tartozó inline blokk lehet benne, más blokk és újabb <connection> nem.
        let allowed = "<connection>\nremote a 1\nhttp-proxy p 8080 [inline]\n<http-proxy-user-pass>\nu\np\n</http-proxy-user-pass>\n</connection>\n"
        XCTAssertEqual(OpenVPNValidator().validate(allowed), [])
        let ca = "<connection>\nremote a 1\n<ca>\nup /x\n</ca>\n</connection>\n"
        XCTAssertEqual(OpenVPNValidator().validate(ca).map(\.line), [3])
        let nested = "<connection>\nremote a 1\n<connection>\nremote b 1\n</connection>\n</connection>\n"
        XCTAssertFalse(OpenVPNValidator().validate(nested).isEmpty)
        XCTAssertTrue(OpenVPNValidator().validate(nested).map(\.line).contains(3))
    }

    func testConnectionUnclosedAndBadClose() {
        XCTAssertEqual(OpenVPNValidator().validate("<connection>\nremote a 1\n").map(\.message), ["Unclosed inline block: connection"])
        XCTAssertEqual(OpenVPNValidator().validate("remote a 1\n<connection>\nremote a 1\n</ca>\n</connection>\n").map(\.line), [4])
    }
}

final class WireGuardValueTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    static let privateKey = "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE="
    static let publicKey = "bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE="

    private func wg(interface: [String] = [], peer: [String] = []) -> [ValidationIssue] {
        let text = (["[Interface]", "PrivateKey = \(Self.privateKey)"] + interface
            + ["[Peer]", "PublicKey = \(Self.publicKey)", "AllowedIPs = 0.0.0.0/0"] + peer).joined(separator: "\n")
        return WireGuardValidator().validate(text)
    }

    func testValidValues() {
        XCTAssertEqual(wg(interface: ["Address = 10.0.0.2/32, fd00::2/128", "DNS = 1.1.1.1, 2606:4700::1111, corp.example",
                                      "MTU = 1420", "ListenPort = 51820", "Table = off", "FwMark = 0x1234"],
                          peer: ["Endpoint = vpn.example.com:51820", "PersistentKeepalive = 25", "PresharedKey = \(Self.publicKey)",
                                 "AllowedIPs = 10.0.0.0/8,192.168.1.0/24, ::/0"]), [])
        XCTAssertEqual(wg(interface: ["Table = auto", "Table = 1234", "FwMark = off", "FwMark = 51820", "Address = 10.0.0.2"],
                          peer: ["Endpoint = [2001:db8::1]:51820", "Endpoint = 203.0.113.5:1", "PersistentKeepalive = off"]), [])
    }

    func testInvalidValues() {
        let interfaceCases = ["Address = 10.0.0.2/33", "Address = 10.0.0.256/32", "Address = -x", "Address = /etc/x", "Address =",
                              "DNS = -1.1.1.1", "DNS = a/b", "MTU = 70000", "MTU = x", "ListenPort = 65536", "ListenPort = -1",
                              "Table = maybe", "FwMark = 0xZZ", "FwMark = 0x123456789", "PrivateKey = short", "PrivateKey = \(Self.privateKey)x"]
        for c in interfaceCases {
            XCTAssertEqual(wg(interface: [c]).map(\.line), [3], c)
        }
        let peerCases = ["Endpoint = vpn.example.com", "Endpoint = vpn.example.com:0", "Endpoint = -x:1", "Endpoint = [::1:1",
                         "Endpoint = a b:1", "PersistentKeepalive = 70000", "AllowedIPs = 0.0.0.0/0, x", "PublicKey = -abc",
                         "PresharedKey = \(String(Self.publicKey.dropLast()))"]
        for c in peerCases {
            XCTAssertEqual(wg(peer: [c]).map(\.line), [6], c)
        }
        XCTAssertEqual(wg(interface: ["MTU = 70000"]).first?.message, "Invalid value: mtu")
    }
}

final class StrongSwanAllowlistTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    /// `connections { c { <conn> local { <local> } remote { <remote> } children { n { <child> } } } }` + extra.
    private func swan(conn: String = "", local: String = "", remote: String = "", child: String = "", extra: String = "") -> String {
        """
        connections {
          c {
            remote_addrs = vpn.example.com
            \(conn)
            local {
              auth = eap-mschapv2
              \(local)
            }
            remote {
              auth = pubkey
              \(remote)
            }
            children {
              n {
                remote_ts = 0.0.0.0/0
                \(child)
              }
            }
          }
        }
        \(extra)
        """
    }

    private func lines(_ text: String) -> [Int] { StrongSwanValidator().validate(text).map(\.line) }

    func testRealisticConfigs() {
        let full = swan(conn: "version = 2\n    vips = 0.0.0.0,::\n    proposals = aes256-sha256-modp2048, default\n    send_certreq = yes",
                        local: "eap_id = john.smith\n      id = \"C=CH, O=Example, CN=john\"\n      certs = john.pem",
                        remote: "id = vpn.example.com\n      cacerts = ca.pem, intermediate.crt\n      revocation = relaxed",
                        child: "esp_proposals = aes256gcm16\n        start_action = none\n        dpd_action = restart",
                        extra: "secrets {\n  ike-1 {\n    id = vpn.example.com\n    secret = 0sYWJjZA==\n  }\n}\npools {\n  p {\n    addrs = 10.3.0.0/24\n    dns = 1.1.1.1\n  }\n}\nauthorities {\n  corp {\n    cacert = corp-ca.pem\n    cert_uri_base = http://ca.example/certs\n  }\n}")
        XCTAssertEqual(StrongSwanValidator().validate(full), [])
        XCTAssertEqual(StrongSwanValidator().validate(ConfigImporter.template(for: .strongswan)), [])
    }

    func testValueTokensNamedLikeForbiddenKeysAreFine() {
        // A régi szó-alapú keresés téves riasztásai: ezek értékek, nem kulcsok.
        XCTAssertEqual(lines(swan(local: "id = file", remote: "id = updown.example.com", child: "label = include")), [])
        XCTAssertEqual(lines(swan(local: "eap_id = include")), [])
    }

    func testPathKeysOnlyTakeFileNames() {
        for value in ["/etc/master.passwd", "../../../etc/master.passwd", ".hidden", "a/b.pem", "ok.pem, /etc/x"] {
            XCTAssertEqual(lines(swan(local: "certs = \(value)")), [7], value)
            XCTAssertEqual(lines(swan(remote: "cacerts = \(value)")), [11], value)
            XCTAssertEqual(lines(swan(local: "pubkeys = \"\(value)\"")), [7], value)
            XCTAssertEqual(lines(swan(extra: "authorities {\n  a {\n    cacert = \(value)\n  }\n}")), [23], value)
        }
        XCTAssertEqual(StrongSwanValidator().validate(swan(local: "certs = /etc/x")).first?.message,
                       "Only a file name is allowed, no path: certs")
    }

    func testForbiddenKeys() {
        XCTAssertEqual(lines(swan(child: "updown = /tmp/x")), [16])
        XCTAssertEqual(lines(swan(local: "cert-1 {\n        file = /etc/x\n      }")), [8])
        XCTAssertEqual(lines(swan(extra: "authorities {\n  a {\n    crl_uris = http://x/crl\n    ocsp_uris = http://x/ocsp\n    file = /etc/x\n  }\n}")),
                       [23, 24, 25])
        XCTAssertEqual(lines(swan(extra: "secrets {\n  private-1 {\n    file = /etc/key\n  }\n}")), [23])
        XCTAssertEqual(lines(swan(conn: "include /etc/x")), [4])
        XCTAssertEqual(StrongSwanValidator().validate(swan(child: "updown = /tmp/x")).first?.message, "Forbidden key: updown")
    }

    func testFileURIsRejected() {
        XCTAssertEqual(lines(swan(extra: "authorities {\n  a {\n    cert_uri_base = file:///etc/\n  }\n}")), [23])
        XCTAssertEqual(lines(swan(remote: "id = \"FILE:/etc/x\"")), [11])
    }

    func testUnknownKeysAndSectionsAreDenied() {
        XCTAssertEqual(lines(swan(conn: "foo = bar")), [4])
        XCTAssertEqual(lines(swan(local: "remote_ts = 0.0.0.0/0")), [7])        // jó kulcs, rossz szakasz
        XCTAssertEqual(lines(swan(extra: "evil {\n  x = y\n}")), [21])
        XCTAssertEqual(lines(swan(child: "sub {\n        x = y\n        }")), [16])
        XCTAssertEqual(StrongSwanValidator().validate(swan(conn: "foo = bar")).first?.message, "Key not allowed")
        XCTAssertEqual(StrongSwanValidator().validate(swan(local: "remote_ts = 1")).first?.message, "Key not allowed: remote_ts")
        XCTAssertEqual(StrongSwanValidator().validate(swan(extra: "children {\n}")).first?.message, "Section not allowed: children")
    }

    func testBracesAreTracked() {
        XCTAssertEqual(lines(swan(extra: "}")), [21])
        XCTAssertEqual(lines("connections {\n  c {\n    children {\n      n {\n      }\n    }\n"), [2, 1])
    }

    func testAmbiguousValuesRejected() {
        // Egy értékben álló önálló `=` vagy `{` gyanús (kulcs-csempészés kísérlete), ezért hiba.
        XCTAssertEqual(lines(swan(child: "esp_proposals = \"x\" updown = /tmp/x")), [16])
        XCTAssertEqual(lines(swan(child: "esp_proposals = a{b")), [16])
        XCTAssertEqual(lines(swan(local: "id = CN=vpn.example.com")), [])
    }
}
