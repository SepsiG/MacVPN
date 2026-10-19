import XCTest
@testable import MacVPNCore

final class ValidatorsTests: XCTestCase {
    // Magyar üzeneteket ellenőriz: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() { super.setUp(); AppLanguage.override = .hu }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    let goodOVPN = """
    client
    dev tun
    remote vpn.example.com 1194
    auth-user-pass
    tls-auth [inline] 1
    <ca>
    up /tmp/evil.sh
    </ca>
    # up /tmp/commented.sh
    ; script-security 3
    """

    func testOpenVPNAcceptsInlineAndComments() {
        XCTAssertEqual(OpenVPNValidator().validate(goodOVPN), [])
    }

    func testOpenVPNRejectsEveryForbiddenDirective() {
        for d in OpenVPNValidator.forbidden {
            let issues = OpenVPNValidator().validate("remote a 1\n  \(d.uppercased()) x\n")
            XCTAssertEqual(issues.map(\.line), [2], "nem tiltotta: \(d)")
        }
    }

    func testOpenVPNRejectsDoubleDashForm() {
        XCTAssertEqual(OpenVPNValidator().validate("remote a\n--up /x\n").map(\.line), [2])
    }

    func testOpenVPNRejectsExternalFiles() {
        let issues = OpenVPNValidator().validate("remote a\nca ca.crt\nauth-user-pass creds.txt\n")
        XCTAssertEqual(issues.map(\.line), [2, 3])
    }

    func testOpenVPNRequiresRemote() {
        XCTAssertEqual(OpenVPNValidator().validate("client\n").map(\.line), [0])
    }

    let goodWG = """
    [Interface]
    PrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=
    Address = 10.0.0.2/32
    # PostUp = rm -rf /

    [Peer]
    PublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=
    AllowedIPs = 0.0.0.0/0
    Endpoint = vpn.example.com:51820
    """

    func testWireGuardAcceptsValid() {
        XCTAssertEqual(WireGuardValidator().validate(goodWG), [])
    }

    func testWireGuardRejectsHooks() {
        for key in ["PreUp", "postup", "PreDown", "PostDown", "SaveConfig"] {
            let text = goodWG.replacingOccurrences(of: "Address = 10.0.0.2/32", with: "\(key) = echo hi")
            XCTAssertEqual(WireGuardValidator().validate(text).map(\.line), [3], "nem tiltotta: \(key)")
        }
    }

    func testWireGuardRequiresSections() {
        let issues = WireGuardValidator().validate("[Interface]\nAddress = 1.2.3.4/32\n")
        XCTAssertEqual(issues.map(\.line), [0, 0])
    }

    let goodSwan = """
    connections {
      office {
        remote_addrs = vpn.example.com
        local { auth = eap-mschapv2 }
        children {
          office-net { remote_ts = 0.0.0.0/0 }
        }
      }
    }
    """

    func testStrongSwanAcceptsValid() {
        XCTAssertEqual(StrongSwanValidator().validate(goodSwan), [])
    }

    func testStrongSwanRejectsUpdownIncludeFile() {
        let text = goodSwan + "\ninclude /etc/x.conf\nsecrets {\n  private { file = /etc/key }\n}\n"
        let withUpdown = text.replacingOccurrences(of: "remote_ts = 0.0.0.0/0", with: "updown = /tmp/x")
        XCTAssertEqual(StrongSwanValidator().validate(withUpdown).map(\.line), [6, 10, 12])
    }

    func testStrongSwanRequiresConnectionsAndChildren() {
        XCTAssertEqual(StrongSwanValidator().validate("secrets {\n}\n").map(\.line), [0, 0])
    }

    func testStrongSwanExtractsNames() {
        let names = StrongSwanValidator.names(in: goodSwan)
        XCTAssertEqual(names?.connection, "office")
        XCTAssertEqual(names?.child, "office-net")
    }

    // MARK: Hardening regressions

    private func ovpn(_ body: String) -> [ValidationIssue] { OpenVPNValidator().validate("remote a 1\n" + body) }

    func testOpenVPNRejectsBadClosingTag() {
        let issues = ovpn("<ca>\nX\n</ca>x\nscript-security 2\nup /tmp/e.sh\n")
        XCTAssertEqual(issues.map(\.line), [4, 5, 6])
    }

    func testOpenVPNRejectsQuotedDirectives() {
        XCTAssertEqual(ovpn("\"script-security\" 2\n\"up\" /tmp/e.sh\n").map(\.line), [2, 3])
        XCTAssertEqual(ovpn("script-securit\\y 2\n").map(\.line), [2])
    }

    func testOpenVPNRejectsControlCharacters() {
        XCTAssertEqual(ovpn("up\u{0B}/tmp/e.sh\n").map(\.line), [2])
        XCTAssertEqual(ovpn("<ca>\nX\u{01}\n</ca>\n").map(\.line), [3])
        XCTAssertEqual(ovpn("dev\u{7F}tun\n").map(\.line), [2])
    }

    func testOpenVPNRejectsNewForbiddenAndUnknown() {
        XCTAssertEqual(ovpn("pkcs11-providers /tmp/evil.dylib\n").first?.message.hasPrefix("Tiltott"), true)
        XCTAssertEqual(ovpn("foo-bar 1\n").first?.message, "Kockázatos direktíva, tudomásulvétel szükséges: foo-bar")
    }

    func testOpenVPNRejectsUnknownBlockAndSkipsContent() {
        XCTAssertEqual(ovpn("<up>\n/tmp/e.sh\n</up>\n").map(\.line), [2])
    }

    func testOpenVPNRejectsUnclosedBlock() {
        let issues = ovpn("<ca>\nX\n")
        XCTAssertEqual(issues.map(\.message), ["Lezáratlan inline blokk: ca"])
    }

    func testOpenVPNAllowsQuotedArguments() {
        XCTAssertEqual(ovpn("verify-x509-name \"CN=vpn\" name\n"), [])
    }

    func testStrongSwanRejectsHashInQuotesBypass() {
        // Default-deny: az ismeretlen `x` szakasz (10. sor) is hiba; a lényeg, hogy a 11. sori updown nem csúszik át.
        let text = goodSwan + "\nx {\n  esp_proposals = \"#\" } net2 { updown = /tmp/x\n}\n"
        XCTAssertTrue(StrongSwanValidator().validate(text).map(\.line).contains(11))
    }

    func testStrongSwanRejectsIncludeAnywhere() {
        let text = goodSwan + "\nnet { include /tmp/e.conf\n}\n"
        XCTAssertEqual(StrongSwanValidator().validate(text).map(\.line), [10])
    }

    func testStrongSwanRejectsControlCharacters() {
        let text = goodSwan.replacingOccurrences(of: "remote_addrs", with: "remote\u{0B}_addrs")
        XCTAssertEqual(StrongSwanValidator().validate(text).map(\.line), [3])
    }

    func testStrongSwanIgnoresEqualsInQuotes() {
        let text = goodSwan.replacingOccurrences(of: "remote_addrs = vpn.example.com", with: "proposals = \"a=b\"")
        XCTAssertEqual(StrongSwanValidator().validate(text), [])
    }

    func testWireGuardRejectsControlUnknownKeyAndSection() {
        let ctrl = goodWG.replacingOccurrences(of: "Address = 10.0.0.2/32", with: "\u{0B}PostUp = id")
        XCTAssertEqual(WireGuardValidator().validate(ctrl).map(\.line), [3])
        let foo = goodWG.replacingOccurrences(of: "Address = 10.0.0.2/32", with: "Foo = 1")
        XCTAssertEqual(WireGuardValidator().validate(foo).map(\.line), [3])
        let evil = goodWG + "\n[Evil]\nAddress = 1\n"
        XCTAssertEqual(WireGuardValidator().validate(evil).map(\.line), [10, 11])
        let noEq = goodWG.replacingOccurrences(of: "Address = 10.0.0.2/32", with: "garbage")
        XCTAssertEqual(WireGuardValidator().validate(noEq).map(\.line), [3])
        let outside = "Address = 1\n" + goodWG
        XCTAssertEqual(WireGuardValidator().validate(outside).map(\.line), [1])
    }

    func testStrongSwanRejectsBackslash() {
        let text = goodSwan + "\nx = \"a\\\" # y\n"
        XCTAssertEqual(StrongSwanValidator().validate(text).map(\.line), [10])
    }

    func testStrongSwanRejectsIncludeAsKey() {
        let text = goodSwan + "\nnet { include=/tmp/e.conf }\n"
        XCTAssertEqual(StrongSwanValidator().validate(text).map(\.line), [10])
    }

    func testStrongSwanRejectsUnbalancedQuoteBypass() {
        let text = "connections {\n office {\n  remote_addrs = v\n  children {\n   net { esp_proposals = \"aes\nx\" } n2 { a = \"#\" } n3 { updown = /tmp/x }\n  }\n }\n}\n"
        let lines = StrongSwanValidator().validate(text).map(\.line)
        XCTAssertTrue(lines.contains(5) || lines.contains(6), "\(lines)")
        XCTAssertTrue(StrongSwanValidator().validate(goodSwan + "\nnet { esp_proposals = \"x\" updown = /tmp/x }\n").map(\.line).contains(10))
    }

    func testStrongSwanQuotedValuesStillFine() {
        let text = goodSwan.replacingOccurrences(of: "remote_addrs = vpn.example.com", with: "remote_addrs = \"file # updown\" # c")
        XCTAssertEqual(StrongSwanValidator().validate(text), [])
    }

    let accessServer = """
    client
    dev tun
    remote x 1194 udp
    nobind
    setenv FORWARD_COMPATIBLE 1
    setenv UV_ID abc123
    setenv PUSH_PEER_INFO
    auth-user-pass
    remote-cert-tls server
    cipher AES-256-CBC
    verb 3
    <ca>
    -----BEGIN CERTIFICATE-----
    </ca>
    <tls-crypt>
    KEY
    </tls-crypt>
    """

    let provider = """
    client
    dev tun
    proto udp
    remote a 1194
    remote b 1194
    remote-random
    resolv-retry infinite
    nobind
    persist-key
    persist-tun
    ping-timer-rem
    setenv CLIENT_CERT 0
    setenv opt block-outside-dns
    <crl-verify>
    X
    </crl-verify>
    <ca>
    X
    </ca>
    """

    func testOpenVPNAcceptsRealisticProfiles() {
        XCTAssertEqual(OpenVPNValidator().validate(accessServer), [])
        XCTAssertEqual(OpenVPNValidator().validate(provider), [])
    }

    func testOpenVPNSetenvAndHttpProxyNegatives() {
        XCTAssertEqual(ovpn("setenv BASH_ENV /tmp/x\n").map(\.line), [2])
        XCTAssertEqual(ovpn("setenv opt up /x\n").map(\.line), [2])
        XCTAssertEqual(ovpn("setenv opt ca /x\n").map(\.line), [2])
        XCTAssertEqual(ovpn("setenv\n").map(\.line), [2])
        XCTAssertEqual(ovpn("setenv opt\n").map(\.line), [2])
        XCTAssertEqual(ovpn("http-proxy p 8080 /etc/creds\n").map(\.line), [2])
        XCTAssertEqual(ovpn("http-proxy p 8080 auto\nhttp-proxy p 8080\n"), [])
        XCTAssertTrue(ovpn("up /x\n").first?.message.hasSuffix("töröld vagy tedd megjegyzésbe (#) a sort") == true)
    }

    func testOpenVPNSocksProxyAuthfile() {
        XCTAssertEqual(ovpn("socks-proxy p 1080 /etc/creds\n").map(\.line), [2])
        XCTAssertEqual(ovpn("socks-proxy p 1080 creds.txt\n").map(\.line), [2])
        XCTAssertEqual(ovpn("socks-proxy p 1080 [inline]\nsocks-proxy p 1080\nsocks-proxy p\n"), [])
    }

    /// A hibaüzenetek nem idézhetnek nyers config-tartalmat (a root validátor kimenete a felhasználóhoz jut).
    func testIssuesNeverEchoRawContent() {
        let secret = "SECRET123"
        let lines = ["abc=\(secret)", "x\(secret)=1", "ab c=\(secret)", "\"up\" \(secret)", "setenv abc=\(secret) x",
                     "setenv opt abc=\(secret)", "<ca=\(secret)>", "[\(secret)]", "a\u{0B}\(secret)", "\(secret)!=1",
                     "socks-proxy p 1 \(secret)", "http-proxy p 1 \(secret)", "ca \(secret)", "include \(secret)",
                     "updown = \(secret)", "x = \"\(secret)", "a\\\(secret)"]
        for line in lines {
            let all = OpenVPNValidator().validate("remote a 1\n" + line + "\n")
                + WireGuardValidator().validate(goodWG + "\n" + line + "\n")
                + StrongSwanValidator().validate(goodSwan + "\n" + line + "\n")
            for issue in all {
                XCTAssertFalse(issue.display.contains(secret), "idézte: \(line) -> \(issue.display)")
            }
        }
        // Az engedélyezett karakterkészletű nevek továbbra is látszanak.
        XCTAssertEqual(ovpn("setenv LD_PRELOAD x\n").first?.message.hasPrefix("Nem engedélyezett setenv: LD_PRELOAD"), true)
        XCTAssertEqual(ovpn("setenv a=b x\n").first?.message.hasPrefix("Nem engedélyezett setenv – "), true)
        let wg = WireGuardValidator().validate(goodWG.replacingOccurrences(of: "Address = 10.0.0.2/32", with: "a b = 1"))
        XCTAssertEqual(wg.first?.message, "Nem engedélyezett kulcs")
    }
}
