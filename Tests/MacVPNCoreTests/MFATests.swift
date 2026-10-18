import XCTest
import SystemConfiguration
@testable import MacVPNCore

/// MFA (spec 10f): SCRV1, statikus challenge, kód a jelszó végén, időkorlát, URL- és állapotfájl-validálás.
final class MFATests: XCTestCase {
    // MARK: SCRV1 és statikus challenge

    /// A management-notes.txt példája: "bar" + "8675309".
    func testSCRV1Format() {
        XCTAssertEqual(MFA.scrv1(password: "bar", code: "8675309"), "SCRV1:YmFy:ODY3NTMwOQ==")
        XCTAssertEqual(MFA.scrv1(password: "", code: ""), "SCRV1::")
        XCTAssertEqual(MFA.scrv1(password: "jó:jelszó", code: "1"), "SCRV1:asOzOmplbHN6w7M=:MQ==")
        XCTAssertEqual(MFA.staticChallengePassword(password: "bar", code: "8675309", format: .concat), "bar8675309")
        XCTAssertEqual(MFA.staticChallengePassword(password: "bar", code: "8675309", format: .scrv1), "SCRV1:YmFy:ODY3NTMwOQ==")
    }

    func testStaticChallengeParse() {
        let base = "client\nremote vpn.example.com 1194\nauth-user-pass\n"
        XCTAssertNil(MFA.staticChallenge(in: base))
        XCTAssertEqual(MFA.staticChallenge(in: base + "static-challenge \"Enter OTP\" 1\n"),
                       StaticChallenge(text: "Enter OTP", echo: true, format: .scrv1))
        XCTAssertEqual(MFA.staticChallenge(in: base + "static-challenge 'Token code' 0 concat\n"),
                       StaticChallenge(text: "Token code", echo: false, format: .concat))
        XCTAssertEqual(MFA.staticChallenge(in: base + "--static-challenge PIN 0 scrv1\n"),
                       StaticChallenge(text: "PIN", echo: false, format: .scrv1))
        // Az utolsó érvényes sor számít; a hibás sorok kimaradnak.
        XCTAssertEqual(MFA.staticChallenge(in: base + "static-challenge \"A\" 1\nstatic-challenge \"B\" 0\n")?.text, "B")
        XCTAssertNil(MFA.staticChallenge(in: base + "static-challenge \"A\" 2\n"))
        XCTAssertNil(MFA.staticChallenge(in: base + "static-challenge \"A\" 1 other\n"))
        XCTAssertNil(MFA.staticChallenge(in: base + "static-challenge \"A\"\n"))
        XCTAssertNil(MFA.staticChallenge(in: base + "# static-challenge \"A\" 1\n"))
        XCTAssertNil(MFA.staticChallenge(in: base + "static-challenge \"unterminated 1\n"))
        // Inline blokk tartalma nem direktíva.
        XCTAssertNil(MFA.staticChallenge(in: base + "<ca>\nstatic-challenge \"A\" 1\n</ca>\n"))
        XCTAssertNil(MFA.staticChallenge(in: base + "<connection>\nremote x\nstatic-challenge \"A\" 1\n</connection>\n"))
        XCTAssertEqual(MFA.staticChallenge(in: "<ca>\nx\n</ca>\nstatic-challenge \"After\" 1\n")?.text, "After")
    }

    func testApplyStaticChallenge() throws {
        let sc = StaticChallenge(text: "OTP", echo: true)
        let s = try MFA.applyStaticChallenge(sc, code: "246810", to: Secrets(username: "bob", password: "StatPass"))
        XCTAssertEqual(s.password, "SCRV1:U3RhdFBhc3M=:MjQ2ODEw")
        XCTAssertTrue(s.challengePacked)
        XCTAssertEqual(s.oneTimeCode, "246810")
        XCTAssertEqual(s.stdinPayload, "username=bob\npassword=SCRV1:U3RhdFBhc3M=:MjQ2ODEw\notp=246810\nchallenge=packed\n")
        let concat = try MFA.applyStaticChallenge(StaticChallenge(text: "x", echo: false, format: .concat), code: "1",
                                                  to: Secrets(username: "bob", password: "p"))
        XCTAssertEqual(concat.password, "p1")
        XCTAssertThrowsError(try MFA.applyStaticChallenge(sc, code: "1\n2", to: Secrets(password: "p")))
        XCTAssertThrowsError(try MFA.applyStaticChallenge(sc, code: "1", to: Secrets(password: String(repeating: "x", count: 200)))) {
            XCTAssertEqual($0 as? MFAError, .tooLong)
        }
    }

    // MARK: Kód a jelszó végén

    func testAppendCodeSeparators() {
        XCTAssertEqual(MFA.appendCode(password: "pw", code: "123456", separator: .none), "pw123456")
        XCTAssertEqual(MFA.appendCode(password: "pw", code: "123456", separator: .comma), "pw,123456")
        XCTAssertEqual(MFA.appendCode(password: "pw", code: "123456", separator: .colon), "pw:123456")
        XCTAssertEqual(MFA.appendCode(password: "", code: "123456", separator: .colon), "123456")
    }

    func testApplyCodeForEachKind() throws {
        let base = Secrets(username: "bob", password: "pw", psk: "k")
        for kind in [VPNKind.openvpn, .strongswan, .sstp, .l2tp, .cisco] {
            let s = try MFA.applyCode("123456", separator: .comma, to: base, kind: kind)
            XCTAssertEqual(s.password, "pw,123456", "\(kind)")
            XCTAssertEqual(s.username, "bob")
            XCTAssertEqual(s.psk, "k")
            XCTAssertEqual(s.oneTimeCode, "123456")
            XCTAssertFalse(s.challengePacked)
        }
        // Root típusok: stdin; a kód külön is (csak maszkoláshoz).
        let root = try MFA.applyCode("777", separator: .colon, to: base, kind: .strongswan)
        XCTAssertEqual(root.stdinPayload, "username=bob\npassword=pw:777\npsk=k\notp=777\n")
        // Natív L2TP / Cisco IPsec: a SCNetworkConnection opcióiban.
        let l2tp = try MFA.applyCode("999", separator: .none, to: base, kind: .l2tp)
        let ppp = NativeStartOptions.make(kind: .l2tp, secrets: l2tp)?[kSCEntNetPPP as String] as? [String: Any]
        XCTAssertEqual(ppp?[kSCPropNetPPPAuthPassword as String] as? String, "pw999")
        let cisco = try MFA.applyCode("999", separator: .colon, to: base, kind: .cisco)
        let ipsec = NativeStartOptions.make(kind: .ciscoIPSec, secrets: cisco)?[kSCEntNetIPSec as String] as? [String: Any]
        XCTAssertEqual(ipsec?[kSCPropNetIPSecXAuthPassword as String] as? String, "pw:999")
        // SSTP: az összefűzött jelszóra is a jelszó-szabály vonatkozik.
        XCTAssertThrowsError(try MFA.applyCode("12\"3", separator: .none, to: base, kind: .sstp)) {
            XCTAssertEqual($0 as? MFAError, .sstpPassword)
        }
        XCTAssertThrowsError(try MFA.applyCode("12\\3", separator: .none, to: base, kind: .sstp))
        XCTAssertNoThrow(try MFA.applyCode("12\"3", separator: .none, to: base, kind: .openvpn))
        // Érvénytelen kód: üres, sortörés, vezérlőkarakter, túl hosszú.
        for bad in ["", "1\n2", "1\r2", "1\u{7}2", "1\u{85}2", "1\u{2028}2", String(repeating: "1", count: 257)] {
            XCTAssertThrowsError(try MFA.applyCode(bad, separator: .none, to: base, kind: .openvpn), bad.debugDescription) {
                XCTAssertEqual($0 as? MFAError, .invalidCode)
            }
        }
        XCTAssertNoThrow(try MFA.applyCode(String(repeating: "1", count: 256), separator: .none, to: base, kind: .openvpn))
    }

    /// meta.json: a hiányzó `otp` (régebbi fájl) kikapcsolt; az ismeretlen elválasztó: nincs.
    func testOTPSettingBackwardCompatible() throws {
        let c = Connection(name: "x", kind: .openvpn)
        var dict = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(c)) as? [String: Any])
        XCTAssertNotNil(dict["otp"])
        dict["otp"] = nil
        let old = try JSONDecoder().decode(Connection.self, from: JSONSerialization.data(withJSONObject: dict))
        XCTAssertEqual(old.otp, OTPSetting())
        var on = c
        on.otp = OTPSetting(enabled: true, separator: .colon)
        let round = try JSONDecoder().decode(Connection.self, from: JSONEncoder().encode(on))
        XCTAssertEqual(round.otp, OTPSetting(enabled: true, separator: .colon))
        let future = try JSONDecoder().decode(OTPSetting.self, from: Data(#"{"enabled":true,"separator":"slash"}"#.utf8))
        XCTAssertEqual(future, OTPSetting(enabled: true, separator: .none))
    }

    func testSystemOTPStore() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-otp-\(UUID().uuidString)/system-otp.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = SystemOTPStore(url: url)
        XCTAssertEqual(store.load(), [:])
        try store.save(["A": OTPSetting(enabled: true, separator: .comma), "B": OTPSetting()])
        XCTAssertEqual(store.load(), ["A": OTPSetting(enabled: true, separator: .comma)])
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    // MARK: Időkorlát

    func testPromptDeadline() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        let d = PromptDeadline(start: t0)
        XCTAssertEqual(d.duration, 120)
        XCTAssertEqual(d.remaining(at: t0), 120)
        XCTAssertEqual(d.remaining(at: t0.addingTimeInterval(119.2)), 1)
        XCTAssertFalse(d.isExpired(at: t0.addingTimeInterval(119.9)))
        XCTAssertTrue(d.isExpired(at: t0.addingTimeInterval(120)))
        XCTAssertEqual(d.remaining(at: t0.addingTimeInterval(500)), 0)
        // A közvetítő határideje, de legfeljebb a maximum; a múltbeli határidő azonnal lejár.
        XCTAssertEqual(PromptDeadline(start: t0, until: t0.addingTimeInterval(30), maximum: 120).duration, 30)
        XCTAssertEqual(PromptDeadline(start: t0, until: t0.addingTimeInterval(900), maximum: 300).duration, 300)
        XCTAssertEqual(PromptDeadline(start: t0, until: nil, maximum: 300).duration, 300)
        XCTAssertTrue(PromptDeadline(start: t0, until: t0.addingTimeInterval(-5), maximum: 120).isExpired(at: t0))
    }

    // MARK: Szöveg, URL, állapotfájl

    func testAuthTextSanitize() {
        XCTAssertEqual(AuthText.sanitize("Enter\u{1b}[31m PIN\u{7}"), "Enter [31m PIN")
        XCTAssertEqual(AuthText.sanitize(String(repeating: "x", count: 500)).count, 201)
        XCTAssertEqual(AuthText.sanitize("  a\u{2028}b "), "a b")
        // Unicode formázó karakterek (Cf: bidi, zero-width, BOM) kimaradnak.
        XCTAssertEqual(AuthText.sanitize("Enter\u{202E}NIP\u{202C} code"), "EnterNIP code")
        XCTAssertEqual(AuthText.sanitize("a\u{200B}b\u{200F}c\u{2066}d\u{2069}e\u{FEFF}f\u{00AD}g"), "abcdefg")
        XCTAssertFalse(AuthText.sanitize("x\u{061C}y\u{2060}z").unicodeScalars.contains { $0.properties.generalCategory == .format })
    }

    func testWebAuthURLValidation() {
        XCTAssertEqual(WebAuthURL.validate("https://sso.example.com/auth?session=abc&x=1#f")?.host, "sso.example.com")
        XCTAssertNotNil(WebAuthURL.validate("HTTPS://SSO.example.com:8443/p"))
        XCTAssertNotNil(WebAuthURL.validate("https://[2001:db8::1]/x"))
        for bad in ["http://sso.example.com/", "javascript:alert(1)", "file:///etc/passwd", "ftp://x/", "https://",
                    "https:///path", "https://user:pw@sso.example.com/", "https://sso.example.com/a b",
                    "https://sso.example.com/\"x", "https://sso.example.com/<x>", "https://sso.example.com/é",
                    "https://sso.example.com/\n", "//sso.example.com", "",
                    "https://sso.example.com/" + String(repeating: "a", count: 1010),
                    // Százalék-kódolt hoszt (homográf, sortörés, bidi), userinfo trükk, Unicode, záró pont, rossz címkék.
                    "https://%D0%B0pple.com/", "https://a%0Ab.com/", "https://%E2%80%AEx.com/", "https://apple.com%40evil.com/",
                    "https://apple.com@evil.com/", "https://аpple.com/", "https://sso.example.com./", "https://-x.example.com/",
                    "https://x-.example.com/", "https://a..b.com/", "https://a_b.example.com/", "https://sso.example.com:0/",
                    "https://sso.example.com:99999/", "https://sso.example.com:/", "https://[zz::1]/",
                    "https://" + String(repeating: "a", count: 64) + ".com/"] {
            XCTAssertNil(WebAuthURL.validate(bad), bad)
        }
    }

    /// A megjelenített és naplózott hoszt az eredeti ASCII alak kisbetűvel (punycode dekódolás nélkül).
    func testWebAuthDisplayHost() throws {
        let puny = try XCTUnwrap(WebAuthURL.validate("https://XN--pple-43d.Example.COM/login?x=1"))
        XCTAssertEqual(WebAuthURL.displayHost(puny), "xn--pple-43d.example.com")
        XCTAssertEqual(puny.absoluteString, "https://XN--pple-43d.Example.COM/login?x=1")
        XCTAssertEqual(WebAuthURL.displayHost(try XCTUnwrap(WebAuthURL.validate("https://[2001:DB8::1]:8443/x"))), "[2001:db8::1]")
        XCTAssertEqual(WebAuthURL.displayHost(try XCTUnwrap(WebAuthURL.validate("https://10.0.0.1/"))), "10.0.0.1")
        XCTAssertNil(WebAuthURL.asciiHost("https://%D0%B0pple.com/"))
    }

    func testAuthUIStateParse() throws {
        let challenge = AuthUIState(seq: 3, state: .challenge, method: .crv1, text: "Enter PIN", echo: false, deadline: 1_760_000_000)
        XCTAssertEqual(AuthUIState.parse(challenge.encoded()), challenge)
        // A nem https URL a beolvasáskor is eldobva; a webauth állapot ilyenkor pending.
        let web = AuthUIState(seq: 1, state: .webauth, method: .webauth, url: "http://evil.example.com/")
        let parsed = try XCTUnwrap(AuthUIState.parse(web.encoded()))
        XCTAssertNil(parsed.url)
        XCTAssertEqual(parsed.state, .pending)
        XCTAssertEqual(AuthUIState.parse(Data(#"{"v":1,"seq":1,"state":"challenge","text":"a\u001bb"}"#.utf8))?.text, "a b")
        XCTAssertNil(AuthUIState.parse(Data(#"{"v":2,"seq":1,"state":"done"}"#.utf8)))
        XCTAssertNil(AuthUIState.parse(Data(#"{"v":1,"seq":1,"state":"hacked"}"#.utf8)))
        XCTAssertNil(AuthUIState.parse(Data(repeating: 0x20, count: 9000)))
        XCTAssertNil(AuthUIState.parse(Data("not json".utf8)))
        XCTAssertEqual(AuthUIState.path(for: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!),
                       "/var/run/macvpn-ui/11111111-2222-3333-4444-555555555555.json")
    }

    func testAuthUIStateReaderRejectsSymlink() throws {
        let dir = try SecureTempDirectory.make(prefix: "macvpn-ui-test.", in: FileManager.default.temporaryDirectory)
        defer { SecureTempDirectory.removeIfOwned(dir, prefix: "macvpn-ui-test.") }
        let file = dir.appendingPathComponent("a.json")
        try AuthUIState(seq: 1, state: .pending).encoded().write(to: file)
        XCTAssertEqual(AuthUIStateReader.read(path: file.path)?.state, .pending)
        let link = dir.appendingPathComponent("b.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertNil(AuthUIStateReader.read(path: link.path))
        XCTAssertNil(AuthUIStateReader.read(path: dir.appendingPathComponent("missing.json").path))
    }

    func testRespondPayload() {
        XCTAssertEqual(AuthResponseKind.crv1.stdinPayload(response: "123"), "kind=crv1\nresponse=123\n")
        XCTAssertEqual(AuthResponseKind.static.stdinPayload(response: ""), "kind=static\nresponse=\n")
        XCTAssertEqual(AuthResponseKind.cancel.stdinPayload(response: "ignored"), "kind=cancel\nresponse=\n")
        XCTAssertEqual(AuthResponseKind.webauthAck.stdinPayload(response: ""), "kind=webauth-ack\nresponse=\n")
        XCTAssertNil(AuthResponseKind.crv1.stdinPayload(response: "1\nkind=cancel"))
        XCTAssertNil(AuthResponseKind.crv1.stdinPayload(response: String(repeating: "1", count: 257)))
        XCTAssertEqual(AuthResponseKind.allCases.map(\.rawValue), ["crv1", "static", "webauth-ack", "cancel"])
    }
}
