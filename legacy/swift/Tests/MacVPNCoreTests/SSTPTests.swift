import XCTest
@testable import MacVPNCore

final class SSTPTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    let pem = """
    -----BEGIN CERTIFICATE-----
    MIIBszCCAVmgAwIBAgIUQ2E+/=
    -----END CERTIFICATE-----
    """

    var good: String {
        """
        # office
        server=vpn.example.com
        port=4443
        user=alice@corp.example
        cert=ca
        route_all=no
        peer_dns=yes
        <ca>
        \(pem)
        </ca>

        """
    }

    func validate(_ s: String) -> [ValidationIssue] { SSTPValidator().validate(s) }

    // MARK: Config

    func testParseAndSerializeRoundTrip() {
        let c = SSTPConfig.parse(good)
        XCTAssertEqual(c, SSTPConfig(server: "vpn.example.com", port: 4443, user: "alice@corp.example", cert: .ca,
                                     routeAll: false, peerDNS: true, caPEM: pem))
        XCTAssertEqual(SSTPConfig.parse(c.serialized()), c)
        XCTAssertEqual(validate(c.serialized()), [])
        XCTAssertEqual(SSTPConfig.certificateCount(in: pem + "\n" + pem), 2)
    }

    func testDefaultsAndCADroppedOutsideCAMode() {
        let c = SSTPConfig.parse("server=a.example\nuser=bob\n")
        XCTAssertEqual(c.port, 443)
        XCTAssertEqual(c.cert, .system)
        XCTAssertTrue(c.routeAll)
        XCTAssertTrue(c.peerDNS)
        var withCA = c
        withCA.caPEM = pem
        XCTAssertFalse(withCA.serialized().contains("<ca>"))
        withCA.cert = .ca
        XCTAssertTrue(withCA.serialized().contains("<ca>\n-----BEGIN CERTIFICATE-----"))
    }

    func testExtractCertificatesFromBundle() {
        let bundle = "subject=CN=Corp\r\n\(pem)\nissuer=x\n\(pem)\n"
        XCTAssertEqual(SSTPConfig.extractCertificates(from: bundle), pem + "\n" + pem)
        XCTAssertNil(SSTPConfig.extractCertificates(from: "no cert here"))
        XCTAssertNil(SSTPConfig.extractCertificates(from: "-----BEGIN CERTIFICATE-----\n$(id);\n-----END CERTIFICATE-----"))
        XCTAssertNil(SSTPConfig.extractCertificates(from: "-----BEGIN CERTIFICATE-----\nAAAA\n"))
    }

    func testSerializedHasNoPasswordKey() {
        XCTAssertFalse(SSTPConfig(server: "a", user: "b").serialized().contains("password"))
    }

    // MARK: Validator

    func testAcceptsGoodConfigAndMinimal() {
        XCTAssertEqual(validate(good), [])
        XCTAssertEqual(validate("server=10.0.0.1\nuser=bob\n"), [])
        XCTAssertEqual(validate("server=fd00::1\nuser=bob\ncert=insecure\n"), [])
        XCTAssertEqual(validate("server=vpn.example.com.\r\nuser=a.b_c+d-e\r\n"), [])
    }

    func testRequiredKeys() {
        XCTAssertEqual(validate("port=443\n").map(\.message), ["Missing key: server", "Missing key: user"])
    }

    func testRejectsUnknownAndPasswordKeys() {
        XCTAssertEqual(validate("server=a\nuser=b\npassword=x\n").map(\.line), [3])
        XCTAssertEqual(validate("server=a\nuser=b\npassword=x\n").first?.message, "Key not allowed: password")
        // Nem [a-z_] kulcs: az üzenet nem idézi.
        XCTAssertEqual(validate("server=a\nuser=b\nX-Y=1\n").first?.message, "Key not allowed")
        XCTAssertEqual(validate("server=a\nuser=b\nfoo bar\n").first?.message, "Invalid line")
        XCTAssertEqual(validate("server=a\nuser=b\nuser=c\n").map(\.line), [3])
    }

    func testStrictServer() {
        for bad in ["vpn example.com", "\"vpn\"", "-vpn.example.com", "vpn.example.com:443", "[fd00::1]",
                    "1.2.3", "999.1.1.1", "a..b", "a;b", "$(id)", "a/b", "ünnep.hu", String(repeating: "a", count: 254)] {
            let issues = validate("server=\(bad)\nuser=bob\n")
            XCTAssertEqual(issues.map(\.line), [1], "nem utasította el: \(bad)")
            XCTAssertFalse(issues.first?.message.contains(bad) ?? true, "az üzenet idézi az értéket")
        }
        XCTAssertTrue(SSTPValidator.isValidServer("2001:db8::8a2e:370:7334"))
        XCTAssertFalse(SSTPValidator.isValidServer("2001:db8:::1"))
    }

    func testRejectsUnspecifiedAndLoopbackServers() {
        for bad in ["0.0.0.0", "127.0.0.1", "127.8.9.10", "::", "::1", "0:0:0:0:0:0:0:1", "0:0::0", "localhost", "LOCALHOST."] {
            XCTAssertFalse(SSTPValidator.isValidServer(bad), bad)
            XCTAssertEqual(validate("server=\(bad)\nuser=bob\n").map(\.line), [1], bad)
        }
        XCTAssertTrue(SSTPValidator.isValidServer("128.0.0.1"))
        XCTAssertTrue(SSTPValidator.isValidServer("::2"))
        XCTAssertTrue(SSTPValidator.isValidServer("1.2.3.4"))
    }

    func testPasswordRule() {
        for good in ["", "S3cret!pw", "pässwörd €", "a'b$c`d;e|f&g*h?i(j)k{l}m<n>o#p%q ~ space"] {
            XCTAssertTrue(SSTPConfig.isAcceptablePassword(good), good)
        }
        for bad in ["a\"b", "a\\b", "a\nb", "a\rb", "a\tb", "a\u{0}b", "a\u{7F}b", "a\u{85}b", "\"\nplugin /tmp/x.so\n\""] {
            XCTAssertFalse(SSTPConfig.isAcceptablePassword(bad), bad.debugDescription)
        }
        XCTAssertEqual(SSTPConfig.passwordRuleMessage,
                       "The SSTP password must not contain quotation marks, backslashes or control characters")
        AppLanguage.override = .hu
        XCTAssertEqual(SSTPConfig.passwordRuleMessage, "Az SSTP jelszóban nem lehet idézőjel, fordított perjel és vezérlőkarakter")
    }

    func testStrictPort() {
        for bad in ["0", "65536", "-1", "44 3", "abc", "443x", "999999"] {
            XCTAssertEqual(validate("server=a\nport=\(bad)\nuser=b\n").map(\.line), [2], "nem utasította el: \(bad)")
        }
        XCTAssertEqual(validate("server=a\nport=65535\nuser=b\n"), [])
    }

    func testUserCharset() {
        for bad in ["bob smith", "\"bob\"", "bob'", "-bob", "b$ob", "b;ob", "", String(repeating: "a", count: 129),
                    ".", "..", "...", "bob.", "corp.example."] {
            XCTAssertEqual(validate("server=a\nuser=\(bad)\n").map(\.line), [2], "nem utasította el: \(bad)")
        }
        XCTAssertEqual(validate("server=a\nuser=DOMAIN\\bob\n").first?.message, "Character not allowed: \\")
        XCTAssertTrue(SSTPValidator.isValidUser(".bob"))
        XCTAssertTrue(SSTPValidator.isValidUser("bob.smith@corp.example"))
    }

    func testEnumsAndControlCharacters() {
        XCTAssertEqual(validate("server=a\nuser=b\ncert=none\n").first?.message, "Invalid value for cert: allowed: system, ca, insecure")
        XCTAssertEqual(validate("server=a\nuser=b\nroute_all=true\n").map(\.line), [3])
        XCTAssertEqual(validate("server=a\nuser=b\npeer_dns=YES\n").map(\.line), [3])
        XCTAssertEqual(validate("server=a\u{01}\nuser=b\n").first?.message, "Control character not allowed")
        XCTAssertEqual(validate("server=a\nuser=b\u{7F}\n").map(\.line), [2, 0])
    }

    func testCABlockRules() {
        XCTAssertEqual(validate("server=a\nuser=b\ncert=ca\n").map(\.message), ["cert=ca requires a <ca> block with a PEM certificate"])
        XCTAssertEqual(validate("server=a\nuser=b\n<ca>\n\(pem)\n").map(\.message), ["Unclosed inline block: ca"])
        XCTAssertEqual(validate("server=a\nuser=b\n<ca>\nrm -rf /;\n</ca>\n").map(\.line), [4])
        XCTAssertEqual(validate("server=a\nuser=b\n<ca>\n</ca>\n<ca>\n</ca>\n").map(\.line), [5])
        // A blokk cert=ca nélkül nem hiba (a serialize úgyis elhagyja), és a blokkon belüli "server=" nem kulcs.
        XCTAssertEqual(validate("server=a\nuser=b\n<ca>\n\(pem)\n</ca>\n"), [])
    }

    func testRootParameters() {
        XCTAssertEqual(SSTPValidator.parameters(in: good), ["vpn.example.com", "4443", "alice@corp.example", "ca", "no", "yes"])
        XCTAssertEqual(SSTPValidator.parameters(in: "server=a.b\nuser=c\n"), ["a.b", "443", "c", "system", "yes", "yes"])
        XCTAssertNil(SSTPValidator.parameters(in: "server=a b\nuser=c\n"))
        XCTAssertEqual(SSTPValidator.caPEM(in: good), pem)
        XCTAssertNil(SSTPValidator.caPEM(in: "server=a.b\nuser=c\n"))
    }

    func testHungarianMessages() {
        AppLanguage.override = .hu
        XCTAssertEqual(validate("server=a\nport=0\nuser=b\n").first?.display, "2. sor: Érvénytelen port: 1–65535")
    }

    func testRegisteredValidator() {
        XCTAssertTrue(Validators.validator(for: .sstp) is SSTPValidator)
        XCTAssertEqual(VPNKind.sstp.displayName, "SSTP")
        XCTAssertFalse(VPNKind.sstp.isNative)
    }

    // MARK: Import / export / template / setup

    func testImportDetection() throws {
        XCTAssertEqual(try ConfigImporter.kind(fileName: "x.sstp", content: ""), .sstp)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "x.txt", content: good), .sstp)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "x.txt", content: "server=a\nuser=b\n"), .sstp)
        XCTAssertNil(ConfigImporter.detectKind(fileName: "x.txt", content: "server = a\n"))
    }

    func testTemplateParsesAndExportFileName() {
        let t = ConfigImporter.template(for: .sstp)
        XCTAssertEqual(SSTPConfig.parse(t).server, "vpn.example.com")
        // A sablonban a felhasználónév üres: ki kell tölteni, különben nem menthető.
        XCTAssertEqual(validate(t).map(\.line), [3])
        XCTAssertEqual(ConfigExporter.fileName(for: Connection(name: "Iroda", kind: .sstp)), "Iroda.sstp")
    }

    func testExportIsConfigWithoutPassword() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: base) }
        let store = ConnectionStore(baseURL: base)
        let c = Connection(name: "S", kind: .sstp)
        try store.save(c, config: good)
        let data = try ConfigExporter.export(c, store: store)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), good)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: ConfigExporter.fileName(for: c), content: good), .sstp)
    }

    func testSetupRequiresSstpcOnlyForSSTP() {
        XCTAssertEqual(SetupChecker.requiredTools.first { $0.kind == .sstp }?.tools, ["sstpc"])
        XCTAssertTrue(SetupChecker.brewPackages.contains("sstp-client"))
        XCTAssertTrue(SetupChecker.candidates(tool: "sstpc", prefix: "/opt/homebrew").contains("/opt/homebrew/sbin/sstpc"))
        let r = SetupReport(brewPrefix: "/opt/homebrew", missingTools: ["sstpc"], installedRootVersion: "3",
                            bundledRootVersion: "3", sudoWorks: true)
        XCTAssertFalse(r.isAvailable(.sstp))
        XCTAssertTrue(r.isAvailable(.openvpn))
    }
}
