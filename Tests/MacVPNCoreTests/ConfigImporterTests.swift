import XCTest
@testable import MacVPNCore

final class ConfigImporterTests: XCTestCase {
    func testDetectKind() {
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "a.ovpn", content: ""), .openvpn)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "wg0.conf", content: "[Interface]\nPrivateKey = x\n"), .wireguard)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "s.conf", content: "connections {\n}\n"), .strongswan)
        XCTAssertEqual(ConfigImporter.detectKind(fileName: "c.conf", content: "client\nremote a 1194\n"), .openvpn)
        XCTAssertNil(ConfigImporter.detectKind(fileName: "x.txt", content: "hello"))
    }

    func testMobileconfigIsRejectedWithFinderHint() {
        XCTAssertThrowsError(try ConfigImporter.kind(fileName: "Office.mobileconfig", content: "<?xml version=\"1.0\"?><plist/>")) {
            XCTAssertEqual($0 as? ConfigImportError, .nativeProfile)
        }
        XCTAssertThrowsError(try ConfigImporter.kind(fileName: "x.txt", content: "hello")) {
            XCTAssertEqual($0 as? ConfigImportError, .unknownType)
        }
        XCTAssertEqual(try ConfigImporter.kind(fileName: "a.ovpn", content: ""), .openvpn)

        AppLanguage.override = .en
        defer { AppLanguage.override = nil }
        XCTAssertEqual(ConfigImportError.nativeProfile.localizedDescription,
                       "A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles).")
        AppLanguage.override = .hu
        XCTAssertEqual(ConfigImportError.nativeProfile.localizedDescription,
                       "A .mobileconfig profil nem importálható a MacVPN-be. Kattints rá duplán a Finderben: a macOS profilként telepíti, utána a Rendszerbeállítások → Általános → Eszközkezelés (Profilok) alatt hagyd jóvá.")
    }

    static let cert = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
    static let key = "-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----\n"
    static let staticKey = "#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\nabcdef\n-----END OpenVPN Static key V1-----\n"
    static let v2Key = "-----BEGIN OpenVPN tls-crypt-v2 client key-----\nabc\n-----END OpenVPN tls-crypt-v2 client key-----\n"
    static let dh = "-----BEGIN DH PARAMETERS-----\nMIIBfake\n-----END DH PARAMETERS-----\n"

    var root: URL!
    var dir: URL!

    override func setUpWithError() throws {
        // realpath: a /var -> /private/var symlink se zavarja az összehasonlítást.
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        dir = root.appendingPathComponent("vpn")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    func put(_ name: String, _ content: String, in base: URL? = nil) throws {
        try content.write(to: (base ?? dir).appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    func testInlinesReferencedFiles() throws {
        try put("ca.crt", Self.cert)
        try put("ta.key", Self.staticKey)
        let input = "remote a 1\nca \"ca.crt\"\ntls-auth ta.key 1\nauth-user-pass creds.txt\n"
        let out = try ConfigImporter.inlineOpenVPNFiles(input, baseDirectory: dir)
        XCTAssertEqual(out.config, "remote a 1\n<ca>\n\(Self.cert.dropLast())\n</ca>\n<tls-auth>\n\(Self.staticKey.dropLast())\n</tls-auth>\nkey-direction 1\nauth-user-pass\n")
        XCTAssertEqual(out.inlinedFiles, ["ca.crt", "ta.key"])
        XCTAssertEqual(OpenVPNValidator().validate(out.config), [])
    }

    func testInlinesEveryDirectiveWithItsFormat() throws {
        try put("ca.crt", Self.cert)
        try put("c.crt", Self.cert)
        try put("c.key", Self.key)
        try put("tc.key", Self.staticKey)
        try put("v2.key", Self.v2Key)
        try put("dh.pem", Self.dh)
        try put("rsa.key", "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n")
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("sub"), withIntermediateDirectories: true)
        try put("sub/extra.crt", Self.cert)
        let input = "remote a 1\nca ca.crt\ncert c.crt\nkey c.key\ntls-crypt tc.key\ntls-crypt-v2 v2.key\ndh dh.pem\nextra-certs sub/extra.crt\nsecret tc.key\n"
        let out = try ConfigImporter.inlineOpenVPNFiles(input, baseDirectory: dir)
        XCTAssertEqual(out.inlinedFiles, ["ca.crt", "c.crt", "c.key", "tc.key", "v2.key", "dh.pem", "sub/extra.crt", "tc.key"])
        XCTAssertTrue(out.config.contains("<tls-crypt-v2>\n-----BEGIN OpenVPN tls-crypt-v2 client key-----"))
        XCTAssertEqual(try ConfigImporter.inlineOpenVPNFiles("key rsa.key\n", baseDirectory: dir).inlinedFiles, ["rsa.key"])
        XCTAssertEqual(try ConfigImporter.inlineOpenVPNFiles("dh none\n", baseDirectory: dir).config, "dh none\n")
    }

    func testAbsolutePathInsideBaseIsAllowed() throws {
        try put("ca.crt", Self.cert)
        let out = try ConfigImporter.inlineOpenVPNFiles("ca \(dir.path)/ca.crt\n", baseDirectory: dir)
        XCTAssertEqual(out.inlinedFiles, ["\(dir.path)/ca.crt"])
    }

    func assertRejected(_ line: String, _ expected: ConfigImportError, file: StaticString = #filePath, lineNo: UInt = #line) {
        XCTAssertThrowsError(try ConfigImporter.inlineOpenVPNFiles(line + "\n", baseDirectory: dir), file: file, line: lineNo) {
            XCTAssertEqual($0 as? ConfigImportError, expected, file: file, line: lineNo)
        }
    }

    func testParentDirectoryEscapeIsRejected() throws {
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".ssh"), withIntermediateDirectories: true)
        try put("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n",
                in: root.appendingPathComponent(".ssh"))
        assertRejected("key ../.ssh/id_ed25519", .outsideBaseDirectory("../.ssh/id_ed25519"))
        assertRejected("ca sub/../../.ssh/id_ed25519", .outsideBaseDirectory("sub/../../.ssh/id_ed25519"))
    }

    func testAbsolutePathOutsideBaseIsRejected() {
        assertRejected("ca /etc/hosts", .outsideBaseDirectory("/etc/hosts"))
    }

    func testSymlinkEscapingBaseIsRejected() throws {
        try put("outside.crt", Self.cert, in: root)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("ca.crt"),
                                                   withDestinationURL: root.appendingPathComponent("outside.crt"))
        assertRejected("ca ca.crt", .outsideBaseDirectory("ca.crt"))
        // Könyvtár-symlink is.
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("up"), withDestinationURL: root)
        assertRejected("ca up/outside.crt", .outsideBaseDirectory("up/outside.crt"))
    }

    func testWrongFormatIsRejected() throws {
        try put("hosts", "127.0.0.1 localhost\n")
        try put("ca.crt", Self.cert)
        try put("c.key", Self.key)
        assertRejected("ca hosts", .wrongFormat(directive: "ca", file: "hosts"))
        assertRejected("key ca.crt", .wrongFormat(directive: "key", file: "ca.crt"))
        assertRejected("ca c.key", .wrongFormat(directive: "ca", file: "c.key"))
        assertRejected("tls-auth c.key", .wrongFormat(directive: "tls-auth", file: "c.key"))
        assertRejected("tls-crypt-v2 ca.crt", .wrongFormat(directive: "tls-crypt-v2", file: "ca.crt"))
        assertRejected("dh ca.crt", .wrongFormat(directive: "dh", file: "ca.crt"))
        // A fájl tartalma nem zárhatja le a blokkot (direktíva-csempészés).
        try put("evil.crt", Self.cert + "</ca>\nup /tmp/x\n<ca>\n")
        assertRejected("ca evil.crt", .wrongFormat(directive: "ca", file: "evil.crt"))
    }

    func testOversizeFileIsRejected() throws {
        let big = Self.cert + String(repeating: "#", count: ConfigImporter.maxInlineFileSize)
        try put("big.crt", big)
        assertRejected("ca big.crt", .fileTooLarge("big.crt"))
    }

    func testDirectoryAndMissingFileAreRejected() throws {
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("d"), withIntermediateDirectories: true)
        assertRejected("ca d", .missingFile("d"))
        assertRejected("ca nope.crt", .missingFile("nope.crt"))
    }

    func testPrepareValidatesButKeepsTheConfig() throws {
        try put("ca.crt", Self.cert)
        let ok = try ConfigImporter.prepare(fileName: "a.ovpn", content: "client\nremote a 1194\nca ca.crt\n", baseDirectory: dir)
        XCTAssertEqual(ok.kind, .openvpn)
        XCTAssertEqual(ok.inlinedFiles, ["ca.crt"])
        XCTAssertEqual(ok.issues, [])
        let bad = try ConfigImporter.prepare(fileName: "b.ovpn", content: "client\nremote a 1194\nup /tmp/x\n", baseDirectory: dir)
        XCTAssertEqual(bad.config, "client\nremote a 1194\nup /tmp/x\n")
        XCTAssertEqual(bad.issues.map(\.line), [3])
        let wg = try ConfigImporter.prepare(fileName: "wg.conf", content: "[Interface]\nPrivateKey = x\nPostUp = rm -rf /\n", baseDirectory: dir)
        XCTAssertEqual(wg.kind, .wireguard)
        XCTAssertFalse(wg.issues.isEmpty)
        XCTAssertEqual(wg.inlinedFiles, [])
    }

    func testImportErrorsAreLocalized() {
        AppLanguage.override = .hu
        defer { AppLanguage.override = nil }
        XCTAssertEqual(ConfigImportError.outsideBaseDirectory("../x").localizedDescription,
                       "A hivatkozott fájl a config mappáján kívül van: ../x")
        XCTAssertEqual(ConfigImportError.fileTooLarge("x").localizedDescription, "A hivatkozott fájl nagyobb 1 MB-nál: x")
        XCTAssertEqual(ConfigImportError.wrongFormat(directive: "ca", file: "x").localizedDescription,
                       "A(z) ca direktíva fájlja (x) nem a várt formátumú")
    }

    func testTemplatesForTextKindsAreValidShape() {
        XCTAssertFalse(ConfigImporter.template(for: .openvpn).isEmpty)
        XCTAssertNotNil(StrongSwanValidator.names(in: ConfigImporter.template(for: .strongswan)))
        XCTAssertEqual(ConfigImporter.template(for: .l2tp), "")
    }
}
