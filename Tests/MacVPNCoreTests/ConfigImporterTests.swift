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

    func testInlinesReferencedFiles() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "CA-DATA\n".write(to: dir.appendingPathComponent("ca.crt"), atomically: true, encoding: .utf8)
        try "TA-DATA".write(to: dir.appendingPathComponent("ta.key"), atomically: true, encoding: .utf8)
        let input = "remote a 1\nca \"ca.crt\"\ntls-auth ta.key 1\nauth-user-pass creds.txt\n"
        let out = try ConfigImporter.inlineOpenVPNFiles(input, baseDirectory: dir)
        XCTAssertEqual(out, "remote a 1\n<ca>\nCA-DATA\n</ca>\n<tls-auth>\nTA-DATA\n</tls-auth>\nkey-direction 1\nauth-user-pass\n")
        XCTAssertEqual(OpenVPNValidator().validate(out), [])
    }

    func testInlineMissingFileThrows() {
        XCTAssertThrowsError(try ConfigImporter.inlineOpenVPNFiles("ca nope.crt\n", baseDirectory: URL(fileURLWithPath: "/tmp")))
    }

    func testTemplatesForTextKindsAreValidShape() {
        XCTAssertFalse(ConfigImporter.template(for: .openvpn).isEmpty)
        XCTAssertNotNil(StrongSwanValidator.names(in: ConfigImporter.template(for: .strongswan)))
        XCTAssertEqual(ConfigImporter.template(for: .l2tp), "")
    }
}
