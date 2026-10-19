import XCTest
@testable import MacVPNCore

final class LocalizationTests: XCTestCase {
    override func tearDown() {
        AppLanguage.override = nil
        super.tearDown()
    }

    /// A Swift csomag gyökere (legacy/swift, a tesztfájl helyéből).
    static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    /// A teljes repó gyökere (Tests/Fixtures, docs, scripts): a legacy/swift két szinttel feljebb.
    static let projectRoot = repoRoot.deletingLastPathComponent().deletingLastPathComponent()

    // MARK: Nyelvválasztás

    func testResolvePicksFirstHungarianOrEnglishElseEnglish() {
        XCTAssertEqual(AppLanguage.resolve(preferred: ["hu-HU", "en-US"]), .hu)
        XCTAssertEqual(AppLanguage.resolve(preferred: ["en-GB", "hu"]), .en)
        XCTAssertEqual(AppLanguage.resolve(preferred: ["de-DE", "hu-HU"]), .hu)
        XCTAssertEqual(AppLanguage.resolve(preferred: ["de-DE", "fr"]), .en)
        XCTAssertEqual(AppLanguage.resolve(preferred: ["hr-HR"]), .en)
        XCTAssertEqual(AppLanguage.resolve(preferred: []), .en)
    }

    func testLangArgumentUnknownMeansEnglish() {
        XCTAssertEqual(AppLanguage(argument: "hu"), .hu)
        XCTAssertEqual(AppLanguage(argument: "en"), .en)
        XCTAssertEqual(AppLanguage(argument: "de"), .en)
        XCTAssertEqual(AppLanguage(argument: ""), .en)
    }

    // MARK: Validátor-üzenetek

    func testValidatorMessageFollowsLanguage() {
        AppLanguage.override = .en
        let en = OpenVPNValidator().validate("remote a 1\nup /x\n")
        XCTAssertEqual(en.first?.message, "Forbidden directive: up – delete the line or comment it out (#)")
        XCTAssertEqual(en.first?.display, "Line 2: Forbidden directive: up – delete the line or comment it out (#)")

        AppLanguage.override = .hu
        let hu = OpenVPNValidator().validate("remote a 1\nup /x\n")
        XCTAssertEqual(hu.first?.message, "Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort")
        XCTAssertEqual(hu.first?.display, "2. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort")
    }

    func testExplicitLanguageParameter() {
        XCTAssertEqual(L10n.tr("Missing remote directive", language: .en), "Missing remote directive")
        XCTAssertEqual(L10n.tr("Missing remote directive", language: .hu), "Hiányzik a remote direktíva")
        XCTAssertEqual(L10n.tr("Line %ld: %@", 3, "x", language: .hu), "3. sor: x")
    }

    func testMvpnClientPassesLanguage() async throws {
        let mock = MockCommandRunner()
        _ = try? await MvpnClient(runner: mock, language: .hu).status()
        _ = try? await MvpnClient(runner: mock, language: .en).status()
        XCTAssertEqual(mock.calls.map(\.commandLine), [
            "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu",
            "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang en",
        ])
    }

    // MARK: A Core tábla lefedettsége

    /// Formátum-jelölők (`%@`, `%ld`, `%d`, pozicionális alakban is) multihalmaza, pozíció nélkül.
    static func specifiers(_ s: String) -> [String] {
        let regex = try! NSRegularExpression(pattern: "%(?:[0-9]+\\$)?(l{0,2}[dfu]|@)")
        let ns = s as NSString
        return regex.matches(in: s, range: NSRange(location: 0, length: ns.length))
            .map { ns.substring(with: $0.range(at: 1)) }.sorted()
    }

    func testCoreTableHasBothLanguagesForEveryKey() {
        XCTAssertFalse(L10n.hungarian.isEmpty)
        for (key, hu) in L10n.hungarian {
            XCTAssertFalse(key.isEmpty)
            XCTAssertFalse(hu.trimmingCharacters(in: .whitespaces).isEmpty, "üres magyar fordítás: \(key)")
            XCTAssertEqual(Self.specifiers(key), Self.specifiers(hu), "eltérő formátum-jelölők: \(key)")
        }
    }

    /// Minden `L10n.tr("…")` hívás kulcsa szerepel a táblában (Core és mvpn-validate forrás).
    func testEveryCoreCallSiteHasATranslation() throws {
        let dirs = ["Sources/MacVPNCore", "Sources/mvpn-validate"].map { Self.repoRoot.appendingPathComponent($0) }
        let call = try NSRegularExpression(pattern: #"L10n\.tr\(\s*"((?:[^"\\]|\\.)*)""#)
        var found = 0
        for dir in dirs {
            let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "swift" }
            for file in files {
                let source = try String(contentsOf: file, encoding: .utf8)
                let ns = source as NSString
                for m in call.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                    let key = ns.substring(with: m.range(at: 1))
                        .replacingOccurrences(of: "\\n", with: "\n")
                        .replacingOccurrences(of: "\\\\", with: "\\")
                    found += 1
                    XCTAssertNotNil(L10n.hungarian[key], "nincs magyar fordítás (\(file.lastPathComponent)): \(key)")
                }
            }
        }
        XCTAssertGreaterThan(found, 50)
    }

    // MARK: Az app String Catalogja

    func testAppCatalogHasHungarianForEveryKey() throws {
        let url = Self.repoRoot.appendingPathComponent("Sources/MacVPN/Resources/Localizable.xcstrings")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        XCTAssertEqual(json["sourceLanguage"] as? String, "en")
        let strings = try XCTUnwrap(json["strings"] as? [String: Any])
        XCTAssertGreaterThan(strings.count, 100)
        for (key, value) in strings {
            let entry = value as? [String: Any]
            let hu = ((entry?["localizations"] as? [String: Any])?["hu"] as? [String: Any])?["stringUnit"] as? [String: Any]
            let text = hu?["value"] as? String ?? ""
            XCTAssertFalse(text.isEmpty, "nincs magyar fordítás: \(key)")
            XCTAssertEqual(hu?["state"] as? String, "translated", key)
            XCTAssertEqual(Self.specifiers(key), Self.specifiers(text), "eltérő formátum-jelölők: \(key)")
        }
    }
}
