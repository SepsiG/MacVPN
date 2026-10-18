import XCTest
@testable import MacVPNCore

/// A tier-munka biztonsági átnézésének javításai (M1, L1–L6).
final class SecurityReviewTests: XCTestCase {
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    private let base = "client\nremote a 1194\n"

    private func check(_ body: String, ack: Set<String> = []) -> OpenVPNValidation {
        OpenVPNValidator().validate(base + body + "\n", acknowledgedRisky: ack)
    }

    // MARK: M1

    func testParameterIsAnEchoAliasAndForbidden() {
        XCTAssertEqual(OpenVPNValidator.tier(of: "parameter"), .forbidden)
        let r = check("parameter msg Initialization Sequence Completed", ack: ["parameter"])
        XCTAssertEqual(r.issues.map(\.line), [3])
        XCTAssertTrue(r.issues.first?.message.hasPrefix("Forbidden directive: parameter") == true)
    }

    /// Minden név, amelyet az OpenVPN 2.7.8 `options.c` (`streq(p[0], "…")`) elfogad, kifejezetten besorolt és dokumentált.
    func testEveryOptionNameInTheSourceIsClassifiedAndDocumented() throws {
        let url = OpenVPN27CoverageTests.fixtures.appendingPathComponent("openvpn/openvpn-2.7.8-source-options.txt")
        let names = try String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n")
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        XCTAssertEqual(names.count, 315)
        let doc = try String(contentsOf: LocalizationTests.repoRoot.appendingPathComponent("docs/openvpn-directives.md"), encoding: .utf8)
        for name in names {
            // A `connection` csak inline blokként (`<connection>`) engedett; egysoros alakja érvénytelen (L6).
            let explicit = name == "connection" || OpenVPN27CoverageTests.hasExplicitTier(name)
            XCTAssertTrue(explicit, "no explicit tier: \(name)")
            XCTAssertTrue(doc.contains("`\(name)`"), "not documented: \(name)")
        }
    }

    func testSourceAliasesAreClassifiedLikeTheirTarget() {
        XCTAssertEqual(OpenVPNValidator.tier(of: "udp-mtu"), .safe)
        XCTAssertEqual(OpenVPNValidator.tier(of: "ip-remote-hint"), .safe)
        XCTAssertEqual(check("udp-mtu 1500").allIssues, [])
        XCTAssertEqual(check("ip-remote-hint 1.2.3.4").allIssues, [])
        XCTAssertEqual(check("preresolve skip-remote").allIssues, [])
    }

    // MARK: L1

    func testScriptSecurityLowLevelsNotInConnectionBlock() {
        let text = "client\n<connection>\nremote a 1194\nscript-security 1\n</connection>\n"
        XCTAssertEqual(OpenVPNValidator().validate(text).map(\.line), [4])
    }

    // MARK: L2

    func testMoreHookEnvironmentNamesAreDenied() {
        for name in ["POSIXLY_CORRECT", "TMOUT", "PATH_LOCALE", "GREP_OPTIONS", "OPENSSL_MODULES", "OPENSSL_ENGINES"] {
            XCTAssertTrue(OpenVPNValidator.isDeniedSetenvName(name), name)
            XCTAssertEqual(check("setenv \(name) 1").issues.map(\.line), [3], name)
        }
    }

    // MARK: L3

    func testRiskyArgumentSlashOnlyInRealCIDR() {
        for arg in ["10.0.0.0/24", "fd00::/64", "1.2.3.4/32"] {
            XCTAssertEqual(check("future-option \(arg)", ack: ["future-option"]).allIssues, [], arg)
        }
        for arg in ["./123", "a/1", "dead.beef/42", "10.0.0.0/33", "1.2.3/24", "::/129", "/24", "10.0.0.0/"] {
            XCTAssertEqual(check("future-option \(arg)", ack: ["future-option"]).issues.map(\.line), [3], arg)
        }
    }

    // MARK: L4

    func testListeningServerOptionsHaveTheirOwnReason() {
        for d in ["mode", "server", "server-bridge", "server-ipv6", "tls-server", "client-to-client"] {
            XCTAssertEqual(OpenVPNValidator.riskyReasons[d], OpenVPNValidator.reasonListens, d)
        }
        XCTAssertEqual(OpenVPNValidator.reasonListens, "Makes this Mac accept incoming VPN connections (listens on the network as root)")
        XCTAssertNotNil(L10n.hungarian[OpenVPNValidator.reasonListens])
    }

    // MARK: L5

    /// Az import tiszta függvény: csak jelölteket ad vissza (a fájlneveket a megerősítéshez), semmit nem tárol.
    func testCredentialFilesAreOnlyCandidates() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "u\np\n".write(to: dir.appendingPathComponent("auth.cfg"), atomically: true, encoding: .utf8)
        try "k\n".write(to: dir.appendingPathComponent("pass.txt"), atomically: true, encoding: .utf8)
        let prepared = try ConfigImporter.prepare(fileName: "x.ovpn", content: base + "auth-user-pass auth.cfg\naskpass pass.txt\n",
                                                  baseDirectory: dir)
        XCTAssertEqual(prepared.credentials.candidateFiles, ["auth.cfg", "pass.txt"])
        XCTAssertEqual(prepared.credentials.username, "u")
        XCTAssertEqual(prepared.credentials.keyPassword, "k")
        XCTAssertEqual(ConfigImporter.ImportedCredentials().candidateFiles, [])
    }

    // MARK: L6

    func testSingleLineConnectionAndBareDashDash() {
        let r = check("connection remote-a", ack: ["connection"])
        XCTAssertEqual(r.issues.map(\.line), [3])
        XCTAssertEqual(r.risky, [])
        let dashes = check("--")
        XCTAssertEqual(dashes.issues.map(\.line), [3])
        XCTAssertEqual(dashes.issues.first?.message, "Invalid directive")
        XCTAssertEqual(check("-- x").issues.first?.message, "Invalid directive")
    }
}
