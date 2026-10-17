import XCTest
import CryptoKit
@testable import MacVPNCore

/// Hálózat nélküli HTTP kliens: URL → válasz.
final class MockHTTPClient: HTTPClient, @unchecked Sendable {
    private let lock = NSLock()
    var responses: [URL: HTTPResponse] = [:]
    private var _requested: [URL] = []
    var requested: [URL] { lock.withLock { _requested } }

    func get(_ url: URL) async throws -> HTTPResponse {
        lock.withLock { _requested.append(url) }
        return responses[url] ?? HTTPResponse(status: 404, data: Data())
    }

    func download(_ url: URL) async throws -> (file: URL, status: Int) {
        lock.withLock { _requested.append(url) }
        let r = responses[url] ?? HTTPResponse(status: 404, data: Data())
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("mock-dl-\(UUID().uuidString)")
        try r.data.write(to: file)
        return (file, r.status)
    }
}

/// `/bin/bash -n`: a script szintaktikailag helyes (nem futtatja).
func assertBashSyntax(_ script: String, file: StaticString = #filePath, line: UInt = #line) throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-syntax-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let url = dir.appendingPathComponent("s.sh")
    try script.write(to: url, atomically: true, encoding: .utf8)
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/bash")
    p.arguments = ["-n", url.path]
    let err = Pipe()
    p.standardError = err
    try p.run()
    p.waitUntilExit()
    let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    XCTAssertEqual(p.terminationStatus, 0, msg, file: file, line: line)
}

final class SemVerTests: XCTestCase {
    func testOrdering() {
        XCTAssertGreaterThan(SemVer("0.1.10")!, SemVer("0.1.9")!)
        XCTAssertGreaterThan(SemVer("1.0.0")!, SemVer("0.99.99")!)
        XCTAssertLessThan(SemVer("0.2")!, SemVer("0.2.1")!)
    }

    func testPrefixAndPrerelease() {
        XCTAssertEqual(SemVer("v1.0.0"), SemVer("1.0.0"))
        XCTAssertEqual(SemVer("1.2.3-beta.1"), SemVer("1.2.3"))
        XCTAssertEqual(SemVer("v1.2.3+build5"), SemVer("1.2.3"))
    }

    func testInvalid() {
        XCTAssertNil(SemVer(""))
        XCTAssertNil(SemVer("abc"))
        XCTAssertNil(SemVer("1..2"))
        XCTAssertNil(SemVer("1.2.3.4"))
        XCTAssertNil(SemVer("1.٣.0"))  // nem ASCII számjegy
    }
}

final class UpdateCheckerTests: XCTestCase {
    static let repoID: Int64 = 1422472799
    static let repo = "SepsiG/MacVPN"

    static func releaseJSON(tag: String = "v0.2.0", dmgURL: String = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                            sumURL: String = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256",
                            sigURL: String? = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig",
                            version: String = "0.2.0", htmlURL: String? = nil,
                            publishedAt: String? = "2026-10-01T12:00:00Z") -> Data {
        var json: [String: Any] = [
            "tag_name": tag,
            "body": "## Újdonságok\n- frissítés az appból",
            "html_url": htmlURL ?? "https://github.com/SepsiG/MacVPN/releases/tag/\(tag)",
            "draft": false, "prerelease": false,
            "assets": [
                ["name": "MacVPN-\(version).dmg.sha256", "browser_download_url": sumURL],
                ["name": "Source.zip", "browser_download_url": "https://github.com/x.zip"],
                ["name": "MacVPN-\(version).dmg", "browser_download_url": dmgURL],
            ],
        ]
        if let publishedAt { json["published_at"] = publishedAt }
        if let sigURL {
            json["assets"] = (json["assets"] as! [[String: String]]) + [["name": "MacVPN-\(version).dmg.sig", "browser_download_url": sigURL]]
        }
        return try! JSONSerialization.data(withJSONObject: json)
    }

    static func parse(_ data: Data, repo: String = repo) throws -> Release {
        try UpdateChecker.parseRelease(data, repo: repo)
    }

    func checker(_ http: MockHTTPClient) throws -> UpdateChecker {
        try UpdateChecker(repoID: Self.repoID, repo: Self.repo, http: http)
    }

    /// A lekérdezés a megváltoztathatatlan numerikus repo ID-vel megy, nem a (átvehető) névvel.
    func testLatestReleaseURLUsesImmutableRepoID() throws {
        let c = try checker(MockHTTPClient())
        XCTAssertEqual(c.latestReleaseURL.absoluteString, "https://api.github.com/repositories/1422472799/releases/latest")
        XCTAssertFalse(c.latestReleaseURL.absoluteString.contains("SepsiG"))
        XCTAssertThrowsError(try UpdateChecker(repoID: 0, repo: Self.repo, http: MockHTTPClient()))
        XCTAssertThrowsError(try UpdateChecker(repoID: -5, repo: Self.repo, http: MockHTTPClient()))
    }

    func testRepoIDKey() {
        XCTAssertEqual(UpdateChecker.repoIDInfoPlistKey, "MacVPNUpdateRepoID")
        XCTAssertEqual(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": "1422472799"]), 1422472799)
        XCTAssertEqual(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": " 1422472799 "]), 1422472799)
        XCTAssertEqual(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": NSNumber(value: 1422472799)]), 1422472799)
        XCTAssertEqual(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": 1422472799]), 1422472799)
        // Hiányzó vagy érvénytelen ID: nincs frissítés (nincs visszaesés a névre).
        XCTAssertNil(UpdateChecker.repoID(fromInfo: nil))
        XCTAssertNil(UpdateChecker.repoID(fromInfo: [:]))
        XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepo": "SepsiG/MacVPN"]))
        for bad in ["", "0", "-1", "abc", "12a", "1e9", "+12", "0x10", "١٢", "99999999999999999999", "12/34", "1 2"] {
            XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": bad]), bad)
        }
        XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": 0]))
        XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": -3]))
        XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": 1.5]))
        XCTAssertNil(UpdateChecker.repoID(fromInfo: ["MacVPNUpdateRepoID": true]))
    }

    /// A források együtt: az ID a lekérdezéshez, a név az asset útvonalak ellenőrzéséhez kell; bármelyik hiánya kikapcsol.
    func testSourceFromInfo() {
        let full: [String: Any] = ["MacVPNUpdateRepo": "SepsiG/MacVPN", "MacVPNUpdateRepoID": "1422472799"]
        XCTAssertEqual(UpdateChecker.source(fromInfo: full)?.id, 1422472799)
        XCTAssertEqual(UpdateChecker.source(fromInfo: full)?.repo, "SepsiG/MacVPN")
        XCTAssertNil(UpdateChecker.source(fromInfo: ["MacVPNUpdateRepo": "SepsiG/MacVPN"]))
        XCTAssertNil(UpdateChecker.source(fromInfo: ["MacVPNUpdateRepoID": "1422472799"]))
        XCTAssertNil(UpdateChecker.source(fromInfo: ["MacVPNUpdateRepo": "SepsiG/MacVPN", "MacVPNUpdateRepoID": "x"]))
    }

    /// A becsomagolt Info.plist a rögzített ID-t tartalmazza.
    func testBundledInfoPlistPinsRepoID() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Resources/Info.plist")
        let info = try XCTUnwrap(PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as? [String: Any])
        XCTAssertEqual(info["MacVPNUpdateRepoID"] as? String, "1422472799")
        XCTAssertEqual(UpdateChecker.source(fromInfo: info)?.id, 1422472799)
        XCTAssertEqual(UpdateChecker.source(fromInfo: info)?.repo, "SepsiG/MacVPN")
    }

    func testLatestReleaseParsesAssets() async throws {
        let http = MockHTTPClient()
        let checker = try checker(http)
        http.responses[checker.latestReleaseURL] = HTTPResponse(status: 200, data: Self.releaseJSON())
        let r = try await checker.latestRelease()
        XCTAssertEqual(http.requested, [URL(string: "https://api.github.com/repositories/1422472799/releases/latest")!])
        XCTAssertEqual(r.tag, "v0.2.0")
        XCTAssertEqual(r.version, "0.2.0")
        XCTAssertEqual(r.notes, "## Újdonságok\n- frissítés az appból")
        XCTAssertEqual(r.dmg.name, "MacVPN-0.2.0.dmg")
        XCTAssertEqual(r.checksum.name, "MacVPN-0.2.0.dmg.sha256")
        XCTAssertEqual(r.checksum.url.absoluteString, "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256")
        XCTAssertEqual(r.signature?.name, "MacVPN-0.2.0.dmg.sig")
        XCTAssertEqual(r.signature?.url.absoluteString, "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig")
        XCTAssertEqual(r.pageURL?.absoluteString, "https://github.com/SepsiG/MacVPN/releases/tag/v0.2.0")
        XCTAssertEqual(r.publishedAt, ISO8601DateFormatter().date(from: "2026-10-01T12:00:00Z"))
        XCTAssertTrue(r.isNewer(than: "0.1.0"))
        XCTAssertFalse(r.isNewer(than: "0.2.0"))
        XCTAssertFalse(r.isNewer(than: "0.10.0"))
    }

    func testHTTPErrors() async throws {
        let http = MockHTTPClient()
        let checker = try checker(http)
        do { _ = try await checker.latestRelease(); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .http(404)) }
        http.responses[checker.latestReleaseURL] = HTTPResponse(status: 200, data: Data("nem json".utf8))
        do { _ = try await checker.latestRelease(); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .invalidResponse) }
    }

    func testRejectsUntrustedAssetURLs() {
        for bad in ["http://github.com/a/MacVPN-0.2.0.dmg", "https://evil.example.com/MacVPN-0.2.0.dmg",
                    "https://github.com.evil.example/MacVPN-0.2.0.dmg", "https://user@github.com/MacVPN-0.2.0.dmg",
                    "https://github.com:8443/MacVPN-0.2.0.dmg",
                    "https://objects.githubusercontent.com/github-production-release-asset/1/MacVPN-0.2.0.dmg"] {
            XCTAssertThrowsError(try Self.parse(Self.releaseJSON(dmgURL: bad)), bad) {
                XCTAssertEqual($0 as? UpdateError, .untrustedURL(bad))
            }
        }
    }

    /// Az asset útvonala pontosan `/<owner>/<repo>/releases/download/<tag>/<név>` (owner/repo kis-nagybetű függetlenül).
    func testAssetPathMustMatchRepoTagAndName() {
        let base = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/"
        for bad in ["https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                    "https://github.com/SepsiG/Other/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                    "https://github.com/SepsiG/MacVPN/releases/download/v0.1.0/MacVPN-0.2.0.dmg",
                    base + "Other.dmg",
                    base + "MacVPN-0.2.0.dmg/x",
                    base + "MacVPN-0.2.0.dmg?x=1",
                    base + "MacVPN-0.2.0.dmg#frag",
                    "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/../v0.2.0/MacVPN-0.2.0.dmg",
                    "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0%2FMacVPN-0.2.0.dmg",
                    "https://github.com/SepsiG%2FMacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                    "https://github.com//SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                    "https://github.com/SepsiG/MacVPN/releases/v0.2.0/MacVPN-0.2.0.dmg"] {
            XCTAssertThrowsError(try Self.parse(Self.releaseJSON(dmgURL: bad)), bad) {
                XCTAssertEqual($0 as? UpdateError, .untrustedURL(bad))
            }
        }
        // A checksum assetre ugyanez vonatkozik.
        let badSum = "https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256"
        XCTAssertThrowsError(try Self.parse(Self.releaseJSON(sumURL: badSum))) {
            XCTAssertEqual($0 as? UpdateError, .untrustedURL(badSum))
        }
        // És a `.sig` assetre is.
        for badSig in ["https://github.com/Evil/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig",
                       "https://evil.example/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig",
                       "https://github.com/SepsiG/MacVPN/releases/download/v0.1.0/MacVPN-0.2.0.dmg.sig",
                       "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig?x=1"] {
            XCTAssertThrowsError(try Self.parse(Self.releaseJSON(sigURL: badSig)), badSig) {
                XCTAssertEqual($0 as? UpdateError, .untrustedURL(badSig))
            }
        }
        // Owner/repo kis-nagybetű függetlenül; a host is.
        XCTAssertNoThrow(try Self.parse(Self.releaseJSON(dmgURL: "https://GitHub.com/sepsig/macvpn/releases/download/v0.2.0/MacVPN-0.2.0.dmg")))
        XCTAssertNoThrow(try Self.parse(Self.releaseJSON(), repo: "sepsig/MACVPN"))
        // Más (érvényes) repóra állított app a SepsiG assetjeit nem fogadja el.
        XCTAssertThrowsError(try Self.parse(Self.releaseJSON(), repo: "Other/MacVPN"))
    }

    func testAssetURLPathCheckIsPure() {
        let ok = URL(string: "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg")!
        XCTAssertTrue(UpdateURLPolicy.isExpectedAsset(ok, repo: "SepsiG/MacVPN", tag: "v0.2.0", name: "MacVPN-0.2.0.dmg"))
        XCTAssertFalse(UpdateURLPolicy.isExpectedAsset(ok, repo: "SepsiG/MacVPN", tag: "v0.2.0", name: "MacVPN-0.2.0.DMG"))
        XCTAssertFalse(UpdateURLPolicy.isExpectedAsset(ok, repo: "SepsiG/MacVPN", tag: "V0.2.0", name: "MacVPN-0.2.0.dmg"))
        XCTAssertFalse(UpdateURLPolicy.isExpectedAsset(ok, repo: "SepsiG/MacVPNx", tag: "v0.2.0", name: "MacVPN-0.2.0.dmg"))
    }

    /// A release oldal linkje csak `https://github.com/<owner>/<repo>/releases/…` lehet; más esetben nincs link.
    func testHTMLURLHostAndPrefix() throws {
        XCTAssertEqual(try Self.parse(Self.releaseJSON()).pageURL?.absoluteString, "https://github.com/SepsiG/MacVPN/releases/tag/v0.2.0")
        for bad in ["https://evil.example/SepsiG/MacVPN/releases/tag/v0.2.0", "http://github.com/SepsiG/MacVPN/releases/tag/v0.2.0",
                    "https://github.com/Evil/MacVPN/releases/tag/v0.2.0", "https://github.com/SepsiG/MacVPN/issues/1",
                    "https://github.com/SepsiG/MacVPNx/releases/tag/v0.2.0",
                    "https://github.com/SepsiG/MacVPN/releases/../../../Evil/x",
                    "https://objects.githubusercontent.com/SepsiG/MacVPN/releases/tag/v0.2.0"] {
            XCTAssertNil(try Self.parse(Self.releaseJSON(htmlURL: bad)).pageURL, bad)
        }
    }

    func testMissingAssetsAndBadTags() {
        XCTAssertThrowsError(try Self.parse(Self.releaseJSON(version: "0.1.9"))) {
            XCTAssertEqual($0 as? UpdateError, .missingAsset("MacVPN-0.2.0.dmg"))
        }
        XCTAssertThrowsError(try Self.parse(Self.releaseJSON(tag: "v0.2.0/../x")))
        XCTAssertThrowsError(try Self.parse(Self.releaseJSON(tag: "nightly")))
    }

    /// Opcionális késleltetés: csak a legalább 24 órája közzétett kiadást ajánlja fel.
    func testMinimumAge() throws {
        let published = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-10-01T12:00:00Z"))
        let r = try Self.parse(Self.releaseJSON())
        XCTAssertEqual(UpdateChecker.minimumReleaseAge, 24 * 60 * 60)
        XCTAssertFalse(r.isOldEnough(minimumAge: UpdateChecker.minimumReleaseAge, now: published))
        XCTAssertFalse(r.isOldEnough(minimumAge: UpdateChecker.minimumReleaseAge, now: published.addingTimeInterval(23 * 3600 + 3599)))
        XCTAssertTrue(r.isOldEnough(minimumAge: UpdateChecker.minimumReleaseAge, now: published.addingTimeInterval(24 * 3600)))
        XCTAssertTrue(r.isOldEnough(minimumAge: 0, now: published.addingTimeInterval(-60)))
        // Közzétételi idő nélkül (vagy hibással) a késleltetés bekapcsolva nem ajánl fel semmit.
        let undated = try Self.parse(Self.releaseJSON(publishedAt: nil))
        XCTAssertNil(undated.publishedAt)
        XCTAssertFalse(undated.isOldEnough(minimumAge: UpdateChecker.minimumReleaseAge, now: published.addingTimeInterval(1e7)))
        XCTAssertTrue(undated.isOldEnough(minimumAge: 0, now: published))
        XCTAssertNil(try Self.parse(Self.releaseJSON(publishedAt: "tegnap")).publishedAt)
    }

    /// Mit ajánl fel az app: újabb verzió, és ha a késleltetés be van kapcsolva, legalább 24 órás.
    func testOfferDecision() throws {
        let published = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-10-01T12:00:00Z"))
        let r = try Self.parse(Self.releaseJSON())
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.1.0", delayed: false, now: published), .offer)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.2.0", delayed: false, now: published), .upToDate)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.1.0", delayed: true, now: published.addingTimeInterval(3600)), .tooRecent)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.1.0", delayed: true, now: published.addingTimeInterval(86400)), .offer)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.2.0", delayed: true, now: published), .upToDate)
    }

    /// `.sig` asset nélküli (még nem aláírt) kiadást nem ajánl fel; régebbi aláíratlan kiadás „naprakész”.
    func testReleaseWithoutSignatureAssetIsNotOffered() throws {
        let published = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-10-01T12:00:00Z"))
        let r = try Self.parse(Self.releaseJSON(sigURL: nil))
        XCTAssertNil(r.signature)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.1.0", delayed: false, now: published), .awaitingSignature)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.1.0", delayed: true, now: published.addingTimeInterval(86400)),
                       .awaitingSignature)
        XCTAssertEqual(UpdateChecker.offer(r, currentVersion: "0.2.0", delayed: false, now: published), .upToDate)
        XCTAssertEqual(UpdateError.unsignedUpdate.errorDescription, L10n.tr("The update is not signed by the MacVPN maintainer"))
        XCTAssertEqual(L10n.tr("The update is not signed by the MacVPN maintainer", language: .hu),
                       "A frissítést nem a MacVPN fejlesztője írta alá")
    }

    func testRepoKey() {
        XCTAssertEqual(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "SepsiG/MacVPN"]), "SepsiG/MacVPN")
        XCTAssertNil(UpdateChecker.repo(fromInfo: nil))
        XCTAssertNil(UpdateChecker.repo(fromInfo: [:]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": ""]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a/b/c"]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a/.."]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a b/c"]))
        XCTAssertThrowsError(try UpdateChecker(repoID: Self.repoID, repo: "x?y=1/z", http: MockHTTPClient()))
    }

    func testURLPolicy() {
        XCTAssertTrue(UpdateURLPolicy.isAllowedRedirect(URL(string: "https://release-assets.githubusercontent.com/x")!))
        XCTAssertTrue(UpdateURLPolicy.isAllowedRedirect(URL(string: "https://objects.githubusercontent.com/x")!))
        XCTAssertTrue(UpdateURLPolicy.isAllowedRedirect(URL(string: "https://api.github.com/repositories/1/releases/latest")!))
        XCTAssertFalse(UpdateURLPolicy.isAllowedDownload(URL(string: "https://release-assets.githubusercontent.com/x")!))
        XCTAssertFalse(UpdateURLPolicy.isAllowedDownload(URL(string: "https://objects.githubusercontent.com/x")!))
        XCTAssertTrue(UpdateURLPolicy.isAllowedDownload(URL(string: "https://github.com/x")!))
        XCTAssertFalse(UpdateURLPolicy.isAllowedRedirect(URL(string: "http://objects.githubusercontent.com/x")!))
        XCTAssertFalse(UpdateURLPolicy.isAllowedRedirect(URL(string: "https://example.com/x")!))
    }

    func testUserGuideURL() {
        XCTAssertEqual(UserGuide.url(repo: "SepsiG/MacVPN", preferredLanguages: ["hu-HU", "en-US"]).absoluteString,
                       "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.hu.md")
        XCTAssertEqual(UserGuide.url(repo: "SepsiG/MacVPN", preferredLanguages: ["en-US", "hu-HU"]).absoluteString,
                       "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.en.md")
        XCTAssertEqual(UserGuide.url(repo: nil, preferredLanguages: ["hu"]).absoluteString,
                       "https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.hu.md")
        XCTAssertEqual(UserGuide.language(preferred: []), "en")
        XCTAssertEqual(UserGuide.language(preferred: ["hr-HR"]), "en")
    }
}

final class UpdateInstallerTests: XCTestCase {
    var cache: URL!

    override func setUpWithError() throws {
        cache = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-update-test-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: cache)
    }

    func release() throws -> Release { try UpdateCheckerTests.parse(UpdateCheckerTests.releaseJSON()) }

    static func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    /// Eldobható aláíró kulcs (nem a valódi kiadási kulcs).
    static let signingKey = Curve25519.Signing.PrivateKey()

    /// A `.sig` tartalma: base64 aláírás + újsor.
    static func sig(_ dmg: Data, version: String = "0.2.0", key: Curve25519.Signing.PrivateKey = signingKey) throws -> Data {
        let message = try XCTUnwrap(UpdateSignature.message(version: version, sha256Hex: hex(dmg)))
        return Data((try key.signature(for: message).base64EncodedString() + "\n").utf8)
    }

    func installer(_ http: MockHTTPClient, runner: MockCommandRunner = MockCommandRunner()) -> UpdateInstaller {
        UpdateInstaller(http: http, runner: runner, cacheDirectory: cache, publicKeys: [Self.signingKey.publicKey.rawRepresentation])
    }

    func testChecksumParsing() throws {
        let h = String(repeating: "ab", count: 32)
        XCTAssertEqual(try UpdateInstaller.parseChecksum("\(h)  MacVPN-0.2.0.dmg\n", expectedName: "MacVPN-0.2.0.dmg"), h)
        XCTAssertEqual(try UpdateInstaller.parseChecksum("\(h.uppercased()) *MacVPN-0.2.0.dmg", expectedName: "MacVPN-0.2.0.dmg"), h)
        XCTAssertThrowsError(try UpdateInstaller.parseChecksum("\(h)  Other.dmg", expectedName: "MacVPN-0.2.0.dmg"))
        XCTAssertThrowsError(try UpdateInstaller.parseChecksum("abc  MacVPN-0.2.0.dmg", expectedName: "MacVPN-0.2.0.dmg"))
        XCTAssertThrowsError(try UpdateInstaller.parseChecksum("", expectedName: "MacVPN-0.2.0.dmg"))
    }

    func verifiedDownload(_ dmg: Data = Data("fake dmg contents".utf8)) async throws -> (UpdateInstaller, MockCommandRunner, VerifiedDownload) {
        let r = try release()
        let http = MockHTTPClient()
        http.responses[r.dmg.url] = HTTPResponse(status: 200, data: dmg)
        http.responses[r.checksum.url] = HTTPResponse(status: 200, data: Data("\(Self.hex(dmg))  MacVPN-0.2.0.dmg\n".utf8))
        http.responses[try XCTUnwrap(r.signature).url] = HTTPResponse(status: 200, data: try Self.sig(dmg))
        let runner = MockCommandRunner()
        let installer = installer(http, runner: runner)
        return (installer, runner, try await installer.downloadVerified(r))
    }

    func mode(_ url: URL) throws -> Int? {
        try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
    }

    /// Minden letöltés friss, 0700-as (mkdtemp) könyvtárba kerül a cache alatt.
    func testDownloadVerifiesChecksumIntoFreshPrivateDirectory() async throws {
        let dmg = Data("fake dmg contents".utf8)
        let (_, _, d1) = try await verifiedDownload(dmg)
        let (_, _, d2) = try await verifiedDownload(dmg)
        XCTAssertNotEqual(d1.directory, d2.directory)
        for d in [d1, d2] {
            XCTAssertEqual(d.directory.deletingLastPathComponent().standardizedFileURL, cache.standardizedFileURL)
            XCTAssertTrue(d.directory.lastPathComponent.hasPrefix("download."))
            XCTAssertEqual(d.dmg, d.directory.appendingPathComponent("MacVPN-0.2.0.dmg"))
            XCTAssertEqual(try Data(contentsOf: d.dmg), dmg)
            XCTAssertEqual(d.sha256, Self.hex(dmg))
            XCTAssertEqual(try mode(d.directory), 0o700)
        }
        XCTAssertEqual(try mode(cache), 0o700)
    }

    func testChecksumMismatchDeletesDownload() async throws {
        let r = try release()
        let http = MockHTTPClient()
        http.responses[r.dmg.url] = HTTPResponse(status: 200, data: Data("tampered".utf8))
        http.responses[r.checksum.url] = HTTPResponse(status: 200, data: Data("\(Self.hex(Data("original".utf8)))  MacVPN-0.2.0.dmg".utf8))
        http.responses[try XCTUnwrap(r.signature).url] = HTTPResponse(status: 200, data: try Self.sig(Data("original".utf8)))
        let installer = installer(http)
        do {
            _ = try await installer.downloadVerified(r)
            XCTFail("checksumMismatch várt")
        } catch {
            XCTAssertEqual(error as? UpdateError, .checksumMismatch)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: cache.path), [])
    }

    func testDownloadHTTPFailure() async throws {
        let r = try release()
        let http = MockHTTPClient()
        http.responses[r.checksum.url] = HTTPResponse(status: 200, data: Data("\(String(repeating: "0", count: 64))  MacVPN-0.2.0.dmg".utf8))
        http.responses[try XCTUnwrap(r.signature).url] = HTTPResponse(status: 200, data: try Self.sig(Data()))
        let installer = installer(http)
        do { _ = try await installer.downloadVerified(r); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .http(404)) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: cache.path), [])
    }

    /// Hiányzó, rossz kulcsú, más tartalomra szóló, túl nagy vagy hibás `.sig`: nincs telepítés, a letöltés törlődik.
    /// Az aláírás a helyben számolt hash-re szól: egy, a `.sha256`-tal együtt cserélt DMG sem megy át.
    func testDownloadRequiresValidSignature() async throws {
        let dmg = Data("fake dmg contents".utf8)
        let r = try release()
        let sigURL = try XCTUnwrap(r.signature).url
        func attempt(dmg served: Data, sum: Data, sig: HTTPResponse?, release: Release? = nil) async -> Error? {
            let http = MockHTTPClient()
            http.responses[r.dmg.url] = HTTPResponse(status: 200, data: served)
            http.responses[r.checksum.url] = HTTPResponse(status: 200, data: Data("\(Self.hex(sum))  MacVPN-0.2.0.dmg".utf8))
            if let sig { http.responses[sigURL] = sig }
            do { _ = try await installer(http).downloadVerified(release ?? r); return nil } catch { return error }
        }
        let good = try Self.sig(dmg)
        let evil = Data("evil dmg".utf8)
        let cases: [(String, Error?)] = [
            ("nincs .sig asset (404)", await attempt(dmg: dmg, sum: dmg, sig: nil)),
            ("idegen kulcs", await attempt(dmg: dmg, sum: dmg,
                                           sig: HTTPResponse(status: 200, data: try Self.sig(dmg, key: Curve25519.Signing.PrivateKey())))),
            ("más verzióra szól", await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 200, data: try Self.sig(dmg, version: "0.1.9")))),
            ("DMG és .sha256 együtt cserélve", await attempt(dmg: evil, sum: evil, sig: HTTPResponse(status: 200, data: good))),
            ("túl nagy", await attempt(dmg: dmg, sum: dmg,
                                       sig: HTTPResponse(status: 200, data: good + Data(repeating: 0x0a, count: 1024)))),
            ("nem base64", await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 200, data: Data("not base64!\n".utf8)))),
            ("üres", await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 200, data: Data()))),
        ]
        for (name, error) in cases {
            XCTAssertEqual(error as? UpdateError, .unsignedUpdate, name)
        }
        // Release `.sig` asset nélkül: le sem tölt semmit.
        let unsigned = try UpdateCheckerTests.parse(UpdateCheckerTests.releaseJSON(sigURL: nil))
        let none = await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 200, data: good), release: unsigned)
        XCTAssertEqual(none as? UpdateError, .unsignedUpdate)
        // Más HTTP hiba a .sig letöltésekor: az marad.
        let rateLimited = await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 403, data: Data()))
        XCTAssertEqual(rateLimited as? UpdateError, .http(403))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: cache.path), [])
        // Az éles telepítő a beágyazott kulcsokat használja: az eldobható kulccsal aláírtat elutasítja.
        let http = MockHTTPClient()
        http.responses[r.dmg.url] = HTTPResponse(status: 200, data: dmg)
        http.responses[r.checksum.url] = HTTPResponse(status: 200, data: Data("\(Self.hex(dmg))  MacVPN-0.2.0.dmg".utf8))
        http.responses[sigURL] = HTTPResponse(status: 200, data: good)
        do {
            _ = try await UpdateInstaller(http: http, runner: MockCommandRunner(), cacheDirectory: cache).downloadVerified(r)
            XCTFail("unsignedUpdate várt")
        } catch {
            XCTAssertEqual(error as? UpdateError, .unsignedUpdate)
        }
        // A jó aláírás pedig átmegy.
        let ok = await attempt(dmg: dmg, sum: dmg, sig: HTTPResponse(status: 200, data: good))
        XCTAssertNil(ok)
    }

    static let attachPlist = """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict><key>system-entities</key><array>
    <dict><key>content-hint</key><string>GUID_partition_scheme</string><key>dev-entry</key><string>/dev/disk9</string></dict>
    <dict><key>dev-entry</key><string>/dev/disk9s1</string><key>mount-point</key><string>/Volumes/MacVPN 1</string></dict>
    </array></dict></plist>
    """

    static func infoPlist(imagePath: String, mountPoint: String = "/Volumes/MacVPN 1") -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>images</key><array>
        <dict><key>image-path</key><string>/other/image.dmg</string><key>system-entities</key><array>
          <dict><key>mount-point</key><string>/Volumes/Other</string></dict></array></dict>
        <dict><key>image-path</key><string>\(imagePath)</string><key>system-entities</key><array>
          <dict><key>dev-entry</key><string>/dev/disk9</string></dict>
          <dict><key>mount-point</key><string>\(mountPoint)</string></dict></array></dict>
        </array></dict></plist>
        """
    }

    func attachKey(_ d: VerifiedDownload) -> String { "/usr/bin/hdiutil attach -nobrowse -readonly -noautoopen -plist \(d.dmg.path)" }

    func testMountRehashesAndChecksImagePath() async throws {
        let (installer, runner, d) = try await verifiedDownload()
        runner.responses[attachKey(d)] = CommandResult(exitCode: 0, stdout: "checksum ok\n" + Self.attachPlist)
        runner.responses["/usr/bin/hdiutil info -plist"] = CommandResult(exitCode: 0, stdout: Self.infoPlist(imagePath: d.dmg.path))
        let mp = try await installer.mount(d)
        XCTAssertEqual(mp, "/Volumes/MacVPN 1")
        XCTAssertEqual(runner.calls.map(\.commandLine), [attachKey(d), "/usr/bin/hdiutil info -plist"])
        XCTAssertThrowsError(try UpdateInstaller.parseMountPoint(Data("<plist><dict/></plist>".utf8)))
    }

    /// Ha a fájl a hash és a csatolás között megváltozott, nincs csatolás.
    func testMountRejectsFileChangedAfterHash() async throws {
        let (installer, runner, d) = try await verifiedDownload()
        try Data("swapped".utf8).write(to: d.dmg)
        do { _ = try await installer.mount(d); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .checksumMismatch) }
        XCTAssertTrue(runner.calls.isEmpty)
    }

    /// Ha a csatolt kép nem a hash-elt fájl, leválasztja és hibát ad.
    func testMountRejectsDifferentImagePath() async throws {
        let (installer, runner, d) = try await verifiedDownload()
        runner.responses[attachKey(d)] = CommandResult(exitCode: 0, stdout: Self.attachPlist)
        runner.responses["/usr/bin/hdiutil info -plist"] = CommandResult(exitCode: 0, stdout: Self.infoPlist(imagePath: "/tmp/evil.dmg"))
        do { _ = try await installer.mount(d); XCTFail() } catch {
            guard case .mountFailed? = error as? UpdateError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(runner.calls.last?.commandLine, "/usr/bin/hdiutil detach /Volumes/MacVPN 1 -quiet")
    }

    func testImagePathParsing() {
        let info = Data(Self.infoPlist(imagePath: "/a/b.dmg").utf8)
        XCTAssertEqual(UpdateInstaller.imagePath(forMountPoint: "/Volumes/MacVPN 1", infoPlist: info), "/a/b.dmg")
        XCTAssertEqual(UpdateInstaller.imagePath(forMountPoint: "/Volumes/Other", infoPlist: info), "/other/image.dmg")
        XCTAssertNil(UpdateInstaller.imagePath(forMountPoint: "/Volumes/None", infoPlist: info))
    }

    func testMountFailure() async throws {
        let (installer, runner, d) = try await verifiedDownload()
        runner.responses[attachKey(d)] = CommandResult(exitCode: 1, stderr: "hdiutil: attach failed - image not recognized")
        do { _ = try await installer.mount(d); XCTFail() } catch {
            XCTAssertEqual(error as? UpdateError, .mountFailed("hdiutil: attach failed - image not recognized"))
        }
    }

    func makeApp(bundleID: String, version: String) throws -> URL {
        let app = cache.appendingPathComponent("MacVPN.app")
        try? FileManager.default.removeItem(at: app)
        try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let info: [String: Any] = ["CFBundleIdentifier": bundleID, "CFBundleShortVersionString": version]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: app.appendingPathComponent("Contents/Info.plist"))
        return app
    }

    func testVerifyBundle() throws {
        XCTAssertNoThrow(try UpdateInstaller.verifyBundle(at: makeApp(bundleID: "local.macvpn", version: "0.2.0"), expectedVersion: "0.2.0"))
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: makeApp(bundleID: "com.evil", version: "0.2.0"), expectedVersion: "0.2.0"))
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: makeApp(bundleID: "local.macvpn", version: "0.1.9"), expectedVersion: "0.2.0"))
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: cache.appendingPathComponent("Nope.app"), expectedVersion: "0.2.0"))
        // Symlink nem fogadható el.
        let real = try makeApp(bundleID: "local.macvpn", version: "0.2.0")
        let link = cache.appendingPathComponent("Link.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: link, expectedVersion: "0.2.0"))
    }

    /// A Contents alatti symlink nem mutathat a bundle-ön kívülre; a belső (relatív) link rendben van.
    func testVerifyBundleRejectsSymlinksEscapingBundle() throws {
        let fm = FileManager.default
        let app = try makeApp(bundleID: "local.macvpn", version: "0.2.0")
        let res = app.appendingPathComponent("Contents/Resources")
        try fm.createDirectory(at: res.appendingPathComponent("root"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(atPath: res.appendingPathComponent("inner").path, withDestinationPath: "root")
        XCTAssertNoThrow(try UpdateInstaller.verifyBundle(at: app, expectedVersion: "0.2.0"))

        try fm.createSymbolicLink(atPath: res.appendingPathComponent("root/escape").path, withDestinationPath: "../../../../")
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: app, expectedVersion: "0.2.0"))
        try fm.removeItem(at: res.appendingPathComponent("root/escape"))
        try fm.createSymbolicLink(atPath: res.appendingPathComponent("abs").path, withDestinationPath: "/etc")
        XCTAssertThrowsError(try UpdateInstaller.verifyBundle(at: app, expectedVersion: "0.2.0"))
    }

    func testVerifyAppRunsCodesign() async throws {
        let app = try makeApp(bundleID: "local.macvpn", version: "0.2.0")
        let runner = MockCommandRunner()
        let installer = UpdateInstaller(http: MockHTTPClient(), runner: runner, cacheDirectory: cache)
        let key = "/usr/bin/codesign --verify --strict \(app.path)"
        try await installer.verifyApp(at: app, expectedVersion: "0.2.0")
        XCTAssertEqual(runner.calls.map(\.commandLine), [key])
        runner.responses[key] = CommandResult(exitCode: 1, stderr: "a sealed resource is missing or invalid")
        do { try await installer.verifyApp(at: app, expectedVersion: "0.2.0"); XCTFail() } catch {
            guard case .invalidApp? = error as? UpdateError else { return XCTFail("\(error)") }
        }
    }

    func testInstallTarget() throws {
        let app = try makeApp(bundleID: "local.macvpn", version: "0.1.0")
        XCTAssertEqual(try UpdateInstaller.checkInstallTarget(app).path, app.resolvingSymlinksInPath().path)
        XCTAssertThrowsError(try UpdateInstaller.checkInstallTarget(URL(fileURLWithPath: "/usr/bin")))
        XCTAssertThrowsError(try UpdateInstaller.checkInstallTarget(URL(fileURLWithPath: "/System/Applications/Calculator.app")))
    }

    static func script(target: String = "/Users/o'neil/Apps/MacVPN.app") -> String {
        UpdateInstaller.helperScript(pid: 4242, sourceApp: "/Volumes/MacVPN 1/MacVPN.app",
                                     targetApp: target, mountPoint: "/Volumes/MacVPN 1",
                                     scriptDirectory: "/var/folders/x/T/macvpn-update.AbC123",
                                     downloadDirectory: "/Users/o'neil/Library/Caches/MacVPN/download.Xy12",
                                     logFile: "/Users/o'neil/Library/Caches/MacVPN/update.log", token: "T1")
    }

    func testHelperScript() throws {
        let s = Self.script()
        XCTAssertTrue(s.hasPrefix("#!/bin/bash\n"))
        // Pid-várakozás (kill -0, legfeljebb 30 mp).
        XCTAssertTrue(s.contains("APP_PID=4242"))
        XCTAssertTrue(s.contains("while /bin/kill -0 \"$APP_PID\""))
        XCTAssertTrue(s.contains("[ \"$waited\" -ge 60 ]") && s.contains("/bin/sleep 0.5"))
        // Útvonalak egyszeres idézőjelben, a ' escape-elve.
        XCTAssertTrue(s.contains("SRC='/Volumes/MacVPN 1/MacVPN.app'"))
        XCTAssertTrue(s.contains("DEST='/Users/o'\\''neil/Apps/MacVPN.app'"))
        XCTAssertTrue(s.contains("STAGED='/Users/o'\\''neil/Apps/.MacVPN.app.update-T1'"))
        XCTAssertTrue(s.contains("OLD='/Users/o'\\''neil/Apps/.MacVPN.app.old-T1'"))
        XCTAssertTrue(s.contains("MOUNT='/Volumes/MacVPN 1'"))
        XCTAssertTrue(s.contains("SELF_DIR='/var/folders/x/T/macvpn-update.AbC123'"))
        XCTAssertTrue(s.contains("DOWNLOAD_DIR='/Users/o'\\''neil/Library/Caches/MacVPN/download.Xy12'"))
        // Csere: ditto a cél mellé, átnevezés, a cél üres-e, beköltözés, quarantine, detach, újraindítás.
        let steps = ["/usr/bin/ditto \"$SRC\" \"$STAGED\"", "/bin/mv \"$DEST\" \"$OLD\"", "if [ -e \"$DEST\" ]; then",
                     "/bin/mv \"$STAGED\" \"$DEST\"", "/bin/rm -rf \"$OLD\"", "/usr/bin/xattr -dr com.apple.quarantine \"$DEST\"",
                     "finish\n/usr/bin/open \"$DEST\""]
        var cursor = s.startIndex
        for step in steps {
            let r = try XCTUnwrap(s.range(of: step, range: cursor..<s.endIndex), step)
            cursor = r.upperBound
        }
        // finish: detach, utána a letöltési könyvtár és a script törlése.
        let finish = try XCTUnwrap(s.range(of: "finish() {"))
        let detach = try XCTUnwrap(s.range(of: "/usr/bin/hdiutil detach \"$MOUNT\"", range: finish.upperBound..<s.endIndex))
        let rmDownload = try XCTUnwrap(s.range(of: "/bin/rm -rf \"$DOWNLOAD_DIR\"", range: detach.upperBound..<s.endIndex))
        XCTAssertNotNil(s.range(of: "/bin/rm -rf \"$SELF_DIR\"", range: rmDownload.upperBound..<s.endIndex))
        XCTAssertTrue(s.contains("restore failed"))
        // Az útvonalak csak a változókon keresztül szerepelnek (nincs idézetlen útvonal).
        for line in s.split(separator: "\n") where line.contains("/Volumes/") || line.contains("/Users/") {
            XCTAssertTrue(line.contains("='"), String(line))
        }
        try assertBashSyntax(s)
    }

    /// A segédscript a valóságban (stubolt open/hdiutil mellett): csere, rollback, a cél foglalt.
    func testHelperScriptRunsInSandbox() throws {
        let fm = FileManager.default
        let root = cache.appendingPathComponent("sandbox o'k")
        func setUp() throws -> (String, URL) {
            try? fm.removeItem(at: root)
            for (dir, v) in [("vol/MacVPN.app/Contents", "new"), ("apps/MacVPN.app/Contents", "old")] {
                try fm.createDirectory(at: root.appendingPathComponent(dir), withIntermediateDirectories: true)
                try v.write(to: root.appendingPathComponent(dir + "/v"), atomically: true, encoding: .utf8)
            }
            for d in ["self", "download", "bin"] { try fm.createDirectory(at: root.appendingPathComponent(d), withIntermediateDirectories: true) }
            // open és hdiutil stub: csak naplóz.
            for tool in ["open", "hdiutil"] {
                let stub = root.appendingPathComponent("bin/\(tool)")
                try "#!/bin/bash\necho \"\(tool.uppercased()) $*\"\n".write(to: stub, atomically: true, encoding: .utf8)
                _ = chmod(stub.path, 0o755)
            }
            var s = UpdateInstaller.helperScript(pid: 999_999, sourceApp: root.appendingPathComponent("vol/MacVPN.app").path,
                                                 targetApp: root.appendingPathComponent("apps/MacVPN.app").path,
                                                 mountPoint: root.appendingPathComponent("vol").path,
                                                 scriptDirectory: root.appendingPathComponent("self").path,
                                                 downloadDirectory: root.appendingPathComponent("download").path,
                                                 logFile: root.appendingPathComponent("update.log").path, token: "T")
            let bin = RootInstaller.shellQuote(root.appendingPathComponent("bin").path)
            s = s.replacingOccurrences(of: "/usr/bin/open", with: "\(bin)/open")
                .replacingOccurrences(of: "/usr/bin/hdiutil", with: "\(bin)/hdiutil")
            return (s, root.appendingPathComponent("apps/MacVPN.app/Contents/v"))
        }
        func run(_ script: String) throws -> String {
            let url = root.appendingPathComponent("u.sh")
            try script.write(to: url, atomically: true, encoding: .utf8)
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/bash")
            p.arguments = [url.path]
            try p.run()
            p.waitUntilExit()
            return (try? String(contentsOf: root.appendingPathComponent("update.log"), encoding: .utf8)) ?? ""
        }

        // Sikeres csere.
        var (script, version) = try setUp()
        var log = try run(script)
        XCTAssertEqual(try String(contentsOf: version, encoding: .utf8), "new", log)
        XCTAssertTrue(log.contains("HDIUTIL detach"), log)
        XCTAssertTrue(log.contains("OPEN \(root.appendingPathComponent("apps/MacVPN.app").path)"), log)
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("download").path))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("self").path))
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: root.appendingPathComponent("apps").path), ["MacVPN.app"])

        // Ha a régi app átnevezése után a cél (versenyhelyzetben) újra létezik: megszakít, nem cserél.
        (script, version) = try setUp()
        script = script.replacingOccurrences(of: "if [ -e \"$DEST\" ]; then",
                                             with: "/bin/mkdir -p \"$DEST\"\nif [ -e \"$DEST\" ]; then")
        log = try run(script)
        XCTAssertTrue(log.contains("the target still exists"), log)
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("apps/.MacVPN.app.update-T").path))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("download").path))
    }

    /// A csere szakaszában (a két átnevezés körül) a TERM/INT figyelmen kívül marad, utána visszaáll.
    func testHelperScriptTrapsTermDuringSwap() throws {
        let s = Self.script()
        let ignore = try XCTUnwrap(s.range(of: "trap '' TERM INT"))
        let firstMove = try XCTUnwrap(s.range(of: "/bin/mv \"$DEST\" \"$OLD\""))
        let secondMove = try XCTUnwrap(s.range(of: "/bin/mv \"$STAGED\" \"$DEST\""))
        let ditto = try XCTUnwrap(s.range(of: "/usr/bin/ditto \"$SRC\" \"$STAGED\""))
        XCTAssertLessThan(ditto.lowerBound, ignore.lowerBound)
        XCTAssertLessThan(ignore.lowerBound, firstMove.lowerBound)
        let restore = try XCTUnwrap(s.range(of: "trap - TERM INT", range: secondMove.upperBound..<s.endIndex))
        XCTAssertNotNil(s.range(of: "/usr/bin/open \"$DEST\"", range: restore.upperBound..<s.endIndex))
        // A sikeres csere a megnyitás előtt naplózódik (az új app induláskor már a végeredményt látja).
        let ok = try XCTUnwrap(s.range(of: "echo \"done\""))
        XCTAssertLessThan(ok.lowerBound, try XCTUnwrap(s.range(of: "finish\n/usr/bin/open \"$DEST\"")).lowerBound)
        try assertBashSyntax(s)
    }

    /// Valódi futás: a két átnevezés között érkező SIGTERM nem hagyja hiányzó appal a célt.
    func testHelperScriptSurvivesTermBetweenRenames() throws {
        let fm = FileManager.default
        let root = cache.appendingPathComponent("term")
        for (dir, v) in [("vol/MacVPN.app/Contents", "new"), ("apps/MacVPN.app/Contents", "old")] {
            try fm.createDirectory(at: root.appendingPathComponent(dir), withIntermediateDirectories: true)
            try v.write(to: root.appendingPathComponent(dir + "/v"), atomically: true, encoding: .utf8)
        }
        for d in ["self", "download", "bin"] { try fm.createDirectory(at: root.appendingPathComponent(d), withIntermediateDirectories: true) }
        for tool in ["open", "hdiutil"] {
            let stub = root.appendingPathComponent("bin/\(tool)")
            try "#!/bin/bash\necho \"\(tool.uppercased()) $*\"\n".write(to: stub, atomically: true, encoding: .utf8)
            _ = chmod(stub.path, 0o755)
        }
        let bin = RootInstaller.shellQuote(root.appendingPathComponent("bin").path)
        let s = UpdateInstaller.helperScript(pid: 999_999, sourceApp: root.appendingPathComponent("vol/MacVPN.app").path,
                                             targetApp: root.appendingPathComponent("apps/MacVPN.app").path,
                                             mountPoint: root.appendingPathComponent("vol").path,
                                             scriptDirectory: root.appendingPathComponent("self").path,
                                             downloadDirectory: root.appendingPathComponent("download").path,
                                             logFile: root.appendingPathComponent("update.log").path, token: "T")
            .replacingOccurrences(of: "/usr/bin/open", with: "\(bin)/open")
            .replacingOccurrences(of: "/usr/bin/hdiutil", with: "\(bin)/hdiutil")
            // Kijelentkezés szimulálása: SIGTERM a saját folyamatnak az első átnevezés után.
            .replacingOccurrences(of: "if [ -e \"$DEST\" ]; then", with: "/bin/kill -TERM $$\nif [ -e \"$DEST\" ]; then")
        let url = root.appendingPathComponent("u.sh")
        try s.write(to: url, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [url.path]
        try p.run()
        p.waitUntilExit()
        let log = (try? String(contentsOf: root.appendingPathComponent("update.log"), encoding: .utf8)) ?? ""
        XCTAssertEqual(try String(contentsOf: root.appendingPathComponent("apps/MacVPN.app/Contents/v"), encoding: .utf8), "new", log)
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: root.appendingPathComponent("apps").path), ["MacVPN.app"])
        XCTAssertTrue(log.contains("done"), log)
    }

    /// Induláskori takarítás: a futó bundle melletti `.<App>.update-*` és `.<App>.old-*` maradványok törlése.
    func testSweepLeftovers() throws {
        let fm = FileManager.default
        let dir = cache.appendingPathComponent("Apps")
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let bundle = dir.appendingPathComponent("MacVPN.app")
        let leftovers = [".MacVPN.app.update-8F1C2D3E-0000-4000-8000-000000000001", ".MacVPN.app.old-T1"]
        let keep = ["MacVPN.app", "Other.app", ".Other.app.old-T1", ".MacVPN.app.update-", ".MacVPN.app.oldish",
                    "MacVPN.app.old-T1", ".MacVPN.app.old-a b", ".MacVPN.app.old-../x"]
        for name in leftovers + keep where !name.contains("/") {
            try fm.createDirectory(at: dir.appendingPathComponent(name + "/Contents"), withIntermediateDirectories: true)
        }
        // Symlink maradvány: csak a link törlődik, a célja nem.
        let target = cache.appendingPathComponent("linktarget")
        try fm.createDirectory(at: target, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: dir.appendingPathComponent(".MacVPN.app.old-L"), withDestinationURL: target)

        let removed = UpdateInstaller.sweepLeftovers(nextTo: bundle)
        XCTAssertEqual(Set(removed.map(\.lastPathComponent)), Set(leftovers + [".MacVPN.app.old-L"]))
        let remaining = Set(try fm.contentsOfDirectory(atPath: dir.path))
        XCTAssertEqual(remaining, Set(keep.filter { !$0.contains("/") }))
        XCTAssertTrue(fm.fileExists(atPath: target.path))
    }

    func testSweepSkipsWhenBundleMissing() throws {
        let fm = FileManager.default
        let dir = cache.appendingPathComponent("Apps")
        try fm.createDirectory(at: dir.appendingPathComponent(".MacVPN.app.old-T1"), withIntermediateDirectories: true)
        XCTAssertEqual(UpdateInstaller.sweepLeftovers(nextTo: dir.appendingPathComponent("MacVPN.app")), [])
        XCTAssertTrue(fm.fileExists(atPath: dir.appendingPathComponent(".MacVPN.app.old-T1").path))
        XCTAssertEqual(UpdateInstaller.sweepLeftovers(nextTo: cache.appendingPathComponent("nope/MacVPN.app")), [])
    }

    /// A segédscript naplójának utolsó futása: sikeres, időtúllépés miatt megszakadt, vagy hibás.
    func testHelperLogOutcome() {
        let ok = """
        === 2026-10-01 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===
        the app did not quit within 30 s, update cancelled
        === 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===
        HDIUTIL detach
        done

        """
        XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: ok)?.outcome, .succeeded)
        XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: ok)?.run,
                       "=== 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===")

        let timeout = """
        === 2026-10-02 10:00:00 update: a -> b ===
        done
        === 2026-10-03 11:00:00 update: a -> b ===
        the app did not quit within 30 s, update cancelled
        """
        XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: timeout)?.outcome, .timedOut)
        XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: timeout)?.run, "=== 2026-10-03 11:00:00 update: a -> b ===")

        for line in ["copy (ditto) failed", "cannot rename the old app", "cannot move the new app into place, restoring",
                     "the target still exists after the rename, update cancelled"] {
            let failed = "=== 2026-10-03 11:00:00 update: a -> b ===\nsome output\n\(line)\nold app restored\n"
            XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: failed)?.outcome, .failed(line), line)
        }
        // Még futó (vagy régi, a „done"-t a megnyitás után író) script: nincs hibajel, nem jelez hibát.
        XCTAssertEqual(UpdateInstaller.lastHelperOutcome(log: "=== 2026-10-03 11:00:00 update: a -> b ===\nHDIUTIL detach\n")?.outcome,
                       .unknown)
        XCTAssertNil(UpdateInstaller.lastHelperOutcome(log: ""))
        XCTAssertNil(UpdateInstaller.lastHelperOutcome(log: "random\n"))
    }

    func testWriteHelperPrivate() throws {
        var dirSeen: URL?
        let url = try UpdateInstaller.writeHelper { dir in
            dirSeen = dir
            return "#!/bin/bash\necho hi\n"
        }
        let dir = try XCTUnwrap(dirSeen)
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertEqual(url.deletingLastPathComponent().standardizedFileURL, dir.standardizedFileURL)
        XCTAssertTrue(dir.lastPathComponent.hasPrefix("macvpn-update."))
        XCTAssertEqual(try mode(dir), 0o700)
        XCTAssertEqual(try mode(url), 0o700)
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "#!/bin/bash\necho hi\n")
    }

    /// Kettős fork: a külső bash azonnal kilép, a script nohup alatt, leválasztva fut tovább.
    func testHelperLaunchArgumentsDetach() {
        let args = UpdateInstaller.helperLaunchArguments(script: URL(fileURLWithPath: "/tmp/a b/it's.sh"))
        XCTAssertEqual(args, ["-c", "/usr/bin/nohup /bin/bash \"$1\" >/dev/null 2>&1 </dev/null & disown", "macvpn-update",
                              "/tmp/a b/it's.sh"])
    }

    func testLaunchHelperSurvivesLauncher() throws {
        let dir = cache.appendingPathComponent("launch")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let marker = dir.appendingPathComponent("done")
        let script = dir.appendingPathComponent("s.sh")
        try "#!/bin/bash\n/bin/sleep 0.3\necho ok > \(RootInstaller.shellQuote(marker.path))\n".write(to: script, atomically: true, encoding: .utf8)
        try UpdateInstaller.launchHelper(script)
        // A launcher már kilépett; a script tovább fut és megírja a jelzőt.
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: marker.path), Date() < deadline { usleep(50_000) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
    }
}
