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
    static func releaseJSON(tag: String = "v0.2.0", dmgURL: String = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg",
                            sumURL: String = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256",
                            version: String = "0.2.0") -> Data {
        let json: [String: Any] = [
            "tag_name": tag,
            "body": "## Újdonságok\n- frissítés az appból",
            "html_url": "https://github.com/SepsiG/MacVPN/releases/tag/\(tag)",
            "draft": false, "prerelease": false,
            "assets": [
                ["name": "MacVPN-\(version).dmg.sha256", "browser_download_url": sumURL],
                ["name": "Source.zip", "browser_download_url": "https://github.com/x.zip"],
                ["name": "MacVPN-\(version).dmg", "browser_download_url": dmgURL],
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: json)
    }

    func testLatestReleaseParsesAssets() async throws {
        let http = MockHTTPClient()
        let checker = try UpdateChecker(repo: "SepsiG/MacVPN", http: http)
        http.responses[checker.latestReleaseURL] = HTTPResponse(status: 200, data: Self.releaseJSON())
        let r = try await checker.latestRelease()
        XCTAssertEqual(http.requested, [URL(string: "https://api.github.com/repos/SepsiG/MacVPN/releases/latest")!])
        XCTAssertEqual(r.tag, "v0.2.0")
        XCTAssertEqual(r.version, "0.2.0")
        XCTAssertEqual(r.notes, "## Újdonságok\n- frissítés az appból")
        XCTAssertEqual(r.dmg.name, "MacVPN-0.2.0.dmg")
        XCTAssertEqual(r.checksum.name, "MacVPN-0.2.0.dmg.sha256")
        XCTAssertEqual(r.checksum.url.absoluteString, "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256")
        XCTAssertTrue(r.isNewer(than: "0.1.0"))
        XCTAssertFalse(r.isNewer(than: "0.2.0"))
        XCTAssertFalse(r.isNewer(than: "0.10.0"))
    }

    func testHTTPErrors() async throws {
        let http = MockHTTPClient()
        let checker = try UpdateChecker(repo: "SepsiG/MacVPN", http: http)
        do { _ = try await checker.latestRelease(); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .http(404)) }
        http.responses[checker.latestReleaseURL] = HTTPResponse(status: 200, data: Data("nem json".utf8))
        do { _ = try await checker.latestRelease(); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .invalidResponse) }
    }

    func testRejectsUntrustedAssetURLs() {
        for bad in ["http://github.com/a/MacVPN-0.2.0.dmg", "https://evil.example.com/MacVPN-0.2.0.dmg",
                    "https://github.com.evil.example/MacVPN-0.2.0.dmg", "https://user@github.com/MacVPN-0.2.0.dmg",
                    "https://github.com:8443/MacVPN-0.2.0.dmg"] {
            XCTAssertThrowsError(try UpdateChecker.parseRelease(Self.releaseJSON(dmgURL: bad)), bad) {
                XCTAssertEqual($0 as? UpdateError, .untrustedURL(bad))
            }
        }
        XCTAssertNoThrow(try UpdateChecker.parseRelease(Self.releaseJSON(
            dmgURL: "https://objects.githubusercontent.com/github-production-release-asset/1/MacVPN-0.2.0.dmg")))
    }

    func testMissingAssetsAndBadTags() {
        XCTAssertThrowsError(try UpdateChecker.parseRelease(Self.releaseJSON(version: "0.1.9"))) {
            XCTAssertEqual($0 as? UpdateError, .missingAsset("MacVPN-0.2.0.dmg"))
        }
        XCTAssertThrowsError(try UpdateChecker.parseRelease(Self.releaseJSON(tag: "v0.2.0/../x")))
        XCTAssertThrowsError(try UpdateChecker.parseRelease(Self.releaseJSON(tag: "nightly")))
    }

    func testRepoKey() {
        XCTAssertEqual(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "SepsiG/MacVPN"]), "SepsiG/MacVPN")
        XCTAssertNil(UpdateChecker.repo(fromInfo: nil))
        XCTAssertNil(UpdateChecker.repo(fromInfo: [:]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": ""]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a/b/c"]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a/.."]))
        XCTAssertNil(UpdateChecker.repo(fromInfo: ["MacVPNUpdateRepo": "a b/c"]))
        XCTAssertThrowsError(try UpdateChecker(repo: "x?y=1/z", http: MockHTTPClient()))
    }

    func testURLPolicy() {
        XCTAssertTrue(UpdateURLPolicy.isAllowedRedirect(URL(string: "https://release-assets.githubusercontent.com/x")!))
        XCTAssertFalse(UpdateURLPolicy.isAllowedDownload(URL(string: "https://release-assets.githubusercontent.com/x")!))
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

    func release() throws -> Release { try UpdateChecker.parseRelease(UpdateCheckerTests.releaseJSON()) }

    static func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

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
        let runner = MockCommandRunner()
        let installer = UpdateInstaller(http: http, runner: runner, cacheDirectory: cache)
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
        let installer = UpdateInstaller(http: http, runner: MockCommandRunner(), cacheDirectory: cache)
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
        let installer = UpdateInstaller(http: http, runner: MockCommandRunner(), cacheDirectory: cache)
        do { _ = try await installer.downloadVerified(r); XCTFail() } catch { XCTAssertEqual(error as? UpdateError, .http(404)) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: cache.path), [])
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
