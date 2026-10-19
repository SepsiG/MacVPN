import XCTest
@testable import MacVPNCore

final class SecureTempDirectoryTests: XCTestCase {
    var parent: URL!

    override func setUpWithError() throws {
        parent = FileManager.default.temporaryDirectory.appendingPathComponent("stdt-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: parent)
    }

    func testMakeCreatesPrivateDirectoryInParentWithPrefix() throws {
        // Sokszor: optimalizált buildben a régi (visszatérési pointeres) változat itt adott üres/szemét útvonalat.
        for _ in 0..<50 {
            let dir = try SecureTempDirectory.make(prefix: "macvpn-test.", in: parent)
            XCTAssertTrue(dir.path.hasPrefix("/"))
            XCTAssertEqual(dir.deletingLastPathComponent().standardizedFileURL.path, parent.standardizedFileURL.path)
            XCTAssertTrue(dir.lastPathComponent.hasPrefix("macvpn-test."))
            XCTAssertEqual(dir.lastPathComponent.count, "macvpn-test.".count + 8)
            let mode = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
            XCTAssertEqual(mode, 0o700)
        }
    }

    func testMakeRejectsRelativeParentAndBadPrefix() {
        XCTAssertThrowsError(try SecureTempDirectory.make(prefix: "a/b", in: parent))
        XCTAssertThrowsError(try SecureTempDirectory.make(prefix: "", in: parent))
    }

    func testRemoveIfOwnedNeverTouchesForeignPaths() throws {
        let keep = parent.appendingPathComponent("keep")
        try FileManager.default.createDirectory(at: keep, withIntermediateDirectories: true)
        let sentinel = keep.appendingPathComponent("sentinel")
        try Data("x".utf8).write(to: sentinel)

        let cwd = FileManager.default.currentDirectoryPath
        for candidate in [URL(fileURLWithPath: "/"), URL(fileURLWithPath: ""), URL(fileURLWithPath: "."),
                          URL(fileURLWithPath: cwd), keep,
                          parent.appendingPathComponent("macvpn-test.")] {
            SecureTempDirectory.removeIfOwned(candidate, prefix: "macvpn-test.")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: sentinel.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: cwd))

        // Előtaggal kezdődő, de symlink: nem követi, nem törli a célt.
        let link = parent.appendingPathComponent("macvpn-test.ABCDEFGH")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: keep)
        SecureTempDirectory.removeIfOwned(link, prefix: "macvpn-test.")
        XCTAssertTrue(FileManager.default.fileExists(atPath: sentinel.path))
    }

    func testRemoveIfOwnedRemovesOwnDirectory() throws {
        let dir = try SecureTempDirectory.make(prefix: "macvpn-test.", in: parent)
        try Data("x".utf8).write(to: dir.appendingPathComponent("f"))
        SecureTempDirectory.removeIfOwned(dir, prefix: "macvpn-test.")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path))
    }
}
