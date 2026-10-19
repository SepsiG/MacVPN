import XCTest
@testable import MacVPNCore

final class ConnectionStoreTests: XCTestCase {
    var base: URL!
    var store: ConnectionStore!

    override func setUpWithError() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = ConnectionStore(baseURL: base)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: base)
    }

    func testSaveListLoadDelete() throws {
        let b = Connection(name: "B", kind: .wireguard)
        let a = Connection(name: "A", kind: .openvpn)
        try store.save(b, config: "[Interface]\n")
        try store.save(a, config: "remote x\n")
        XCTAssertEqual(try store.list().map(\.name), ["A", "B"])
        XCTAssertEqual(try store.loadConfig(a.id), "remote x\n")

        let attrs = try FileManager.default.attributesOfItem(atPath: store.configURL(for: a.id).path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(store.directory(for: a.id).lastPathComponent, a.id.uuidString)

        try store.delete(a.id)
        XCTAssertEqual(try store.list().map(\.name), ["B"])
    }

    func testSaveWithoutConfigKeepsExisting() throws {
        var c = Connection(name: "A", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        c.name = "Átnevezve"
        try store.save(c, config: nil)
        XCTAssertEqual(try store.loadConfig(c.id), "remote x\n")
        XCTAssertEqual(try store.list().first?.name, "Átnevezve")
    }

    func testListOnMissingDirIsEmpty() throws {
        XCTAssertEqual(try store.list(), [])
    }

    func testFilesArePrivateAndDirectoryIsTightened() throws {
        let c = Connection(name: "A", kind: .openvpn)
        try FileManager.default.createDirectory(at: store.directory(for: c.id), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try store.save(c, config: "remote x\n")
        func mode(_ u: URL) throws -> Int {
            (try FileManager.default.attributesOfItem(atPath: u.path)[.posixPermissions] as? NSNumber)?.intValue ?? -1
        }
        XCTAssertEqual(try mode(store.metaURL(for: c.id)), 0o600)
        XCTAssertEqual(try mode(store.configURL(for: c.id)), 0o600)
        XCTAssertEqual(try mode(store.directory(for: c.id)), 0o700)
    }

    func testListSkipsCorruptMeta() throws {
        try store.save(Connection(name: "A", kind: .openvpn), config: nil)
        let bad = base.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: bad, withIntermediateDirectories: true)
        try Data("{nope".utf8).write(to: bad.appendingPathComponent("meta.json"))
        XCTAssertEqual(try store.list().map(\.name), ["A"])
    }
}

final class UserDataRemovalTests: XCTestCase {
    func testDefaultApplicationSupportDirectory() {
        XCTAssertEqual(ConnectionStore.applicationSupportDirectory.path,
                       FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MacVPN").path)
        XCTAssertEqual(ConnectionStore.defaultBaseURL.deletingLastPathComponent().standardizedFileURL.path,
                       ConnectionStore.applicationSupportDirectory.standardizedFileURL.path)
    }

    func testRemovesOnlyDirectoryNamedMacVPN() throws {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("macvpn-userdata-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: root) }
        let good = root.appendingPathComponent("MacVPN/connections")
        let other = root.appendingPathComponent("Other")
        try fm.createDirectory(at: good, withIntermediateDirectories: true)
        try fm.createDirectory(at: other, withIntermediateDirectories: true)

        XCTAssertThrowsError(try ConnectionStore.removeApplicationSupportDirectory(other))
        XCTAssertTrue(fm.fileExists(atPath: other.path))
        // Symlinket sem követ.
        let link = root.appendingPathComponent("link/MacVPN")
        try fm.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: link, withDestinationURL: other)
        XCTAssertThrowsError(try ConnectionStore.removeApplicationSupportDirectory(link))
        XCTAssertTrue(fm.fileExists(atPath: other.path))

        try ConnectionStore.removeApplicationSupportDirectory(root.appendingPathComponent("MacVPN"))
        XCTAssertFalse(fm.fileExists(atPath: root.appendingPathComponent("MacVPN").path))
        // Nem létező könyvtár: nincs hiba.
        XCTAssertNoThrow(try ConnectionStore.removeApplicationSupportDirectory(root.appendingPathComponent("MacVPN")))
    }
}
