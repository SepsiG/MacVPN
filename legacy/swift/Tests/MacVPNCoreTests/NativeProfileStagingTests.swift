import XCTest
@testable import MacVPNCore

final class NativeProfileStagingTests: XCTestCase {
    var parent: URL!
    let fm = FileManager.default

    override func setUpWithError() throws {
        parent = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? fm.removeItem(at: parent) }

    private func mode(_ path: String) throws -> Int {
        (try fm.attributesOfItem(atPath: path)[.posixPermissions] as! NSNumber).intValue & 0o777
    }

    func testStageWritesPrivateFileInFreshPrivateDirectory() throws {
        let a = try NativeProfileStaging.stage(Data("x".utf8), fileName: "Office.mobileconfig", in: parent)
        let b = try NativeProfileStaging.stage(Data("y".utf8), fileName: "Office.mobileconfig", in: parent)
        XCTAssertNotEqual(a.deletingLastPathComponent(), b.deletingLastPathComponent())
        XCTAssertEqual(a.lastPathComponent, "Office.mobileconfig")
        XCTAssertTrue(a.deletingLastPathComponent().lastPathComponent.hasPrefix(NativeProfileStaging.prefix))
        XCTAssertEqual(try Data(contentsOf: a), Data("x".utf8))
        XCTAssertEqual(try mode(a.path), 0o600)
        XCTAssertEqual(try mode(a.deletingLastPathComponent().path), 0o700)
    }

    func testStageRejectsPathInFileName() {
        XCTAssertThrowsError(try NativeProfileStaging.stage(Data(), fileName: "../x.mobileconfig", in: parent))
    }

    func testRemoveDeletesOnlyStagedDirectories() throws {
        let staged = try NativeProfileStaging.stage(Data("x".utf8), fileName: "A.mobileconfig", in: parent)
        NativeProfileStaging.remove(staged)
        XCTAssertFalse(fm.fileExists(atPath: staged.deletingLastPathComponent().path))
        // Nem staging könyvtárban lévő fájlt nem töröl.
        let other = parent.appendingPathComponent("keep/A.mobileconfig")
        try fm.createDirectory(at: other.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data().write(to: other)
        NativeProfileStaging.remove(other)
        XCTAssertTrue(fm.fileExists(atPath: other.path))
    }

    func testSweepRemovesLeftoversButNotOtherFilesOrSymlinks() throws {
        _ = try NativeProfileStaging.stage(Data("x".utf8), fileName: "A.mobileconfig", in: parent)
        _ = try NativeProfileStaging.stage(Data("y".utf8), fileName: "B.mobileconfig", in: parent)
        let unrelated = parent.appendingPathComponent("other")
        try fm.createDirectory(at: unrelated, withIntermediateDirectories: true)
        let target = parent.appendingPathComponent("target")
        try fm.createDirectory(at: target, withIntermediateDirectories: true)
        try Data().write(to: target.appendingPathComponent("keep"))
        try fm.createSymbolicLink(at: parent.appendingPathComponent(NativeProfileStaging.prefix + "link"), withDestinationURL: target)
        XCTAssertEqual(NativeProfileStaging.sweep(in: parent), 2)
        let left = try fm.contentsOfDirectory(atPath: parent.path).sorted()
        XCTAssertEqual(left, [NativeProfileStaging.prefix + "link", "other", "target"])
        XCTAssertTrue(fm.fileExists(atPath: target.appendingPathComponent("keep").path))
        XCTAssertEqual(NativeProfileStaging.sweep(in: parent.appendingPathComponent("missing")), 0)
    }

    func testLegacyProfilesAreRemovedFromConnectionDirectories() throws {
        let store = ConnectionStore(baseURL: parent.appendingPathComponent("connections"))
        let a = Connection(name: "A", kind: .l2tp), b = Connection(name: "B", kind: .openvpn)
        try store.save(a, config: nil)
        try store.save(b, config: "remote x\n")
        let legacy = store.directory(for: a.id).appendingPathComponent(ConnectionStore.legacyProfileName)
        try Data("<AuthPassword>pw</AuthPassword>".utf8).write(to: legacy)
        XCTAssertEqual(store.removeLegacyProfiles(), 1)
        XCTAssertFalse(fm.fileExists(atPath: legacy.path))
        XCTAssertEqual(try store.list().count, 2)
        XCTAssertEqual(try store.loadConfig(b.id), "remote x\n")
        XCTAssertEqual(store.removeLegacyProfiles(), 0)
        XCTAssertEqual(ConnectionStore(baseURL: parent.appendingPathComponent("none")).removeLegacyProfiles(), 0)
    }

    func testTrackerRemovesWhenServiceAppears() throws {
        var now = Date(timeIntervalSince1970: 1000)
        let tracker = StagedProfiles(clock: { now })
        let id = UUID(), other = UUID()
        let profile = try NativeProfileStaging.stage(Data("x".utf8), fileName: "A.mobileconfig", in: parent)
        tracker.track(id, profile: profile, serviceExisted: false)
        XCTAssertEqual(tracker.pendingIDs, [id])
        tracker.servicesSeen([other])
        XCTAssertTrue(fm.fileExists(atPath: profile.path), "not installed yet")
        now += 1
        tracker.servicesSeen([id])
        XCTAssertFalse(fm.fileExists(atPath: profile.deletingLastPathComponent().path))
        XCTAssertEqual(tracker.pendingIDs, [])
    }

    func testTrackerWaitsBeforeRemovingARegeneratedProfile() throws {
        var now = Date(timeIntervalSince1970: 1000)
        let tracker = StagedProfiles(clock: { now })
        let id = UUID()
        let profile = try NativeProfileStaging.stage(Data("x".utf8), fileName: "A.mobileconfig", in: parent)
        // A szolgáltatás már létezett: a megjelenése nem jelzi, hogy az új profil települt.
        tracker.track(id, profile: profile, serviceExisted: true)
        now += 60
        tracker.servicesSeen([id])
        XCTAssertTrue(fm.fileExists(atPath: profile.path))
        now += StagedProfiles.regeneratedGrace
        tracker.servicesSeen([id])
        XCTAssertFalse(fm.fileExists(atPath: profile.path))
    }

    func testTrackingAgainReplacesThePreviousProfile() throws {
        let tracker = StagedProfiles()
        let id = UUID()
        let first = try NativeProfileStaging.stage(Data("x".utf8), fileName: "A.mobileconfig", in: parent)
        let second = try NativeProfileStaging.stage(Data("y".utf8), fileName: "A.mobileconfig", in: parent)
        tracker.track(id, profile: first, serviceExisted: false)
        tracker.track(id, profile: second, serviceExisted: false)
        XCTAssertFalse(fm.fileExists(atPath: first.path))
        XCTAssertTrue(fm.fileExists(atPath: second.path))
        tracker.removeAll()
        XCTAssertFalse(fm.fileExists(atPath: second.path))
    }
}
