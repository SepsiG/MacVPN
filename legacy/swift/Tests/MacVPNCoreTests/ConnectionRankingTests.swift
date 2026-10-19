import XCTest
@testable import MacVPNCore

final class ConnectionRankingTests: XCTestCase {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let day: TimeInterval = 24 * 60 * 60

    // MARK: - Decay

    func testScoreHalvesEveryFourteenDays() {
        var r = ConnectionRanking()
        r.recordSuccess(id: "a", at: t0)
        XCTAssertEqual(r.score(id: "a", at: t0), 1, accuracy: 1e-12)
        XCTAssertEqual(r.score(id: "a", at: t0 + 14 * day), 0.5, accuracy: 1e-12)
        XCTAssertEqual(r.score(id: "a", at: t0 + 28 * day), 0.25, accuracy: 1e-12)
        XCTAssertEqual(r.score(id: "a", at: t0 + 7 * day), pow(0.5, 0.5), accuracy: 1e-12)
        XCTAssertEqual(r.score(id: "missing", at: t0), 0)
    }

    func testRecordSuccessDecaysThenAddsOne() {
        var r = ConnectionRanking()
        r.recordSuccess(id: "a", at: t0)
        r.recordSuccess(id: "a", at: t0)
        XCTAssertEqual(r.score(id: "a", at: t0), 2, accuracy: 1e-12)
        r.recordSuccess(id: "a", at: t0 + 14 * day)
        XCTAssertEqual(r.score(id: "a", at: t0 + 14 * day), 2, accuracy: 1e-12, "2 → 1 after a half-life, +1")
        XCTAssertEqual(r.usage["a"]?.lastUpdated, t0 + 14 * day)
        XCTAssertEqual(r.score(id: "a", at: t0 + 28 * day), 1, accuracy: 1e-12)
    }

    func testClockGoingBackwardsDoesNotInflateTheScore() {
        var r = ConnectionRanking()
        r.recordSuccess(id: "a", at: t0)
        XCTAssertEqual(r.score(id: "a", at: t0 - day), 1, accuracy: 1e-12)
        r.recordSuccess(id: "a", at: t0 - day)
        XCTAssertEqual(r.usage["a"]?.lastUpdated, t0)
        XCTAssertEqual(r.score(id: "a", at: t0), 2, accuracy: 1e-12)
    }

    func testRecentUseOutranksOldHeavyUse() {
        var r = ConnectionRanking()
        for _ in 0..<3 { r.recordSuccess(id: "old", at: t0) }
        r.recordSuccess(id: "new", at: t0 + 60 * day)
        // 3 · 0.5^(60/14) ≈ 0.153 < 1
        XCTAssertEqual(r.order(ids: ["old", "new"], now: t0 + 60 * day, name: { $0 }), ["new", "old"])
    }

    // MARK: - Ordering

    func testPinnedFirstInTheirOrderThenScoreThenName() {
        var r = ConnectionRanking()
        r.recordSuccess(id: "busy", at: t0)
        r.recordSuccess(id: "busy", at: t0)
        r.recordSuccess(id: "used", at: t0)
        r.recordSuccess(id: "pinB", at: t0)
        r.pin("pinB")
        r.pin("pinA")
        let names = ["busy": "Zulu", "used": "Yankee", "pinA": "Alpha", "pinB": "Bravo",
                     "x": "éjszakai", "y": "Ember", "z": "alpha"]
        let order = r.order(ids: ["x", "busy", "pinA", "y", "used", "z", "pinB"], now: t0, name: { names[$0]! })
        XCTAssertEqual(Array(order.prefix(2)), ["pinB", "pinA"], "pinned, in the user's order, regardless of score")
        XCTAssertEqual(Array(order[2...3]), ["busy", "used"], "then by score")
        // Ties (score 0): case-insensitive, localized name order (alpha < éjszakai < Ember is not ASCII order).
        let tail = Array(order.suffix(3))
        let expected = ["z", "x", "y"].sorted { names[$0]!.localizedCaseInsensitiveCompare(names[$1]!) == .orderedAscending }
        XCTAssertEqual(tail, expected)
        XCTAssertEqual(tail.first, "z")
    }

    func testEqualNamesAndScoresAreStable() {
        let r = ConnectionRanking()
        XCTAssertEqual(r.order(ids: ["b", "a"], now: t0, name: { _ in "Same" }), ["a", "b"])
        XCTAssertEqual(r.order(ids: ["a", "b"], now: t0, name: { _ in "Same" }), ["a", "b"])
    }

    func testPinnedButMissingIDsAreSkipped() {
        var r = ConnectionRanking()
        r.pin("gone")
        r.pin("a")
        XCTAssertEqual(r.order(ids: ["b", "a"], now: t0, name: { $0 }), ["a", "b"])
    }

    func testPinUnpin() {
        var r = ConnectionRanking()
        r.pin("a")
        r.pin("b")
        r.pin("a")
        XCTAssertEqual(r.pinned, ["a", "b"])
        r.unpin("a")
        XCTAssertEqual(r.pinned, ["b"])
        XCTAssertFalse(r.isPinned("a"))
        XCTAssertEqual(r.order(ids: ["a", "b"], now: t0, name: { $0 }), ["b", "a"])
    }

    func testMovePinnedLikeOnMove() {
        var r = ConnectionRanking(pinned: ["a", "b", "c", "d"])
        r.movePinned(visible: ["a", "b", "c", "d"], fromOffsets: IndexSet(integer: 0), toOffset: 3)
        XCTAssertEqual(r.pinned, ["b", "c", "a", "d"])
        r.movePinned(visible: r.pinned, fromOffsets: IndexSet(integer: 3), toOffset: 0)
        XCTAssertEqual(r.pinned, ["d", "b", "c", "a"])
        r.movePinned(visible: r.pinned, fromOffsets: IndexSet([0, 2]), toOffset: 4)
        XCTAssertEqual(r.pinned, ["b", "a", "d", "c"])
    }

    func testMovePinnedKeepsHiddenPinsAtTheEnd() {
        var r = ConnectionRanking(pinned: ["a", "hidden", "b"])
        r.movePinned(visible: ["a", "b"], fromOffsets: IndexSet(integer: 1), toOffset: 0)
        XCTAssertEqual(r.pinned, ["b", "a", "hidden"])
    }

    // MARK: - Pruning

    func testPruneRemovesDeletedConnections() {
        var r = ConnectionRanking()
        r.recordSuccess(id: "keep", at: t0)
        r.recordSuccess(id: "gone", at: t0)
        r.pin("gone")
        r.pin("keep")
        XCTAssertTrue(r.prune(keeping: ["keep", "new"]))
        XCTAssertEqual(r.pinned, ["keep"])
        XCTAssertEqual(Set(r.usage.keys), ["keep"])
        XCTAssertFalse(r.prune(keeping: ["keep"]), "nothing to remove")
    }

    // MARK: - Persistence

    func testStoreRoundTripWith0600File() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = ConnectionRankingStore(url: dir.appendingPathComponent("MacVPN/connection-order.json"))
        XCTAssertEqual(store.load(), ConnectionRanking(), "missing file: empty")
        var r = ConnectionRanking()
        r.recordSuccess(id: "a", at: t0)
        r.recordSuccess(id: "a", at: t0 + 3 * day)
        r.pin("b")
        try store.save(r)
        let loaded = store.load()
        XCTAssertEqual(loaded.pinned, ["b"])
        XCTAssertEqual(loaded.score(id: "a", at: t0 + 10 * day), r.score(id: "a", at: t0 + 10 * day), accuracy: 1e-9)
        let attrs = try FileManager.default.attributesOfItem(atPath: store.url.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let dirAttrs = try FileManager.default.attributesOfItem(atPath: store.url.deletingLastPathComponent().path)
        XCTAssertEqual((dirAttrs[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    func testCorruptFileLoadsEmpty() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = ConnectionRankingStore(url: dir.appendingPathComponent("connection-order.json"))
        try Data("{not json".utf8).write(to: store.url)
        XCTAssertEqual(store.load(), ConnectionRanking())
    }

    func testDefaultLocationIsApplicationSupport() {
        XCTAssertEqual(ConnectionRankingStore.defaultURL.lastPathComponent, "connection-order.json")
        XCTAssertEqual(ConnectionRankingStore.defaultURL.deletingLastPathComponent(),
                       ConnectionStore.applicationSupportDirectory)
    }
}
