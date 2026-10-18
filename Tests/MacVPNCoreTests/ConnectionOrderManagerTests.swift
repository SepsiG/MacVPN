import XCTest
@testable import MacVPNCore

/// Spec 10e: a sikeres csatlakozás számlálása, a sorrend és a törölt kapcsolatok bejegyzéseinek törlése.
extension ConnectionManagerTests {
    func usage(_ m: ConnectionManager, _ key: String) -> Double {
        // A valódi óra miatt a pontszám a mérésig parányit csökken: 6 tizedesre kerekítve.
        (m.ranking.score(id: key, at: m.now()) * 1e6).rounded() / 1e6
    }

    func testRootConnectCountsOnceAndRefreshesDoNotAddMore() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        mock.responses[statusCmd] = connectedJSON(c)
        let m = makeManager()
        let t = Date(timeIntervalSince1970: 1_800_000_000)
        m.now = { t }
        await m.connect(c, debug: false)
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
        XCTAssertEqual(usage(m, c.id.uuidString), 1)
        await m.refresh()
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 1, "polling an already connected tunnel does not count")
        await m.disconnect(c)
        mock.responses[statusCmd] = connectedJSON(c)
        await m.connect(c, debug: false)
        XCTAssertEqual(usage(m, c.id.uuidString), 2, "a new user-initiated connect counts again")
    }

    func testConnectionNotStartedByTheUserDoesNotCount() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        let m = makeManager()
        mock.responses[statusCmd] = connectedJSON(c)
        await m.refresh()
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
        // Lebomlik, majd magától (nem a felhasználó indította) újra fent van.
        mock.responses[statusCmd] = connectedJSON(c, state: "failed")
        await m.refresh()
        mock.responses[statusCmd] = connectedJSON(c)
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 0)
    }

    func testFailedConnectDoesNotCountAndDoesNotLinger() async throws {
        let c = Connection(name: "WG", kind: .wireguard)
        try store.save(c, config: "x")
        mock.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(c.id.uuidString) --lang hu"] =
            CommandResult(exitCode: 1, stderr: "időtúllépés")
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let m = makeManager()
        await m.connect(c, debug: false)
        XCTAssertEqual(usage(m, c.id.uuidString), 0)
        // Egy később, kívülről létrejött kapcsolat sem számít a sikertelen kísérlet javára.
        mock.responses[statusCmd] = CommandResult(stdout:
            #"[{"id":"\#(c.id.uuidString)","kind":"wireguard","state":"connected","iface":null,"ip":null,"since":null}]"#)
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 0)
    }

    func testNativeConnectCountsOnceWhenItComesUp() async throws {
        let (m, c) = try nativeManager()
        await m.connect(c, debug: false)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 0, "connecting is not a success yet")
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 1)
    }

    func testNativeConnectFailureDoesNotCount() async throws {
        let (m, c) = try nativeManager()
        await m.connect(c, debug: false)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertEqual(usage(m, c.id.uuidString), 0)
    }

    func testSystemServiceConnectCountsOnceUnderItsServiceID() async throws {
        let (m, s) = try await systemManager()
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        await m.refresh()
        XCTAssertEqual(usage(m, svcID), 1)
        mock.responses[listCmd] = list("Disconnected")
        await m.disconnectSystem(s)
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertEqual(usage(m, svcID), 1, "a connect started outside MacVPN does not count")
    }

    func testOrderedItemsMixManagedAndSystemAndPinsComeFirst() async throws {
        let a = Connection(name: "alpha", kind: .openvpn)
        let b = Connection(name: "Bravo", kind: .openvpn)
        try store.save(a, config: "remote x\n")
        try store.save(b, config: "remote x\n")
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[listCmd] = list("Disconnected")   // "Office L2TP" rendszer-VPN
        let m = makeManager()
        await m.refresh()
        XCTAssertEqual(m.orderedItems.map(\.name), ["alpha", "Bravo", "Office L2TP"], "no usage: by name")
        let s = try XCTUnwrap(m.systemServices.first)
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertEqual(m.orderedItems.map(\.name), ["Office L2TP", "alpha", "Bravo"])
        m.pin(b.id.uuidString)
        XCTAssertEqual(m.orderedItems.map(\.name), ["Bravo", "Office L2TP", "alpha"])
        XCTAssertEqual(m.pinnedItems.map(\.id), [b.id.uuidString])
        XCTAssertEqual(m.unpinnedItems.map(\.name), ["Office L2TP", "alpha"])
        m.pin(a.id.uuidString)
        m.movePinned(fromOffsets: IndexSet(integer: 1), toOffset: 0)
        XCTAssertEqual(m.pinnedItems.map(\.name), ["alpha", "Bravo"])
        m.unpin(a.id.uuidString)
        XCTAssertEqual(m.orderedItems.map(\.name), ["Bravo", "Office L2TP", "alpha"])
    }

    func testDeletedConnectionsArePrunedAfterAFullListingAndPersisted() async throws {
        let a = Connection(name: "A", kind: .openvpn)
        let b = Connection(name: "B", kind: .openvpn)
        try store.save(a, config: "remote x\n")
        try store.save(b, config: "remote x\n")
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[listCmd] = list("Disconnected")
        let rankingStore = ConnectionRankingStore(url: base.appendingPathComponent("connection-order.json"))
        let m = ConnectionManager(store: store, secrets: secrets, mvpn: MvpnClient(runner: mock),
                                  native: NativeVPNController(runner: mock, driver: driver), rankingStore: rankingStore)
        // Még nincs reload: az üres lista nem törölheti a bejegyzéseket.
        m.pin(a.id.uuidString)
        m.pin(b.id.uuidString)
        m.pin(svcID)
        await m.refresh()
        XCTAssertEqual(m.ranking.pinned, [a.id.uuidString, b.id.uuidString, svcID])
        m.reload()
        await m.refresh()
        XCTAssertEqual(m.ranking.pinned, [a.id.uuidString, b.id.uuidString, svcID])
        try store.delete(a.id)
        m.reload()
        mock.responses[listCmd] = CommandResult(stdout: "")
        await m.refresh()
        XCTAssertEqual(m.ranking.pinned, [b.id.uuidString])
        XCTAssertEqual(rankingStore.load().pinned, [b.id.uuidString], "saved")
        // Új manager ugyanabból a fájlból (újraindítás).
        let restarted = ConnectionManager(store: store, secrets: secrets, mvpn: MvpnClient(runner: mock),
                                          native: NativeVPNController(runner: mock, driver: driver),
                                          rankingStore: rankingStore)
        XCTAssertEqual(restarted.ranking, m.ranking)
    }

    func testListFailureDoesNotPrune() async throws {
        mock.responses[listCmd] = list("Disconnected")
        let m = makeManager()
        await m.refresh()
        m.pin(svcID)
        mock.responses[listCmd] = CommandResult(exitCode: 1, stderr: "scutil hiba")
        await m.refresh()
        XCTAssertEqual(m.ranking.pinned, [svcID])
    }
}
