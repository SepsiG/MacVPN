import XCTest
@testable import MacVPNCore

@MainActor
final class ConnectionManagerTests: XCTestCase {
    let statusCmd = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu"
    let listCmd = "/usr/sbin/scutil --nc list"
    var base: URL!
    var store: ConnectionStore!
    var mock: MockCommandRunner!
    var secrets: InMemorySecretStore!

    // A magyar üzeneteket és a `--lang hu` parancssort ellenőrzi: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() async throws {
        AppLanguage.override = .hu
        base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = ConnectionStore(baseURL: base)
        mock = MockCommandRunner()
        secrets = InMemorySecretStore()
    }

    override func tearDown() async throws {
        AppLanguage.override = nil
        try? FileManager.default.removeItem(at: base)
    }

    func makeManager() -> ConnectionManager {
        let m = ConnectionManager(store: store, secrets: secrets,
                                  mvpn: MvpnClient(runner: mock), native: NativeVPNController(runner: mock))
        m.reload()
        return m
    }

    func testRefreshMergesRootAndNativeAndHidesManagedNative() async throws {
        let ovpn = Connection(name: "Iroda", kind: .openvpn)
        let l2tp = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP")
        try store.save(ovpn, config: "remote x\n")
        try store.save(l2tp, config: nil)
        mock.responses[statusCmd] = CommandResult(stdout:
            #"[{"id":"\#(ovpn.id.uuidString)","kind":"openvpn","state":"connected","iface":"utun5","ip":"10.8.0.2","since":null}]"#)
        mock.responses[listCmd] = CommandResult(stdout: """
        * (Connected)      38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Office L2TP"     [PPP:L2TP]
        * (Disconnected)   052ED352-624D-4F75-BD84-D3E278CFD84F VPN (com.wireguard.macos) "Home"   [VPN:com.wireguard.macos]
        """)
        let m = makeManager()
        await m.refresh()
        XCTAssertEqual(m.state(for: ovpn.id.uuidString), .connected(ip: "10.8.0.2", since: nil))
        XCTAssertEqual(m.state(for: l2tp.id.uuidString), .connected(ip: nil, since: nil))
        XCTAssertEqual(m.systemServices.map(\.name), ["Home"])
        XCTAssertEqual(m.state(for: "052ED352-624D-4F75-BD84-D3E278CFD84F"), .disconnected)
        XCTAssertTrue(m.hasActive)
    }

    func testConnectFailureSetsFailedAndEmitsEvent() async throws {
        let c = Connection(name: "WG", kind: .wireguard)
        try store.save(c, config: "x")
        mock.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(c.id.uuidString) --lang hu"] =
            CommandResult(exitCode: 1, stderr: "időtúllépés")
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(c, debug: false)
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("időtúllépés"))
        XCTAssertEqual(events, [.failed(connectionID: c.id.uuidString, name: "WG", reason: "időtúllépés")])
        XCTAssertTrue(m.hasFailure)
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("időtúllépés"), "a refresh nem törölheti a hibát")
    }

    func testDropDetection() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        mock.responses[statusCmd] = CommandResult(stdout:
            #"[{"id":"\#(c.id.uuidString)","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}]"#)
        await m.refresh()
        mock.responses[statusCmd] = CommandResult(stdout:
            #"[{"id":"\#(c.id.uuidString)","kind":"openvpn","state":"failed","iface":null,"ip":null,"since":null}]"#)
        await m.refresh()
        XCTAssertEqual(events, [.dropped(connectionID: c.id.uuidString, name: "Iroda")])
    }

    func testConnectPassesSecretsAndDisconnectClearsFailure() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        secrets.set("bob", for: c.id, field: .username)
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let m = makeManager()
        await m.connect(c, debug: true)
        let up = mock.calls.first { $0.arguments.contains("up") }
        XCTAssertEqual(up?.arguments.suffix(3), ["--debug", "--lang", "hu"])
        XCTAssertEqual(up?.stdin, "username=bob\n")
        await m.disconnect(c)
        XCTAssertEqual(m.state(for: c.id.uuidString), .disconnected)
    }

    // MARK: - Állapotgép, versenyhelyzetek

    let svcID = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"

    func list(_ status: String) -> CommandResult {
        CommandResult(stdout: "* (\(status))      \(svcID) PPP --> L2TP       \"Office L2TP\"     [PPP:L2TP]\n")
    }

    func connectedJSON(_ c: Connection, state: String = "connected") -> CommandResult {
        CommandResult(stdout: #"[{"id":"\#(c.id.uuidString)","kind":"openvpn","state":"\#(state)","iface":null,"ip":null,"since":null}]"#)
    }

    func testTransientStatusFailureKeepsConnected() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        mock.responses[statusCmd] = connectedJSON(c)
        await m.refresh()
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
        mock.responses[statusCmd] = CommandResult(exitCode: 1, stderr: "sudo hiba")
        await m.refresh()
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
        XCTAssertTrue(events.isEmpty)
    }

    func testStatusErrorAfterThreeFailuresAndClearedOnSuccess() async throws {
        try store.save(Connection(name: "Iroda", kind: .openvpn), config: "remote x\n")
        mock.responses[statusCmd] = CommandResult(exitCode: 1, stderr: "sudo hiba")
        let m = makeManager()
        await m.refresh(); await m.refresh()
        XCTAssertNil(m.statusError)
        await m.refresh()
        XCTAssertEqual(m.statusError, "Az állapot nem kérdezhető le: sudo hiba")
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        await m.refresh()
        XCTAssertNil(m.statusError)
    }

    func testRootStatusSkippedWithoutRootBackedConnections() async throws {
        let (m, _) = try nativeManager()
        mock.responses[statusCmd] = CommandResult(exitCode: 1, stderr: "nincs telepítve")
        for _ in 0..<3 { await m.refresh() }
        XCTAssertNil(m.statusError)
        XCTAssertFalse(mock.calls.contains { $0.commandLine == statusCmd })
    }

    func testStaleRefreshDoesNotOverwriteDisconnect() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        mock.responses[statusCmd] = connectedJSON(c)
        await m.refresh()
        let key = c.id.uuidString
        let downCmd = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn down openvpn \(key) --lang hu"
        mock.delays[statusCmd] = 0.1
        mock.delays[downCmd] = 0.3
        let stale = Task { await m.refresh() }          // a régi "connected" választ olvassa
        try await Task.sleep(nanoseconds: 20_000_000)
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let disc = Task { await m.disconnect(c) }
        try await Task.sleep(nanoseconds: 150_000_000)  // a stale refresh közben lefutott
        await stale.value
        XCTAssertEqual(m.state(for: key), .disconnecting)
        await disc.value
        XCTAssertEqual(m.state(for: key), .disconnected)
        XCTAssertTrue(events.isEmpty)
    }

    func testStaleResultFromOlderRefreshIsDiscarded() async throws {
        let c = Connection(name: "Iroda", kind: .openvpn)
        try store.save(c, config: "remote x\n")
        let m = makeManager()
        mock.responses[statusCmd] = connectedJSON(c)
        mock.delays[statusCmd] = 0.15
        let slow = Task { await m.refresh() }           // connected-et olvas, lassan
        try await Task.sleep(nanoseconds: 20_000_000)
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.delays[statusCmd] = 0
        await m.refresh()                               // újabb, gyors: disconnected
        await slow.value
        XCTAssertEqual(m.state(for: c.id.uuidString), .disconnected)
    }

    func nativeManager() throws -> (ConnectionManager, Connection) {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP")
        try store.save(c, config: nil)
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[listCmd] = list("Disconnected")
        return (makeManager(), c)
    }

    func testNativeConnectFailureDetected() async throws {
        let (m, c) = try nativeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(c, debug: false)
        XCTAssertEqual(m.state(for: c.id.uuidString), .connecting)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .connecting)
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        let reason = "A kapcsolat nem jött létre – részletek: debug csatlakozás"
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(reason))
        XCTAssertEqual(events, [.failed(connectionID: c.id.uuidString, name: "Office L2TP", reason: reason)])
    }

    func testNativeConnectSuccess() async throws {
        let (m, c) = try nativeManager()
        await m.connect(c, debug: false)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .connected(ip: nil, since: nil))
    }

    func testNativeNeverConnectingFailsAfterGracePeriodAndTimeout() async throws {
        let (m, c) = try nativeManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(c, debug: false)
        clock += 3
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .connecting, "5 mp-en belül még nem hiba")
        clock += 3
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("A kapcsolat nem jött létre – részletek: debug csatlakozás"))
        XCTAssertEqual(events.count, 1)
    }

    func testNativeStuckConnectingTimesOut() async throws {
        let (m, c) = try nativeManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        await m.connect(c, debug: false)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        clock += 46
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("Időtúllépés"))
    }

    func testNativeDropDetected() async throws {
        let (m, c) = try nativeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .disconnected)
        XCTAssertEqual(events, [.dropped(connectionID: c.id.uuidString, name: "Office L2TP")])
    }

    func testListFailureKeepsNativeAndSystemStates() async throws {
        let (m, c) = try nativeManager()
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        mock.responses[listCmd] = CommandResult(exitCode: 1, stderr: "scutil hiba")
        await m.refresh()
        XCTAssertTrue(m.state(for: c.id.uuidString).isConnected)
    }

    func testDisconnectDuringPendingConnectThenUpFailsIsSilent() async throws {
        let c = Connection(name: "WG", kind: .wireguard)
        try store.save(c, config: "x")
        let key = c.id.uuidString
        let upCmd = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(key) --lang hu"
        mock.responses[upCmd] = CommandResult(exitCode: 1, stderr: "megszakítva")
        mock.delays[upCmd] = 0.2
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        let connecting = Task { await m.connect(c, debug: false) }
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(m.state(for: key), .connecting)
        await m.disconnect(c)
        await connecting.value
        XCTAssertEqual(m.state(for: key), .disconnected)
        XCTAssertTrue(events.isEmpty)
    }

    func testFailedSystemConnectIsSticky() async throws {
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[listCmd] = CommandResult(stdout: "* (Disconnected)   052ED352-624D-4F75-BD84-D3E278CFD84F VPN (com.wireguard.macos) \"Home\"   [VPN:com.wireguard.macos]\n")
        let sysID = "052ED352-624D-4F75-BD84-D3E278CFD84F"
        let m = makeManager()
        await m.refresh()
        let s = try XCTUnwrap(m.systemServices.first)
        mock.responses["/usr/sbin/scutil --nc start \(sysID)"] = CommandResult(exitCode: 1, stderr: "nem indul")
        await m.connectSystem(s)
        XCTAssertEqual(m.state(for: sysID), .failed("nem indul"))
        await m.refresh()
        XCTAssertEqual(m.state(for: sysID), .failed("nem indul"))
        await m.disconnectSystem(s)
        XCTAssertEqual(m.state(for: sysID), .disconnected)
    }

    func testReloadKeepsListOnStoreError() throws {
        let c = Connection(name: "A", kind: .openvpn)
        try store.save(c, config: "x")
        let m = makeManager()
        XCTAssertEqual(m.connections.count, 1)
        // a baseURL fájlra cserélése -> list() hibát dob
        try FileManager.default.removeItem(at: base)
        try Data("x".utf8).write(to: base)
        m.reload()
        XCTAssertEqual(m.connections.count, 1)
    }

    // MARK: - Megszakított csatlakozás, tokenek

    func testLateSuccessfulUpAfterCancelIsTornDown() async throws {
        let c = Connection(name: "WG", kind: .wireguard)
        try store.save(c, config: "x")
        let key = c.id.uuidString
        let upCmd = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(key) --lang hu"
        mock.delays[upCmd] = 0.2
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        let connecting = Task { await m.connect(c, debug: false) }
        try await Task.sleep(nanoseconds: 50_000_000)
        await m.disconnect(c)
        await connecting.value
        let cmds = mock.calls.map(\.commandLine)
        let upIndex = try XCTUnwrap(cmds.firstIndex(of: upCmd))
        let downs = cmds.enumerated().filter { $0.element.contains(" down wireguard ") }.map(\.offset)
        XCTAssertEqual(downs.count, 2, "a disconnect down + a late teardown down")
        XCTAssertTrue(downs.allSatisfy { $0 > upIndex })
        XCTAssertEqual(m.state(for: key), .disconnected)
        XCTAssertTrue(events.isEmpty)
    }

    func testStaleFailureDoesNotTouchNewerConnect() async throws {
        let c = Connection(name: "WG", kind: .wireguard)
        try store.save(c, config: "x")
        let key = c.id.uuidString
        let upCmd = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(key) --lang hu"
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[upCmd] = CommandResult(exitCode: 1, stderr: "A hibája")
        mock.delays[upCmd] = 0.3
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        let a = Task { await m.connect(c, debug: false) }
        try await Task.sleep(nanoseconds: 50_000_000)
        await m.disconnect(c)
        mock.responses[upCmd] = CommandResult()
        mock.delays[upCmd] = 0.6
        let b = Task { await m.connect(c, debug: false) }
        try await Task.sleep(nanoseconds: 50_000_000)
        await a.value                                  // A most bukik el
        XCTAssertTrue(events.isEmpty)
        XCTAssertEqual(m.state(for: key), .connecting, "B művelete érintetlen")
        await b.value
        XCTAssertTrue(events.isEmpty)
    }

    func testNativeTimeoutStopsServiceAndWorksWithoutList() async throws {
        let (m, c) = try nativeManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        await m.connect(c, debug: false)
        mock.responses[listCmd] = CommandResult(exitCode: 1, stderr: "scutil hiba")
        clock += 46
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("Időtúllépés"))
        XCTAssertTrue(mock.calls.contains { $0.commandLine == "/usr/sbin/scutil --nc stop \(svcID)" })
    }

    func testEventsAreEmittedAfterStateIsPublished() async throws {
        let (m, c) = try nativeManager()
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        var seen: ConnectionState?
        m.onEvent = { _ in seen = m.state(for: c.id.uuidString) }
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        XCTAssertEqual(seen, .disconnected)
    }
}
