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
    var driver: MockNativeDriver!

    // A magyar üzeneteket és a `--lang hu` parancssort ellenőrzi: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() async throws {
        AppLanguage.override = .hu
        base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        store = ConnectionStore(baseURL: base)
        mock = MockCommandRunner()
        secrets = InMemorySecretStore()
        driver = MockNativeDriver()
    }

    override func tearDown() async throws {
        AppLanguage.override = nil
        try? FileManager.default.removeItem(at: base)
    }

    func makeManager() -> ConnectionManager {
        let m = ConnectionManager(store: store, secrets: secrets,
                                  mvpn: MvpnClient(runner: mock), native: NativeVPNController(runner: mock, driver: driver))
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

    /// Az SSTP root típus: ugyanazon az úton megy, mint a többi (`mvpn up sstp <id>`, jelszó a stdin-en).
    func testSSTPConnectUsesRootPath() async throws {
        let c = Connection(name: "SSTP", kind: .sstp)
        try store.save(c, config: "server=vpn.example.com\nuser=bob\n")
        secrets.set("Titok123", for: c.id, field: .password)
        let up = "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up sstp \(c.id.uuidString) --lang hu"
        mock.responses[statusCmd] = CommandResult(stdout:
            #"[{"id":"\#(c.id.uuidString)","kind":"sstp","state":"connected","iface":"ppp0","ip":"10.0.0.7","since":null}]"#)
        let m = makeManager()
        await m.connect(c, debug: false)
        let call = try XCTUnwrap(mock.calls.first { $0.commandLine == up })
        XCTAssertEqual(call.stdin, "password=Titok123\n")
        XCTAssertFalse(call.arguments.contains { $0.contains("Titok123") })
        XCTAssertEqual(m.state(for: c.id.uuidString), .connected(ip: "10.0.0.7", since: nil))
        await m.disconnect(c)
        XCTAssertTrue(mock.calls.contains { $0.commandLine == "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn down sstp \(c.id.uuidString) --lang hu" })
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

    /// An unbound managed connection whose only same-named service points to its server (secrets may be passed).
    func nativeManager() throws -> (ConnectionManager, Connection) {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP",
                           native: NativeSettings(server: "vpn.example.com", account: "bob"))
        try store.save(c, config: nil)
        mock.responses[statusCmd] = CommandResult(stdout: "[]")
        mock.responses[listCmd] = list("Disconnected")
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = show("vpn.example.com")
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
        driver.startError = MvpnError.failed("nem indul")
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
        XCTAssertEqual(driver.stops, [svcID])
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

    // MARK: - In-process native start: secrets

    func testManagedNativeConnectPassesSecretsToDriver() async throws {
        let (m, c) = try nativeManager()
        secrets.set("bob", for: c.id, field: .username)
        secrets.set("pw", for: c.id, field: .password)
        secrets.set("k", for: c.id, field: .psk)
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts, [.init(serviceID: svcID, options: [
            "IPSec": ["SharedSecret": "k"],
            "PPP": ["AuthName": "bob", "AuthPassword": "pw"],
        ] as NSDictionary, linger: true)])
        XCTAssertFalse(mock.calls.contains { $0.arguments.contains("start") }, "no scutil --nc start")
        XCTAssertEqual(m.state(for: c.id.uuidString), .connecting)
    }

    func testManagedCiscoConnectPassesXAuth() async throws {
        let c = Connection(name: "Partner", kind: .cisco, nativeServiceName: "Partner",
                           native: NativeSettings(server: "1.2.3.4", account: "bob", groupName: "g"))
        try store.save(c, config: nil)
        mock.responses[listCmd] = CommandResult(stdout: "  (Disconnected)     \(svcID) IPSec              \"Partner\"    [IPSec]\n")
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = CommandResult(stdout: "IPSec <dictionary> {\n  RemoteAddress : 1.2.3.4\n}\n")
        secrets.set("bob", for: c.id, field: .username)
        secrets.set("k", for: c.id, field: .psk)
        let m = makeManager()
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts.first?.options,
                       ["IPSec": ["SharedSecret": "k", "XAuthName": "bob"]] as NSDictionary)
    }

    func testManagedNativeConnectWithoutSecretsUsesStoredConfig() async throws {
        let (m, c) = try nativeManager()
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts, [.init(serviceID: svcID, options: nil, linger: true)])
    }

    func testManagedNativeDriverFailure() async throws {
        let (m, c) = try nativeManager()
        driver.startError = NativeDriverError.start("No service")
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(c, debug: false)
        let reason = "A VPN szolgáltatás nem indítható: No service"
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(reason))
        XCTAssertEqual(events, [.failed(connectionID: c.id.uuidString, name: "Office L2TP", reason: reason)])
    }

    func systemManager() async throws -> (ConnectionManager, SystemVPNService) {
        mock.responses[listCmd] = list("Disconnected")
        let m = makeManager()
        await m.refresh()
        return (m, try XCTUnwrap(m.systemServices.first))
    }

    func testSystemConnectPassesStoredSecrets() async throws {
        let (m, s) = try await systemManager()
        let id = try XCTUnwrap(UUID(uuidString: svcID))
        secrets.set("k", for: id, field: .psk)
        secrets.set("pw", for: id, field: .password)
        await m.connectSystem(s)
        XCTAssertEqual(driver.starts, [.init(serviceID: svcID, options: [
            "IPSec": ["SharedSecret": "k"], "PPP": ["AuthPassword": "pw"],
        ] as NSDictionary, linger: true)])
        XCTAssertEqual(m.state(for: svcID), .connecting)
    }

    func testSystemConnectWithoutSecretsPassesNoOptions() async throws {
        let (m, s) = try await systemManager()
        await m.connectSystem(s)
        XCTAssertEqual(driver.starts, [.init(serviceID: svcID, options: nil, linger: true)])
    }

    func testSystemConnectIgnoresSecretsForUnsupportedType() async throws {
        let wgID = "052ED352-624D-4F75-BD84-D3E278CFD84F"
        mock.responses[listCmd] = CommandResult(stdout: "* (Disconnected)   \(wgID) VPN (com.wireguard.macos) \"Home\"   [VPN:com.wireguard.macos]\n")
        let m = makeManager()
        await m.refresh()
        let s = try XCTUnwrap(m.systemServices.first)
        secrets.set("k", for: try XCTUnwrap(UUID(uuidString: wgID)), field: .psk)
        await m.connectSystem(s)
        XCTAssertEqual(driver.starts.map(\.options), [nil])
    }

    static let pskHint = "A kapcsolat nem jött létre. Ha ez egy L2TP/IPsec VPN, add meg a közös kulcsát (PSK) itt: MacVPN → Kapcsolatok → Office L2TP."
    static let systemGeneric = "A kapcsolat nem jött létre."

    func testSystemConnectingThenDisconnectedFailsWithPSKHint() async throws {
        let (m, s) = try await systemManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .connecting)
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed(Self.pskHint))
        XCTAssertEqual(events, [.failed(connectionID: svcID, name: "Office L2TP", reason: Self.pskHint)])
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed(Self.pskHint), "sticky")
    }

    func testSystemFailureWithStoredPSKUsesGenericReason() async throws {
        let (m, s) = try await systemManager()
        secrets.set("k", for: try XCTUnwrap(UUID(uuidString: svcID)), field: .psk)
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed(Self.systemGeneric))
    }

    func testSystemPSKHintIsEnglishToo() async throws {
        AppLanguage.override = .en
        let (m, s) = try await systemManager()
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        mock.responses[listCmd] = list("Disconnected")
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed(
            "The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → Office L2TP."))
    }

    func testSystemNeverConnectingFailsAfterGrace() async throws {
        let (m, s) = try await systemManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        await m.connectSystem(s)
        clock += 3
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .connecting, "5 mp-en belül még nem hiba")
        clock += 3
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed(Self.pskHint))
    }

    func testSystemStuckConnectingTimesOutAndStops() async throws {
        let (m, s) = try await systemManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connecting")
        await m.refresh()
        clock += 46
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed("Időtúllépés"))
        XCTAssertEqual(driver.stops, [svcID])
    }

    func testSystemTimeoutWorksWithoutList() async throws {
        let (m, s) = try await systemManager()
        var clock = Date(timeIntervalSince1970: 1000)
        m.now = { clock }
        await m.connectSystem(s)
        mock.responses[listCmd] = CommandResult(exitCode: 1, stderr: "scutil hiba")
        clock += 46
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .failed("Időtúllépés"))
        XCTAssertEqual(driver.stops, [svcID])
    }

    func testSystemConnectSuccessThenDisconnect() async throws {
        let (m, s) = try await systemManager()
        await m.connectSystem(s)
        mock.responses[listCmd] = list("Connected")
        await m.refresh()
        XCTAssertEqual(m.state(for: svcID), .connected(ip: nil, since: nil))
        mock.responses[listCmd] = list("Disconnected")
        await m.disconnectSystem(s)
        XCTAssertEqual(m.state(for: svcID), .disconnected)
        XCTAssertEqual(driver.stops, [svcID])
    }

    // MARK: - Native service binding (scutil service ID)

    let otherID = "AAAAAAAA-1111-2222-3333-444444444444"

    func twoServices(_ firstStatus: String = "Disconnected", _ secondStatus: String = "Disconnected") -> CommandResult {
        CommandResult(stdout: """
        * (\(firstStatus))      \(otherID) PPP --> L2TP       "Office L2TP"     [PPP:L2TP]
        * (\(secondStatus))      \(svcID) PPP --> L2TP       "Office L2TP"     [PPP:L2TP]

        """)
    }

    func show(_ address: String) -> CommandResult {
        CommandResult(stdout: "* (Disconnected) x PPP --> L2TP \"Office L2TP\" [PPP:L2TP]\nPPP <dictionary> {\n  AuthName : bob\n  CommRemoteAddress : \(address)\n}\n")
    }

    func boundCandidate() throws -> Connection {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP",
                           native: NativeSettings(server: "vpn.example.com", account: "bob"))
        try store.save(c, config: nil)
        mock.responses[listCmd] = twoServices()
        mock.responses["/usr/sbin/scutil --nc show \(otherID)"] = show("evil.example.net")
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = show("VPN.example.com")
        return c
    }

    func testRefreshBindsServiceByNameAndServerAddress() async throws {
        let c = try boundCandidate()
        let m = makeManager()
        await m.refresh()
        XCTAssertEqual(m.connections.first?.nativeServiceID, svcID)
        XCTAssertEqual(try store.list().first?.nativeServiceID, svcID, "persisted in meta.json")
        // The same-named foreign service is not hidden as "managed".
        XCTAssertEqual(m.systemServices.map(\.id), [otherID])
        // Once bound, no more scutil --nc show.
        let shows = mock.calls.filter { $0.arguments.contains("show") }.count
        await m.refresh()
        XCTAssertEqual(mock.calls.filter { $0.arguments.contains("show") }.count, shows)
        _ = c
    }

    func testBoundConnectAndStatusUseTheServiceID() async throws {
        let c = try boundCandidate()
        secrets.set("pw", for: c.id, field: .password)
        let m = makeManager()
        await m.refresh()
        let bound = try XCTUnwrap(m.connections.first)
        await m.connect(bound, debug: false)
        XCTAssertEqual(driver.starts.map(\.serviceID), [svcID])
        mock.responses[listCmd] = twoServices("Connected", "Disconnected")
        await m.refresh()
        XCTAssertNotEqual(m.state(for: c.id.uuidString), .connected(ip: nil, since: nil),
                          "the foreign service's state is not ours")
        mock.responses[listCmd] = twoServices("Disconnected", "Connected")
        await m.refresh()
        XCTAssertEqual(m.state(for: c.id.uuidString), .connected(ip: nil, since: nil))
        await m.disconnect(bound)
        XCTAssertEqual(driver.stops, [svcID])
    }

    func testAmbiguousNameRefusesToPassSecrets() async throws {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP")
        try store.save(c, config: nil)
        secrets.set("pw", for: c.id, field: .password)
        mock.responses[listCmd] = twoServices()
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts, [])
        let reason = "Több „Office L2TP” nevű VPN szolgáltatás van. A MacVPN nem adja át a jelszót, amíg nem egyértelmű, melyik az övé: nevezd át vagy töröld a másikat a Rendszerbeállítások → Hálózat alatt."
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(reason))
        XCTAssertEqual(events, [.failed(connectionID: c.id.uuidString, name: "Office L2TP", reason: reason)])
    }

    static let serverMismatchHU = "A(z) „Office L2TP” nevű VPN szolgáltatás szervercíme nem egyezik a kapcsolat szerverével. A MacVPN nem adja át neki a jelszót és a PSK-t: telepítsd újra a profilt a MacVPN → Kapcsolatok alatt, vagy töröld a másik szolgáltatást a Rendszerbeállítások → Hálózat alatt."

    /// Unbound, the only same-named service points to another server: no start at all (neither with nor without secrets).
    func testUnboundNameMatchWithOtherServerRefusesToStart() async throws {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP",
                           native: NativeSettings(server: "other.example.com", account: "bob"))
        try store.save(c, config: nil)
        secrets.set("pw", for: c.id, field: .password)
        secrets.set("k", for: c.id, field: .psk)
        mock.responses[listCmd] = list("Disconnected")
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = show("vpn.example.com")
        let m = makeManager()
        await m.refresh()
        XCTAssertNil(m.connections.first?.nativeServiceID)
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        await m.connect(try XCTUnwrap(m.connections.first), debug: false)
        XCTAssertEqual(driver.starts, [])
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(Self.serverMismatchHU))
        XCTAssertEqual(events, [.failed(connectionID: c.id.uuidString, name: "Office L2TP", reason: Self.serverMismatchHU)])
    }

    /// Unbound and the server address cannot be read (or the connection has no server): refused too.
    func testUnboundNameMatchWithUnknownAddressRefusesToStart() async throws {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP",
                           native: NativeSettings(server: "vpn.example.com", account: "bob"))
        try store.save(c, config: nil)
        secrets.set("pw", for: c.id, field: .password)
        mock.responses[listCmd] = list("Disconnected")
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = CommandResult(exitCode: 1, stderr: "nope")
        let m = makeManager()
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts, [])
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(Self.serverMismatchHU))

        let legacy = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP")
        try store.save(legacy, config: nil)
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = show("vpn.example.com")
        m.reload()
        await m.connect(legacy, debug: false)
        XCTAssertEqual(driver.starts, [])
        XCTAssertEqual(m.state(for: legacy.id.uuidString), .failed(Self.serverMismatchHU))
    }

    /// Unbound, address matches (case-insensitively) at connect time even without a prior refresh: secrets passed.
    func testUnboundNameMatchWithSameServerPassesSecrets() async throws {
        let (m, c) = try nativeManager()
        mock.responses["/usr/sbin/scutil --nc show \(svcID)"] = show("VPN.Example.com")
        secrets.set("pw", for: c.id, field: .password)
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts.map(\.serviceID), [svcID])
        XCTAssertEqual(driver.starts.first?.options, ["PPP": ["AuthPassword": "pw"]] as NSDictionary)
    }

    func testServerMismatchMessageIsEnglishToo() {
        AppLanguage.override = .en
        XCTAssertEqual(ConnectionManager.serverMismatchReason("Office L2TP"),
                       "The server address of the VPN service named “Office L2TP” does not match this connection’s server. MacVPN does not pass the password or the PSK to it: reinstall the profile in MacVPN → Connections, or remove the other service in System Settings → Network.")
    }

    func testVanishedBoundServiceIsUnbound() async throws {
        var c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP")
        c.nativeServiceID = otherID
        try store.save(c, config: nil)
        mock.responses[listCmd] = list("Disconnected")
        let m = makeManager()
        await m.connect(c, debug: false)
        XCTAssertEqual(driver.starts, [], "a bound but missing service is not replaced by a name match")
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("A profil nincs telepítve: Office L2TP"))
        await m.refresh()
        XCTAssertNil(m.connections.first?.nativeServiceID)
        XCTAssertNil(try store.list().first?.nativeServiceID)
    }

    func testInstalledNativeIDsAreReported() async throws {
        let (m, c) = try nativeManager()
        var seen: [Set<UUID>] = []
        m.onNativeServicesSeen = { seen.append($0) }
        await m.refresh()
        XCTAssertEqual(seen, [[c.id]])
        mock.responses[listCmd] = CommandResult(stdout: "")
        await m.refresh()
        XCTAssertEqual(seen, [[c.id], []])
        XCTAssertEqual(m.installedNativeIDs, [])
    }
}
