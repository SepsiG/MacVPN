import XCTest
@testable import MacVPNCore

final class NativeVPNTests: XCTestCase {
    // Magyar üzeneteket ellenőriz: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() { super.setUp(); AppLanguage.override = .hu }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    let sample = """
    Available network connection services in the current set (*=enabled):
    * (Disconnected)   BB566669-2725-4F23-9181-0AC6F242F1CF PPP --> XR21B1411  "XR21B1411"                      [PPP:Modem]
    * (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Office L2TP"                        [PPP:L2TP]
    * (Connected)      052ED352-624D-4F75-BD84-D3E278CFD84F VPN (com.wireguard.macos) "Home"                           [VPN:com.wireguard.macos]
      (Connecting)     AAAAAAAA-624D-4F75-BD84-D3E278CFD84F IPSec              "Partner Cisco"                  [IPSec]
    """

    func testParseListFiltersVPNs() {
        let list = ScutilParser.parseList(sample)
        XCTAssertEqual(list.map(\.name), ["Office L2TP", "Home", "Partner Cisco"])
        XCTAssertEqual(list[0].id, "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4")
        XCTAssertEqual(list[0].typeLabel, "L2TP")
        XCTAssertEqual(list[1].typeLabel, "WireGuard (app)")
        XCTAssertEqual(list[2].typeLabel, "Cisco IPsec")
        XCTAssertEqual(list[0].connectionState, .disconnected)
        XCTAssertEqual(list[1].connectionState, .connected(ip: nil, since: nil))
        XCTAssertEqual(list[2].connectionState, .connecting)
    }

    func testStartStopGoThroughDriverNotScutil() async throws {
        let mock = MockCommandRunner()
        let driver = MockNativeDriver()
        let c = NativeVPNController(runner: mock, driver: driver)
        try await c.start(serviceID: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4")
        try await c.stop(serviceID: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4")
        XCTAssertTrue(mock.calls.isEmpty, "no scutil start/stop (secrets must never reach argv)")
        XCTAssertEqual(driver.starts, [.init(serviceID: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", options: nil, linger: true)])
        XCTAssertEqual(driver.stops, ["38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"])
    }

    func testStartLingers() {
        // The VPN must survive a MacVPN quit ("keep running"), so the in-process start lingers.
        XCTAssertTrue(NativeVPNController.linger)
    }

    func testStartPassesOptionsForKind() async throws {
        let driver = MockNativeDriver()
        let c = NativeVPNController(runner: MockCommandRunner(), driver: driver)
        try await c.start(serviceID: "S", kind: .l2tp, secrets: Secrets(password: "pw", psk: "k"))
        XCTAssertEqual(driver.starts.first?.options,
                       ["IPSec": ["SharedSecret": "k"], "PPP": ["AuthPassword": "pw"]] as NSDictionary)
        XCTAssertEqual(driver.starts.first?.linger, true)
    }

    func testStartErrorPropagates() async {
        let driver = MockNativeDriver()
        driver.startError = MvpnError.failed("nem indul")
        do {
            try await NativeVPNController(runner: MockCommandRunner(), driver: driver).start(serviceID: "S")
            XCTFail("nem dobott")
        } catch {
            XCTAssertEqual(error.localizedDescription, "nem indul")
        }
    }

    func testDriverErrorMessageIsLocalized() {
        XCTAssertEqual(NativeDriverError.start("No service").localizedDescription,
                       "A VPN szolgáltatás nem indítható: No service")
        XCTAssertEqual(NativeDriverError.stop("No service").localizedDescription,
                       "A VPN szolgáltatás nem állítható le: No service")
        XCTAssertEqual(NativeDriverError.open("No service").localizedDescription,
                       "A VPN szolgáltatás nem nyitható meg: No service")
    }

    // MARK: - Start options

    func testNativeKindMapping() {
        XCTAssertEqual(NativeKind(kind: .l2tp), .l2tp)
        XCTAssertEqual(NativeKind(kind: .cisco), .ciscoIPSec)
        XCTAssertNil(NativeKind(kind: .openvpn))
        XCTAssertEqual(NativeKind(typeLabel: "L2TP"), .l2tp)
        XCTAssertEqual(NativeKind(typeLabel: "Cisco IPsec"), .ciscoIPSec)
        XCTAssertNil(NativeKind(typeLabel: "IKEv2"))
        XCTAssertNil(NativeKind(typeLabel: "WireGuard (app)"))
    }

    func testL2TPOptionsWithAllSecrets() {
        let o = NativeStartOptions.make(kind: .l2tp, secrets: Secrets(username: "bob", password: "pw", psk: "k"))
        XCTAssertEqual(o as NSDictionary?, [
            "IPSec": ["SharedSecret": "k"],
            "PPP": ["AuthName": "bob", "AuthPassword": "pw"],
        ] as NSDictionary)
    }

    func testL2TPOptionsPSKOnly() {
        let o = NativeStartOptions.make(kind: .l2tp, secrets: Secrets(username: "", password: nil, psk: "k"))
        XCTAssertEqual(o as NSDictionary?, ["IPSec": ["SharedSecret": "k"]] as NSDictionary)
    }

    func testL2TPOptionsPasswordOnly() {
        let o = NativeStartOptions.make(kind: .l2tp, secrets: Secrets(password: "pw"))
        XCTAssertEqual(o as NSDictionary?, ["PPP": ["AuthPassword": "pw"]] as NSDictionary)
    }

    func testCiscoOptionsWithAllSecrets() {
        let o = NativeStartOptions.make(kind: .ciscoIPSec, secrets: Secrets(username: "bob", password: "pw", psk: "k"))
        XCTAssertEqual(o as NSDictionary?, [
            "IPSec": ["SharedSecret": "k", "XAuthName": "bob", "XAuthPassword": "pw"],
        ] as NSDictionary)
    }

    func testCiscoOptionsPSKOnly() {
        let o = NativeStartOptions.make(kind: .ciscoIPSec, secrets: Secrets(psk: "k"))
        XCTAssertEqual(o as NSDictionary?, ["IPSec": ["SharedSecret": "k"]] as NSDictionary)
    }

    func testOptionsNilWithoutSecrets() {
        XCTAssertNil(NativeStartOptions.make(kind: .l2tp, secrets: Secrets()))
        XCTAssertNil(NativeStartOptions.make(kind: .ciscoIPSec, secrets: Secrets(username: "", password: "", psk: "")))
    }

    func testSystemServiceSecretSupport() {
        let l2tp = SystemVPNService(id: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", name: "Office", typeLabel: "L2TP", status: "Disconnected")
        XCTAssertEqual(l2tp.secretID, UUID(uuidString: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"))
        XCTAssertTrue(l2tp.supportsStoredSecrets)
        let bad = SystemVPNService(id: "not-a-uuid", name: "X", typeLabel: "L2TP", status: "Disconnected")
        XCTAssertNil(bad.secretID)
        XCTAssertFalse(bad.supportsStoredSecrets)
        let wg = SystemVPNService(id: "052ED352-624D-4F75-BD84-D3E278CFD84F", name: "Home", typeLabel: "WireGuard (app)", status: "Connected")
        XCTAssertFalse(wg.supportsStoredSecrets)
    }

    func testNameWithQuotesAndApostrophe() {
        let line = #"* (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Bob's "work" VPN"   [PPP:L2TP]"#
        XCTAssertEqual(ScutilParser.parseList(line).map(\.name), [#"Bob's "work" VPN"#])
    }

    func testListThrowsOnNonZeroExit() async {
        let mock = MockCommandRunner()
        mock.responses["/usr/sbin/scutil --nc list"] = CommandResult(exitCode: 1)
        do {
            _ = try await NativeVPNController(runner: mock, driver: MockNativeDriver()).list()
            XCTFail("nem dobott")
        } catch {
            XCTAssertEqual(error.localizedDescription, "scutil hiba (kilépési kód: 1)")
        }
    }
}
