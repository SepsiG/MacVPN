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

    func testStartStopCommands() async throws {
        let mock = MockCommandRunner()
        let c = NativeVPNController(runner: mock)
        try await c.start(serviceID: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4")
        try await c.stop(serviceID: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4")
        XCTAssertEqual(mock.calls.map(\.commandLine), [
            "/usr/sbin/scutil --nc start 38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
            "/usr/sbin/scutil --nc stop 38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        ])
    }

    func testNameWithQuotesAndApostrophe() {
        let line = #"* (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Bob's "work" VPN"   [PPP:L2TP]"#
        XCTAssertEqual(ScutilParser.parseList(line).map(\.name), [#"Bob's "work" VPN"#])
    }

    func testListThrowsOnNonZeroExit() async {
        let mock = MockCommandRunner()
        mock.responses["/usr/sbin/scutil --nc list"] = CommandResult(exitCode: 1)
        do {
            _ = try await NativeVPNController(runner: mock).list()
            XCTFail("nem dobott")
        } catch {
            XCTAssertEqual(error.localizedDescription, "scutil hiba (kilépési kód: 1)")
        }
    }
}
