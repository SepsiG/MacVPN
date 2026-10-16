import XCTest
@testable import MacVPNCore

final class MvpnClientTests: XCTestCase {
    let id = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!

    // A magyar üzenetet ellenőrzi; a `--lang` a rögzített nyelvből jön, nem a gép locale-jából.
    override func setUp() { super.setUp(); AppLanguage.override = .hu }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    func testUpPassesKindIdDebugAndSecretsOnStdin() async throws {
        let mock = MockCommandRunner()
        try await MvpnClient(runner: mock).up(kind: .openvpn, id: id, secrets: Secrets(username: "u", password: "p"), debug: true)
        XCTAssertEqual(mock.calls.first?.commandLine,
                       "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up openvpn 11111111-2222-3333-4444-555555555555 --debug --lang hu")
        XCTAssertEqual(mock.calls.first?.stdin, "username=u\npassword=p\n")
    }

    func testUpFailureThrowsStderr() async {
        let mock = MockCommandRunner()
        mock.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn up wireguard \(id.uuidString) --lang hu"] =
            CommandResult(exitCode: 1, stderr: "AUTH_FAILED\n")
        do {
            try await MvpnClient(runner: mock).up(kind: .wireguard, id: id, secrets: Secrets(), debug: false)
            XCTFail("nem dobott")
        } catch {
            XCTAssertEqual(error.localizedDescription, "AUTH_FAILED")
        }
    }

    func testUpUsesTheLongRunnerStatusTheQuickOneDownTheDefault() async throws {
        let main = MockCommandRunner(), long = MockCommandRunner(), quick = MockCommandRunner()
        main.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu"] = CommandResult(exitCode: 1)
        long.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu"] = CommandResult(exitCode: 1)
        quick.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status --lang hu"] = CommandResult(stdout: "[]\n")
        let client = MvpnClient(runner: main, upRunner: long, statusRunner: quick)
        try await client.up(kind: .openvpn, id: id, secrets: Secrets(), debug: false)
        try await client.down(kind: .openvpn, id: id)
        let statuses = try await client.status()
        XCTAssertEqual(statuses, [])
        XCTAssertEqual(long.calls.map { $0.arguments[2] }, ["up"])
        XCTAssertEqual(main.calls.map { $0.arguments[2] }, ["down"])
        XCTAssertEqual(quick.calls.map { $0.arguments[2] }, ["status"])
    }

    func testRunnerTimeoutBudget() {
        // mvpn up legrosszabb esetben: 45 mp zárvárakozás + 30 mp kapcsolódás + pillanatképek, korábbi futás bontása.
        XCTAssertEqual(RunnerTimeouts.up, 150)
        XCTAssertGreaterThan(RunnerTimeouts.up, 45 + 30 + 45)
        XCTAssertEqual(RunnerTimeouts.quick, 20)
        XCTAssertLessThan(RunnerTimeouts.quick, RunnerTimeouts.standard)
        XCTAssertEqual(RunnerTimeouts.standard, ProcessCommandRunner().timeout)
    }

    func testParseStatus() throws {
        let json = """
        [{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"connected","iface":"utun5","ip":"10.8.0.2","since":1700000000},
         {"id":"11111111-2222-3333-4444-555555555556","kind":"strongswan","state":"connecting","iface":null,"ip":null,"since":null}]
        """
        let list = try MvpnClient.parseStatus(json)
        XCTAssertEqual(list.count, 2)
        XCTAssertEqual(list[0].connectionState, .connected(ip: "10.8.0.2", since: Date(timeIntervalSince1970: 1_700_000_000)))
        XCTAssertEqual(list[1].connectionState, .connecting)
        XCTAssertEqual(try MvpnClient.parseStatus("[]\n"), [])
    }

    func testFailedStatusMapsToFailed() throws {
        let s = try MvpnClient.parseStatus(#"[{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"failed","iface":null,"ip":null,"since":null}]"#)
        XCTAssertEqual(s[0].connectionState, .failed("A kapcsolat megszakadt"))
    }
}
