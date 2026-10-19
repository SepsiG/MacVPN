import XCTest
import SystemConfiguration
@testable import MacVPNCore

/// A ConnectionManager MFA folyamata: kódkérés csatlakozás előtt (kód a jelszó végén, statikus challenge), a közvetítő
/// állapotfájljának figyelése az `up` alatt (dinamikus challenge, webes hitelesítés), megszakítás és lejárat.
@MainActor
final class MFAConnectionTests: XCTestCase {
    var base: URL!
    var store: ConnectionStore!
    var mock: MockCommandRunner!
    var secrets: InMemorySecretStore!
    var driver: MockNativeDriver!

    override func setUp() async throws {
        AppLanguage.override = .en
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
        m.authStateReader = { _ in nil }
        m.authPollInterval = 0.05
        m.reload()
        return m
    }

    func cmd(_ args: String) -> String { "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn \(args) --lang en" }

    func upCall(_ c: Connection) -> MockCommandRunner.Call? {
        mock.calls.first { $0.commandLine == cmd("up \(c.kind.rawValue) \(c.id.uuidString)") }
    }

    func respondCalls(_ c: Connection) -> [String] {
        mock.calls.filter { $0.commandLine == cmd("respond openvpn \(c.id.uuidString)") }.compactMap(\.stdin)
    }

    func testOTPAppendedOnStdin() async throws {
        let c = Connection(name: "Office", kind: .openvpn, otp: OTPSetting(enabled: true, separator: .comma))
        try store.save(c, config: "client\nremote vpn.example.com 1194\nauth-user-pass\n")
        secrets.set("bob", for: c.id, field: .username)
        secrets.set("pass", for: c.id, field: .password)
        let m = makeManager()
        var prompts: [AuthPrompt] = []
        var stateDuringPrompt: ConnectionState?
        m.promptHandler = { prompt in
            prompts.append(prompt)
            stateDuringPrompt = m.state(for: c.id.uuidString)
            return .code("123456")
        }
        await m.connect(c, debug: false)
        XCTAssertEqual(prompts.count, 1)
        // A saját szövegünk: nem „a VPN-szerver üzenete”.
        if case .code(_, let echo, let fromServer)? = prompts.first?.kind { XCTAssertTrue(echo); XCTAssertFalse(fromServer) } else { XCTFail("\(prompts)") }
        XCTAssertEqual(prompts.first?.deadline.duration, 120)
        if case .awaitingAuth(let wait)? = stateDuringPrompt { XCTAssertEqual(wait.kind, .code) } else { XCTFail("\(String(describing: stateDuringPrompt))") }
        XCTAssertEqual(upCall(c)?.stdin, "username=bob\npassword=pass,123456\notp=123456\n")
        // A kód nem tárolódik.
        XCTAssertEqual(secrets.get(c.id, field: .password), "pass")
    }

    func testPromptCancelledDoesNotConnect() async throws {
        let c = Connection(name: "Office", kind: .strongswan, otp: OTPSetting(enabled: true))
        try store.save(c, config: "x")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        m.promptHandler = { _ in .cancelled }
        await m.connect(c, debug: false)
        XCTAssertNil(upCall(c))
        XCTAssertEqual(m.state(for: c.id.uuidString), .disconnected)
        XCTAssertEqual(events, [])
    }

    func testPromptTimeoutFails() async throws {
        let c = Connection(name: "Office", kind: .sstp, otp: OTPSetting(enabled: true))
        try store.save(c, config: "server=vpn.example.com\nuser=bob\n")
        let m = makeManager()
        var events: [ConnectionEvent] = []
        m.onEvent = { events.append($0) }
        m.promptHandler = { _ in .timedOut }
        await m.connect(c, debug: false)
        XCTAssertNil(upCall(c))
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed("Authentication was not completed in time"))
        XCTAssertEqual(events.count, 1)
    }

    func testSSTPCodeMustKeepPasswordRule() async throws {
        let c = Connection(name: "S", kind: .sstp, otp: OTPSetting(enabled: true))
        try store.save(c, config: "server=vpn.example.com\nuser=bob\n")
        secrets.set("pw", for: c.id, field: .password)
        let m = makeManager()
        m.promptHandler = { _ in .code("12\"3") }
        await m.connect(c, debug: false)
        XCTAssertNil(upCall(c))
        XCTAssertEqual(m.state(for: c.id.uuidString), .failed(MFAError.sstpPassword.errorDescription!))
    }

    func testStaticChallengePackedOnStdin() async throws {
        let c = Connection(name: "Office", kind: .openvpn, otp: OTPSetting(enabled: true, separator: .colon))
        try store.save(c, config: "client\nremote vpn.example.com 1194\nauth-user-pass\nstatic-challenge \"Enter OTP\" 1\n")
        secrets.set("bob", for: c.id, field: .username)
        secrets.set("StatPass", for: c.id, field: .password)
        let m = makeManager()
        var prompts: [AuthPrompt] = []
        m.promptHandler = { prompts.append($0); return .code("246810") }
        await m.connect(c, debug: false)
        // A statikus challenge elsőbbséget élvez: egyetlen kérés, a config szövegével és echo-jával.
        XCTAssertEqual(prompts.map(\.kind), [.code(text: "Enter OTP", echo: true, fromServer: false)])
        XCTAssertEqual(upCall(c)?.stdin, "username=bob\npassword=SCRV1:U3RhdFBhc3M=:MjQ2ODEw\notp=246810\nchallenge=packed\n")
    }

    func testNativeOTPInStartOptions() async throws {
        let c = Connection(name: "Office L2TP", kind: .l2tp, nativeServiceName: "Office L2TP",
                           native: NativeSettings(server: "vpn.example.com", account: "bob"),
                           otp: OTPSetting(enabled: true, separator: .colon))
        var bound = c
        bound.nativeServiceID = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"
        try store.save(bound, config: nil)
        secrets.set("bob", for: c.id, field: .username)
        secrets.set("pw", for: c.id, field: .password)
        mock.responses["/usr/sbin/scutil --nc list"] = CommandResult(stdout:
            #"* (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Office L2TP"     [PPP:L2TP]"#)
        let m = makeManager()
        m.promptHandler = { _ in .code("4711") }
        await m.connect(bound, debug: false)
        let ppp = driver.starts.first?.options?[kSCEntNetPPP as String] as? [String: Any]
        XCTAssertEqual(ppp?[kSCPropNetPPPAuthPassword as String] as? String, "pw:4711")
    }

    func testSystemServiceOTP() async throws {
        let sid = "052ED352-624D-4F75-BD84-D3E278CFD84F"
        let s = SystemVPNService(id: sid, name: "Corp", typeLabel: "Cisco IPsec", status: "Disconnected")
        secrets.set("pw", for: UUID(uuidString: sid)!, field: .password)
        let m = makeManager()
        m.setSystemOTP(OTPSetting(enabled: true, separator: .none), for: sid)
        XCTAssertEqual(m.systemOTPSetting(for: sid), OTPSetting(enabled: true, separator: .none))
        m.promptHandler = { _ in .code("8080") }
        await m.connectSystem(s)
        let ipsec = driver.starts.first?.options?[kSCEntNetIPSec as String] as? [String: Any]
        XCTAssertEqual(ipsec?[kSCPropNetIPSecXAuthPassword as String] as? String, "pw8080")
        m.setSystemOTP(OTPSetting(), for: sid)
        XCTAssertEqual(m.systemOTP, [:])
    }

    /// Dinamikus challenge az `up` alatt: a közvetítő állapotfájlja alapján kódot kér, és `mvpn respond`-dal válaszol.
    func testDynamicChallengeDuringUp() async throws {
        let c = Connection(name: "Office", kind: .openvpn)
        try store.save(c, config: "client\nremote vpn.example.com 1194\n")
        mock.delays[cmd("up openvpn \(c.id.uuidString)")] = 1.0
        let m = makeManager()
        let deadline = Date().addingTimeInterval(60).timeIntervalSince1970
        m.authStateReader = { id in
            id == c.id ? AuthUIState(seq: 1, state: .challenge, method: .crv1, text: "Enter PIN", echo: false, deadline: deadline) : nil
        }
        var prompts: [AuthPrompt] = []
        var stateDuringPrompt: ConnectionState?
        m.promptHandler = { prompt in
            prompts.append(prompt)
            stateDuringPrompt = m.state(for: c.id.uuidString)
            return .code("4242")
        }
        await m.connect(c, debug: false)
        // A közvetítőtől jövő szöveg a szerveré: a kérés így jelöli.
        XCTAssertEqual(prompts.map(\.kind), [.code(text: "Enter PIN", echo: false, fromServer: true)])
        XCTAssertLessThanOrEqual(prompts.first?.deadline.duration ?? 999, 60)
        if case .awaitingAuth? = stateDuringPrompt {} else { XCTFail("\(String(describing: stateDuringPrompt))") }
        XCTAssertEqual(respondCalls(c), ["kind=crv1\nresponse=4242\n"])
        XCTAssertEqual(upCall(c)?.stdin, "")
    }

    func testExpiredStateIsIgnored() async throws {
        let c = Connection(name: "Office", kind: .openvpn)
        try store.save(c, config: "client\nremote vpn.example.com 1194\n")
        let m = makeManager()
        var prompts = 0
        m.promptHandler = { _ in prompts += 1; return .code("1") }
        await m.handleAuthState(AuthUIState(seq: 1, state: .challenge, method: .crv1, text: "old",
                                            deadline: Date().addingTimeInterval(-10).timeIntervalSince1970), c)
        XCTAssertEqual(prompts, 0)
        XCTAssertEqual(respondCalls(c), [])
    }

    func testStaticFallbackAndCancelResponses() async throws {
        let c = Connection(name: "Office", kind: .openvpn)
        try store.save(c, config: "client\nremote vpn.example.com 1194\n")
        let m = makeManager()
        m.promptHandler = { _ in .code("1") }
        await m.handleAuthState(AuthUIState(seq: 1, state: .challenge, method: .static, text: "OTP", echo: true), c)
        m.promptHandler = { _ in .timedOut }
        await m.handleAuthState(AuthUIState(seq: 2, state: .challenge, method: .crtext, text: "x"), c)
        XCTAssertEqual(respondCalls(c), ["kind=static\nresponse=1\n", "kind=cancel\nresponse=\n"])
    }

    func testWebAuthConfirmationAndHTTPDropped() async throws {
        let c = Connection(name: "Office", kind: .openvpn)
        try store.save(c, config: "client\nremote vpn.example.com 1194\n")
        let m = makeManager()
        var prompts: [AuthPrompt] = []
        m.promptHandler = { prompts.append($0); return .openedURL }
        await m.handleAuthState(AuthUIState(seq: 1, state: .webauth, method: .webauth, url: "https://sso.example.com/a"), c)
        XCTAssertEqual(prompts.map(\.kind), [.webAuth(url: URL(string: "https://sso.example.com/a")!)])
        XCTAssertEqual(prompts.first?.deadline.duration, 300)
        XCTAssertEqual(respondCalls(c), ["kind=webauth-ack\nresponse=\n"])
        // Megnyitás után a kapcsolat „webes hitelesítésre vár”.
        if case .awaitingAuth(let wait) = m.state(for: c.id.uuidString) { XCTAssertEqual(wait.kind, .web) } else { XCTFail() }
        // Nem https URL: nincs kérés, nincs válasz.
        await m.handleAuthState(AuthUIState(seq: 2, state: .webauth, method: .webauth, url: "http://evil.example.com/"), c)
        XCTAssertEqual(prompts.count, 1)
        // Elutasítás: megszakítás.
        m.promptHandler = { _ in .cancelled }
        await m.handleAuthState(AuthUIState(seq: 3, state: .webauth, method: .webauth, url: "https://sso.example.com/b"), c)
        XCTAssertEqual(respondCalls(c).last, "kind=cancel\nresponse=\n")
    }

    /// Bontás csatlakozás közben: a nyitott kérés bezárul, és a közvetítő megszakítást kap a `down` előtt.
    func testDisconnectWhileConnectingCancelsViaBridge() async throws {
        let c = Connection(name: "Office", kind: .openvpn)
        try store.save(c, config: "client\nremote vpn.example.com 1194\n")
        mock.delays[cmd("up openvpn \(c.id.uuidString)")] = 0.5
        mock.responses[cmd("status")] = CommandResult(stdout: "[]")
        let m = makeManager()
        var dismissed: [String] = []
        m.dismissPrompt = { dismissed.append($0) }
        let connecting = Task { await m.connect(c, debug: false) }
        try await Task.sleep(nanoseconds: 100_000_000)
        await m.disconnect(c)
        await connecting.value
        let lines = mock.calls.map(\.commandLine)
        let respond = try XCTUnwrap(lines.firstIndex(of: cmd("respond openvpn \(c.id.uuidString)")))
        let down = try XCTUnwrap(lines.firstIndex(of: cmd("down openvpn \(c.id.uuidString)")))
        XCTAssertLessThan(respond, down)
        XCTAssertEqual(respondCalls(c), ["kind=cancel\nresponse=\n"])
        XCTAssertTrue(dismissed.contains(c.id.uuidString))
        XCTAssertEqual(m.state(for: c.id.uuidString), .disconnected)
    }

    func testRespondArguments() async throws {
        let id = UUID()
        let client = MvpnClient(runner: mock, language: .hu)
        try await client.respond(id: id, kind: .crv1, response: "99")
        XCTAssertEqual(mock.calls.last?.arguments, ["-n", "/usr/local/libexec/macvpn/mvpn", "respond", "openvpn", id.uuidString, "--lang", "hu"])
        XCTAssertEqual(mock.calls.last?.stdin, "kind=crv1\nresponse=99\n")
        do {
            try await client.respond(id: id, kind: .crv1, response: "9\n9")
            XCTFail("a sortöréses kód nem mehet át")
        } catch {
            XCTAssertEqual(error as? MFAError, .invalidCode)
        }
    }
}
