import XCTest
@testable import MacVPNCore

/// A management közvetítő (`mvpn-mgmt`) tiszta logikája: bemenet-értelmezés és a parancs-engedélyezőlista.
final class ManagementProtocolTests: XCTestCase {
    func testHoldStateAndIgnoredLines() {
        XCTAssertEqual(ManagementParser.parse(">HOLD:Waiting for hold release:10"), .hold)
        XCTAssertEqual(ManagementParser.parse(">FATAL:Cannot open TUN/TAP dev"), .fatal)
        XCTAssertEqual(ManagementParser.parse(">STATE:1760000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,"), .connected)
        XCTAssertEqual(ManagementParser.parse(">STATE:1760000000,AUTH_PENDING,timeout 120,,,,,"), .authPending(timeout: 120))
        XCTAssertEqual(ManagementParser.parse(">STATE:1760000000,AUTH_PENDING,,,,,,"), .authPending(timeout: nil))
        XCTAssertEqual(ManagementParser.parse(">STATE:1760000000,AUTH_PENDING,timeout x,,,,,"), .authPending(timeout: nil))
        for line in [">STATE:1760000000,RECONNECTING,SIGUSR1,,,,,", ">ECHO:1760000000,Initialization Sequence Completed",
                     ">LOG:1760000000,I,Initialization Sequence Completed", ">INFO:OpenVPN Management Interface Version 5",
                     ">BYTECOUNT:1,2", ">NEED-OK:Need 'token-insertion-request' confirmation MSG:x", "SUCCESS: hold release succeeded",
                     "ERROR: unknown command", "END", ">CLIENT:CONNECT,0,1", ">PASSWORD:Auth-Token:T0kenS3cret",
                     ">INFOMSG:SOMETHING:else", ">STATE:x", "Initialization Sequence Completed",
                     ">HOLD:" + String(repeating: "x", count: 5000)] {
            XCTAssertEqual(ManagementParser.parse(line), .ignored, line)
        }
    }

    func testPasswordRequests() {
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Need 'Auth' username/password"), .needAuth(nil))
        for (flag, echo, concat) in [(0, false, false), (1, true, false), (2, false, true), (3, true, true)] {
            XCTAssertEqual(ManagementParser.parse(">PASSWORD:Need 'Auth' username/password SC:\(flag),Enter OTP, please"),
                           .needAuth(ManagementStaticRequest(echo: echo, concat: concat, text: "Enter OTP, please")))
        }
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Need 'Auth' username/password SC:4,x"), .authFailed)
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Need 'Auth' username/password SC:x"), .authFailed)
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Need 'Auth' username/password SC:1,a\u{1b}b"),
                       .needAuth(ManagementStaticRequest(echo: true, concat: false, text: "a b")))
        for other in ["Need 'Private Key' password", "Need 'HTTP Proxy' username/password", "Need 'Auth' username",
                      "Need 'Auth' password"] {
            XCTAssertEqual(ManagementParser.parse(">PASSWORD:" + other), .needOther, other)
        }
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Auth'"), .authFailed)
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Private Key'"), .authFailed)
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Auth' ['denied by policy']"), .authFailed)
        // Lejárt auth-token és átmeneti hiba: az OpenVPN újrapróbál, nem végleges.
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Auth' ['SESSION: token expired']"), .authRetry)
        XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Auth' ['TEMP[backoff 30]:busy']"), .authRetry)
    }

    func testCRV1() throws {
        let event = ManagementParser.parse(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN']")
        guard case .dynamicChallenge(let c) = event else { return XCTFail("\(event)") }
        XCTAssertEqual(c, CRV1Challenge(echo: true, responseRequired: true, stateID: "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l",
                                        username: "cr1", text: "Please enter token PIN"))
        // management-notes példa válasza.
        XCTAssertEqual(ManagementCommand.password(c.password(response: "8675309")).line,
                       #"password "Auth" "CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::8675309""#)
        XCTAssertEqual(ManagementCommand.username(c.username).line, #"username "Auth" "cr1""#)
        // A szövegben lehet kettőspont; üres flag-lista és üres felhasználónév is érvényes.
        XCTAssertEqual(CRV1Challenge.parse("CRV1::st::Code: 6 digits")?.text, "Code: 6 digits")
        XCTAssertEqual(CRV1Challenge.parse("CRV1::st::x")?.username, "")
        XCTAssertEqual(CRV1Challenge.parse("CRV1:R:st:Ym9i:" + String(repeating: "x", count: 300))?.text.count, 201)
        for bad in ["CRV1:X:st:Ym9i:t", "CRV1:R:st\"x:Ym9i:t", "CRV1:R::Ym9i:t", "CRV1:R:st:not base64!:t",
                    "CRV1:R:st:Ym9", "CRV1:R:st", "XRV1:R:st:Ym9i:t", "CRV1:R:" + String(repeating: "s", count: 129) + ":Ym9i:t",
                    "CRV1:R:st:" + Data("a\nb".utf8).base64EncodedString() + ":t", "CRV1:R:s\\t:Ym9i:t"] {
            XCTAssertNil(CRV1Challenge.parse(bad), bad)
            XCTAssertEqual(ManagementParser.parse(">PASSWORD:Verification Failed: 'Auth' ['\(bad)']"), .authFailed, bad)
        }
    }

    func testInfoMessages() {
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:OPEN_URL:https://sso.example.com/a?b=c"),
                       .webAuth(url: URL(string: "https://sso.example.com/a?b=c")))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:OPEN_URL:http://sso.example.com/"), .webAuth(url: nil))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:OPEN_URL:javascript:alert(1)"), .webAuth(url: nil))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:WEB_AUTH::https://sso.example.com/x"),
                       .webAuth(url: URL(string: "https://sso.example.com/x")))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:WEB_AUTH:external,hidden:https://sso.example.com/x"),
                       .webAuth(url: URL(string: "https://sso.example.com/x")))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:WEB_AUTH:proxy=10.0.0.1;8080;dXNlcg==;cGFzcw==,external:https://sso.example.com/x"),
                       .webAuth(url: nil))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:WEB_AUTH:https"), .webAuth(url: nil))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:CR_TEXT:R,E:Enter the code"), .crText(echo: true, text: "Enter the code"))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:CR_TEXT:R:Code: 6 digits"), .crText(echo: false, text: "Code: 6 digits"))
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:CR_TEXT:Q:x"), .authFailed)
        XCTAssertEqual(ManagementParser.parse(">INFOMSG:CR_TEXT:nocolon"), .authFailed)
    }

    /// Csak az engedélyezőlistás parancsok állíthatók elő, és mind egyetlen, vezérlőkarakter nélküli sor.
    func testCommandBuilderAllowlist() throws {
        XCTAssertEqual(ManagementCommand.stateOn.line, "state on")
        XCTAssertEqual(ManagementCommand.holdRelease.line, "hold release")
        XCTAssertEqual(ManagementCommand.username("bob").line, #"username "Auth" "bob""#)
        XCTAssertEqual(ManagementCommand.password(#"p"a\ss"#).line, #"password "Auth" "p\"a\\ss""#)
        XCTAssertEqual(ManagementCommand.password("").line, #"password "Auth" """#)
        XCTAssertEqual(ManagementCommand.crResponse("112233").line, "cr-response MTEyMjMz")
        XCTAssertNil(ManagementCommand.username("").line)
        for bad in ["a\nsignal SIGTERM", "a\rb", "a\u{0}b", "a\u{7f}b", "a\u{85}b"] {
            XCTAssertNil(ManagementCommand.username(bad).line, bad.debugDescription)
            XCTAssertNil(ManagementCommand.password(bad).line, bad.debugDescription)
        }
        XCTAssertNotNil(ManagementCommand.password(String(repeating: "x", count: 255)).line)
        XCTAssertNil(ManagementCommand.password(String(repeating: "x", count: 256)).line)
        XCTAssertNil(ManagementCommand.crResponse(String(repeating: "x", count: 200)).line)
        // Az OpenVPN az 1024. bájt utáni részt új parancsként futtatná: minden felépített sor rövidebb ennél.
        let worst: [ManagementCommand] = [.username(String(repeating: "\"", count: 255)), .password(String(repeating: "\\", count: 255)),
                                          .password(String(repeating: "é", count: 127)), .crResponse(String(repeating: "9", count: 189)),
                                          .username(String(repeating: "x", count: 255))]
        for command in worst {
            let line = try XCTUnwrap(command.line, "\(command)")
            XCTAssertLessThan(line.utf8.count, 1024)
        }
        let allowed = try NSRegularExpression(pattern: #"^(state on|hold release|username "Auth" "([^"\\]|\\.)+"|password "Auth" "([^"\\]|\\.)*"|cr-response [A-Za-z0-9+/=]+)$"#)
        let samples: [ManagementCommand] = [.stateOn, .holdRelease, .username("u s\"e\\r"), .password("signal SIGTERM\" kill"),
                                            .password("x\"\nexit"), .crResponse("9 9"), .username("hold release")]
        for command in samples {
            guard let line = command.line else { continue }
            XCTAssertFalse(line.contains("\n"))
            XCTAssertEqual(allowed.numberOfMatches(in: line, range: NSRange(line.startIndex..., in: line)), 1, line)
        }
    }

    func testResponseFileParse() {
        XCTAssertEqual(ManagementResponse.parse(Data("kind=crv1\nresponse=123456\n".utf8)),
                       ManagementResponse(kind: .crv1, response: "123456"))
        XCTAssertEqual(ManagementResponse.parse(Data("kind=cancel\nresponse=\n".utf8)), ManagementResponse(kind: .cancel, response: ""))
        XCTAssertEqual(ManagementResponse.parse(Data("kind=webauth-ack\n".utf8)), ManagementResponse(kind: .webauthAck, response: ""))
        for bad in ["kind=password\nresponse=x\n", "kind=crv1\nresponse=1\nextra=2\n", "response=1\n", "",
                    "kind=crv1\nresponse=1\u{7}2\n", "kind=crv1\nresponse=" + String(repeating: "1", count: 257) + "\n",
                    "kind=crv1 \nresponse=1\n"] {
            XCTAssertNil(ManagementResponse.parse(Data(bad.utf8)), bad.debugDescription)
        }
        XCTAssertNil(ManagementResponse.parse(Data(repeating: 0x41, count: 2000)))
    }

    func testCredentialsFileParse() {
        XCTAssertEqual(ManagementCredentials.parse(Data("username=bob\npassword=p=w\npacked=1\n".utf8)),
                       ManagementCredentials(username: "bob", password: "p=w", packed: true))
        XCTAssertEqual(ManagementCredentials.parse(Data("username=bob\npassword=x\npacked=0\n".utf8))?.packed, false)
        XCTAssertNil(ManagementCredentials.parse(Data("username=bob\nevil=1\n".utf8)))
    }

    func testBase64Check() {
        XCTAssertTrue(ManagementParser.isBase64("Ym9i"))
        XCTAssertTrue(ManagementParser.isBase64("Ym8="))
        XCTAssertTrue(ManagementParser.isBase64("", allowEmpty: true))
        XCTAssertFalse(ManagementParser.isBase64(""))
        XCTAssertFalse(ManagementParser.isBase64("Ym9"))
        XCTAssertFalse(ManagementParser.isBase64("Ym9i\n"))
        XCTAssertFalse(ManagementParser.isBase64("Y===" ))
    }
}
