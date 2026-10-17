import XCTest
@testable import MacVPNCore

final class SetupCheckerTests: XCTestCase {
    // A `--lang` a rögzített nyelvből jön, nem a gép locale-jából.
    override func setUp() { super.setUp(); AppLanguage.override = .en }
    override func tearDown() { AppLanguage.override = nil; super.tearDown() }

    func makeChecker(existing: Set<String>, sudoOK: Bool, installed: String?, bundled: String?) -> SetupChecker {
        let mock = MockCommandRunner()
        mock.responses["/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn version --lang en"] =
            CommandResult(exitCode: sudoOK ? 0 : 1, stdout: installed ?? "")
        return SetupChecker(runner: mock,
                            fileExists: { existing.contains($0) },
                            readFile: { path in
                                if path == "/usr/local/libexec/macvpn/VERSION" { return installed }
                                if path == "/bundle/VERSION" { return bundled }
                                return nil
                            },
                            bundledRootDir: URL(fileURLWithPath: "/bundle"))
    }

    func testNothingInstalled() async {
        let r = await makeChecker(existing: [], sudoOK: false, installed: nil, bundled: "1").check()
        XCTAssertNil(r.brewPrefix)
        XCTAssertFalse(r.rootOK)
        XCTAssertFalse(r.isComplete)
        XCTAssertFalse(r.isAvailable(.openvpn))
        XCTAssertTrue(r.isAvailable(.l2tp))
    }

    func testPartialTools() async {
        let existing: Set<String> = ["/opt/homebrew/bin/brew", "/opt/homebrew/sbin/openvpn"]
        let r = await makeChecker(existing: existing, sudoOK: true, installed: "1\n", bundled: "1\n").check()
        XCTAssertEqual(r.brewPrefix, "/opt/homebrew")
        XCTAssertTrue(r.rootOK)
        XCTAssertTrue(r.isAvailable(.openvpn))
        XCTAssertFalse(r.isAvailable(.wireguard))
        XCTAssertEqual(r.missingTools, ["wg", "wg-quick", "wireguard-go", "bash", "swanctl", "charon", "sstpc"])
    }

    func testVersionMismatchNeedsReinstall() async {
        let r = await makeChecker(existing: [], sudoOK: true, installed: "1", bundled: "2").check()
        XCTAssertFalse(r.rootOK)
    }

    func testCharonCandidates() {
        XCTAssertTrue(SetupChecker.candidates(tool: "charon", prefix: "/opt/homebrew")
            .contains("/opt/homebrew/opt/strongswan/libexec/ipsec/charon"))
    }
}
