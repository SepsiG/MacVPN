import XCTest
@testable import MacVPNCore

final class RootInstallerTests: XCTestCase {
    func testScriptContents() throws {
        let s = try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/Applications/MacVPN.app/Contents/Resources/root"), user: "alice")
        XCTAssertTrue(s.contains("install -o root -g wheel -m 755 '/Applications/MacVPN.app/Contents/Resources/root/mvpn' /usr/local/libexec/macvpn/mvpn"))
        XCTAssertTrue(s.contains("alice ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn"))
        XCTAssertTrue(s.contains("/usr/local/libexec/macvpn/mvpn-validate"))
        XCTAssertTrue(s.contains("visudo -c -f"))
        XCTAssertTrue(s.contains("install -o root -g wheel -m 440"))
        XCTAssertTrue(s.hasPrefix("#!/bin/bash\nset -euo pipefail\n"))
    }

    func testRejectsBadUser() {
        XCTAssertThrowsError(try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob ALL=(ALL) ALL"))
    }

    func testAppleScriptQuotesPath() {
        XCTAssertEqual(RootInstaller.appleScript(scriptPath: "/tmp/a b/install.sh"),
                       #"do shell script "/bin/bash " & quoted form of "/tmp/a b/install.sh" with administrator privileges"#)
    }
}

final class RootUninstallerTests: XCTestCase {
    // A magyar szövegeket ellenőrzi: a nyelv rögzítve, nem a gép locale-ja dönt.
    override func setUp() { AppLanguage.override = .hu }
    override func tearDown() { AppLanguage.override = nil }

    func testUninstallScriptContents() throws {
        let s = try RootInstaller.uninstallScript(user: "alice")
        XCTAssertTrue(s.hasPrefix("#!/bin/bash\n"))
        // A futó kapcsolatok bontása a kind fájl alapján, ellenőrzött uuid-dal és típussal.
        XCTAssertTrue(s.contains("MVPN='/usr/local/libexec/macvpn/mvpn'"))
        XCTAssertTrue(s.contains("\"$RUN_BASE\"/*/"))
        XCTAssertTrue(s.contains(#"[[ "$id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || continue"#))
        XCTAssertTrue(s.contains("case \"$kind\" in openvpn|wireguard|strongswan) ;; *) continue ;; esac"))
        XCTAssertTrue(s.contains("if ! SUDO_USER='alice' \"$MVPN\" down \"$kind\" \"$id\" --lang hu </dev/null; then"))
        XCTAssertTrue(s.contains("FAILED=\"$FAILED $id\""))
        // Sikertelen bontásnál kilép, mielőtt bármit törölne.
        let guardRange = try XCTUnwrap(s.range(of: "if [ -n \"$FAILED\" ]; then"))
        let exitRange = try XCTUnwrap(s.range(of: "exit 1", range: guardRange.upperBound..<s.endIndex))
        let firstRm = try XCTUnwrap(s.range(of: "/bin/rm"))
        XCTAssertTrue(exitRange.upperBound < firstRm.lowerBound)
        XCTAssertTrue(s.contains("echo 'Nem bontható kapcsolat:'\"$FAILED\" >&2"))
        // Törlés: a bontás után.
        let down = try XCTUnwrap(s.range(of: "down \"$kind\""))
        for path in ["/etc/sudoers.d/macvpn", "/usr/local/libexec/macvpn /var/run/macvpn /var/log/macvpn"] {
            let r = try XCTUnwrap(s.range(of: path, range: down.upperBound..<s.endIndex), path)
            XCTAssertTrue(r.lowerBound > down.upperBound)
        }
        XCTAssertTrue(s.contains("/bin/rm -f /etc/sudoers.d/macvpn"))
        XCTAssertTrue(s.contains("/bin/rm -rf /usr/local/libexec/macvpn /var/run/macvpn /var/log/macvpn"))
    }

    func testUninstallScriptRejectsBadUser() {
        XCTAssertThrowsError(try RootInstaller.uninstallScript(user: "x' ; rm -rf / ; '"))
    }

    func testUninstallScriptSyntax() throws {
        try assertBashSyntax(RootInstaller.uninstallScript(user: "bob"))
    }

    func testUninstallRunsViaOsascriptAndCleansUp() async throws {
        let runner = MockCommandRunner()
        try await RootInstaller.uninstall(user: "bob", runner: runner)
        let call = try XCTUnwrap(runner.calls.first)
        XCTAssertEqual(call.executable, "/usr/bin/osascript")
        let script = try XCTUnwrap(call.arguments.last)
        XCTAssertTrue(script.hasSuffix("with administrator privileges"))
        let path = try XCTUnwrap(script.components(separatedBy: "quoted form of \"").last?.components(separatedBy: "\"").first)
        XCTAssertFalse(FileManager.default.fileExists(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path))
    }

    /// A script futtatása homokozóban: hamis mvpn, futási könyvtár, a törlések `echo RM`-re cserélve.
    func runUninstallSandbox(failingID: String?) throws -> (status: Int32, output: String, mvpnCalls: [String]) {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("macvpn-uninstall-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: root) }
        let run = root.appendingPathComponent("run")
        let good = "11111111-2222-3333-4444-555555555555", other = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        for (dir, kind) in [(good, "openvpn"), (other, "wireguard"), ("notauuid", "openvpn"), ("99999999-2222-3333-4444-555555555555", "evil;rm")] {
            try fm.createDirectory(at: run.appendingPathComponent(dir), withIntermediateDirectories: true)
            try "\(kind)\n".write(to: run.appendingPathComponent("\(dir)/kind"), atomically: true, encoding: .utf8)
        }
        let calls = root.appendingPathComponent("calls")
        let mvpn = root.appendingPathComponent("mvpn")
        try """
        #!/bin/bash
        echo "$SUDO_USER $*" >> \(RootInstaller.shellQuote(calls.path))
        [ "$3" = "\(failingID ?? "-")" ] && exit 1
        exit 0

        """.write(to: mvpn, atomically: true, encoding: .utf8)
        _ = chmod(mvpn.path, 0o755)
        let script = try RootInstaller.uninstallScript(user: "bob")
            .replacingOccurrences(of: "MVPN='/usr/local/libexec/macvpn/mvpn'", with: "MVPN=\(RootInstaller.shellQuote(mvpn.path))")
            .replacingOccurrences(of: "RUN_BASE=/var/run/macvpn", with: "RUN_BASE=\(RootInstaller.shellQuote(run.path))")
            .replacingOccurrences(of: "/bin/rm", with: "echo RM")
        XCTAssertFalse(script.contains("/var/run/macvpn\n") && script.contains("RUN_BASE=/var/run"))
        let url = root.appendingPathComponent("u.sh")
        try script.write(to: url, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [url.path]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let mvpnCalls = ((try? String(contentsOf: calls, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init).sorted()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self), mvpnCalls)
    }

    func testUninstallSandboxSuccess() throws {
        let r = try runUninstallSandbox(failingID: nil)
        XCTAssertEqual(r.status, 0, r.output)
        XCTAssertEqual(r.mvpnCalls, ["bob down openvpn 11111111-2222-3333-4444-555555555555 --lang hu",
                                     "bob down wireguard AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE --lang hu"])
        XCTAssertTrue(r.output.contains("RM -f /etc/sudoers.d/macvpn"), r.output)
        XCTAssertTrue(r.output.contains("RM -rf /usr/local/libexec/macvpn /var/run/macvpn /var/log/macvpn"), r.output)
    }

    func testUninstallSandboxFailedDownKeepsRootLayer() throws {
        let r = try runUninstallSandbox(failingID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        XCTAssertEqual(r.status, 1)
        XCTAssertEqual(r.mvpnCalls.count, 2)
        XCTAssertTrue(r.output.contains("Nem bontható kapcsolat: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), r.output)
        XCTAssertFalse(r.output.contains("RM"), r.output)
    }

    func testUninstallDownFailureMessage() async {
        let failing = FailingRunner(result: CommandResult(exitCode: 1,
            stderr: "0:120: execution error: Nem bontható kapcsolat: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE (1)"))
        do {
            try await RootInstaller.uninstall(user: "bob", runner: failing)
            XCTFail("hibát vártunk")
        } catch {
            let msg = error.localizedDescription
            XCTAssertTrue(msg.hasPrefix("Egy kapcsolat nem bontható, az eltávolítás megszakítva"), msg)
            XCTAssertTrue(msg.contains("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), msg)
        }
    }

    func testUninstallCancelled() async {
        let failing = FailingRunner(result: CommandResult(exitCode: 1, stderr: "execution error: User canceled. (-128)"))
        do {
            try await RootInstaller.uninstall(user: "bob", runner: failing)
            XCTFail("hibát vártunk")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Az eltávolítás megszakítva")
        }
    }
}

/// Minden hívásra ugyanazt a választ adja.
struct FailingRunner: CommandRunner {
    let result: CommandResult
    func run(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult { result }
}

final class RootInstallerTempTests: XCTestCase {
    func testPrivateTempDirectoryAndScriptModes() throws {
        let dir = try RootInstaller.makePrivateTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let dirMode = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        XCTAssertEqual(dirMode, 0o700)
        let url = try RootInstaller.writeScript("#!/bin/bash\necho hi\n", in: dir)
        let fileMode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(fileMode, 0o700)
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "#!/bin/bash\necho hi\n")
        // Második írás ugyanoda: O_EXCL miatt hiba (nem írja felül, nem követ symlinket).
        XCTAssertThrowsError(try RootInstaller.writeScript("x", in: dir))
    }

    func testInstallRemovesTempDirectory() async throws {
        let runner = MockCommandRunner()
        try await RootInstaller.install(sourceDir: URL(fileURLWithPath: "/x"), user: "bob", runner: runner)
        let script = try XCTUnwrap(runner.calls.first?.arguments.last)
        let path = try XCTUnwrap(script.components(separatedBy: "quoted form of \"").last?.components(separatedBy: "\"").first)
        XCTAssertTrue(path.hasSuffix("/install.sh"))
        XCTAssertTrue(URL(fileURLWithPath: path).deletingLastPathComponent().lastPathComponent.hasPrefix("macvpn-install."))
        XCTAssertFalse(FileManager.default.fileExists(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path))
    }
}
