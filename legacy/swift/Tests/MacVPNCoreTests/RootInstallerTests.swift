import XCTest
@testable import MacVPNCore

final class RootInstallerTests: XCTestCase {
    static let fakeHashes = Dictionary(uniqueKeysWithValues: RootInstaller.rootFiles.map { ($0, String(repeating: "a", count: 64)) })

    func testScriptContents() throws {
        let s = try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/Applications/MacVPN.app/Contents/Resources/root"),
                                                user: "alice", hashes: Self.fakeHashes)
        XCTAssertTrue(s.contains("stage '/Applications/MacVPN.app/Contents/Resources/root/mvpn' mvpn \(String(repeating: "a", count: 64))"))
        XCTAssertTrue(s.contains("install -o root -g wheel -m 755 \"$STAGE/mvpn\" \"$DIR/mvpn\""))
        XCTAssertTrue(s.contains("DIR=/usr/local/libexec/macvpn"))
        XCTAssertTrue(s.contains("'alice ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn'"))
        XCTAssertTrue(s.contains("\"$STAGE/mvpn-validate\" \"$DIR/mvpn-validate\""))
        XCTAssertTrue(s.contains("install -o root -g wheel -m 755 \"$STAGE/mvpn-mgmt\" \"$DIR/mvpn-mgmt\""))
        XCTAssertTrue(s.contains("stage '/Applications/MacVPN.app/Contents/Resources/root/mvpn-mgmt' mvpn-mgmt \(String(repeating: "a", count: 64))"))
        XCTAssertTrue(s.contains("visudo -c -f"))
        XCTAssertTrue(s.contains("install -o root -g wheel -m 440"))
        XCTAssertTrue(s.hasPrefix("#!/bin/bash\nset -euo pipefail\n"))
        XCTAssertTrue(s.contains("shasum -a 256"))
        // Az ellenőrzés minden fájlra megtörténik, mielőtt bármi települne.
        let lastStage = try XCTUnwrap(s.range(of: "stage '/Applications/MacVPN.app/Contents/Resources/root/VERSION'"))
        let firstInstall = try XCTUnwrap(s.range(of: "install -o root"))
        XCTAssertTrue(lastStage.upperBound < firstInstall.lowerBound)
        try assertBashSyntax(s)
    }

    func testScriptRequiresAllHashes() {
        var hashes = Self.fakeHashes
        hashes["mvpn-validate"] = nil
        XCTAssertThrowsError(try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob", hashes: hashes))
        hashes = Self.fakeHashes
        hashes["mvpn-mgmt"] = nil
        XCTAssertThrowsError(try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob", hashes: hashes))
        hashes = Self.fakeHashes
        hashes["mvpn-validate"] = nil
        hashes["mvpn-validate"] = "not-a-hash"
        XCTAssertThrowsError(try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob", hashes: hashes))
    }

    func testFileHashes() throws {
        let dir = try Self.makeRootSource()
        defer { try? FileManager.default.removeItem(at: dir) }
        let hashes = try RootInstaller.fileHashes(in: dir)
        XCTAssertEqual(hashes["VERSION"], "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a") // "4"
        XCTAssertEqual(Set(hashes.keys), Set(RootInstaller.rootFiles))
        try FileManager.default.removeItem(at: dir.appendingPathComponent("ovpn-dns"))
        XCTAssertThrowsError(try RootInstaller.fileHashes(in: dir))
    }

    /// A sudoers sorok a valódi `visudo -c`-n is átmennek (root nem kell hozzá).
    func testSudoersLinesPassVisudo() throws {
        let lines = RootInstaller.sudoersLines(user: "alice")
        XCTAssertEqual(lines, [
            "alice ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn",
            "Defaults!/usr/local/libexec/macvpn/mvpn env_reset, !env_keep",
            "Defaults!/usr/local/libexec/macvpn/mvpn env_delete += \"LANG LANGUAGE LC_* CHARSET\"",
        ])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-sudoers-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: url) }
        try (lines.joined(separator: "\n") + "\n").write(to: url, atomically: true, encoding: .utf8)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/visudo")
        p.arguments = ["-c", "-f", url.path]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, text)
    }

    /// Az öt root fájl egy átmeneti könyvtárban (a VERSION tartalma "4").
    static func makeRootSource() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("macvpn-rootsrc-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for name in RootInstaller.rootFiles {
            try Data((name == "VERSION" ? "4" : "#!/bin/bash\n# \(name)\n").utf8).write(to: dir.appendingPathComponent(name))
        }
        return dir
    }

    enum ParentState { case safe, writable, foreignOwner, symlink }

    /// A telepítő script homokozóban (nem rootként): a rendszerútvonalak a homokozóba mutatnak, a root-tulajdonos
    /// beállítása (`-o root -g wheel`, `chown`) kimarad / `echo CHOWN` lesz. `.safe`/`.writable` esetén a tesztelő
    /// felhasználó számít „root”-nak (uid-csere a tulajdonos-ellenőrzésben), `.foreignOwner` esetén nem.
    /// A saját `macvpn` könyvtár előre létezik 0777-tel (ezt a script javítja).
    func runInstallSandbox(tamper: Bool = false, parent: ParentState = .safe) throws -> (status: Int32, output: String, root: URL) {
        let fm = FileManager.default
        let src = try Self.makeRootSource()
        defer { try? fm.removeItem(at: src) }
        let root = fm.temporaryDirectory.appendingPathComponent("macvpn-install-\(UUID().uuidString)")
        for d in ["usr", "var/run", "var/log", "etc/sudoers.d"] {
            try fm.createDirectory(at: root.appendingPathComponent(d), withIntermediateDirectories: true)
        }
        let local = root.appendingPathComponent("usr/local")
        if parent == .symlink {
            try fm.createSymbolicLink(at: local, withDestinationURL: fm.temporaryDirectory)
        } else {
            let own = local.appendingPathComponent("libexec/macvpn")
            try fm.createDirectory(at: own, withIntermediateDirectories: true)
            _ = chmod(local.path, parent == .writable ? 0o777 : 0o755)
            _ = chmod(local.appendingPathComponent("libexec").path, 0o755)
            _ = chmod(own.path, 0o777)
        }
        let hashes = try RootInstaller.fileHashes(in: src)
        if tamper { try Data("#!/bin/bash\nid\n".utf8).write(to: src.appendingPathComponent("mvpn")) }
        let r = root.path
        let script = try RootInstaller.installScript(sourceDir: src, user: "bob", hashes: hashes)
            .replacingOccurrences(of: "-o root -g wheel ", with: "")
            .replacingOccurrences(of: #"chown root:wheel "$1""#, with: #"echo CHOWN "$1""#)
            .replacingOccurrences(of: "/usr/local", with: r + "/usr/local")
            .replacingOccurrences(of: "/var/run/", with: r + "/var/run/")
            .replacingOccurrences(of: "/var/log/", with: r + "/var/log/")
            .replacingOccurrences(of: "/etc/sudoers.d/", with: r + "/etc/sudoers.d/")
            .replacingOccurrences(of: #"[ "$(stat -f %u "$1")" != 0 ]"#,
                                  with: #"[ "$(stat -f %u "$1")" != \#(parent == .foreignOwner ? 0 : getuid()) ]"#)
        let url = root.appendingPathComponent("install.sh")
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
        return (p.terminationStatus, String(decoding: data, as: UTF8.self), root)
    }

    func testInstallSandboxVerifiesAndInstalls() throws {
        AppLanguage.override = .en
        defer { AppLanguage.override = nil }
        let r = try runInstallSandbox()
        defer { try? FileManager.default.removeItem(at: r.root) }
        XCTAssertEqual(r.status, 0, r.output)
        let dir = r.root.appendingPathComponent("usr/local/libexec/macvpn")
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("VERSION"), encoding: .utf8), "4")
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("mvpn-validate").path))
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: dir.appendingPathComponent("mvpn-mgmt").path))
        // Csak a saját (0777-es) macvpn könyvtárat javítja; a szülőkhöz nem nyúl.
        XCTAssertEqual(r.output.components(separatedBy: "CHOWN").count - 1, 1, r.output)
        XCTAssertTrue(r.output.contains("CHOWN " + dir.path + "\n"), r.output)
        let mode = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        XCTAssertEqual((mode ?? 0) & 0o022, 0)
        let sudoers = try String(contentsOf: r.root.appendingPathComponent("etc/sudoers.d/macvpn"), encoding: .utf8)
        XCTAssertTrue(sudoers.contains("env_reset, !env_keep"), sudoers)
        // Az átmeneti (staging) könyvtár törölve.
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: r.root.appendingPathComponent("var/run").path)
        XCTAssertFalse(leftovers.contains { $0.hasPrefix("macvpn-install.") }, "\(leftovers)")
    }

    func testInstallSandboxCreatesMissingParentsRootOwned() throws {
        let s = try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob", hashes: Self.fakeHashes)
        XCTAssertTrue(s.contains(#"install -d -o root -g wheel -m 755 "$1""#))
        XCTAssertTrue(s.contains("check_dir /usr/local '"))
        XCTAssertTrue(s.contains("check_dir /usr/local/libexec '"))
        XCTAssertTrue(s.contains(#"check_dir "$DIR" """#))
    }

    func testInstallSandboxRefusesUnsafeParents() throws {
        for (state, lang) in [(ParentState.writable, AppLanguage.en), (.foreignOwner, .en), (.writable, .hu)] {
            AppLanguage.override = lang
            defer { AppLanguage.override = nil }
            let r = try runInstallSandbox(parent: state)
            defer { try? FileManager.default.removeItem(at: r.root) }
            let local = r.root.path + "/usr/local"
            XCTAssertEqual(r.status, 1, r.output)
            XCTAssertFalse(r.output.contains("CHOWN"), r.output)
            if lang == .en {
                XCTAssertTrue(r.output.contains("Installation cancelled: \(local) is not owned by root or is writable by other users, so anything running as that user could replace the MacVPN root scripts."), r.output)
                XCTAssertTrue(r.output.contains("sudo chown root:wheel \(local) && sudo chmod go-w \(local) (on Intel Macs this may affect Homebrew)"), r.output)
            } else {
                XCTAssertTrue(r.output.contains("A telepítés megszakítva: a(z) \(local) nem a root tulajdona"), r.output)
                XCTAssertTrue(r.output.contains("(Intel Macen ez érintheti a Homebrew-t)"), r.output)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: local + "/libexec/macvpn/mvpn"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: r.root.path + "/etc/sudoers.d/macvpn"))
            let mode = try FileManager.default.attributesOfItem(atPath: local)[.posixPermissions] as? Int
            XCTAssertEqual(mode, state == .writable ? 0o777 : 0o755, "a szülő érintetlen")
        }
    }

    func testInstallSandboxRejectsTamperedFile() throws {
        AppLanguage.override = .en
        defer { AppLanguage.override = nil }
        let r = try runInstallSandbox(tamper: true)
        defer { try? FileManager.default.removeItem(at: r.root) }
        XCTAssertEqual(r.status, 1, r.output)
        XCTAssertTrue(r.output.contains("Integrity check failed, installation cancelled: mvpn"), r.output)
        XCTAssertFalse(FileManager.default.fileExists(atPath: r.root.appendingPathComponent("usr/local/libexec/macvpn/mvpn").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: r.root.appendingPathComponent("etc/sudoers.d/macvpn").path))
    }

    func testInstallSandboxRejectsSymlinkParent() throws {
        AppLanguage.override = .en
        defer { AppLanguage.override = nil }
        let r = try runInstallSandbox(parent: .symlink)
        defer { try? FileManager.default.removeItem(at: r.root) }
        XCTAssertEqual(r.status, 1, r.output)
        XCTAssertTrue(r.output.contains("Unsafe directory, installation cancelled: " + r.root.path + "/usr/local"), r.output)
    }

    func testRejectsBadUser() {
        XCTAssertThrowsError(try RootInstaller.installScript(sourceDir: URL(fileURLWithPath: "/x"), user: "bob ALL=(ALL) ALL", hashes: Self.fakeHashes))
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
        XCTAssertTrue(s.contains("case \"$kind\" in openvpn|wireguard|strongswan|sstp) ;; *) continue ;; esac"))
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
        for path in ["/etc/sudoers.d/macvpn", "/usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"] {
            let r = try XCTUnwrap(s.range(of: path, range: down.upperBound..<s.endIndex), path)
            XCTAssertTrue(r.lowerBound > down.upperBound)
        }
        XCTAssertTrue(s.contains("/bin/rm -f /etc/sudoers.d/macvpn"))
        XCTAssertTrue(s.contains("/bin/rm -rf /usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"))
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
    func runUninstallSandbox(failingID: String?, pppMarker: Bool = false,
                             pppContent: String? = nil) throws -> (status: Int32, output: String, mvpnCalls: [String]) {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("macvpn-uninstall-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: root) }
        let run = root.appendingPathComponent("run")
        let good = "11111111-2222-3333-4444-555555555555", other = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        for (dir, kind) in [(good, "openvpn"), (other, "wireguard"), ("notauuid", "openvpn"), ("99999999-2222-3333-4444-555555555555", "evil;rm")] {
            try fm.createDirectory(at: run.appendingPathComponent(dir), withIntermediateDirectories: true)
            try "\(kind)\n".write(to: run.appendingPathComponent("\(dir)/kind"), atomically: true, encoding: .utf8)
        }
        let pppOptions = root.appendingPathComponent("ppp-options"), marker = root.appendingPathComponent(".created-ppp-options")
        if let content = pppContent { try content.write(to: pppOptions, atomically: true, encoding: .utf8) }
        if pppMarker { try "".write(to: marker, atomically: true, encoding: .utf8) }
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
            .replacingOccurrences(of: "PPP_OPTIONS=/etc/ppp/options", with: "PPP_OPTIONS=\(RootInstaller.shellQuote(pppOptions.path))")
            .replacingOccurrences(of: "PPP_MARKER=/usr/local/libexec/macvpn/.created-ppp-options",
                                  with: "PPP_MARKER=\(RootInstaller.shellQuote(marker.path))")
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
        XCTAssertTrue(r.output.contains("RM -rf /usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"), r.output)
    }

    /// A /etc/ppp/options csak a mvpn jelölője mellett, és csak üresen törlődik.
    func testUninstallPPPOptions() throws {
        let removed = try runUninstallSandbox(failingID: nil, pppMarker: true, pppContent: "")
        XCTAssertEqual(removed.status, 0, removed.output)
        XCTAssertTrue(removed.output.contains("RM -f ") && removed.output.contains("/ppp-options\n"), removed.output)
        for (marker, content) in [(false, ""), (true, "lock\n"), (true, nil), (false, nil)] as [(Bool, String?)] {
            let kept = try runUninstallSandbox(failingID: nil, pppMarker: marker, pppContent: content)
            XCTAssertEqual(kept.status, 0, kept.output)
            XCTAssertFalse(kept.output.contains("ppp-options"), "\(marker) \(String(describing: content)): \(kept.output)")
        }
        let s = try RootInstaller.uninstallScript(user: "bob")
        XCTAssertTrue(s.contains("PPP_OPTIONS=/etc/ppp/options"))
        XCTAssertTrue(s.contains("PPP_MARKER=/usr/local/libexec/macvpn/.created-ppp-options"))
        // A jelölő a root könyvtárban van: a törlése (rm -rf a könyvtárra) csak a ppp ellenőrzése után jöhet.
        let ppp = try XCTUnwrap(s.range(of: "/bin/rm -f \"$PPP_OPTIONS\""))
        let dir = try XCTUnwrap(s.range(of: "/bin/rm -rf /usr/local/libexec/macvpn"))
        XCTAssertTrue(ppp.upperBound < dir.lowerBound)
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
        let src = try RootInstallerTests.makeRootSource()
        defer { try? FileManager.default.removeItem(at: src) }
        try await RootInstaller.install(sourceDir: src, user: "bob", runner: runner)
        let script = try XCTUnwrap(runner.calls.first?.arguments.last)
        let path = try XCTUnwrap(script.components(separatedBy: "quoted form of \"").last?.components(separatedBy: "\"").first)
        XCTAssertTrue(path.hasSuffix("/install.sh"))
        XCTAssertTrue(URL(fileURLWithPath: path).deletingLastPathComponent().lastPathComponent.hasPrefix("macvpn-install."))
        XCTAssertFalse(FileManager.default.fileExists(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path))
    }
}
