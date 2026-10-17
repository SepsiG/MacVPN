import XCTest
@testable import MacVPNCore

final class BrewBootstrapTests: XCTestCase {
    func testEnvironmentIsMinimal() {
        let env = BrewEnvironment.make(from: [
            "HOME": "/Users/bob", "USER": "bob", "LOGNAME": "bob", "TMPDIR": "/var/folders/x/T/", "LANG": "hu_HU.UTF-8",
            "PATH": "/evil:/usr/bin", "HOMEBREW_GITHUB_API_TOKEN": "t", "HOMEBREW_BREW_GIT_REMOTE": "https://evil",
            "DYLD_INSERT_LIBRARIES": "/x.dylib", "RUBYOPT": "-r/x", "SSH_AUTH_SOCK": "/s",
        ], brewPrefix: "/opt/homebrew")
        XCTAssertEqual(env, [
            "HOME": "/Users/bob", "USER": "bob", "LOGNAME": "bob", "TMPDIR": "/var/folders/x/T/", "LANG": "hu_HU.UTF-8",
            "PATH": "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOMEBREW_NO_ENV_HINTS": "1",
        ])
        XCTAssertEqual(BrewEnvironment.make(from: [:], brewPrefix: "/usr/local").keys.sorted(), ["HOMEBREW_NO_ENV_HINTS", "PATH"])
    }

    func testScriptAbortsWhenTheDownloadFails() {
        let script = BrewBootstrap.script(start: "Start", done: "Done", failed: "It's broken", cleanupDirectory: "/tmp/d x")
        XCTAssertTrue(script.hasPrefix("#!/bin/bash\n"))
        XCTAssertTrue(script.contains("s=$(/usr/bin/curl -fsSL \(BrewBootstrap.installerURL)) || { echo 'It'\\''s broken'; exit 1; }\n"))
        XCTAssertTrue(script.contains("/bin/bash -c \"$s\"\n"))
        XCTAssertTrue(script.contains("trap 'rm -rf -- '\\''/tmp/d x'\\''' EXIT\n"))
        XCTAssertFalse(script.contains("$(curl"))
    }

    /// The generated script is valid bash, and a failing download stops it before anything runs.
    func testScriptIsValidBashAndStopsOnCurlFailure() throws {
        let script = BrewBootstrap.script(start: "a", done: "b", failed: "FAILED", cleanupDirectory: "/nonexistent")
        let check = Process()
        check.executableURL = URL(fileURLWithPath: "/bin/bash")
        check.arguments = ["-n", "-c", script]
        try check.run()
        check.waitUntilExit()
        XCTAssertEqual(check.terminationStatus, 0)

        // curl to an unreachable URL (no network needed): the script must exit 1 and never print "b".
        let offline = script.replacingOccurrences(of: BrewBootstrap.installerURL, with: "http://127.0.0.1:9/install.sh")
        let run = Process()
        let out = Pipe()
        run.executableURL = URL(fileURLWithPath: "/bin/bash")
        run.arguments = ["-c", offline]
        run.standardOutput = out
        run.standardError = Pipe()
        try run.run()
        run.waitUntilExit()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(run.terminationStatus, 1)
        XCTAssertTrue(text.contains("FAILED"))
        XCTAssertFalse(text.contains("b\n"))
    }

    func testWriteCreatesExecutableInFreshPrivateDirectory() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        let a = try BrewBootstrap.write(script: { "#!/bin/bash\necho \($0)\n" }, in: parent)
        let b = try BrewBootstrap.write(script: { "#!/bin/bash\necho \($0)\n" }, in: parent)
        XCTAssertNotEqual(a.deletingLastPathComponent(), b.deletingLastPathComponent())
        XCTAssertEqual(a.pathExtension, "command")
        let attrs = try FileManager.default.attributesOfItem(atPath: a.path)
        XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue & 0o777, 0o700)
        let dirAttrs = try FileManager.default.attributesOfItem(atPath: a.deletingLastPathComponent().path)
        XCTAssertEqual((dirAttrs[.posixPermissions] as! NSNumber).intValue & 0o777, 0o700)
        XCTAssertEqual(try String(contentsOf: a, encoding: .utf8), "#!/bin/bash\necho \(a.deletingLastPathComponent().path)\n")
        XCTAssertThrowsError(try BrewBootstrap.write(script: { _ in "" }, in: parent.appendingPathComponent("missing")))
    }
}
