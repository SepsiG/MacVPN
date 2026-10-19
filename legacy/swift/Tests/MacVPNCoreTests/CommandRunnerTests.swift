import XCTest
@testable import MacVPNCore

final class CommandRunnerTests: XCTestCase {
    func testRunsProcessWithStdin() async throws {
        let r = try await ProcessCommandRunner().run("/bin/cat", [], stdin: "hello\n")
        XCTAssertEqual(r.exitCode, 0)
        XCTAssertEqual(r.stdout, "hello\n")
    }

    func testCapturesStderrAndExitCode() async throws {
        let r = try await ProcessCommandRunner().run("/bin/sh", ["-c", "echo oops >&2; exit 3"], stdin: nil)
        XCTAssertEqual(r.exitCode, 3)
        XCTAssertEqual(r.stderr, "oops\n")
    }

    func testReturnsWhenBackgroundChildHoldsPipe() async throws {
        let start = Date()
        let r = try await ProcessCommandRunner().run("/bin/sh", ["-c", "sleep 5 & echo done"], stdin: nil)
        XCTAssertEqual(r.stdout, "done\n")
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0)
    }

    func testTimeoutThrowsTimedOut() async {
        let start = Date()
        do {
            _ = try await ProcessCommandRunner(timeout: 0.5).run("/bin/sleep", ["5"], stdin: nil)
            XCTFail("nem dobott")
        } catch let e as CommandError {
            XCTAssertEqual(e, .timedOut("/bin/sleep"))
        } catch {
            XCTFail("rossz hiba: \(error)")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3.0)
    }

    func testLargeStdinToNonReadingChildDoesNotCrashOrHang() async throws {
        let big = String(repeating: "x", count: 1_000_000)
        let r = try await ProcessCommandRunner().run("/usr/bin/true", [], stdin: big)
        XCTAssertEqual(r.exitCode, 0)
    }

    func testLargeStdoutCapturedFully() async throws {
        let r = try await ProcessCommandRunner().run("/bin/sh", ["-c", "head -c 2097152 /dev/zero | tr '\\0' 'a'"], stdin: nil)
        XCTAssertEqual(r.stdout.utf8.count, 2_097_152)
    }

    func testCancellationTerminatesProcess() async {
        let start = Date()
        let task = Task { try await ProcessCommandRunner().run("/bin/sleep", ["5"], stdin: nil) }
        try? await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        _ = try? await task.value
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }
}
