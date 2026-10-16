import Foundation
@testable import MacVPNCore

/// A kulcs a teljes parancssor szóközzel összefűzve, pl. "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn status".
final class MockCommandRunner: CommandRunner, @unchecked Sendable {
    struct Call: Equatable {
        let executable: String
        let arguments: [String]
        let stdin: String?
        var commandLine: String { ([executable] + arguments).joined(separator: " ") }
    }

    private let lock = NSLock()
    private var _calls: [Call] = []
    var responses: [String: CommandResult] = [:]
    /// A megadott parancssor ennyit vár (a válasz a hívás pillanatában dől el), így a tesztek összefésülhetik a hívásokat.
    var delays: [String: TimeInterval] = [:]

    var calls: [Call] { lock.lock(); defer { lock.unlock() }; return _calls }

    func run(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult {
        let call = Call(executable: executable, arguments: arguments, stdin: stdin)
        let (response, delay) = lock.withLock {
            _calls.append(call)
            return (responses[call.commandLine], delays[call.commandLine])
        }
        if let delay { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
        return response ?? CommandResult()
    }
}

/// Records the native start/stop calls instead of calling SystemConfiguration (no real VPN is touched).
final class MockNativeDriver: NativeConnectionDriver, @unchecked Sendable {
    struct Start: Equatable {
        let serviceID: String
        let options: NSDictionary?
        let linger: Bool
    }

    private let lock = NSLock()
    private var _starts: [Start] = []
    private var _stops: [String] = []
    /// Thrown by `start` when set.
    var startError: Error?
    var stopError: Error?

    var starts: [Start] { lock.withLock { _starts } }
    var stops: [String] { lock.withLock { _stops } }

    func start(serviceID: String, options: [String: Any]?, linger: Bool) throws {
        let error: Error? = lock.withLock {
            _starts.append(Start(serviceID: serviceID, options: options.map { $0 as NSDictionary }, linger: linger))
            return startError
        }
        if let error { throw error }
    }

    func stop(serviceID: String) throws {
        let error: Error? = lock.withLock {
            _stops.append(serviceID)
            return stopError
        }
        if let error { throw error }
    }
}
