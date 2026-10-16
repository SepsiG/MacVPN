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
