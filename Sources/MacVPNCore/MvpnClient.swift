import Foundation

public struct RootStatus: Decodable, Equatable, Sendable {
    public let id: UUID
    public let kind: String
    public let state: String
    public let iface: String?
    public let ip: String?
    public let since: Double?

    public var connectionState: ConnectionState {
        switch state {
        case "connected": return .connected(ip: ip, since: since.map { Date(timeIntervalSince1970: $0) })
        case "connecting": return .connecting
        default: return .failed(L10n.tr("The connection dropped"))
        }
    }
}

public enum MvpnError: LocalizedError, Equatable {
    case failed(String)

    public var errorDescription: String? {
        switch self { case .failed(let message): return message }
    }
}

/// A root dispatcher (`Resources/root/mvpn`) Swift oldali kliense.
public struct MvpnClient: Sendable {
    public static let installDir = "/usr/local/libexec/macvpn"
    public static var executable: String { installDir + "/mvpn" }
    public static let logDir = "/var/log/macvpn"

    public static func logURL(for id: UUID) -> URL {
        URL(fileURLWithPath: "\(logDir)/\(id.uuidString).log")
    }

    /// `down` (és alapértelmezésként minden más) futtatója.
    let runner: CommandRunner
    /// `up`: hosszabb időkorlát (`RunnerTimeouts.up`).
    let upRunner: CommandRunner
    /// `status`: rövid időkorlát (`RunnerTimeouts.quick`).
    let statusRunner: CommandRunner
    /// A `mvpn` üzeneteinek nyelve. Nil: hívásonként az `AppLanguage.current`.
    let language: AppLanguage?

    public init(runner: CommandRunner, upRunner: CommandRunner? = nil, statusRunner: CommandRunner? = nil,
                language: AppLanguage? = nil) {
        self.runner = runner
        self.upRunner = upRunner ?? runner
        self.statusRunner = statusRunner ?? runner
        self.language = language
    }

    /// `sudo -n mvpn <args…> --lang <en|hu>`. A `--lang` a végén van, így egy régebbi, még `--lang` nélküli
    /// telepített `mvpn` is a helyes parancsot és argumentumokat látja.
    public static func sudoArguments(_ args: [String], language: AppLanguage = .current) -> [String] {
        ["-n", executable] + args + ["--lang", language.rawValue]
    }

    private func sudo(_ args: [String], stdin: String?, using runner: CommandRunner? = nil) async throws -> CommandResult {
        try await (runner ?? self.runner).run("/usr/bin/sudo", Self.sudoArguments(args, language: language ?? .current), stdin: stdin)
    }

    public func up(kind: VPNKind, id: UUID, secrets: Secrets, debug: Bool) async throws {
        var args = ["up", kind.rawValue, id.uuidString]
        if debug { args.append("--debug") }
        try check(await sudo(args, stdin: secrets.stdinPayload, using: upRunner))
    }

    public func down(kind: VPNKind, id: UUID) async throws {
        try check(await sudo(["down", kind.rawValue, id.uuidString], stdin: nil))
    }

    public func status() async throws -> [RootStatus] {
        let result = try await sudo(["status"], stdin: nil, using: statusRunner)
        try check(result)
        return try Self.parseStatus(result.stdout)
    }

    public static func parseStatus(_ json: String) throws -> [RootStatus] {
        try JSONDecoder().decode([RootStatus].self, from: Data(json.utf8))
    }

    private func check(_ result: CommandResult) throws {
        guard result.exitCode == 0 else {
            let message = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw MvpnError.failed(message.isEmpty ? L10n.tr("mvpn error (exit code: %d)", result.exitCode) : message)
        }
    }
}
