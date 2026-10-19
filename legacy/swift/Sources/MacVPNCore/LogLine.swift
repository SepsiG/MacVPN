import Foundation

public enum LogFilter: String, CaseIterable, Identifiable, Sendable {
    case all, commands, errors
    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .all: return L10n.tr("All")
        case .commands: return L10n.tr("Commands")
        case .errors: return L10n.tr("Errors")
        }
    }
}

public struct LogLine: Equatable, Sendable {
    public enum Kind: Sendable { case header, step, command, error, output }

    public let text: String
    public let kind: Kind

    static let errorMarkers = ["AUTH_FAILED", "TLS handshake failed", "TLS Error", "Exiting due to fatal error",
                               "establishing connection failed", "failed to establish", "Connection refused"]

    public init(_ text: String) {
        self.text = text
        if text.hasPrefix("═══") { kind = .header }
        else if text.hasPrefix("▶ [mvpn]") { kind = .step }
        else if text.hasPrefix("$ ") || text.hasPrefix("[#] ") { kind = .command }
        else if text.hasPrefix("✗") || Self.errorMarkers.contains(where: { text.contains($0) }) { kind = .error }
        else { kind = .output }
    }

    public func matches(_ filter: LogFilter) -> Bool {
        switch filter {
        case .all: return true
        case .commands: return kind == .command || kind == .step || kind == .header
        case .errors: return kind == .error
        }
    }
}
