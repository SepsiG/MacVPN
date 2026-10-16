import Foundation

public struct SystemVPNService: Equatable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let typeLabel: String
    public let status: String

    public var connectionState: ConnectionState {
        switch status {
        case "Connected": return .connected(ip: nil, since: nil)
        case "Connecting": return .connecting
        case "Disconnecting": return .disconnecting
        default: return .disconnected
        }
    }
}

public enum ScutilParser {
    private static let regex = try! NSRegularExpression(
        pattern: #"^\*?\s*\(([^)]+)\)\s+([0-9A-Fa-f-]{36})\s+.*?"(.*)"\s+\[([^\]]+)\]\s*$"#)

    public static func parseList(_ output: String) -> [SystemVPNService] {
        output.components(separatedBy: "\n").compactMap { line in
            let ns = line as NSString
            guard let m = regex.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) else { return nil }
            let type = ns.substring(with: m.range(at: 4))
            guard let label = typeLabel(type) else { return nil }
            return SystemVPNService(id: ns.substring(with: m.range(at: 2)),
                                    name: ns.substring(with: m.range(at: 3)),
                                    typeLabel: label,
                                    status: ns.substring(with: m.range(at: 1)))
        }
    }

    /// nil: nem VPN (pl. modem).
    static func typeLabel(_ raw: String) -> String? {
        switch raw {
        case "PPP:L2TP": return "L2TP"
        case "IPSec": return "Cisco IPsec"
        case "IKEv2": return "IKEv2"
        case "VPN:com.wireguard.macos": return "WireGuard (app)"
        case "VPN:net.tunnelblick.tunnelblick": return "OpenVPN (app)"
        default: return raw.hasPrefix("VPN:") ? "VPN" : nil
        }
    }
}

public struct NativeVPNController: Sendable {
    let runner: CommandRunner

    public init(runner: CommandRunner) {
        self.runner = runner
    }

    public func list() async throws -> [SystemVPNService] {
        let result = try await runner.run("/usr/sbin/scutil", ["--nc", "list"], stdin: nil)
        try check(result)
        return ScutilParser.parseList(result.stdout)
    }

    public func start(serviceID: String) async throws {
        try check(await runner.run("/usr/sbin/scutil", ["--nc", "start", serviceID], stdin: nil))
    }

    public func stop(serviceID: String) async throws {
        try check(await runner.run("/usr/sbin/scutil", ["--nc", "stop", serviceID], stdin: nil))
    }

    private func check(_ r: CommandResult) throws {
        guard r.exitCode == 0 else {
            let message = (r.stderr + r.stdout).trimmingCharacters(in: .whitespacesAndNewlines)
            throw MvpnError.failed(message.isEmpty ? L10n.tr("scutil error (exit code: %d)", r.exitCode) : message)
        }
    }
}
