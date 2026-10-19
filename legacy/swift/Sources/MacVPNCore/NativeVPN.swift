import Foundation
import SystemConfiguration

public struct SystemVPNService: Equatable, Identifiable, Sendable {
    public let id: String
    public let name: String
    public let typeLabel: String
    public let status: String

    /// MacVPN keychain key for this service's PSK/password. scutil service IDs are UUIDs; nil if this one is not.
    public var secretID: UUID? { UUID(uuidString: id) }

    /// The PSK/password can be stored in MacVPN and passed when starting (L2TP and Cisco IPsec only).
    public var supportsStoredSecrets: Bool { secretID != nil && NativeKind(typeLabel: typeLabel) != nil }

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

    /// The server address from `scutil --nc show <id>` (`CommRemoteAddress` for L2TP, `RemoteAddress` for IPsec).
    public static func remoteAddress(_ output: String) -> String? {
        for line in output.components(separatedBy: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2, parts[0] == "CommRemoteAddress" || parts[0] == "RemoteAddress", !parts[1].isEmpty else { continue }
            return parts[1]
        }
        return nil
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

/// The native service types whose secrets can be passed when starting.
public enum NativeKind: Equatable, Sendable {
    case l2tp, ciscoIPSec

    public init?(kind: VPNKind) {
        switch kind {
        case .l2tp: self = .l2tp
        case .cisco: self = .ciscoIPSec
        default: return nil
        }
    }

    /// `SystemVPNService.typeLabel` (see `ScutilParser.typeLabel`).
    public init?(typeLabel: String) {
        switch typeLabel {
        case "L2TP": self = .l2tp
        case "Cisco IPsec": self = .ciscoIPSec
        default: return nil
        }
    }
}

/// User options for `SCNetworkConnectionStart`. They override the service's stored configuration for this start,
/// so a PSK that pppd/racoon cannot read from the System keychain is still used. Never logged, never put into argv.
public enum NativeStartOptions {
    /// nil: no secret given, the stored configuration is used as it is.
    public static func make(kind: NativeKind, secrets: Secrets) -> [String: Any]? {
        func value(_ s: String?) -> String? { (s?.isEmpty ?? true) ? nil : s }
        var ipsec: [String: Any] = [:]
        var ppp: [String: Any] = [:]
        if let psk = value(secrets.psk) { ipsec[kSCPropNetIPSecSharedSecret as String] = psk }
        switch kind {
        case .l2tp:
            if let name = value(secrets.username) { ppp[kSCPropNetPPPAuthName as String] = name }
            if let password = value(secrets.password) { ppp[kSCPropNetPPPAuthPassword as String] = password }
        case .ciscoIPSec:
            if let name = value(secrets.username) { ipsec[kSCPropNetIPSecXAuthName as String] = name }
            if let password = value(secrets.password) { ipsec[kSCPropNetIPSecXAuthPassword as String] = password }
        }
        var options: [String: Any] = [:]
        if !ipsec.isEmpty { options[kSCEntNetIPSec as String] = ipsec }
        if !ppp.isEmpty { options[kSCEntNetPPP as String] = ppp }
        return options.isEmpty ? nil : options
    }
}

/// Starts and stops a native (scutil-listed) VPN service. Behind a protocol so tests never touch a real VPN.
public protocol NativeConnectionDriver: Sendable {
    func start(serviceID: String, options: [String: Any]?, linger: Bool) throws
    func stop(serviceID: String) throws
}

public enum NativeDriverError: LocalizedError, Equatable {
    case open(String)
    case start(String)
    case stop(String)

    public var errorDescription: String? {
        switch self {
        case .open(let detail): return L10n.tr("Cannot open the VPN service: %@", detail)
        case .start(let detail): return L10n.tr("Cannot start the VPN service: %@", detail)
        case .stop(let detail): return L10n.tr("Cannot stop the VPN service: %@", detail)
        }
    }
}

/// In-process `SCNetworkConnection`. Unlike `scutil --nc start`, it can pass the PSK/password as user options
/// (an L2TP PSK in the System keychain is otherwise not found: "L2TP: incorrect user shared secret found").
public struct SystemConfigurationDriver: NativeConnectionDriver {
    public init() {}

    private func connection(_ serviceID: String) throws -> SCNetworkConnection {
        guard let conn = SCNetworkConnectionCreateWithServiceID(nil, serviceID as CFString, nil, nil) else {
            throw NativeDriverError.open(Self.lastError())
        }
        return conn
    }

    public func start(serviceID: String, options: [String: Any]?, linger: Bool) throws {
        let conn = try connection(serviceID)
        guard SCNetworkConnectionStart(conn, options as CFDictionary?, linger) else {
            throw NativeDriverError.start(Self.lastError())
        }
    }

    public func stop(serviceID: String) throws {
        let conn = try connection(serviceID)
        guard SCNetworkConnectionStop(conn, true) else {
            throw NativeDriverError.stop(Self.lastError())
        }
    }

    static func lastError() -> String {
        let code = SCError()
        return "\(String(cString: SCErrorString(code))) (\(code))"
    }
}

public struct NativeVPNController: Sendable {
    let runner: CommandRunner
    let driver: NativeConnectionDriver

    /// The started connection outlives this process: the VPN keeps running after MacVPN quits ("keep running").
    public static let linger = true

    /// No default driver: tests must never reach the real `SystemConfigurationDriver` by accident.
    public init(runner: CommandRunner, driver: NativeConnectionDriver) {
        self.runner = runner
        self.driver = driver
    }

    public func list() async throws -> [SystemVPNService] {
        let result = try await runner.run("/usr/sbin/scutil", ["--nc", "list"], stdin: nil)
        try check(result)
        return ScutilParser.parseList(result.stdout)
    }

    /// The service's server address (`scutil --nc show`); nil if it cannot be read.
    public func remoteAddress(serviceID: String) async -> String? {
        guard let result = try? await runner.run("/usr/sbin/scutil", ["--nc", "show", serviceID], stdin: nil),
              result.exitCode == 0 else { return nil }
        return ScutilParser.remoteAddress(result.stdout)
    }

    /// `kind` nil or no secrets: started with the stored configuration only.
    public func start(serviceID: String, kind: NativeKind? = nil, secrets: Secrets = Secrets()) async throws {
        let options = kind.flatMap { NativeStartOptions.make(kind: $0, secrets: secrets) }
        try driver.start(serviceID: serviceID, options: options, linger: Self.linger)
    }

    public func stop(serviceID: String) async throws {
        try driver.stop(serviceID: serviceID)
    }

    private func check(_ r: CommandResult) throws {
        guard r.exitCode == 0 else {
            let message = (r.stderr + r.stdout).trimmingCharacters(in: .whitespacesAndNewlines)
            throw MvpnError.failed(message.isEmpty ? L10n.tr("scutil error (exit code: %d)", r.exitCode) : message)
        }
    }
}
