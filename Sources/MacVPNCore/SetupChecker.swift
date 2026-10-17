import Foundation

public struct SetupReport: Equatable, Sendable {
    public var brewPrefix: String?
    /// Sorrend: SetupChecker.requiredTools sorrendje.
    public var missingTools: [String]
    public var installedRootVersion: String?
    public var bundledRootVersion: String?
    public var sudoWorks: Bool

    public static let unknown = SetupReport(brewPrefix: nil, missingTools: [], installedRootVersion: nil,
                                            bundledRootVersion: nil, sudoWorks: false)

    public var rootOK: Bool {
        sudoWorks && installedRootVersion != nil && installedRootVersion == bundledRootVersion
    }

    public var isComplete: Bool { brewPrefix != nil && missingTools.isEmpty && rootOK }

    public func isAvailable(_ kind: VPNKind) -> Bool {
        if kind.isNative { return true }
        guard rootOK, brewPrefix != nil else { return false }
        let needed = SetupChecker.requiredTools.first { $0.kind == kind }?.tools ?? []
        return needed.allSatisfy { !missingTools.contains($0) }
    }
}

public struct SetupChecker {
    public static let requiredTools: [(kind: VPNKind, tools: [String])] = [
        (.openvpn, ["openvpn"]),
        (.wireguard, ["wg", "wg-quick", "wireguard-go", "bash"]),
        (.strongswan, ["swanctl", "charon"]),
        (.sstp, ["sstpc"]),
    ]
    public static let brewPackages = ["openvpn", "wireguard-tools", "strongswan", "sstp-client", "bash"]
    public static let brewPrefixes = ["/opt/homebrew", "/usr/local"]

    let runner: CommandRunner
    let fileExists: (String) -> Bool
    let readFile: (String) -> String?
    let bundledRootDir: URL?

    public init(runner: CommandRunner,
                fileExists: @escaping (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) },
                readFile: @escaping (String) -> String? = { try? String(contentsOfFile: $0, encoding: .utf8) },
                bundledRootDir: URL?) {
        self.runner = runner
        self.fileExists = fileExists
        self.readFile = readFile
        self.bundledRootDir = bundledRootDir
    }

    /// Tükrözi a `mvpn` find_tool / find_charon útvonalait.
    public static func candidates(tool: String, prefix: String) -> [String] {
        if tool == "charon" {
            return ["\(prefix)/opt/strongswan/libexec/ipsec/charon", "\(prefix)/opt/strongswan/libexec/charon"]
        }
        return ["\(prefix)/bin/\(tool)", "\(prefix)/sbin/\(tool)"]
    }

    public func check() async -> SetupReport {
        let prefix = Self.brewPrefixes.first { fileExists("\($0)/bin/brew") }
        var missing: [String] = []
        for (_, tools) in Self.requiredTools {
            for tool in tools where !missing.contains(tool) {
                let found = prefix.map { p in Self.candidates(tool: tool, prefix: p).contains(where: fileExists) } ?? false
                if !found { missing.append(tool) }
            }
        }
        let trim = { (s: String?) in s?.trimmingCharacters(in: .whitespacesAndNewlines) }
        let installed = trim(readFile(MvpnClient.installDir + "/VERSION"))
        let bundled = trim(bundledRootDir.flatMap { readFile($0.appendingPathComponent("VERSION").path) })
        let sudo = (try? await runner.run("/usr/bin/sudo", MvpnClient.sudoArguments(["version"]), stdin: nil))?.exitCode == 0
        return SetupReport(brewPrefix: prefix, missingTools: missing, installedRootVersion: installed,
                           bundledRootVersion: bundled, sudoWorks: sudo)
    }
}
