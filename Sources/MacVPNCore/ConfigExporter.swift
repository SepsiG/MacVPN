import Foundation

/// Export a config eredeti formátumában. Jelszó, PSK, felhasználónév nem kerül bele.
public enum ConfigExporter {
    public static func fileName(for c: Connection) -> String {
        var safe = c.name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if safe.isEmpty { safe = "MacVPN" }
        switch c.kind {
        case .openvpn: return "\(safe).ovpn"
        case .wireguard: return "\(safe).conf"
        case .strongswan: return "\(safe).swanctl.conf"
        case .l2tp, .cisco: return "\(safe).mobileconfig"
        }
    }

    public static func export(_ c: Connection, store: ConnectionStore) throws -> Data {
        if c.kind.isNative {
            // A fióknév is titok: az exportált profilban üres marad.
            var copy = c
            if var native = copy.native {
                native.account = ""
                copy.native = native
            }
            return try MobileconfigGenerator.generate(connection: copy, password: "", psk: "")
        }
        return Data(try store.loadConfig(c.id).utf8)
    }

    public struct WriteError: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// Az exportot eleve 0600-as jogosultsággal hozza létre: ideiglenes fájl a célkönyvtárban
    /// (O_EXCL, symlinket nem követ), majd atomikus átnevezés. Meglévő fájl jogosultsága nem öröklődik.
    public static func write(_ data: Data, to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw WriteError(message: L10n.tr("Cannot write: %@", url.path)) }
        do {
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            try handle.close()
            guard chmod(tmp.path, 0o600) == 0 else { throw WriteError(message: L10n.tr("Cannot set the permissions: %@", url.path)) }
            guard rename(tmp.path, url.path) == 0 else { throw WriteError(message: L10n.tr("Cannot write: %@", url.path)) }
        } catch {
            unlink(tmp.path)
            throw error
        }
    }

    public static func warning(for kind: VPNKind) -> String? {
        kind == .wireguard
            ? L10n.tr("The WireGuard config contains the private key (PrivateKey). Only save it to a trusted place or share it with someone you trust.")
            : nil
    }
}
