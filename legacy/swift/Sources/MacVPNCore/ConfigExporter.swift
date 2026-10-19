import Foundation

/// Export a config eredeti formátumában. A Keychainben tárolt jelszó és PSK nem kerül bele (SSTP-nél a felhasználónév
/// a config része); a configban inline álló kulcsanyagot és hitelesítő adatot a `secretMaterial` / `stripSecrets` kezeli.
public enum ConfigExporter {
    public static func fileName(for c: Connection) -> String {
        var safe = c.name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if safe.isEmpty { safe = "MacVPN" }
        switch c.kind {
        case .openvpn: return "\(safe).ovpn"
        case .wireguard: return "\(safe).conf"
        case .strongswan: return "\(safe).swanctl.conf"
        case .sstp: return "\(safe).sstp"
        case .l2tp, .cisco: return "\(safe).mobileconfig"
        }
    }

    public static func export(_ c: Connection, store: ConnectionStore) throws -> Data {
        if c.kind.isNative {
            // A fióknév nem titok (a meta.json-ban nyíltan áll), de személyes: az exportált profilban üres marad,
            // a címzett a sajátját adja meg.
            var copy = c
            if var native = copy.native {
                native.account = ""
                copy.native = native
            }
            return try MobileconfigGenerator.generate(connection: copy, psk: "")
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

    // MARK: - Kulcsanyag

    /// Az OpenVPN inline blokkok, amelyek privát / statikus kulcsot vagy hitelesítő adatot (felhasználónév + jelszó)
    /// tartalmaznak. Az `<http-proxy-user-pass>` a `<connection>` blokkon belül is állhat: a felismerés soronként megy,
    /// így ott is.
    static let openVPNSecretBlocks = ["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret", "pkcs12",
                                      "auth-user-pass", "http-proxy-user-pass"]
    static let wireGuardSecretKeys = ["PrivateKey", "PresharedKey"]

    /// A configban lévő kulcsanyag megnevezése (pl. `<key>`, `PrivateKey`, `secrets`), a figyelmeztetéshez.
    /// Üres: nincs mit levágni. A natív export eleve titok nélküli.
    public static func secretMaterial(in config: String, kind: VPNKind) -> [String] {
        let lines = config.components(separatedBy: "\n")
        switch kind {
        case .openvpn:
            let opened = Set(lines.compactMap(openVPNBlockTag))
            return openVPNSecretBlocks.filter { opened.contains($0) }.map { "<\($0)>" }
        case .wireguard:
            let keys = Set(lines.compactMap { wireGuardSecretKey($0, requireValue: true) })
            return wireGuardSecretKeys.filter { keys.contains($0) }
        case .strongswan:
            return strongSwanStrip(lines).found ? ["secrets"] : []
        case .sstp, .l2tp, .cisco:
            return []
        }
    }

    /// A kulcsanyag nélküli config: OpenVPN-nél a kulcsblokkok törölve, WireGuardnál a kulcsok értéke üres
    /// (a szerkezet megmarad, a címzett beírja a sajátját), strongSwannál a `secrets` szakasz törölve.
    public static func stripSecrets(_ config: String, kind: VPNKind) -> String {
        let lines = config.components(separatedBy: "\n")
        switch kind {
        case .openvpn:
            var out: [String] = []
            var skipping: String?
            for line in lines {
                if let tag = skipping {
                    if line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "</\(tag)>" { skipping = nil }
                    continue
                }
                if let tag = openVPNBlockTag(line) {
                    skipping = tag
                    continue
                }
                out.append(line)
            }
            // Lezáratlan blokk: a fájl végéig minden kimaradt; a záró újsor maradjon meg.
            if skipping != nil, config.hasSuffix("\n"), out.last != "" { out.append("") }
            return out.joined(separator: "\n")
        case .wireguard:
            return lines.map { line in wireGuardSecretKey(line, requireValue: false).map { "\($0) =" } ?? line }
                .joined(separator: "\n")
        case .strongswan:
            return strongSwanStrip(lines).lines.joined(separator: "\n")
        case .sstp, .l2tp, .cisco:
            return config
        }
    }

    /// Kulcsot tartalmazó OpenVPN blokk nyitó tagje (kisbetűvel), különben nil.
    private static func openVPNBlockTag(_ line: String) -> String? {
        let t = line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard t.hasPrefix("<"), t.hasSuffix(">"), !t.hasPrefix("</") else { return nil }
        let tag = String(t.dropFirst().dropLast())
        return openVPNSecretBlocks.contains(tag) ? tag : nil
    }

    /// `PrivateKey = …` / `PresharedKey = …` sor kulcsa (kanonikus írásmóddal), különben nil.
    /// `requireValue`: üres értékű sor (már levágott kulcs) nem számít.
    private static func wireGuardSecretKey(_ line: String, requireValue: Bool) -> String? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        if requireValue, line[line.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
        return wireGuardSecretKeys.first { $0.lowercased() == key }
    }

    /// A legfelső szintű `secrets { … }` szakasz(ok) törlése. A kapcsos zárójeleket idézőjelen és `#` megjegyzésen
    /// kívül számolja.
    private static func strongSwanStrip(_ lines: [String]) -> (lines: [String], found: Bool) {
        var out: [String] = []
        var depth = 0
        var skipping = false
        var found = false
        for line in lines {
            let startDepth = depth
            var inQuote = false
            for ch in line {
                if inQuote {
                    if ch == "\"" { inQuote = false }
                    continue
                }
                if ch == "#" { break }
                if ch == "\"" { inQuote = true } else if ch == "{" { depth += 1 } else if ch == "}" { depth = max(0, depth - 1) }
            }
            if !skipping, startDepth == 0,
               line.range(of: "^\\s*secrets\\s*\\{", options: .regularExpression) != nil {
                skipping = true
                found = true
            }
            if skipping {
                if depth == 0 { skipping = false }
                continue
            }
            out.append(line)
        }
        return (out, found)
    }
}
