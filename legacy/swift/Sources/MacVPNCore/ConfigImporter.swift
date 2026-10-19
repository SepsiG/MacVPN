import Foundation

public enum ConfigImportError: LocalizedError, Equatable {
    case missingFile(String)
    /// A hivatkozott fájl (symlinkek feloldása után) nem a config mappáján belül van.
    case outsideBaseDirectory(String)
    case fileTooLarge(String)
    /// A fájl tartalma nem a direktívához várt formátum (pl. PEM tanúsítvány a `ca`-hoz).
    case wrongFormat(directive: String, file: String)
    case unsupported(String)
    case unknownType
    /// Natív (L2TP / Cisco) export: a Finderből, a macOS Profilokon át kell telepíteni, nem a MacVPN-be importálni.
    case nativeProfile

    public var errorDescription: String? {
        switch self {
        case .missingFile(let f): return L10n.tr("Referenced file not found: %@", f)
        case .outsideBaseDirectory(let f): return L10n.tr("The referenced file is outside the config's folder: %@", f)
        case .fileTooLarge(let f): return L10n.tr("The referenced file is larger than 1 MB: %@", f)
        case .wrongFormat(let d, let f): return L10n.tr("The file for the %@ directive (%@) does not have the expected format", d, f)
        case .unsupported(let d): return L10n.tr("Directive not supported for import: %@", d)
        case .unknownType: return L10n.tr("Cannot detect the config type")
        case .nativeProfile: return L10n.tr("A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles).")
        }
    }
}

public enum ConfigImporter {
    /// Mint a `detectKind`, de hibával jelzi, miért nem importálható a fájl.
    public static func kind(fileName: String, content: String) throws -> VPNKind {
        if (fileName as NSString).pathExtension.lowercased() == "mobileconfig" { throw ConfigImportError.nativeProfile }
        guard let kind = detectKind(fileName: fileName, content: content) else { throw ConfigImportError.unknownType }
        return kind
    }

    public struct PreparedImport: Equatable, Sendable {
        public let kind: VPNKind
        public let config: String
        public let inlinedFiles: [String]
        /// A validátor blokkoló hibái. Az import ettől még mentődik, hogy a szerkesztőben javítható legyen.
        public let issues: [ValidationIssue]
        /// OpenVPN: a tudomásulvételt igénylő (RISKY) direktívák. Nem hiba: a szerkesztő sárga paneljén vehetők tudomásul.
        public var risky: [RiskyFinding] = []
        /// OpenVPN: az `auth-user-pass <fájl>` / `askpass <fájl>` fájlokból kiolvasott titkok (a Keychainbe kerülnek,
        /// a configba soha) és a fájlok, amelyeket nem sikerült beolvasni.
        public var credentials = ImportedCredentials()
        /// OpenVPN: a config titkosított privát kulcsot tartalmaz (a „Privát kulcs jelszava” mező kell hozzá).
        public var hasEncryptedKey = false
    }

    /// Hitelesítő adatok egy OpenVPN import fájljaiból.
    public struct ImportedCredentials: Equatable, Sendable {
        public var username: String?
        public var password: String?
        /// Az `auth-user-pass` fájl neve, ha a felhasználónév/jelszó belőle jött.
        public var credentialsFile: String?
        public var keyPassword: String?
        /// Az `askpass` fájl neve, ha a kulcsjelszó belőle jött.
        public var keyPasswordFile: String?
        /// Hivatkozott, de nem beolvasott (hiányzó, mappán kívüli, túl nagy, rossz formátumú) titokfájlok.
        public var unreadFiles: [String] = []

        public init() {}

        /// A beolvasott titokfájlok (a felhasználónak megerősítésre felajánlandók). Az import maga semmit nem tárol:
        /// a hívó (az app) kérdez rá, és csak megerősítés után teszi a Keychainbe.
        public var candidateFiles: [String] { [credentialsFile, keyPasswordFile].compactMap { $0 } }
    }

    /// Típusfelismerés, OpenVPN-nél a hivatkozott fájlok beemelése, majd validálás.
    public static func prepare(fileName: String, content: String, baseDirectory: URL) throws -> PreparedImport {
        let kind = try kind(fileName: fileName, content: content)
        var config = content
        var inlined: [String] = []
        if kind == .openvpn {
            let result = try inlineOpenVPNFiles(content, baseDirectory: baseDirectory)
            config = result.config
            inlined = result.inlinedFiles
            let validation = OpenVPNValidator().validate(config, acknowledgedRisky: [])
            return PreparedImport(kind: kind, config: config, inlinedFiles: inlined, issues: validation.issues,
                                  risky: validation.risky, credentials: result.credentials,
                                  hasEncryptedKey: containsEncryptedKey(config))
        }
        let issues = Validators.validator(for: kind)?.validate(config) ?? []
        return PreparedImport(kind: kind, config: config, inlinedFiles: inlined, issues: issues)
    }

    public static func detectKind(fileName: String, content: String) -> VPNKind? {
        let ext = (fileName as NSString).pathExtension.lowercased()
        if ext == "ovpn" { return .openvpn }
        if ext == "sstp" { return .sstp }
        let lower = content.lowercased()
        if lower.contains("[interface]"), lower.contains("privatekey") { return .wireguard }
        if content.range(of: "(?m)^\\s*connections\\s*\\{", options: .regularExpression) != nil { return .strongswan }
        if content.range(of: "(?m)^\\s*remote\\s+\\S+", options: .regularExpression) != nil,
           content.range(of: "(?m)^\\s*(client|dev\\s+tun)", options: .regularExpression) != nil { return .openvpn }
        if content.range(of: "(?m)^[ \\t]*server=[^\\s=]+[ \\t]*\r?$", options: .regularExpression) != nil,
           content.range(of: "(?m)^[ \\t]*(user|cert|route_all|peer_dns)=", options: .regularExpression) != nil { return .sstp }
        return nil
    }

    /// Az inline-olt fájl felső mérethatára.
    public static let maxInlineFileSize = 1_048_576

    /// A direktívánként elvárt PEM blokk(ok) típusa (a `-----BEGIN <típus>-----` sorban).
    static let expectedFormat: [String: String] = [
        "ca": "CERTIFICATE",
        "cert": "CERTIFICATE",
        "extra-certs": "CERTIFICATE",
        "key": "(?:[A-Z0-9]+ )*PRIVATE KEY",
        "tls-auth": "OpenVPN Static key V1",
        "tls-crypt": "OpenVPN Static key V1",
        "secret": "OpenVPN Static key V1",
        "tls-crypt-v2": "OpenVPN tls-crypt-v2 client key",
        "dh": "(?:X9\\.42 )?DH PARAMETERS",
    ]

    public struct InlineResult: Equatable, Sendable {
        public let config: String
        /// A beemelt fájlok, ahogy a config hivatkozott rájuk (sorrendben).
        public let inlinedFiles: [String]
        /// Az `auth-user-pass <fájl>` és `askpass <fájl>` titkai (nem kerülnek a configba).
        public var credentials = ImportedCredentials()
    }

    /// A titokfájlok felső mérethatára (`auth-user-pass`, `askpass`).
    public static let maxCredentialsFileSize = 1024

    /// Titkosított PEM privát kulcs a configban (PKCS#8 `ENCRYPTED PRIVATE KEY` vagy régi `Proc-Type: 4,ENCRYPTED`).
    public static func containsEncryptedKey(_ config: String) -> Bool {
        config.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") || config.contains("Proc-Type: 4,ENCRYPTED")
    }

    /// Egy titokfájl sorai (a config mappáján belül, ugyanazzal a beolvasással, legfeljebb 1 KB, UTF-8, sorvégi CR
    /// levágva, vezérlőkarakter nélkül). nil: nem olvasható vagy nem megfelelő.
    static func readCredentialLines(_ path: String, base: String) -> [String]? {
        guard let data = try? readInlineData(path, base: base), data.count <= maxCredentialsFileSize,
              let text = String(data: data, encoding: .utf8) else { return nil }
        var lines = text.components(separatedBy: "\n").map { $0.hasSuffix("\r") ? String($0.dropLast()) : $0 }
        while lines.last == "" { lines.removeLast() }
        guard !lines.isEmpty, Secrets(username: lines.joined()).inputError == nil else { return nil }
        return lines
    }

    /// A külső fájlra hivatkozó OpenVPN direktívákat inline blokká alakítja. Csak a config mappáján belüli
    /// (symlinkek feloldása után is), legfeljebb 1 MB-os, a direktívának megfelelő formátumú fájl emelhető be.
    public static func inlineOpenVPNFiles(_ content: String, baseDirectory: URL) throws -> InlineResult {
        guard let base = realPath(baseDirectory.path) else { throw ConfigImportError.missingFile(baseDirectory.path) }
        var out: [String] = []
        var inlined: [String] = []
        var credentials = ImportedCredentials()
        for raw in content.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: "\r")))
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let first = tokens.first?.lowercased(), tokens.count >= 2, tokens[1] != "[inline]" else {
                out.append(raw)
                continue
            }
            // Felhasználónév/jelszó fájl: soha nem kerül a configba. Ha a mappán belüli, legfeljebb 1 KB-os, pontosan
            // két soros fájl, a tartalma a Keychainbe megy (a hívó tárolja); a sor `auth-user-pass` lesz.
            if first == "auth-user-pass" {
                let path = tokens[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                if let lines = readCredentialLines(path, base: base), lines.count == 2, !lines[0].isEmpty {
                    credentials.username = lines[0]
                    credentials.password = lines[1]
                    credentials.credentialsFile = path
                } else {
                    credentials.unreadFiles.append(path)
                }
                out.append("auth-user-pass")
                continue
            }
            // Kulcsjelszó fájl: az első sora a „Privát kulcs jelszava” (Keychain); a sor `askpass` lesz (a MacVPN a
            // saját --askpass fájlját adja át).
            if first == "askpass" {
                let path = tokens[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                if let lines = readCredentialLines(path, base: base), !lines[0].isEmpty {
                    credentials.keyPassword = lines[0]
                    credentials.keyPasswordFile = path
                } else {
                    credentials.unreadFiles.append(path)
                }
                out.append("askpass")
                continue
            }
            if first == "pkcs12" {
                let path = tokens[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                let data = try readInlineData(path, base: base)
                guard isPKCS12(data) else { throw ConfigImportError.wrongFormat(directive: first, file: path) }
                out.append("<pkcs12>")
                out.append(contentsOf: base64Lines(data))
                out.append("</pkcs12>")
                inlined.append(path)
                continue
            }
            guard let format = expectedFormat[first], !(first == "dh" && tokens[1] == "none") else {
                out.append(raw)
                continue
            }
            let path = tokens[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let data = try readInlineFile(path, base: base, directive: first)
            guard hasFormat(data, pemType: format) else { throw ConfigImportError.wrongFormat(directive: first, file: path) }
            out.append("<\(first)>")
            out.append(data.hasSuffix("\n") ? String(data.dropLast()) : data)
            out.append("</\(first)>")
            inlined.append(path)
            if (first == "tls-auth" || first == "secret"), tokens.count >= 3 { out.append("key-direction \(tokens[2])") }
        }
        return InlineResult(config: out.joined(separator: "\n"), inlinedFiles: inlined, credentials: credentials)
    }

    static func realPath(_ path: String) -> String? {
        guard let p = realpath(path, nil) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }

    /// A `path` (relatív a `base`-hez, vagy abszolút) feloldása és beolvasása. A feloldott útvonalat O_NOFOLLOW-val
    /// nyitja, és a megnyitott fájlt ellenőrzi (szabályos fájl, méret), így a vizsgálat és az olvasás ugyanarra vonatkozik.
    static func readInlineFile(_ path: String, base: String, directive: String) throws -> String {
        guard let text = String(data: try readInlineData(path, base: base), encoding: .utf8) else {
            throw ConfigImportError.wrongFormat(directive: directive, file: path)
        }
        return text
    }

    /// Mint a `readInlineFile`, de nyers bájtokat ad (PKCS#12).
    static func readInlineData(_ path: String, base: String) throws -> Data {
        let joined = path.hasPrefix("/") ? path : base + "/" + path
        guard let resolved = realPath(joined) else {
            // Nem létezik: ha már szövegesen is kifelé mutat, azt jelezzük.
            throw lexicallyEscapes(path) ? ConfigImportError.outsideBaseDirectory(path) : ConfigImportError.missingFile(path)
        }
        guard resolved.hasPrefix(base.hasSuffix("/") ? base : base + "/") else {
            throw ConfigImportError.outsideBaseDirectory(path)
        }
        let fd = open(resolved, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw ConfigImportError.missingFile(path) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw ConfigImportError.missingFile(path) }
        guard st.st_size <= maxInlineFileSize else { throw ConfigImportError.fileTooLarge(path) }
        let data = (try? handle.read(upToCount: maxInlineFileSize + 1)) ?? Data()
        guard data.count <= maxInlineFileSize else { throw ConfigImportError.fileTooLarge(path) }
        return data
    }

    /// DER kódolású PKCS#12 (PFX): `SEQUENCE` (rövid, hosszú vagy határozatlan hosszal), utána `INTEGER 3` (a verzió).
    /// Csak formátum-felismerés: a tartalmat nem nyitja meg (a jelszó itt nem kell), a kulcskarikába nem importál.
    static func isPKCS12(_ data: Data) -> Bool {
        let b = [UInt8](data.prefix(8))
        guard data.count >= 32, b.count == 8, b[0] == 0x30 else { return false }
        let lengthBytes: Int
        switch b[1] {
        case 0x00..<0x80: lengthBytes = 0
        case 0x80: lengthBytes = 0                 // határozatlan hossz (BER)
        case 0x81...0x84: lengthBytes = Int(b[1] - 0x80)
        default: return false
        }
        let v = 2 + lengthBytes
        guard v + 2 < b.count else { return false }
        return b[v] == 0x02 && b[v + 1] == 0x01 && b[v + 2] == 0x03
    }

    /// Base64, 64 karakteres sorokra bontva (az OpenVPN inline `<pkcs12>` formája).
    static func base64Lines(_ data: Data) -> [String] {
        let encoded = data.base64EncodedString()
        var lines: [String] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let end = encoded.index(index, offsetBy: 64, limitedBy: encoded.endIndex) ?? encoded.endIndex
            lines.append(String(encoded[index..<end]))
            index = end
        }
        return lines
    }

    /// Relatív útvonal, amely `..`-tal a kiinduló mappa fölé jut (az abszolút útvonalat a realpath ellenőrzi).
    static func lexicallyEscapes(_ path: String) -> Bool {
        guard !path.hasPrefix("/") else { return false }
        var depth = 0
        for part in path.split(separator: "/") {
            if part == ".." { depth -= 1 } else if part != "." { depth += 1 }
            if depth < 0 { return true }
        }
        return false
    }

    /// Van legalább egy teljes, a direktívának megfelelő PEM blokk; más típusú PEM blokk és `<`-vel kezdődő sor
    /// (inline tag, amely lezárhatná a blokkot) nincs benne.
    static func hasFormat(_ text: String, pemType: String) -> Bool {
        let block = "-----BEGIN (\(pemType))-----\\r?\\n(?:(?:[^-\\r\\n].*)?\\r?\\n)*?-----END \\1-----"
        guard text.range(of: block, options: .regularExpression) != nil else { return false }
        let begin = try! NSRegularExpression(pattern: "^-----BEGIN ([^-]+)-----", options: .anchorsMatchLines)
        let ns = text as NSString
        for m in begin.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let type = ns.substring(with: m.range(at: 1))
            if type.range(of: "^(?:\(pemType))$", options: .regularExpression) == nil { return false }
        }
        return text.range(of: "(?m)^\\s*<", options: .regularExpression) == nil
    }

    public static func template(for kind: VPNKind) -> String {
        switch kind {
        case .openvpn:
            return """
            client
            dev tun
            proto udp
            remote vpn.example.com 1194
            nobind
            persist-key
            persist-tun
            remote-cert-tls server
            auth-user-pass
            <ca>
            </ca>

            """
        case .wireguard:
            return """
            [Interface]
            PrivateKey =
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey =
            AllowedIPs = 0.0.0.0/0
            Endpoint = vpn.example.com:51820

            """
        case .strongswan:
            return """
            connections {
              myvpn {
                remote_addrs = vpn.example.com
                vips = 0.0.0.0
                local {
                  auth = eap-mschapv2
                  eap_id = felhasznalo
                }
                remote {
                  auth = pubkey
                  id = vpn.example.com
                }
                children {
                  myvpn {
                    remote_ts = 0.0.0.0/0
                  }
                }
              }
            }

            """
        case .sstp:
            return SSTPConfig(server: "vpn.example.com").serialized()
        case .l2tp, .cisco:
            return ""
        }
    }
}
