import Foundation

/// SSTP kapcsolat configja (`config` fájl, export/import `.sstp`). `kulcs=érték` soronként, opcionális
/// `<ca>…</ca>` PEM blokkal. Jelszó soha nincs benne (Keychain, a `mvpn` stdin-en kapja).
///
/// ```
/// server=vpn.example.com
/// port=443
/// user=alice
/// cert=system            # system | ca | insecure
/// route_all=yes          # yes | no
/// peer_dns=yes           # yes | no
/// <ca>
/// -----BEGIN CERTIFICATE-----
/// …
/// -----END CERTIFICATE-----
/// </ca>
/// ```
public struct SSTPConfig: Equatable, Sendable {
    public enum CertMode: String, CaseIterable, Sendable {
        /// A sstpc alapértelmezett CA-tára (a Homebrew OpenSSL / ca-certificates csomag).
        case system
        /// Saját CA PEM, a configban inline (`<ca>` blokk) tárolva.
        case ca
        /// Tanúsítvány-ellenőrzés nélkül (`sstpc --cert-warn`).
        case insecure
    }

    public static let defaultPort = 443

    public var server: String
    public var port: Int
    public var user: String
    public var cert: CertMode
    public var routeAll: Bool
    public var peerDNS: Bool
    /// PEM szöveg (`-----BEGIN CERTIFICATE-----` … ), sorvégi `\n` nélkül. Csak `cert == .ca` mellett kerül a configba.
    public var caPEM: String

    public init(server: String = "", port: Int = SSTPConfig.defaultPort, user: String = "", cert: CertMode = .system,
                routeAll: Bool = true, peerDNS: Bool = true, caPEM: String = "") {
        self.server = server
        self.port = port
        self.user = user
        self.cert = cert
        self.routeAll = routeAll
        self.peerDNS = peerDNS
        self.caPEM = caPEM
    }

    /// Engedékeny beolvasás az űrlaphoz: ismeretlen vagy hibás sorokat kihagy (a mentéskor a validátor dönt).
    public static func parse(_ text: String) -> SSTPConfig {
        var c = SSTPConfig()
        var inCA = false
        var ca: [String] = []
        for (_, line) in numberedLines(text) {
            let trimmed = trimSpaceTab(line)
            if inCA {
                if trimmed == "</ca>" { inCA = false } else { ca.append(trimmed) }
                continue
            }
            if trimmed == "<ca>" { inCA = true; continue }
            guard !trimmed.hasPrefix("#"), let eq = trimmed.firstIndex(of: "=") else { continue }
            let key = asciiLowercased(trimSpaceTab(String(trimmed[..<eq])))
            let value = trimSpaceTab(String(trimmed[trimmed.index(after: eq)...]))
            switch key {
            case "server": c.server = value
            case "port": c.port = Int(value) ?? defaultPort
            case "user": c.user = value
            case "cert": c.cert = CertMode(rawValue: value) ?? .system
            case "route_all": c.routeAll = value != "no"
            case "peer_dns": c.peerDNS = value != "no"
            default: break
            }
        }
        c.caPEM = ca.joined(separator: "\n").trimmingCharacters(in: .newlines)
        return c
    }

    /// A config szövege. A `<ca>` blokk csak `cert == .ca` mellett kerül bele.
    public func serialized() -> String {
        var lines = [
            "server=\(server)",
            "port=\(port)",
            "user=\(user)",
            "cert=\(cert.rawValue)",
            "route_all=\(routeAll ? "yes" : "no")",
            "peer_dns=\(peerDNS ? "yes" : "no")",
        ]
        let pem = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        if cert == .ca, !pem.isEmpty {
            lines.append("<ca>")
            lines.append(pem)
            lines.append("</ca>")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// A fájl összes `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----` blokkja (a köztük lévő szöveg,
    /// pl. `subject=` sorok nélkül), a sorvégi szóközök és CR levágva. Nil, ha nincs benne tanúsítvány, vagy
    /// a blokkokban nem PEM karakter van.
    public static func extractCertificates(from text: String) -> String? {
        var blocks: [String] = []
        var current: [String]?
        for (_, raw) in numberedLines(text) {
            let line = trimSpaceTab(raw)
            if line == "-----BEGIN CERTIFICATE-----" { current = [line]; continue }
            guard current != nil else { continue }
            guard matches(line, SSTPValidator.pemLinePattern) else { return nil }
            current?.append(line)
            if line == "-----END CERTIFICATE-----" {
                blocks.append(current!.joined(separator: "\n"))
                current = nil
            }
        }
        return blocks.isEmpty ? nil : blocks.joined(separator: "\n")
    }

    /// A PEM szövegben lévő tanúsítványok száma.
    public static func certificateCount(in pem: String) -> Int {
        pem.components(separatedBy: "-----BEGIN CERTIFICATE-----").count - 1
    }

    /// Elfogadható-e az SSTP jelszó. A brew sstpc a jelszót escape nélkül írja a pppd opciófájljába
    /// (`password "%s"`), amit a pppd rootként olvas: egy `"`, `\` vagy vezérlőkarakter (sorvége is) pppd opciót
    /// injektálhatna. Ezeket nem escape-eljük, hanem elutasítjuk (a `mvpn` ugyanígy, a root oldalon is).
    /// Az üres jelszó itt elfogadható (mentéskor nem kötelező; csatlakozáskor a `mvpn` kéri).
    public static func isAcceptablePassword(_ s: String) -> Bool {
        !s.unicodeScalars.contains { $0 == "\"" || $0 == "\\" || $0.value < 0x20 || $0.value == 0x7F || (0x80...0x9F).contains($0.value) }
    }

    /// A jelszó-szabály üzenete (a `mvpn` ugyanezt írja ki angolul/magyarul).
    public static var passwordRuleMessage: String {
        L10n.tr("The SSTP password must not contain quotation marks, backslashes or control characters")
    }
}

/// Allowlist alapú. Rootként a `mvpn-validate sstp` futtatja (és a `--sstp-params` / `--sstp-ca` előtt is).
///
/// Soronként (egy záró CR levágva): vezérlőkarakter (TAB kivételével) -> hiba; bármilyen `\` -> hiba.
/// `<ca>` blokkon belül: a trimmelt `</ca>` zárja; minden más sor csak PEM karakter lehet (`[A-Za-z0-9+/= -]`).
/// Blokkon kívül: üres vagy `#` kezdetű sor kihagyva; a trimmelt `<ca>` nyit (legfeljebb egyszer); egyéb sor
/// `kulcs=érték`, a kulcs csak `[a-z_]` lehet és az `allowedKeys`-ben kell lennie, egy kulcs legfeljebb egyszer.
/// Értékek: `server` hosztnév / IPv4 / IPv6 (legfeljebb 253 karakter, nem kezdődhet `-`-vel); `port` 1–65535;
/// `user` `[A-Za-z0-9._@+-]`, 1–128 karakter, nem kezdődhet `-`-vel; `cert` `system|ca|insecure`;
/// `route_all`, `peer_dns` `yes|no`. Kötelező: `server`, `user`; `cert=ca` mellett nem üres `<ca>` blokk
/// legalább egy tanúsítvánnyal. Az üzenetek soha nem idézik az értéket, csak a (szigorú karakterkészletű) kulcsnevet.
public struct SSTPValidator: ConfigValidator {
    public static let allowedKeys: [String] = ["server", "port", "user", "cert", "route_all", "peer_dns"]
    static let hostnamePattern = "^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\\.?$"
    static let userPattern = "^[A-Za-z0-9._@+][A-Za-z0-9._@+-]{0,127}$"
    static let pemLinePattern = "^[A-Za-z0-9+/= -]*$"

    public init() {}

    public static func isValidServer(_ s: String) -> Bool {
        guard !s.isEmpty, s.utf8.count <= 253 else { return false }
        // A nem meghatározott és a loopback cím nem lehet SSTP szerver (a /1 útvonalak és a szerver-útvonal miatt sem).
        if isIPv4(s) { return s != "0.0.0.0" && !s.hasPrefix("127.") }
        if s.contains(":") { return isIPv6(s) && !isUnspecifiedOrLoopbackIPv6(s) }
        if asciiLowercased(s).trimmingCharacters(in: CharacterSet(charactersIn: ".")) == "localhost" { return false }
        // Csupa számjegyből és pontból álló, de nem érvényes IPv4 (pl. 1.2.3 vagy 999.1.1.1): hiba.
        if matches(s, "^[0-9.]+$") { return false }
        return matches(s, hostnamePattern)
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in matches(String(p), "^[0-9]{1,3}$") && Int(p)! <= 255 }
    }

    static func isIPv6(_ s: String) -> Bool {
        guard matches(s, "^[0-9A-Fa-f:]+$"), s.utf8.count <= 39, s.contains(":") else { return false }
        var addr = in6_addr()
        return inet_pton(AF_INET6, s, &addr) == 1
    }

    static func isUnspecifiedOrLoopbackIPv6(_ s: String) -> Bool {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, s, &addr) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &addr) { Array($0) }
        return bytes.dropLast().allSatisfy { $0 == 0 } && (bytes.last == 0 || bytes.last == 1)
    }

    /// Csak pontokból álló vagy ponttal végződő név nem engedett.
    public static func isValidUser(_ s: String) -> Bool {
        matches(s, userPattern) && !s.hasSuffix(".") && !matches(s, "^\\.+$")
    }

    public static func isValidPort(_ s: String) -> Bool {
        guard matches(s, "^[0-9]{1,5}$"), let n = Int(s) else { return false }
        return (1...65535).contains(n)
    }

    public func validate(_ text: String) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        var seen = Set<String>()
        var values: [String: String] = [:]
        var inCA = false, caLine = 0, caCount = 0
        var caText: [String] = []
        for (lineNo, rawLine) in numberedLines(text) {
            if hasControlCharacter(rawLine) {
                issues.append(ValidationIssue(line: lineNo, message: controlCharacterMessage))
                continue
            }
            if rawLine.utf8.contains(0x5C) {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Character not allowed: \\")))
                continue
            }
            let line = trimSpaceTab(rawLine)
            if inCA {
                if line == "</ca>" {
                    inCA = false
                } else if matches(line, Self.pemLinePattern) {
                    caText.append(line)
                } else {
                    issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid line in the CA certificate block")))
                }
                continue
            }
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line == "<ca>" {
                caCount += 1
                if caCount > 1 { issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Only one <ca> block is allowed"))) }
                inCA = true
                caLine = lineNo
                continue
            }
            guard let eq = line.firstIndex(of: "=") else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid line")))
                continue
            }
            let key = trimSpaceTab(String(line[..<eq]))
            let value = trimSpaceTab(String(line[line.index(after: eq)...]))
            guard matches(key, "^[a-z_]+$") else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Key not allowed")))
                continue
            }
            guard Self.allowedKeys.contains(key) else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Key not allowed: %@", key)))
                continue
            }
            guard seen.insert(key).inserted else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Duplicate key: %@", key)))
                continue
            }
            if let message = Self.check(key: key, value: value) {
                issues.append(ValidationIssue(line: lineNo, message: message))
                continue
            }
            values[key] = value
        }
        if inCA { issues.append(ValidationIssue(line: caLine, message: L10n.tr("Unclosed inline block: %@", "ca"))) }
        if !seen.contains("server") { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing key: %@", "server"))) }
        if !seen.contains("user") { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing key: %@", "user"))) }
        if values["cert"] == "ca" {
            let pem = caText.joined(separator: "\n")
            if !pem.contains("-----BEGIN CERTIFICATE-----") || !pem.contains("-----END CERTIFICATE-----") {
                issues.append(ValidationIssue(line: 0, message: L10n.tr("cert=ca requires a <ca> block with a PEM certificate")))
            }
        }
        return issues
    }

    /// Egy érték ellenőrzése; nil = rendben. Az üzenet az értéket nem idézi.
    static func check(key: String, value: String) -> String? {
        switch key {
        case "server":
            return isValidServer(value) ? nil : L10n.tr("Invalid server: use a host name or an IPv4/IPv6 address, without a port")
        case "port":
            return isValidPort(value) ? nil : L10n.tr("Invalid port: 1–65535")
        case "user":
            return isValidUser(value) ? nil
                : L10n.tr("Invalid user name: letters, digits and . _ @ + - only (use user@domain instead of DOMAIN\\user)")
        case "cert":
            return SSTPConfig.CertMode(rawValue: value) != nil ? nil : L10n.tr("Invalid value for %@: allowed: %@", key, "system, ca, insecure")
        case "route_all", "peer_dns":
            return value == "yes" || value == "no" ? nil : L10n.tr("Invalid value for %@: allowed: %@", key, "yes, no")
        default:
            return L10n.tr("Key not allowed: %@", key)
        }
    }

    /// A root oldalnak: a validált, normalizált paraméterek (`mvpn-validate --sstp-params`), soronként:
    /// server, port, user, cert, route_all, peer_dns. Nil, ha a config hibás.
    public static func parameters(in text: String) -> [String]? {
        guard SSTPValidator().validate(text).isEmpty else { return nil }
        let c = SSTPConfig.parse(text)
        return [c.server, String(c.port), c.user, c.cert.rawValue, c.routeAll ? "yes" : "no", c.peerDNS ? "yes" : "no"]
    }

    /// A `<ca>` blokk PEM tartalma (`mvpn-validate --sstp-ca`). Nil, ha a config hibás vagy nincs `cert=ca`.
    public static func caPEM(in text: String) -> String? {
        guard SSTPValidator().validate(text).isEmpty else { return nil }
        let c = SSTPConfig.parse(text)
        guard c.cert == .ca, !c.caPEM.isEmpty else { return nil }
        return c.caPEM
    }
}
