import Foundation

// BIZTONSÁGI RÉTEG: ezek a validátorok akadályozzák meg, hogy egy config rootként parancsot futtasson.
// Ez a szabályok egyetlen forrása: rootként a `mvpn-validate` bináris (Sources/mvpn-validate) futtatja
// ugyanezt a kódot a `Resources/root/mvpn` számára, az app pedig a szerkesztőben gyors visszajelzésre.
// A hibaüzenetek soha nem idéznek nyers config-tartalmat: csak sorszámot, szabályszöveget és szigorú
// karakterkészleten (`[A-Za-z0-9-]`, setenv névnél `[A-Za-z0-9_]`) átment direktíva-/kulcsnevet.
// A szabályok szándékosan bájt-orientáltak: ASCII karakterkészletek, nincs Unicode-trükk.
//
// Közös szabály: soronként egy záró `\r` levágása, majd ha a (nyers, komment-eltávolítás előtti) sor
// vezérlőkaraktert tartalmaz (0x00-0x1F a TAB kivételével, vagy 0x7F), az hiba. OpenVPN inline blokkon belül is.

public protocol ConfigValidator {
    func validate(_ text: String) -> [ValidationIssue]
}

public enum Validators {
    public static func validator(for kind: VPNKind) -> ConfigValidator? {
        switch kind {
        case .openvpn: return OpenVPNValidator()
        case .wireguard: return WireGuardValidator()
        case .strongswan: return StrongSwanValidator()
        case .l2tp, .cisco: return nil
        }
    }
}

var controlCharacterMessage: String { L10n.tr("Control character not allowed") }
private let spaceTab = CharacterSet(charactersIn: " \t")

/// Soronként, egy záró CR levágva, 1-től számozva. A sor többi része érintetlen.
func numberedLines(_ text: String) -> [(Int, String)] {
    text.components(separatedBy: "\n").enumerated().map { index, raw in
        (index + 1, raw.hasSuffix("\r") ? String(raw.dropLast()) : raw)
    }
}

/// Csak szóköz és tab vágódik le (nem Unicode whitespace).
func trimSpaceTab(_ s: String) -> String { s.trimmingCharacters(in: spaceTab) }

/// Csak A-Z -> a-z, Unicode-os kisbetűsítés nélkül.
func asciiLowercased(_ s: String) -> String {
    String(decoding: s.utf8.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 }, as: UTF8.self)
}

/// 0x00-0x1F (TAB kivételével) vagy 0x7F.
func hasControlCharacter(_ s: String) -> Bool {
    s.utf8.contains { ($0 < 0x20 && $0 != 0x09) || $0 == 0x7F }
}

func matches(_ s: String, _ pattern: String) -> Bool {
    s.range(of: pattern, options: .regularExpression) != nil
}

/// Allowlist alapú. Rootként a `mvpn-validate` futtatja.
///
/// Szabályok sorrendben, soronként:
/// 1. vezérlőkarakter -> hiba (blokkon belül is);
/// 2. blokkon belül: a trimmelt sor `</`-val kezdődik -> a blokk lezárul, és ha nem pontosan `</tag>` (kisbetűsítve), "Hibás záró tag"; egyéb sor kihagyva;
/// 3. üres, `#` vagy `;` kezdetű sor kihagyva;
/// 4. `^<[A-Za-z0-9-]+>$` nyitó tag: csak `allowedBlocks`-beli lehet, különben "Nem engedélyezett inline blokk" (de blokként kezelve, tartalma kihagyva);
/// 5. direktíva = első token (szóköz/tab szerint), egyezzen `^(--)?[A-Za-z0-9-]+$`-val, különben "Érvénytelen direktíva"; kisbetűsítés, `--` levágása;
/// 6. `forbidden` -> "Tiltott direktíva"; ami nincs az `allowed`-ben -> "Nem engedélyezett direktíva";
/// 6b. `setenv` külön: `setenv opt <direktíva> ...` -> a <direktíva> ugyanezen az ellenőrzésen megy át (1.-7. lépés); `setenv NAME ...`
///     -> NAME egyezzen `^(FORWARD_COMPATIBLE|PUSH_PEER_INFO|CLIENT_CERT|UV_[A-Z0-9_]+|IV_[A-Z0-9_]+)$` (kis/nagybetű érzékeny), különben
///     "Nem engedélyezett setenv" (a név csak akkor szerepel az üzenetben, ha `^[A-Za-z0-9_]+$`); `setenv` argumentum nélkül, vagy `setenv opt` direktíva nélkül -> hiba;
/// 7. `fileReferencing` direktíva, ha van argumentuma és az nem `[inline]` -> hiba; `http-proxy`: ha van 4. token és nem `auto`/`auto-nct`/`[inline]` -> hiba;
///    `socks-proxy`: ha van 4. token (authfile) és nem `[inline]` -> hiba. (Az `allowed` lista többi direktívájának nincs fájl-argumentuma.)
/// 8. fájl végén nyitott blokk -> "Lezáratlan inline blokk"; `remote` hiánya -> 0. soros hiba.
public struct OpenVPNValidator: ConfigValidator {
    public static let forbidden: Set<String> = [
        "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify",
        "client-connect", "client-disconnect", "learn-address", "plugin", "script-security", "config",
        "cd", "chroot", "daemon", "log", "log-append", "writepid", "management", "status",
        "iproute", "ifconfig-noexec", "route-noexec", "user", "group",
        "pkcs11-providers", "providers", "engine", "dns-updown", "tls-export-cert", "tmp-dir",
        "tls-crypt-v2-verify",
    ]
    public static let fileReferencing: Set<String> = [
        "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "secret",
        "extra-certs", "dh", "crl-verify", "askpass", "auth-user-pass",
    ]
    public static let allowed: Set<String> = [
        "client", "tls-client", "pull", "dev", "dev-type", "proto", "remote", "port", "rport", "lport",
        "remote-random", "resolv-retry", "nobind", "bind", "float", "persist-key", "persist-tun",
        "persist-remote-ip", "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout",
        "explicit-exit-notify", "remote-cert-tls", "remote-cert-ku", "remote-cert-eku", "ns-cert-type",
        "verify-x509-name", "peer-fingerprint", "ca", "cert", "key", "extra-certs", "dh", "pkcs12", "secret",
        "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "auth-user-pass", "auth-nocache",
        "auth-retry", "auth-token", "static-challenge", "cipher", "ciphers", "data-ciphers",
        "data-ciphers-fallback", "ncp-ciphers", "ncp-disable", "auth", "tls-version-min", "tls-version-max",
        "tls-cipher", "tls-ciphersuites", "tls-groups", "tls-timeout", "hand-window", "reneg-sec",
        "reneg-bytes", "reneg-pkts", "comp-lzo", "compress", "allow-compression", "verb", "mute",
        "mute-replay-warnings", "replay-window", "keepalive", "ping", "ping-restart", "ping-exit", "inactive",
        "redirect-gateway", "redirect-private", "route", "route-ipv6", "route-gateway", "route-metric",
        "route-delay", "route-nopull", "pull-filter", "dhcp-option", "block-ipv6", "ifconfig",
        "ifconfig-ipv6", "topology", "tun-mtu", "tun-mtu-extra", "link-mtu", "mssfix", "fragment",
        "mtu-disc", "tun-ipv6", "sndbuf", "rcvbuf", "fast-io", "txqueuelen", "push-peer-info",
        "setenv-safe", "ignore-unknown-option", "single-session", "http-proxy-retry", "socks-proxy",
        "disable-occ", "opt-verify", "remote-random-hostname", "machine-readable-output",
        "suppress-timestamps", "mark",
        "ping-timer-rem", "crl-verify", "block-outside-dns", "http-proxy", "auth-token-user",
        "tls-cert-profile", "ifconfig-nowarn", "route-method",
    ]
    public static let allowedBlocks: Set<String> = [
        "ca", "cert", "key", "extra-certs", "dh", "pkcs12", "secret", "tls-auth", "tls-crypt",
        "tls-crypt-v2", "peer-fingerprint", "auth-user-pass", "crl-verify", "http-proxy-user-pass",
    ]
    static let setenvNamePattern = "^(FORWARD_COMPATIBLE|PUSH_PEER_INFO|CLIENT_CERT|UV_[A-Z0-9_]+|IV_[A-Z0-9_]+)$"
    static var hint: String { L10n.tr(" – delete the line or comment it out (#)") }

    public init() {}

    public func validate(_ text: String) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        var inBlock: String?
        var blockLine = 0
        var hasRemote = false
        for (lineNo, rawLine) in numberedLines(text) {
            if hasControlCharacter(rawLine) {
                issues.append(ValidationIssue(line: lineNo, message: controlCharacterMessage))
                continue
            }
            let line = trimSpaceTab(rawLine)
            if let block = inBlock {
                if line.hasPrefix("</") {
                    if asciiLowercased(line) != "</\(block)>" {
                        issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid closing tag")))
                    }
                    inBlock = nil
                }
                continue
            }
            if matches(line, "^<[A-Za-z0-9-]+>$") {
                let name = asciiLowercased(String(line.dropFirst().dropLast()))
                if !Self.allowedBlocks.contains(name) {
                    issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Inline block not allowed: %@", name)))
                }
                inBlock = name
                blockLine = lineNo
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            let (messages, directive) = Self.checkDirective(tokens)
            for m in messages { issues.append(ValidationIssue(line: lineNo, message: m)) }
            if directive == "remote", messages.isEmpty { hasRemote = true }
        }
        if let block = inBlock {
            issues.append(ValidationIssue(line: blockLine, message: L10n.tr("Unclosed inline block: %@", block)))
        }
        if !hasRemote { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing remote directive"))) }
        return issues
    }

    /// Egy direktíva-sor (tokenekre bontva) ellenőrzése; a `setenv opt <direktíva> ...` is ezen megy át.
    /// Visszaadja a hibaüzeneteket és a (kisbetűs, `--` nélküli) direktívanevet, ha érvényes volt.
    static func checkDirective(_ tokens: [String]) -> (messages: [String], directive: String?) {
        guard matches(tokens[0], "^(--)?[A-Za-z0-9-]+$") else { return ([L10n.tr("Invalid directive")], nil) }
        var directive = asciiLowercased(tokens[0])
        if directive.hasPrefix("--") { directive.removeFirst(2) }
        if directive == "setenv" {
            guard tokens.count >= 2 else { return ([L10n.tr("setenv: missing argument")], directive) }
            if asciiLowercased(tokens[1]) == "opt" {
                guard tokens.count >= 3 else { return ([L10n.tr("setenv opt: missing directive")], directive) }
                return (checkDirective(Array(tokens.dropFirst(2))).messages, directive)
            }
            if !matches(tokens[1], setenvNamePattern) {
                let message = matches(tokens[1], "^[A-Za-z0-9_]+$")
                    ? L10n.tr("setenv not allowed: %@", tokens[1]) : L10n.tr("setenv not allowed")
                return ([message + hint], directive)
            }
            return ([], directive)
        }
        if forbidden.contains(directive) { return ([L10n.tr("Forbidden directive: %@", directive) + hint], directive) }
        if !allowed.contains(directive) { return ([L10n.tr("Directive not allowed: %@", directive) + hint], directive) }
        var messages: [String] = []
        if fileReferencing.contains(directive), tokens.count >= 2, tokens[1] != "[inline]" {
            messages.append(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        if directive == "http-proxy", tokens.count >= 4, !["auto", "auto-nct", "[inline]"].contains(tokens[3]) {
            messages.append(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        if directive == "socks-proxy", tokens.count >= 4, tokens[3] != "[inline]" {
            messages.append(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        return (messages, directive)
    }
}

/// Allowlist alapú. Rootként a `mvpn-validate` futtatja.
///
/// Soronként: vezérlőkarakter -> hiba; a `#`-tól kezdődő komment levágva, trimmelve, üres kihagyva;
/// `[...]` fejléc: csak `[interface]`/`[peer]` (kisbetűsítve), különben "Ismeretlen szakasz";
/// egyéb sor `=` nélkül -> hiba; kulcs = az első `=` előtti rész, szóköz/tab trimmelve, kisbetűsítve,
/// egyezzen `^[A-Za-z]+$`-val (különben általános "Nem engedélyezett kulcs", a kulcs idézése nélkül); `forbiddenKeys` -> "Tiltott kulcs"; ami nincs a szakasz allowlistjében
/// (szakaszon kívül sincs) -> "Nem engedélyezett kulcs".
public struct WireGuardValidator: ConfigValidator {
    public static let forbiddenKeys: Set<String> = ["preup", "postup", "predown", "postdown", "saveconfig"]
    public static let interfaceKeys: Set<String> = ["privatekey", "listenport", "fwmark", "address", "dns", "mtu", "table"]
    public static let peerKeys: Set<String> = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]

    public init() {}

    public func validate(_ text: String) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        var section = ""
        var interfaceCount = 0, peerCount = 0
        var hasPrivateKey = false, hasPeerKey = false
        for (lineNo, rawLine) in numberedLines(text) {
            if hasControlCharacter(rawLine) {
                issues.append(ValidationIssue(line: lineNo, message: controlCharacterMessage))
                continue
            }
            let line = trimSpaceTab(rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
                .first.map(String.init) ?? "")
            if line.isEmpty { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                let header = asciiLowercased(line)
                if header == "[interface]" {
                    interfaceCount += 1
                    section = header
                } else if header == "[peer]" {
                    peerCount += 1
                    section = header
                } else {
                    section = ""
                    issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Unknown section")))
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid line")))
                continue
            }
            let rawKey = trimSpaceTab(String(line[..<eq]))
            guard matches(rawKey, "^[A-Za-z]+$") else {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Key not allowed")))
                continue
            }
            let key = asciiLowercased(rawKey)
            if Self.forbiddenKeys.contains(key) {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Forbidden key: %@", key)))
                continue
            }
            let ok = (section == "[interface]" && Self.interfaceKeys.contains(key))
                || (section == "[peer]" && Self.peerKeys.contains(key))
            if !ok {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Key not allowed: %@", key)))
                continue
            }
            if section == "[interface]", key == "privatekey" { hasPrivateKey = true }
            if section == "[peer]", key == "publickey" { hasPeerKey = true }
        }
        if interfaceCount != 1 { issues.append(ValidationIssue(line: 0, message: L10n.tr("Exactly one [Interface] section is required"))) }
        if !hasPrivateKey && interfaceCount == 1 { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing PrivateKey"))) }
        if peerCount < 1 || !hasPeerKey { issues.append(ValidationIssue(line: 0, message: L10n.tr("At least one [Peer] with a PublicKey is required"))) }
        return issues
    }
}

/// Rootként a `mvpn-validate` futtatja (validálás és `--swan-names`).
///
/// Soronként: vezérlőkarakter -> hiba; bármilyen `\` (0x5C) -> "Nem engedélyezett karakter: \\";
/// páratlan számú `"` a sorban -> "Páratlan idézőjel (többsoros string nem engedélyezett)" (mindegyik után a sor további ellenőrzése kimarad);
/// komment levágása idézőjel-tudatosan (`#` csak `"`-on kívül kezd kommentet, escape nincs); trimmelt üres sor kihagyva;
/// a `"..."` részek `""`-ra cserélve; a maradék felbontva szóköz, tab, `{`, `}`, `=` mentén; bármelyik szó (kisbetűsítve)
/// `include` -> "Tiltott: include", `updown` vagy `file` -> "Tiltott kulcs: X".
/// Soronként egy üzenet legfeljebb egyszer jelenik meg. `^connections[ \t]*\{` és `^children[ \t]*\{` kötelező.
public struct StrongSwanValidator: ConfigValidator {
    public init() {}

    public func validate(_ text: String) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        var hasConnections = false, hasChildren = false
        for (lineNo, rawLine) in numberedLines(text) {
            if hasControlCharacter(rawLine) {
                issues.append(ValidationIssue(line: lineNo, message: controlCharacterMessage))
                continue
            }
            if rawLine.utf8.contains(0x5C) {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Character not allowed: \\")))
                continue
            }
            if rawLine.utf8.filter({ $0 == 0x22 }).count % 2 != 0 {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Unbalanced quote (multi-line strings are not allowed)")))
                continue
            }
            let line = Self.stripComment(rawLine)
            if line.isEmpty { continue }
            if matches(line, "^connections[ \\t]*\\{") { hasConnections = true }
            if matches(line, "^children[ \\t]*\\{") { hasChildren = true }
            var messages: [String] = []
            let unquoted = Self.removeQuoted(line)
            for word in unquoted.components(separatedBy: CharacterSet(charactersIn: " \t{}=")) {
                let w = asciiLowercased(word)
                if w == "include" { messages.append(L10n.tr("Forbidden: include")) }
                if w == "updown" || w == "file" { messages.append(L10n.tr("Forbidden key: %@", w)) }
            }
            var seen = Set<String>()
            for m in messages where seen.insert(m).inserted {
                issues.append(ValidationIssue(line: lineNo, message: m))
            }
        }
        if !hasConnections { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing connections block"))) }
        if !hasChildren { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing children block"))) }
        return issues
    }

    /// Az első connection és az első child neve (a `swanctl --initiate --child` paraméteréhez).
    public static func names(in text: String) -> (connection: String, child: String)? {
        var inConnections = false, inChildren = false
        var connection: String?, child: String?
        let header = try! NSRegularExpression(pattern: "^([A-Za-z0-9_.-]+)[ \\t]*\\{")
        for (_, rawLine) in numberedLines(text) {
            let line = stripComment(rawLine)
            if matches(line, "^connections[ \\t]*\\{") { inConnections = true; continue }
            if matches(line, "^children[ \\t]*\\{") { inChildren = true; continue }
            let ns = line as NSString
            guard let m = header.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) else { continue }
            let name = ns.substring(with: m.range(at: 1))
            if inConnections, connection == nil { connection = name }
            if inChildren, child == nil { child = name }
        }
        guard let c = connection, let ch = child else { return nil }
        return (c, ch)
    }

    /// `#` csak idézőjelen (`"`) kívül kezd kommentet. Escape-kezelés nincs.
    static func stripComment(_ line: String) -> String {
        var inQuote = false
        var out: [UInt8] = []
        for byte in line.utf8 {
            if byte == 0x22 { inQuote.toggle() }
            if byte == 0x23, !inQuote { break }
            out.append(byte)
        }
        return trimSpaceTab(String(decoding: out, as: UTF8.self))
    }

    /// A `"..."` részeket `""`-ra cseréli (a sorban páros számú idézőjel van).
    static func removeQuoted(_ line: String) -> String {
        var inQuote = false
        var out: [UInt8] = []
        for byte in line.utf8 {
            if byte == 0x22 {
                inQuote.toggle()
                out.append(byte)
            } else if !inQuote {
                out.append(byte)
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}
