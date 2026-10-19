import Foundation

// MFA (spec 10f): egyszer használatos kód a jelszó végén, OpenVPN statikus challenge (SCRV1), a kódbekérő
// időkorlátja, és a root oldali közvetítő (`mvpn-mgmt`) által írt, a felhasználónak olvasható állapotfájl.
// A kód soha nem kerül tárolásra (meta.json, Keychain) vagy naplóba: csak a memóriában él a csatlakozásig.

/// Elválasztó a jelszó és a kód között („Kód a jelszó végén”).
public enum OTPSeparator: String, Codable, CaseIterable, Sendable {
    case none, comma, colon

    public var string: String {
        switch self {
        case .none: return ""
        case .comma: return ","
        case .colon: return ":"
        }
    }
}

/// Kapcsolatonkénti beállítás: csatlakozáskor egyszer használatos kódot kér, és a jelszó végére fűzi.
/// A `meta.json`-ban `otp` kulcs alatt; hiányzó mező (régebbi fájl): kikapcsolva.
public struct OTPSetting: Codable, Hashable, Sendable {
    public var enabled: Bool
    public var separator: OTPSeparator

    public init(enabled: Bool = false, separator: OTPSeparator = .none) {
        self.enabled = enabled
        self.separator = separator
    }

    enum CodingKeys: String, CodingKey { case enabled, separator }

    /// Ismeretlen elválasztó (újabb verzió): nincs elválasztó.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        let raw = try c.decodeIfPresent(String.self, forKey: .separator) ?? ""
        separator = OTPSeparator(rawValue: raw) ?? .none
    }
}

/// OpenVPN `static-challenge "<szöveg>" <echo> [scrv1|concat]`.
public struct StaticChallenge: Equatable, Sendable {
    public enum Format: String, Sendable { case scrv1, concat }

    public let text: String
    public let echo: Bool
    public let format: Format

    public init(text: String, echo: Bool, format: Format = .scrv1) {
        self.text = text
        self.echo = echo
        self.format = format
    }
}

public enum MFAError: LocalizedError, Equatable {
    case invalidCode
    case sstpPassword
    case tooLong

    public var errorDescription: String? {
        switch self {
        case .invalidCode: return L10n.tr("The code must not be empty or contain line breaks or control characters (256 characters at most)")
        case .sstpPassword: return L10n.tr("The password with the code must not contain quotation marks, backslashes or control characters (SSTP)")
        case .tooLong: return L10n.tr("The password and the code together are too long")
        }
    }
}

public enum MFA {
    /// A kód (és a `mvpn respond` válasz) felső korlátja bájtban; a `mvpn` és a `mvpn-mgmt` ugyanezt ellenőrzi.
    public static let maxCodeBytes = 256
    /// A kódbekérő ablak időkorlátja.
    public static let codePromptTimeout: TimeInterval = 120
    /// A webes hitelesítés várakozási ideje (legfeljebb).
    public static let webAuthTimeout: TimeInterval = 300

    /// Nem üres, legfeljebb 256 bájt, nincs benne sortörés és vezérlőkarakter (C0, DEL, C1, U+2028/U+2029).
    public static func isValidCode(_ code: String, allowEmpty: Bool = false) -> Bool {
        if code.isEmpty { return allowEmpty }
        return code.utf8.count <= maxCodeBytes && !hasControl(code)
    }

    static func hasControl(_ s: String) -> Bool {
        s.unicodeScalars.contains {
            $0.value < 0x20 || (0x7F...0x9F).contains($0.value) || $0.value == 0x2028 || $0.value == 0x2029
        }
    }

    /// `SCRV1:<base64 jelszó>:<base64 kód>` (OpenVPN management-notes, „Static protocol”).
    public static func scrv1(password: String, code: String) -> String {
        "SCRV1:" + Data(password.utf8).base64EncodedString() + ":" + Data(code.utf8).base64EncodedString()
    }

    /// A statikus challenge jelszava a config formátuma szerint (`scrv1`: SCRV1, `concat`: jelszó + kód).
    public static func staticChallengePassword(password: String, code: String, format: StaticChallenge.Format) -> String {
        format == .concat ? password + code : scrv1(password: password, code: code)
    }

    /// Jelszó + elválasztó + kód. Üres jelszónál csak a kód (elválasztó nélkül).
    public static func appendCode(password: String, code: String, separator: OTPSeparator) -> String {
        password.isEmpty ? code : password + separator.string + code
    }

    /// A „kód a jelszó végén” beállítás alkalmazása típusonként: a root típusoknál (OpenVPN, strongSwan EAP, SSTP) a stdin
    /// jelszava, natív L2TP / Cisco IPsec és rendszer-VPN esetén a `SCNetworkConnection` opcióinak jelszava lesz az
    /// eredmény. Az SSTP jelszó-szabálya (nincs `"`, `\`, vezérlőkarakter) az összefűzött jelszóra is vonatkozik.
    public static func applyCode(_ code: String, separator: OTPSeparator, to secrets: Secrets, kind: VPNKind) throws -> Secrets {
        guard isValidCode(code) else { throw MFAError.invalidCode }
        var out = secrets
        let combined = appendCode(password: secrets.password ?? "", code: code, separator: separator)
        if kind == .sstp, !SSTPConfig.isAcceptablePassword(combined) { throw MFAError.sstpPassword }
        out.password = combined
        out.oneTimeCode = code
        return out
    }

    /// OpenVPN statikus challenge: a jelszó a config formátuma szerint csomagolva, és a `mvpn` jelzést kap
    /// (`challenge=packed`), hogy a közvetítő változatlanul adja át a management `password "Auth"` válaszban.
    public static func applyStaticChallenge(_ challenge: StaticChallenge, code: String, to secrets: Secrets) throws -> Secrets {
        guard isValidCode(code, allowEmpty: true) else { throw MFAError.invalidCode }
        var out = secrets
        let packed = staticChallengePassword(password: secrets.password ?? "", code: code, format: challenge.format)
        guard packed.utf8.count <= ManagementCommand.maxValueBytes else { throw MFAError.tooLong }
        out.password = packed
        out.challengePacked = true
        if !code.isEmpty { out.oneTimeCode = code }
        return out
    }

    /// A config `static-challenge` sora (a legfelső szinten, inline blokkon kívül; az utolsó érvényes). nil: nincs.
    /// A tokenizálás az OpenVPN `parse_line` tükre (`OpenVPNValidator.tokenize`).
    public static func staticChallenge(in config: String) -> StaticChallenge? {
        var found: StaticChallenge?
        var inBlock: String?
        for (_, raw) in numberedLines(config) {
            let line = trimSpaceTab(raw)
            if let block = inBlock {
                if asciiLowercased(line) == "</\(block)>" { inBlock = nil }
                continue
            }
            if matches(line, "^<[A-Za-z0-9-]+>$") {
                let name = asciiLowercased(String(line.dropFirst().dropLast()))
                // A <connection> blokk sorai connection-opciók; a static-challenge nem az, ezért kihagyjuk.
                inBlock = name
                continue
            }
            guard let tokens = OpenVPNValidator.tokenize(line), let head = tokens.first, !head.quoted,
                  OpenVPNValidator.directiveName(head.text) == "static-challenge",
                  (3...4).contains(tokens.count) else { continue }
            let text = tokens[1].text
            guard !text.isEmpty, !hasControl(text) else { continue }
            let echo: Bool
            switch tokens[2].text {
            case "0": echo = false
            case "1": echo = true
            default: continue
            }
            var format = StaticChallenge.Format.scrv1
            if tokens.count == 4 {
                guard let f = StaticChallenge.Format(rawValue: tokens[3].text) else { continue }
                format = f
            }
            found = StaticChallenge(text: AuthText.sanitize(text), echo: echo, format: format)
        }
        return found
    }
}

/// A kódbekérő időkorlátja (2 perc), az ablaktól független, tesztelhető logika.
public struct PromptDeadline: Equatable, Sendable {
    public let start: Date
    public let duration: TimeInterval

    public init(start: Date, duration: TimeInterval = MFA.codePromptTimeout) {
        self.start = start
        self.duration = max(0, duration)
    }

    /// A közvetítő által adott határidő (unix idő), de legfeljebb `maximum` másodperc innen.
    public init(start: Date, until deadline: Date?, maximum: TimeInterval) {
        self.start = start
        let wanted = deadline.map { $0.timeIntervalSince(start) } ?? maximum
        self.duration = max(0, min(wanted, maximum))
    }

    public var end: Date { start.addingTimeInterval(duration) }
    public func isExpired(at now: Date) -> Bool { now >= end }
    /// Hátralévő egész másodpercek (0, ha lejárt).
    public func remaining(at now: Date) -> Int { max(0, Int(end.timeIntervalSince(now).rounded(.up))) }
}

/// A szerver (vagy a config) által adott szövegek megjelenítés előtti tisztítása: vezérlőkarakter helyett szóköz, a
/// Unicode formázó karakterek (Cf: bidi vezérlők, zero-width, BOM, soft hyphen) kimaradnak, legfeljebb `maxCharacters` karakter.
public enum AuthText {
    public static let maxCharacters = 200

    public static func sanitize(_ s: String) -> String {
        var scalars = String.UnicodeScalarView()
        for u in s.unicodeScalars where u.properties.generalCategory != .format {
            let control = u.value < 0x20 || (0x7F...0x9F).contains(u.value) || u.value == 0x2028 || u.value == 0x2029
            scalars.append(control ? " " : u)
        }
        var out = String(scalars)
        out = out.trimmingCharacters(in: .whitespaces)
        if out.count > maxCharacters { out = String(out.prefix(maxCharacters)) + "…" }
        return out
    }
}

/// Webes hitelesítés URL-je: csak `https://`, legfeljebb 1024 bájt, szigorú ASCII karakterkészlet (RFC 3986, szóköz és
/// vezérlőkarakter nélkül). A hoszt a nyers szövegből jön (a Foundation a punycode-ot Unicode-ra dekódolná): ASCII
/// LDH hosztnév (záró pont nélkül; punycode `xn--` címke maradhat, nem dekódoljuk), IPv4 vagy `[IPv6]` cím; az
/// authority-ben nem lehet `%` és `@`. Minden más URL eldobva.
public enum WebAuthURL {
    public static let maxBytes = 1024

    public static func validate(_ s: String) -> URL? {
        guard !s.isEmpty, s.utf8.count <= maxBytes,
              s.utf8.allSatisfy({ allowed.contains($0) }),
              asciiHost(s) != nil,
              let components = URLComponents(string: s),
              components.scheme?.lowercased() == "https",
              components.user == nil, components.password == nil,
              let url = URL(string: s) else { return nil }
        return url
    }

    /// A megjelenítendő / naplózható hoszt: az eredeti ASCII alak kisbetűvel (IPv6 szögletes zárójelben).
    public static func displayHost(_ url: URL) -> String { asciiHost(url.absoluteString) ?? "" }

    /// Az `https://` URL hosztja a nyers szövegből, ellenőrizve és kisbetűsítve; nil, ha nem megengedett.
    public static func asciiHost(_ s: String) -> String? {
        guard s.utf8.count <= maxBytes, s.lowercased().hasPrefix("https://") else { return nil }
        let rest = s.dropFirst(8)
        let authority = rest.prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        guard !authority.isEmpty, !authority.contains("%"), !authority.contains("@"),
              authority.utf8.allSatisfy({ $0 < 0x80 }) else { return nil }
        var host = Substring(authority)
        var port: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = authority[authority.startIndex...close]
            let after = authority[authority.index(after: close)...]
            if !after.isEmpty {
                guard after.hasPrefix(":") else { return nil }
                port = after.dropFirst()
            }
        } else if let colon = authority.lastIndex(of: ":") {
            host = authority[authority.startIndex..<colon]
            port = authority[authority.index(after: colon)...]
        }
        if let port {
            guard let n = Int(port), (1...65535).contains(n), port.allSatisfy(\.isASCII) else { return nil }
        }
        let lower = host.lowercased()
        if lower.hasPrefix("[") {
            var addr = in6_addr()
            guard inet_pton(AF_INET6, String(lower.dropFirst().dropLast()), &addr) == 1 else { return nil }
            return lower
        }
        return isLDHHostname(lower) ? lower : nil
    }

    /// `[a-z0-9-]` címkék (1–63, nem kezdődik és nem végződik `-`-vel), legfeljebb 253 karakter, záró pont nélkül.
    /// Az IPv4 cím is ilyen alakú.
    static func isLDHHostname(_ h: String) -> Bool {
        guard !h.isEmpty, h.utf8.count <= 253 else { return false }
        let labels = h.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }
        }
    }

    /// `A-Z a-z 0-9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; = %`
    static let allowed: Set<UInt8> = {
        var set = Set<UInt8>()
        for c in UInt8(ascii: "A")...UInt8(ascii: "Z") { set.insert(c) }
        for c in UInt8(ascii: "a")...UInt8(ascii: "z") { set.insert(c) }
        for c in UInt8(ascii: "0")...UInt8(ascii: "9") { set.insert(c) }
        for c in "-._~:/?#[]@!$&'()*+,;=%".utf8 { set.insert(c) }
        return set
    }()
}

/// A közvetítő (`mvpn-mgmt`) állapotfájlja: `/var/run/macvpn-ui/<id>.json` (a felhasználóé, 0600). Csak a
/// challenge szövegét, az echo jelzőt, a webes URL-t és az állapotot tartalmazza, titkot soha.
public struct AuthUIState: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable {
        /// Kódot kér (`method`: crv1, crtext, static).
        case challenge
        /// Webes hitelesítés (`url`: https).
        case webauth
        /// A szerver hitelesítésre vár (auth-pending), használható URL nélkül.
        case pending
        case failed
        case cancelled
        case done
    }

    public enum Method: String, Codable, Sendable { case crv1, crtext, `static`, webauth }

    public var v: Int
    public var seq: Int
    public var state: State
    public var method: Method?
    public var text: String?
    public var echo: Bool?
    public var url: String?
    /// Unix idő; meddig vár a közvetítő / a szerver.
    public var deadline: Double?

    public init(seq: Int, state: State, method: Method? = nil, text: String? = nil, echo: Bool? = nil,
                url: String? = nil, deadline: Double? = nil) {
        self.v = 1
        self.seq = seq
        self.state = state
        self.method = method
        self.text = text
        self.echo = echo
        self.url = url
        self.deadline = deadline
    }

    public static func directory(base: String = "/var/run/macvpn-ui") -> String { base }

    public static func path(for id: UUID, base: String = "/var/run/macvpn-ui") -> String {
        "\(base)/\(id.uuidString).json"
    }

    /// Szigorú beolvasás: legfeljebb 8 KB, ismert verzió, a szöveg tisztítva, az URL újra ellenőrizve (nem https → nil).
    public static func parse(_ data: Data) -> AuthUIState? {
        guard data.count <= 8192, var s = try? JSONDecoder().decode(AuthUIState.self, from: data), s.v == 1 else { return nil }
        s.text = s.text.map(AuthText.sanitize)
        if let url = s.url, WebAuthURL.validate(url) == nil { s.url = nil }
        if s.state == .webauth, s.url == nil { s.state = .pending }
        return s
    }

    public func encoded() -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return (try? e.encode(self)) ?? Data()
    }

    public var deadlineDate: Date? { deadline.map { Date(timeIntervalSince1970: $0) } }
}

/// A `mvpn respond` válaszának típusa (stdin `kind=`).
public enum AuthResponseKind: String, CaseIterable, Sendable {
    case crv1, `static`, webauthAck = "webauth-ack", cancel

    /// A `mvpn respond` stdin formátuma. A válasz csak a kódot hordozó típusoknál kerül bele.
    public func stdinPayload(response: String) -> String? {
        switch self {
        case .crv1, .static:
            guard MFA.isValidCode(response, allowEmpty: true) else { return nil }
            return "kind=\(rawValue)\nresponse=\(response)\n"
        case .webauthAck, .cancel:
            return "kind=\(rawValue)\nresponse=\n"
        }
    }
}

/// A kapcsolat „hitelesítésre vár” állapota (`ConnectionState.awaitingAuth`).
public struct AuthWait: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// Kódra vár (kódbekérő ablak).
        case code
        /// Webes / push jóváhagyásra vár.
        case web
    }

    public let kind: Kind
    public let deadline: Date?

    public init(kind: Kind, deadline: Date?) {
        self.kind = kind
        self.deadline = deadline
    }
}

/// Egy kérés a felhasználói felület felé (kódbekérő vagy webes megerősítés).
public struct AuthPrompt: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// `echo`: a kód látható mezőben (különben rejtett). `fromServer`: a szöveg a VPN-szervertől jön (a felület
        /// „A VPN-szerver üzenete:” címkével, idegen szövegként mutatja).
        case code(text: String, echo: Bool, fromServer: Bool)
        /// A felület megmutatja a hosztot, megerősítést kér, és csak akkor nyitja meg az URL-t a böngészőben.
        case webAuth(url: URL)
    }

    public let connectionID: String
    public let connectionName: String
    public let kind: Kind
    public let deadline: PromptDeadline

    public init(connectionID: String, connectionName: String, kind: Kind, deadline: PromptDeadline) {
        self.connectionID = connectionID
        self.connectionName = connectionName
        self.kind = kind
        self.deadline = deadline
    }
}

public enum AuthPromptResult: Equatable, Sendable {
    case code(String)
    /// A webes hitelesítés URL-je megnyílt a böngészőben.
    case openedURL
    case cancelled
    case timedOut
}

/// Az állapotfájl biztonságos beolvasása: szabályos fájl (symlinket nem követ), a felhasználóé, legfeljebb 8 KB.
public enum AuthUIStateReader {
    public static func read(path: String) -> AuthUIState? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid(),
              st.st_size >= 0, st.st_size <= 8192 else { return nil }
        var data = Data(count: Int(st.st_size))
        let n = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, Int(st.st_size)) }
        guard n == Int(st.st_size) else { return nil }
        return AuthUIState.parse(data)
    }

    public static func read(id: UUID) -> AuthUIState? { read(path: AuthUIState.path(for: id)) }
}

/// A rendszer-VPN-ek (scutil szolgáltatás-ID) „kód a jelszó végén” beállítása:
/// `~/Library/Application Support/MacVPN/system-otp.json` (0600, atomi írás). Nem titkos, nem exportált.
public final class SystemOTPStore {
    public let url: URL

    public static var defaultURL: URL {
        ConnectionStore.applicationSupportDirectory.appendingPathComponent("system-otp.json")
    }

    public init(url: URL = SystemOTPStore.defaultURL) {
        self.url = url
    }

    public func load() -> [String: OTPSetting] {
        guard let data = try? Data(contentsOf: url),
              let map = try? JSONDecoder().decode([String: OTPSetting].self, from: data) else { return [:] }
        return map
    }

    public func save(_ map: [String: OTPSetting]) throws {
        let dir = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        try ConnectionStore.writePrivate(try e.encode(map.filter { $0.value.enabled }), to: url)
    }
}
