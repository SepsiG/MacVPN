import Foundation

// Az OpenVPN management interfész (doc/management-notes.txt, OpenVPN 2.7) azon része, amit a root oldali
// közvetítő (`mvpn-mgmt`) használ. Tiszta, tesztelhető logika: bemeneti sorok értelmezése (szigorú validálással)
// és a kimenő parancsok előállítása. A kimenő parancsok egy zárt felsorolásból jönnek (`ManagementCommand`): nincs
// általános továbbítás, más parancs felépíteni sem lehet.

/// Statikus challenge kérés a `>PASSWORD:Need 'Auth' username/password SC:<flag>,<szöveg>` sorból.
public struct ManagementStaticRequest: Equatable, Sendable {
    public let echo: Bool
    /// FORMAT bit: a jelszó és a kód egyszerű összefűzése (különben SCRV1).
    public let concat: Bool
    public let text: String
}

/// Dinamikus challenge: `CRV1:<flags>:<state_id>:<username_base64>:<challenge_text>`.
public struct CRV1Challenge: Equatable, Sendable {
    public let echo: Bool
    public let responseRequired: Bool
    public let stateID: String
    public let username: String
    public let text: String

    public static let maxStateIDBytes = 128
    public static let maxUsernameBytes = 255

    /// nil: hibás vagy a korlátokat sértő challenge (ilyenkor a közvetítő hitelesítési hibaként kezeli).
    public static func parse(_ s: String) -> CRV1Challenge? {
        guard s.hasPrefix("CRV1:") else { return nil }
        let parts = s.dropFirst(5).split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        let flags = parts[0].split(separator: ",", omittingEmptySubsequences: true).map(String.init)
        guard flags.allSatisfy({ $0 == "E" || $0 == "R" }) else { return nil }
        let state = String(parts[1])
        guard !state.isEmpty, state.utf8.count <= maxStateIDBytes, state.utf8.allSatisfy(Self.isStateByte) else { return nil }
        let user64 = String(parts[2])
        guard user64.utf8.count <= 400, ManagementParser.isBase64(user64, allowEmpty: true),
              let userData = Data(base64Encoded: user64), let user = String(data: userData, encoding: .utf8),
              user.utf8.count <= maxUsernameBytes, !MFA.hasControl(user) else { return nil }
        return CRV1Challenge(echo: flags.contains("E"), responseRequired: flags.contains("R"),
                             stateID: state, username: user, text: AuthText.sanitize(String(parts[3])))
    }

    /// Látható ASCII, idézőjel, aposztróf, backslash és kettőspont nélkül.
    static func isStateByte(_ b: UInt8) -> Bool {
        (0x21...0x7E).contains(b) && b != 0x22 && b != 0x27 && b != 0x5C && b != 0x3A
    }

    /// A válasz jelszava: `CRV1::<state_id>::<válasz>`.
    public func password(response: String) -> String { "CRV1::\(stateID)::\(response)" }
}

/// Egy management sor jelentése. Ami nem szerepel itt, az `.ignored` (a közvetítő nem reagál rá és nem adja tovább).
public enum ManagementEvent: Equatable, Sendable {
    case hold
    /// `>PASSWORD:Need 'Auth' username/password` (opcionális statikus challenge-dzsel).
    case needAuth(ManagementStaticRequest?)
    /// Olyan jelszót kér, amit a közvetítő nem ad meg (pl. 'Private Key', 'HTTP Proxy', csak felhasználónév).
    case needOther
    /// `>PASSWORD:Verification Failed: 'Auth' ['CRV1:…']`: dinamikus challenge, a következő `Need 'Auth'`-ra kell válaszolni.
    case dynamicChallenge(CRV1Challenge)
    /// Bármely más hitelesítési hiba (hibás CRV1 is): végleges.
    case authFailed
    /// `SESSION:` (lejárt auth-token: az OpenVPN a jelszóval újrapróbál) vagy `TEMP` (átmeneti szerverhiba): nem végleges.
    case authRetry
    /// `>INFOMSG:OPEN_URL:` / `WEB_AUTH:` – csak érvényes https URL; a nem https URL eldobva (`url` nil).
    case webAuth(url: URL?)
    /// `>INFOMSG:CR_TEXT:<flags>:<szöveg>`: a válasz `cr-response <base64>`.
    case crText(echo: Bool, text: String)
    /// `>STATE:…,AUTH_PENDING,timeout N,…`
    case authPending(timeout: Int?)
    /// `>STATE:…,CONNECTED,…`
    case connected
    case fatal
    case ignored
}

public enum ManagementParser {
    /// Ennél hosszabb bemeneti sor eldobva (a közvetítő a következő sorvégig átugorja).
    public static let maxLineBytes = 4096

    public static func parse(_ line: String) -> ManagementEvent {
        guard line.utf8.count <= maxLineBytes else { return .ignored }
        if line.hasPrefix(">HOLD:") { return .hold }
        if line.hasPrefix(">FATAL:") { return .fatal }
        if line.hasPrefix(">PASSWORD:") { return parsePassword(String(line.dropFirst(10))) }
        if line.hasPrefix(">INFOMSG:") { return parseInfo(String(line.dropFirst(9))) }
        if line.hasPrefix(">STATE:") { return parseState(String(line.dropFirst(7))) }
        return .ignored
    }

    static func parsePassword(_ s: String) -> ManagementEvent {
        // Auth-Token: titok, soha nem dolgozzuk fel és nem adjuk tovább.
        if s.hasPrefix("Auth-Token:") { return .ignored }
        if s == "Need 'Auth' username/password" { return .needAuth(nil) }
        let scPrefix = "Need 'Auth' username/password SC:"
        if s.hasPrefix(scPrefix) {
            let rest = s.dropFirst(scPrefix.count)
            guard let comma = rest.firstIndex(of: ","), let flag = Int(rest[rest.startIndex..<comma]),
                  (0...3).contains(flag) else { return .authFailed }
            let text = AuthText.sanitize(String(rest[rest.index(after: comma)...]))
            return .needAuth(ManagementStaticRequest(echo: flag & 1 == 1, concat: flag & 2 == 2, text: text))
        }
        if s.hasPrefix("Need ") { return .needOther }
        let failPrefix = "Verification Failed: 'Auth' ['"
        if s.hasPrefix(failPrefix), s.hasSuffix("']") {
            let inner = String(s.dropFirst(failPrefix.count).dropLast(2))
            if let challenge = CRV1Challenge.parse(inner) { return .dynamicChallenge(challenge) }
            if inner.hasPrefix("SESSION:") || inner.hasPrefix("TEMP") { return .authRetry }
            return .authFailed
        }
        if s.hasPrefix("Verification Failed") { return .authFailed }
        return .ignored
    }

    static func parseInfo(_ s: String) -> ManagementEvent {
        if s.hasPrefix("OPEN_URL:") { return .webAuth(url: WebAuthURL.validate(String(s.dropFirst(9)))) }
        if s.hasPrefix("WEB_AUTH:") {
            // WEB_AUTH:<flags>:<url>; a flagek (pl. proxy=…) nem érdekesek, az URL az első kettőspont után.
            let rest = s.dropFirst(9)
            guard let colon = rest.firstIndex(of: ":") else { return .webAuth(url: nil) }
            let flags = rest[rest.startIndex..<colon]
            // A proxy-s változat (WEB_AUTH:proxy=…;…;user64;pass64,flags:url) proxyt és jelszót hordozna: nem támogatjuk.
            if flags.contains("proxy=") { return .webAuth(url: nil) }
            return .webAuth(url: WebAuthURL.validate(String(rest[rest.index(after: colon)...])))
        }
        if s.hasPrefix("CR_TEXT:") {
            let rest = s.dropFirst(8)
            guard let colon = rest.firstIndex(of: ":") else { return .authFailed }
            let flags = rest[rest.startIndex..<colon].split(separator: ",").map(String.init)
            guard flags.allSatisfy({ $0 == "E" || $0 == "R" }) else { return .authFailed }
            return .crText(echo: flags.contains("E"), text: AuthText.sanitize(String(rest[rest.index(after: colon)...])))
        }
        return .ignored
    }

    static func parseState(_ s: String) -> ManagementEvent {
        let fields = s.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard fields.count >= 2 else { return .ignored }
        switch fields[1] {
        case "AUTH_PENDING":
            var timeout: Int?
            if fields.count >= 3, fields[2].hasPrefix("timeout "), let n = Int(fields[2].dropFirst(8)), (0...86_400).contains(n) {
                timeout = n
            }
            return .authPending(timeout: timeout)
        case "CONNECTED": return .connected
        default: return .ignored
        }
    }

    public static func isBase64(_ s: String, allowEmpty: Bool = false) -> Bool {
        if s.isEmpty { return allowEmpty }
        guard s.utf8.count % 4 == 0 else { return false }
        return matches(s, "^[A-Za-z0-9+/]+={0,2}$")
    }
}

/// A közvetítő által küldhető parancsok teljes listája. Más management parancs nem állítható elő.
public enum ManagementCommand: Equatable, Sendable {
    case stateOn
    case holdRelease
    case username(String)
    case password(String)
    /// `cr-response <base64>` (CR_TEXT válasz).
    case crResponse(String)

    /// Egy érték (felhasználónév, jelszó) legfeljebb ennyi bájt: az OpenVPN parancssori tokenje 256 bájtos
    /// (`OPTION_PARM_SIZE`), a hosszabbat csak a többsoros base64 formátum vinné át.
    public static let maxValueBytes = 255

    /// Az OpenVPN 1024 bájtos parancssori pufferje: az ezen túli bájtokat új parancsként futtatná.
    public static let maxLineBytes = 1023

    /// A küldendő sor (sorvég nélkül). nil: az érték nem küldhető (üres felhasználónév, vezérlőkarakter, túl hosszú).
    public var line: String? {
        guard let line = unchecked, line.utf8.count <= Self.maxLineBytes else { return nil }
        return line
    }

    private var unchecked: String? {
        switch self {
        case .stateOn: return "state on"
        case .holdRelease: return "hold release"
        case .username(let v):
            guard !v.isEmpty, let q = Self.quote(v) else { return nil }
            return "username \"Auth\" \(q)"
        case .password(let v):
            guard let q = Self.quote(v) else { return nil }
            return "password \"Auth\" \(q)"
        case .crResponse(let v):
            guard let b64 = v.data(using: .utf8)?.base64EncodedString(), b64.utf8.count <= Self.maxValueBytes else { return nil }
            return "cr-response \(b64)"
        }
    }

    /// Idézőjelek közé, `\` és `"` escape-elve (a management „Command Parsing” szabályai). Vezérlőkarakter, vagy
    /// `maxValueBytes`-nál hosszabb érték: nil.
    static func quote(_ v: String) -> String? {
        guard v.utf8.count <= maxValueBytes, !MFA.hasControl(v) else { return nil }
        return "\"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

/// A `mvpn respond` által a futási könyvtárba írt válasz (`kind=…`, `response=…`), a közvetítő oldali újraellenőrzéssel.
public struct ManagementResponse: Equatable, Sendable {
    public let kind: AuthResponseKind
    public let response: String

    public static let maxFileBytes = 1024

    public static func parse(_ data: Data) -> ManagementResponse? {
        guard data.count <= maxFileBytes, let text = String(data: data, encoding: .utf8) else { return nil }
        var kind: AuthResponseKind?
        var response = ""
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("kind=") {
                kind = AuthResponseKind(rawValue: String(line.dropFirst(5)))
                if kind == nil { return nil }
            } else if line.hasPrefix("response=") {
                response = String(line.dropFirst(9))
            } else {
                return nil
            }
        }
        guard let kind, MFA.isValidCode(response, allowEmpty: true) else { return nil }
        return ManagementResponse(kind: kind, response: response)
    }
}

/// A közvetítő bemenete a `mvpn`-től (`$RUN/mgmt-creds`, root 0600, beolvasás után azonnal törölve).
public struct ManagementCredentials: Equatable, Sendable {
    public var username: String
    public var password: String
    /// A jelszó már SCRV1 / concat formában van (az app statikus challenge-et kezelt).
    public var packed: Bool

    public static func parse(_ data: Data) -> ManagementCredentials? {
        guard data.count <= 4096, let text = String(data: data, encoding: .utf8) else { return nil }
        var out = ManagementCredentials(username: "", password: "", packed: false)
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("username=") { out.username = String(line.dropFirst(9)) }
            else if line.hasPrefix("password=") { out.password = String(line.dropFirst(9)) }
            else if line == "packed=1" { out.packed = true }
            else if line == "packed=0" { out.packed = false }
            else { return nil }
        }
        return out
    }
}
