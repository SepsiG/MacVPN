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
        case .sstp: return SSTPValidator()
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

/// Egy direktíva argumentumának szabálya.
enum ArgRule {
    /// A teljes argumentumra illeszkedő regex.
    case pattern(String)
    /// Egész szám a tartományban (csak számjegyek).
    case number(ClosedRange<Int>)
    /// Szabad szöveg (idézőjelben szóközzel is); a backslash-t már a tokenizálás elutasítja.
    case text
}

/// Argumentumszám-tartomány és pozíciónkénti szabály; a `rest` a `rules`-on túli argumentumokra vonatkozik.
struct ArgSpec {
    let min: Int
    let max: Int
    let rules: [ArgRule]
    var rest: ArgRule?

    init(_ min: Int, _ max: Int, _ rules: [ArgRule] = [], rest: ArgRule? = nil) {
        self.min = min
        self.max = max
        self.rules = rules
        self.rest = rest
    }

    func rule(at index: Int) -> ArgRule? { index < rules.count ? rules[index] : rest }
}

/// Egy OpenVPN config-sor tokenje: a szöveg (idézőjelek nélkül) és hogy idézőjeles volt-e.
struct OpenVPNToken: Equatable {
    let text: String
    let quoted: Bool
}

/// Egy OpenVPN direktíva besorolása (lásd `docs/openvpn-directives.md`).
public enum OpenVPNTier: String, Sendable {
    /// Engedett, argumentum-ellenőrzéssel (`argumentSpecs`).
    case safe
    /// Nem lépi át a root jogosultsági határt, de a kapcsolat vagy a rendszer viselkedését befolyásolja: csak akkor
    /// engedett, ha a kapcsolatnál név szerint tudomásul vették (`acknowledgedRisky`). Ide tartozik minden ismeretlen direktíva.
    case risky
    /// Soha nem engedett: kódot futtat vagy tölt be, tetszőleges fájlt olvas/ír rootként, vagy vezérlőcsatornát nyit.
    case forbidden
}

/// Egy tudomásulvételt igénylő (kockázatos) direktíva előfordulása.
public struct RiskyFinding: Equatable, Sendable {
    public let directive: String
    public let line: Int
    /// Az `L10n` táblabeli angol kulcs (rövid indoklás).
    public let reasonKey: String

    public init(directive: String, line: Int, reasonKey: String) {
        self.directive = directive
        self.line = line
        self.reasonKey = reasonKey
    }

    public var reason: String { L10n.tr(reasonKey) }
}

/// Az OpenVPN validálás teljes eredménye.
public struct OpenVPNValidation: Equatable, Sendable {
    /// Blokkoló hibák (tiltott, érvénytelen, nem engedett) – tudomásulvétellel sem javíthatók.
    public let issues: [ValidationIssue]
    /// Minden kockázatos előfordulás, sorrendben (a tudomásul vettek is).
    public let risky: [RiskyFinding]
    /// A még tudomásul nem vett kockázatos direktívák nevei, rendezve.
    public let unacknowledged: [String]

    /// A kockázatos direktívák nevei (rendezve, egyedi).
    public var riskyNames: [String] { Array(Set(risky.map(\.directive))).sorted() }

    /// A blokkoló hibák, kiegészítve a tudomásul nem vett kockázatos sorokkal (soronként egy hiba).
    public var allIssues: [ValidationIssue] {
        let open = Set(unacknowledged)
        let extra = risky.filter { open.contains($0.directive) }.map {
            ValidationIssue(line: $0.line, message: L10n.tr("Risky directive, acknowledgement required: %@", $0.directive))
        }
        // Soronként rendezve (stabilan); a 0. soros (egész fájlra vonatkozó) hibák a végén maradnak.
        func key(_ i: ValidationIssue) -> Int { i.line == 0 ? Int.max : i.line }
        return (issues + extra).enumerated().sorted { (key($0.element), $0.offset) < (key($1.element), $1.offset) }.map(\.element)
    }
}

/// Egy direktíva-sor ellenőrzésének eredménye.
struct OpenVPNLineResult {
    var messages: [String] = []
    var directive: String?
    /// Kockázatos direktíva (név, indoklás-kulcs), ha a sor egyébként érvényes.
    var risky: (directive: String, reasonKey: String)?
}

/// Táblázatvezérelt, három szintű besorolás. Rootként a `mvpn-validate` futtatja.
///
/// Szabályok sorrendben, soronként:
/// 1. vezérlőkarakter -> hiba (blokkon belül is);
/// 2. adatblokkon belül: a trimmelt sor `</`-val kezdődik -> a blokk lezárul, és ha nem pontosan `</tag>` (kisbetűsítve), "Hibás záró tag"; egyéb sor kihagyva;
/// 3. üres, `#` vagy `;` kezdetű sor kihagyva;
/// 4. `<connection>`: connection blokk nyílik (csak legfelső szinten; benne újabb `<connection>` nem lehet). A benne lévő sorok
///    ugyanazon a direktíva-ellenőrzésen mennek át, de csak a `connectionAllowed` direktívák engedettek (mint az OpenVPN-ben), és
///    adatblokk csak a `connectionBlocks`-ból nyílhat. Csak `</connection>` zárja; más `</…>` benne "Hibás záró tag";
/// 5. `^<[A-Za-z0-9-]+>$` nyitó tag: csak `allowedBlocks`-beli lehet, különben "Nem engedélyezett inline blokk" (de blokként kezelve, tartalma kihagyva);
/// 6. direktíva = első token (szóköz/tab szerint), egyezzen `^(--)?[A-Za-z0-9-]+$`-val, különben "Érvénytelen direktíva"; kisbetűsítés, `--` levágása;
/// 7. besorolás a `tier(of:)` szerint (táblázat: `argumentSpecs` = SAFE, `riskyReasons` = RISKY, `forbidden` = FORBIDDEN;
///    ismeretlen név: `forbiddenPattern`-re illeszkedő -> FORBIDDEN, egyébként RISKY):
///    - FORBIDDEN -> "Tiltott direktíva";
///    - RISKY -> `<connection>` blokkban hiba; az argumentumok a `isHarmlessArgument` szabályán mennek át (nincs vezető `-`,
///      `..`, abszolút út, `~`, `file:`, shell-metakarakter, `/` csak CIDR-ben), különben "Érvénytelen argumentum";
///      érvényes sornál kockázatos találat (nem hiba): a `validate(_:acknowledgedRisky:)` csak a tudomásul nem vett nevekre ad hibát;
/// 7b. `setenv` külön: `setenv opt <direktíva> ...` -> a <direktíva> ugyanezen az ellenőrzésen megy át; `setenv NAME [érték]`
///     -> NAME egyezzen `^[A-Za-z_][A-Za-z0-9_]*$`-val és ne legyen a `setenvDenylist`-ben (ezek az értékek a root `ovpn-dns`
///     bash hookhoz jutnak), különben "Nem engedélyezett setenv"; `setenv` argumentum nélkül, vagy `setenv opt` direktíva nélkül -> hiba;
/// 8. argumentumok (SAFE): az OpenVPN `parse_line` tükre (szóköz/tab határ, `"…"`/`'…'` csak token elején, a záró idézőjel zárja a tokent,
///    token elején álló `#`/`;` a sor végéig komment); backslash vagy lezáratlan idézőjel -> "Érvénytelen argumentum";
///    `fileReferencing` direktíva, ha van argumentuma és az nem `[inline]` -> fájlhivatkozás-hiba; `http-proxy` 3. argumentuma csak
///    `auto`/`auto-nct`/`[inline]`, `socks-proxy` 3. argumentuma csak `[inline]` lehet;
///    minden direktíva argumentumszámát és argumentumait az `argumentSpecs` táblázat ellenőrzi ("Hibás argumentumszám" / "Érvénytelen argumentum").
///    Az üzenet csak a direktíva nevét idézi, az argumentumot soha;
/// 9. fájl végén nyitott blokk -> "Lezáratlan inline blokk"; érvényes `remote` (legfelső szinten vagy connection blokkban) hiánya -> 0. soros hiba.
public struct OpenVPNValidator: ConfigValidator {
    // MARK: FORBIDDEN

    /// Soha nem engedett, tudomásulvétellel sem. Indoklás csoportonként a `docs/openvpn-directives.md`-ben.
    public static let forbidden: Set<String> = {
        var s = Set<String>()
        // Script hookok és parancsfuttatás.
        s.formUnion(["up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify",
                     "client-connect", "client-disconnect", "client-crresponse", "learn-address", "dns-updown", "iproute",
                     "script-security"])
        // Kódbetöltés (a pkcs11-* a provider könyvtár nélkül működésképtelen, a provider kódot tölt be).
        s.formUnion(["plugin", "providers", "engine", "pkcs11-providers", "pkcs11-id", "pkcs11-id-management",
                     "pkcs11-cert-private", "pkcs11-pin-cache", "pkcs11-private-mode", "pkcs11-protected-authentication",
                     "show-pkcs11-ids"])
        // Config- és könyvtárváltás; a chroot után a MacVPN hookjai és a jelszófájlok nem érhetők el.
        s.formUnion(["config", "cd", "chroot"])
        // Kimenet, vezérlőcsatorna, állapotfájl (a MacVPN ezeket maga állítja be, vagy a naplóból dönt).
        s.formUnion(["daemon", "log", "log-append", "syslog", "echo", "parameter", "writepid", "status", "tmp-dir", "management",
                     "management-client", "management-client-auth", "management-client-group", "management-client-pf",
                     "management-client-user", "management-external-cert", "management-external-key",
                     "management-forget-disconnect", "management-hold", "management-log-cache", "management-query-passwords",
                     "management-query-proxy", "management-query-remote", "management-signal", "management-up-down"])
        // Tetszőleges fájl/könyvtár olvasása vagy írása rootként.
        s.formUnion(["dev-node", "tls-export-cert", "client-config-dir", "replay-persist", "ifconfig-pool-persist",
                     "tls-crypt-v2-verify", "capath", "genkey", "port-share", "auth-gen-token-secret"])
        return s
    }()

    /// Ismeretlen (egyik táblában sem szereplő) név, amely a mintája alapján valószínűleg parancsot, fájlt vagy
    /// vezérlőcsatornát jelent: FORBIDDEN, nem RISKY.
    static let forbiddenPattern = "^(management|pkcs11|plugin|script)|-(verify|up|down|connect|disconnect|script|dir|file|persist|path|exec|cmd)$"

    // MARK: RISKY

    static let reasonPrivilegeDrop = "Drops root privileges after start: reconnecting may fail, and DNS is restored only when MacVPN disconnects"
    static let reasonNoExec = "OpenVPN will not configure the interface or the routes: the tunnel may carry no traffic"
    static let reasonHooks = "Changes when MacVPN's DNS hooks run"
    static let reasonServer = "Server-side option, not meant for a client connection"
    static let reasonListens = "Makes this Mac accept incoming VPN connections (listens on the network as root)"
    static let reasonPushed = "Normally sent by the server or used internally by OpenVPN, not set in a client config"
    static let reasonRemoved = "Removed from OpenVPN: the connection will fail to start"
    static let reasonDebug = "Debugging option that deliberately disrupts the connection"
    static let reasonWeakens = "Weakens the security of the tunnel (deprecated or insecure mode)"
    static let reasonRouting = "Allows routing that can bypass or loop the tunnel"
    static let reasonPlatform = "Not supported on macOS (Windows or Linux only)"
    static let reasonStandalone = "Standalone mode: OpenVPN prints information or exits instead of connecting"
    static let reasonUnknown = "Unknown to MacVPN: its effect cannot be checked"

    /// Ismert RISKY direktívák -> indoklás (`L10n` kulcs). Lépésenként épül (gyors típusellenőrzés).
    public static let riskyReasons: [String: String] = {
        var t: [String: String] = [:]
        for d in ["user", "group"] { t[d] = reasonPrivilegeDrop }
        for d in ["route-noexec", "ifconfig-noexec"] { t[d] = reasonNoExec }
        for d in ["up-restart", "down-pre"] { t[d] = reasonHooks }
        for d in ["mode", "server", "server-bridge", "server-ipv6", "tls-server", "client-to-client"] { t[d] = reasonListens }
        let server = ["duplicate-cn",
                      "max-clients", "max-routes-per-client", "ccd-exclusive", "client-nat", "connect-freq",
                      "connect-freq-initial", "hash-size", "bcast-buffers", "stale-routes-check", "verify-client-cert",
                      "client-cert-not-required", "username-as-common-name", "override-username", "auth-user-pass-optional",
                      "auth-gen-token", "ifconfig-pool", "ifconfig-pool-linear", "ifconfig-ipv6-pool", "ifconfig-push",
                      "ifconfig-ipv6-push", "iroute", "iroute-ipv6", "push", "push-reset", "push-remove", "disable",
                      "vlan-tagging", "vlan-accept", "vlan-pvid", "tls-crypt-v2-max-age"]
        for d in server { t[d] = reasonServer }
        t["ifconfig-push-constraint"] = reasonServer
        for d in ["key-derivation", "protocol-flags", "peer-id", "push-continuation", "http-proxy-override"] { t[d] = reasonPushed }
        for d in ["compat-names", "no-name-remapping", "mtu-dynamic"] { t[d] = reasonRemoved }
        t["gremlin"] = reasonDebug
        for d in ["allow-deprecated-insecure-static-crypto", "compat-mode", "no-replay", "no-iv", "key-method"] { t[d] = reasonWeakens }
        t["allow-recursive-routing"] = reasonRouting
        for d in ["win-sys", "service", "cryptoapicert", "allow-nonadmin", "setcon", "msg-channel", "rdns-internal",
                  "dhcp-internal"] {
            t[d] = reasonPlatform
        }
        let standalone = ["help", "version", "show-adapters", "show-ciphers", "show-digests", "show-engines", "show-gateway",
                          "show-groups", "show-net", "show-net-up", "show-tls", "show-valid-subnets", "show-curves",
                          "test-crypto", "mktun", "rmtun"]
        for d in standalone { t[d] = reasonStandalone }
        return t
    }()

    // MARK: SAFE kiegészítők

    public static let fileReferencing: Set<String> = [
        "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "secret",
        "extra-certs", "dh", "crl-verify", "askpass", "auth-user-pass", "http-proxy-user-pass",
    ]
    /// SAFE direktívák (az `argumentSpecs` kulcsai). A `setenv` külön szabállyal SAFE.
    public static var allowed: Set<String> { Set(argumentSpecs.keys) }
    public static let allowedBlocks: Set<String> = [
        "ca", "cert", "key", "extra-certs", "dh", "pkcs12", "secret", "tls-auth", "tls-crypt",
        "tls-crypt-v2", "peer-fingerprint", "auth-user-pass", "crl-verify", "http-proxy-user-pass", "verify-hash",
    ]
    /// A `<connection>` blokkban engedett direktívák: az OpenVPN kézikönyv listája (bind, connect-retry, connect-retry-max,
    /// connect-timeout, explicit-exit-notify, float, fragment, http-proxy, http-proxy-option, link-mtu, local, lport, mssfix,
    /// mtu-disc, nobind, port, proto, remote, rport, socks-proxy, tun-mtu, tun-mtu-extra) metszve a SAFE listával.
    public static let connectionAllowed: Set<String> = [
        "bind", "connect-retry", "connect-retry-max", "connect-timeout", "explicit-exit-notify", "float", "fragment",
        "http-proxy", "http-proxy-option", "link-mtu", "udp-mtu", "local", "lport", "mssfix", "mtu-disc", "nobind", "port", "proto",
        "remote", "rport", "socks-proxy", "tun-mtu", "tun-mtu-extra",
    ]
    /// A `<connection>` blokkon belül nyitható adatblokkok (a connection-opciók inline párja).
    public static let connectionBlocks: Set<String> = ["http-proxy-user-pass"]

    /// `setenv` név: bármely shell-azonosító, a denylist kivételével.
    static let setenvNamePattern = "^[A-Za-z_][A-Za-z0-9_]*$"
    /// Pontos (kis/nagybetű-független) nevek, amelyek a root `ovpn-dns` hookot, a bash-t, a dinamikus linkert vagy a
    /// hook által hívott programokat befolyásolhatják; illetve amelyeket a hook maga olvas.
    static let setenvDeniedNames: Set<String> = [
        "BASH_ENV", "ENV", "PATH", "IFS", "SHELLOPTS", "BASHOPTS", "PS4", "CDPATH", "GLOBIGNORE", "HOME", "TMPDIR",
        "OPENSSL_CONF", "TZDIR", "LANG", "NLSPATH", "LOCPATH", "GCONV_PATH", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN",
        "BASH_XTRACEFD", "BASH_LOADABLES_PATH", "EXECIGNORE", "PROMPT_COMMAND", "ZDOTDIR", "SHELL", "TERMINFO",
        "POSIXLY_CORRECT", "TMOUT", "PATH_LOCALE", "GREP_OPTIONS", "OPENSSL_MODULES", "OPENSSL_ENGINES",
        "SCRIPT_TYPE", "DEV", "IFCONFIG_LOCAL",
    ]
    /// Előtagok, kis/nagybetű-függetlenül.
    static let setenvDeniedPrefixes = ["BASH_FUNC", "DYLD_", "LD_", "MALLOC_", "PYTHON", "PERL", "RUBY", "SSL_CERT_", "LC_",
                                       "FOREIGN_OPTION_"]
    /// Előtagok, kis/nagybetű-érzékenyen (macOS keretrendszer-változók, pl. `MallocStackLoggingDirectory`, `NSObjCMessageLoggingEnabled`).
    static let setenvDeniedCaseSensitivePrefixes = ["Malloc", "NS", "CF", "__CF", "OBJC_"]

    public static func isDeniedSetenvName(_ name: String) -> Bool {
        let upper = name.uppercased()
        if setenvDeniedNames.contains(upper) { return true }
        if setenvDeniedPrefixes.contains(where: { upper.hasPrefix($0) }) { return true }
        return setenvDeniedCaseSensitivePrefixes.contains { name.hasPrefix($0) }
    }

    static var hint: String { L10n.tr(" – delete the line or comment it out (#)") }

    // Argumentum-szabályok. Ahol a teljes nyelvtan túlzás, szigorú karakterkészlet: nincs vezető `-`, és `/` csak
    // maszkban/CIDR-ben (route-ipv6, ifconfig-ipv6).
    static let host = ArgRule.pattern("^[A-Za-z0-9_][A-Za-z0-9_.:%-]*$")
    static let port = ArgRule.number(0...65535)
    static let uint = ArgRule.number(0...Int(UInt32.max))
    static let proto = ArgRule.pattern("^(udp|tcp|udp4|udp6|tcp4|tcp6|tcp-client|tcp4-client|tcp6-client)$")
    static let cipher = ArgRule.pattern("^[A-Za-z0-9?][A-Za-z0-9_:.+?-]*$")
    static let tlsCipher = ArgRule.pattern("^[A-Za-z0-9!?@+][A-Za-z0-9_:.+?!@=-]*$")
    static let ipv4 = ArgRule.pattern("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")
    static let inline = ArgRule.pattern("^\\[inline\\]$")
    static let direction = ArgRule.pattern("^[01]$")
    static let base64ish = ArgRule.pattern("^[A-Za-z0-9+=_.-][A-Za-z0-9+/=_.-]*$")
    static let word = ArgRule.pattern("^[A-Za-z0-9_+][A-Za-z0-9_.:+=@-]*$")
    static let flag = ArgSpec(0, 0)
    static func oneOf(_ values: String) -> ArgRule { .pattern("^(\(values))$") }

    /// Direktíva -> argumentumszám és argumentum-szabályok. Ennek a kulcshalmaza a SAFE szint.
    static let argumentSpecs: [String: ArgSpec] = {
        var t: [String: ArgSpec] = [:]
        let flags1 = ["client", "tls-client", "pull", "nobind", "float", "persist-key", "persist-tun", "persist-remote-ip",
                      "remote-random", "auth-nocache", "ncp-disable", "mute-replay-warnings", "route-nopull", "block-ipv6",
                      "tun-ipv6", "fast-io", "push-peer-info", "single-session", "http-proxy-retry", "disable-occ", "opt-verify",
                      "remote-random-hostname", "machine-readable-output", "suppress-timestamps", "ping-timer-rem",
                      "block-outside-dns", "ifconfig-nowarn"]
        let flags2 = ["allow-pull-fqdn", "disable-dco", "mlock", "errors-to-stderr", "passtos", "tcp-nodelay", "multihome",
                      "persist-local-ip", "mtu-test", "tls-exit", "force-tls-key-material-export", "use-prediction-resistance",
                      "comp-noadapt", "register-dns", "dhcp-renew", "dhcp-release", "dhcp-pre-release", "pause-exit",
                      "socks-proxy-retry", "up-delay", "askpass"]
        for d in flags1 { t[d] = flag }
        for d in flags2 { t[d] = flag }
        t["bind"] = ArgSpec(0, 1, [oneOf("ipv6only")])
        t["dev"] = ArgSpec(1, 1, [.pattern("^(tun|tap|utun[0-9]*|tun[0-9]+|tap[0-9]+)$")])
        t["dev-type"] = ArgSpec(1, 1, [oneOf("tun|tap")])
        t["proto"] = ArgSpec(1, 1, [proto])
        t["proto-force"] = ArgSpec(1, 1, [oneOf("udp|tcp|udp4|udp6|tcp4|tcp6")])
        t["remote"] = ArgSpec(1, 3, [host, port, proto])
        t["local"] = ArgSpec(1, 1, [host])
        for d in ["port", "rport", "lport"] { t[d] = ArgSpec(1, 1, [port]) }
        t["resolv-retry"] = ArgSpec(1, 1, [.pattern("^(infinite|[0-9]{1,9})$")])
        t["connect-retry"] = ArgSpec(1, 2, [uint, uint])
        let numbers = ["connect-retry-max", "connect-timeout", "server-poll-timeout", "tls-timeout", "hand-window", "reneg-bytes",
                       "reneg-pkts", "mute", "ping", "ping-restart", "ping-exit", "route-metric", "tun-mtu-extra", "link-mtu", "udp-mtu",
                       "sndbuf", "rcvbuf", "txqueuelen", "mark", "tran-window", "tun-mtu-max", "max-packet-size",
                       "session-timeout", "route-table", "tap-sleep", "status-version", "tcp-queue-limit", "shaper",
                       "http-proxy-timeout"]
        for d in numbers { t[d] = ArgSpec(1, 1, [uint]) }
        t["max-routes"] = ArgSpec(0, 1, [uint])
        t["explicit-exit-notify"] = ArgSpec(0, 1, [uint])
        // `preresolve [hint]`; az `ip-remote-hint` a régi neve (options.c: ugyanaz az ág).
        for d in ["preresolve", "ip-remote-hint"] { t[d] = ArgSpec(0, 1, [host]) }
        t["remap-usr1"] = ArgSpec(1, 1, [oneOf("SIGHUP|SIGTERM")])
        t["nice"] = ArgSpec(1, 1, [.pattern("^-?[0-9]{1,2}$")])
        t["bind-dev"] = ArgSpec(1, 1, [.pattern("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$")])
        t["lladdr"] = ArgSpec(1, 1, [.pattern("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")])
        t["socket-flags"] = ArgSpec(1, 1, [oneOf("TCP_NODELAY")])
        t["remote-cert-tls"] = ArgSpec(1, 1, [oneOf("client|server")])
        t["ns-cert-type"] = ArgSpec(1, 1, [oneOf("client|server")])
        t["remote-cert-ku"] = ArgSpec(1, 8, [], rest: .pattern("^[0-9A-Fa-f]{1,4}$"))
        t["remote-cert-eku"] = ArgSpec(1, 1, [.pattern("^[A-Za-z0-9][A-Za-z0-9 ._-]*$")])
        t["verify-x509-name"] = ArgSpec(1, 2, [.text, oneOf("subject|name|name-prefix")])
        t["peer-fingerprint"] = ArgSpec(0, 1, [.pattern("^([0-9A-Fa-f:]+|\\[inline\\])$")])
        t["verify-hash"] = ArgSpec(1, 2, [.pattern("^([0-9A-Fa-f:]+|\\[inline\\])$"), oneOf("SHA1|SHA256")])
        t["x509-track"] = ArgSpec(1, 1, [.pattern("^\\+?[A-Za-z0-9_.-]+$")])
        t["x509-username-field"] = ArgSpec(1, 8, [], rest: .pattern("^(ext:)?[A-Za-z0-9_.-]+$"))
        t["keying-material-exporter"] = ArgSpec(2, 2, [.pattern("^EXPORTER[A-Za-z0-9_.-]*$"), .number(16...4095)])
        for d in ["ca", "cert", "key", "extra-certs", "dh", "pkcs12", "tls-crypt", "tls-crypt-v2", "crl-verify", "auth-user-pass",
                  "http-proxy-user-pass"] {
            t[d] = ArgSpec(0, 1, [inline])
        }
        t["tls-auth"] = ArgSpec(0, 2, [inline, direction])
        t["secret"] = ArgSpec(0, 2, [inline, direction])
        t["key-direction"] = ArgSpec(1, 1, [direction])
        t["auth-retry"] = ArgSpec(1, 1, [oneOf("none|nointeract|interact")])
        t["auth-token"] = ArgSpec(1, 1, [base64ish])
        t["auth-token-user"] = ArgSpec(1, 1, [base64ish])
        t["static-challenge"] = ArgSpec(2, 3, [.text, direction, oneOf("scrv1|concat")])
        for d in ["cipher", "ciphers", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth", "ecdh-curve"] {
            t[d] = ArgSpec(1, 1, [cipher])
        }
        t["tls-version-min"] = ArgSpec(1, 2, [.pattern("^[0-9](\\.[0-9])?$"), oneOf("or-highest")])
        t["tls-version-max"] = ArgSpec(1, 1, [.pattern("^[0-9](\\.[0-9])?$")])
        for d in ["tls-cipher", "tls-ciphersuites", "tls-groups"] { t[d] = ArgSpec(1, 1, [tlsCipher]) }
        t["tls-cert-profile"] = ArgSpec(1, 1, [oneOf("legacy|preferred|suiteb|insecure")])
        t["reneg-sec"] = ArgSpec(1, 2, [uint, uint])
        t["comp-lzo"] = ArgSpec(0, 1, [oneOf("yes|no|adaptive")])
        t["compress"] = ArgSpec(0, 1, [oneOf("lzo|lz4|lz4-v2|stub|stub-v2|migrate")])
        t["allow-compression"] = ArgSpec(1, 1, [oneOf("yes|no|asym")])
        t["verb"] = ArgSpec(1, 1, [.number(0...11)])
        t["replay-window"] = ArgSpec(1, 2, [uint, uint])
        t["keepalive"] = ArgSpec(2, 2, [uint, uint])
        t["inactive"] = ArgSpec(1, 2, [uint, uint])
        let gatewayFlags = oneOf("local|autolocal|def1|bypass-dhcp|bypass-dns|block-local|ipv6|!ipv4")
        t["redirect-gateway"] = ArgSpec(0, 8, [], rest: gatewayFlags)
        t["redirect-private"] = ArgSpec(0, 8, [], rest: gatewayFlags)
        t["route"] = ArgSpec(1, 4, [host, .pattern("^([0-9]{1,3}(\\.[0-9]{1,3}){3}|default)$"), host,
                                    .pattern("^([0-9]{1,9}|default)$")])
        t["route-ipv6"] = ArgSpec(1, 3, [.pattern("^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$"),
                                         .pattern("^([0-9A-Fa-f:.]+|default|vpn_gateway|net_gateway|remote_host)$"),
                                         .pattern("^([0-9]{1,9}|default)$")])
        t["route-gateway"] = ArgSpec(1, 1, [.pattern("^([0-9]{1,3}(\\.[0-9]{1,3}){3}|dhcp)$")])
        t["route-ipv6-gateway"] = ArgSpec(1, 1, [.pattern("^[0-9A-Fa-f:.]+$")])
        t["route-delay"] = ArgSpec(0, 2, [uint, uint])
        t["pull-filter"] = ArgSpec(2, 2, [oneOf("accept|ignore|reject"), .text])
        // A típus kisbetűs alakja is átmegy (az OpenVPN dönti el, érvényes-e); a PROXY_* értéke URL is lehet.
        t["dhcp-option"] = ArgSpec(1, 16, [.pattern("^(?i:DNS|DNS6|DOMAIN|DOMAIN-SEARCH|ADAPTER_DOMAIN_SUFFIX|WINS|NBDD|NTP|NBT|NBS|DISABLE-NBT|PROXY_[A-Z_]+)$")],
                                   rest: .pattern("^[A-Za-z0-9_\\[][A-Za-z0-9_.:/?=&%+@~\\[\\]-]*$"))
        // `dns search-domains d…`, `dns server n address|resolve-domains|dnssec|transport|sni …`; n: -128…127.
        t["dns"] = ArgSpec(2, 16, [oneOf("search-domains|server")],
                           rest: .pattern("^(-[0-9]{1,3}|[A-Za-z0-9_\\[][A-Za-z0-9_.:\\[\\]-]*)$"))
        t["ifconfig"] = ArgSpec(2, 2, [ipv4, ipv4])
        t["ifconfig-ipv6"] = ArgSpec(1, 2, [.pattern("^[0-9A-Fa-f:.]+/[0-9]{1,3}$"), .pattern("^[0-9A-Fa-f:.]+$")])
        t["topology"] = ArgSpec(1, 1, [oneOf("net30|p2p|subnet")])
        t["tun-mtu"] = ArgSpec(1, 2, [uint, uint])
        t["fragment"] = ArgSpec(1, 2, [uint, oneOf("mtu")])
        t["mssfix"] = ArgSpec(0, 2, [uint, oneOf("mtu|fixed")])
        t["mtu-disc"] = ArgSpec(1, 1, [oneOf("no|maybe|yes")])
        t["setenv-safe"] = ArgSpec(1, 2, [.pattern("^[A-Za-z0-9_]+$"), .text])
        t["ignore-unknown-option"] = ArgSpec(1, 64, [], rest: .pattern("^[A-Za-z0-9-]+$"))
        t["socks-proxy"] = ArgSpec(1, 3, [host, port, inline])
        t["http-proxy"] = ArgSpec(1, 4, [host, port, oneOf("auto|auto-nct|\\[inline\\]"), oneOf("none|basic|ntlm|ntlm2")])
        t["http-proxy-option"] = ArgSpec(1, 3, [oneOf("VERSION|AGENT|CUSTOM-HEADER")], rest: .text)
        t["route-method"] = ArgSpec(1, 1, [oneOf("adaptive|ipapi|exe")])
        t["ip-win32"] = ArgSpec(1, 3, [oneOf("manual|dynamic|netsh|ipapi|exe|adaptive"), uint, uint])
        t["windows-driver"] = ArgSpec(1, 1, [oneOf("tap-windows6|wintun|ovpn-dco")])
        t["prng"] = ArgSpec(0, 2, [word, uint])
        return t
    }()

    /// Egy direktíva szintje: táblázat, ismeretlen névnél a `forbiddenPattern`, egyébként RISKY.
    public static func tier(of directive: String) -> OpenVPNTier {
        if forbidden.contains(directive) { return .forbidden }
        if directive == "setenv" || argumentSpecs[directive] != nil { return .safe }
        if riskyReasons[directive] != nil { return .risky }
        return matches(directive, forbiddenPattern) ? .forbidden : .risky
    }

    /// A RISKY (köztük az ismeretlen) direktívák argumentumainak szabálya: nem csempészhet be fájlt, útvonalat vagy
    /// parancsot. Nincs vezető `-`, `..`, `/` (csak CIDR-ben), `~`, `file:`, és shell-metakarakter (`` ` $ ; | & < > ``).
    static func isHarmlessArgument(_ arg: String) -> Bool {
        guard !arg.isEmpty, !arg.hasPrefix("-"), !arg.hasPrefix("~"), !arg.contains("..") else { return false }
        if asciiLowercased(arg).contains("file:") { return false }
        if arg.utf8.contains(where: { "`$;|&<>\\".utf8.contains($0) }) { return false }
        if arg.contains("/") { return WireGuardValidator.isCIDR(arg) }
        return true
    }

    public init() {}

    /// A `ConfigValidator` felülete: tudomásulvétel nélkül, a kockázatos sorok is hibák.
    public func validate(_ text: String) -> [ValidationIssue] {
        validate(text, acknowledgedRisky: []).allIssues
    }

    /// Teljes eredmény: blokkoló hibák, kockázatos találatok és a még tudomásul nem vett kockázatos nevek.
    /// Az `acknowledgedRisky` csak RISKY neveket fogadhat el: FORBIDDEN név benne hatástalan.
    public func validate(_ text: String, acknowledgedRisky: Set<String>) -> OpenVPNValidation {
        var issues: [ValidationIssue] = []
        var risky: [RiskyFinding] = []
        var inBlock: String?           // adatblokk (tartalma kihagyva)
        var blockLine = 0
        var connectionLine: Int?       // nyitott <connection> blokk
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
            if connectionLine != nil, line.hasPrefix("</") {
                if asciiLowercased(line) == "</connection>" {
                    connectionLine = nil
                } else {
                    issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid closing tag")))
                }
                continue
            }
            if matches(line, "^<[A-Za-z0-9-]+>$") {
                let name = asciiLowercased(String(line.dropFirst().dropLast()))
                if name == "connection", connectionLine == nil {
                    connectionLine = lineNo
                    continue
                }
                let permitted = connectionLine == nil ? Self.allowedBlocks : Self.connectionBlocks
                if !permitted.contains(name) {
                    issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Inline block not allowed: %@", name)))
                }
                inBlock = name
                blockLine = lineNo
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            let result = Self.checkLine(line, inConnection: connectionLine != nil)
            for m in result.messages { issues.append(ValidationIssue(line: lineNo, message: m)) }
            if let r = result.risky, result.messages.isEmpty {
                risky.append(RiskyFinding(directive: r.directive, line: lineNo, reasonKey: r.reasonKey))
            }
            if result.directive == "remote", result.messages.isEmpty { hasRemote = true }
        }
        if let block = inBlock {
            issues.append(ValidationIssue(line: blockLine, message: L10n.tr("Unclosed inline block: %@", block)))
        }
        if let line = connectionLine {
            issues.append(ValidationIssue(line: line, message: L10n.tr("Unclosed inline block: %@", "connection")))
        }
        if !hasRemote { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing remote directive"))) }
        let names = Set(risky.map(\.directive))
        let open = names.filter { !acknowledgedRisky.contains($0) || tier(of: $0) != .risky }.sorted()
        return OpenVPNValidation(issues: issues, risky: risky, unacknowledged: open)
    }

    private func tier(of d: String) -> OpenVPNTier { Self.tier(of: d) }

    /// Az első tokenből a direktíva neve: opcionális `--` előtag, utána `[a-z0-9]` kezdetű `[A-Za-z0-9-]` név
    /// (kisbetűsítve). nil: érvénytelen (pl. önálló `--`, `---x`).
    static func directiveName(_ token: String) -> String? {
        guard matches(token, "^(--)?[A-Za-z0-9][A-Za-z0-9-]*$") else { return nil }
        var name = asciiLowercased(token)
        if name.hasPrefix("--") { name.removeFirst(2) }
        return name
    }

    /// Egy (trimmelt, nem üres, nem komment) direktíva-sor ellenőrzése.
    static func checkLine(_ line: String, inConnection: Bool = false) -> OpenVPNLineResult {
        let first = String(line.prefix { $0 != " " && $0 != "\t" })
        guard Self.directiveName(first) != nil else { return OpenVPNLineResult(messages: [L10n.tr("Invalid directive")]) }
        guard let tokens = tokenize(line), let head = tokens.first, !head.quoted, head.text == first else {
            var directive = asciiLowercased(first)
            if directive.hasPrefix("--") { directive.removeFirst(2) }
            if tier(of: directive) == .forbidden {
                return OpenVPNLineResult(messages: [L10n.tr("Forbidden directive: %@", directive) + hint], directive: directive)
            }
            return OpenVPNLineResult(messages: [L10n.tr("Invalid argument: %@", directive)], directive: directive)
        }
        return checkDirective(tokens.map(\.text), inConnection: inConnection)
    }

    /// Az OpenVPN `parse_line` tükre: szóköz/tab határolja a tokeneket; `"` vagy `'` csak token elején kezd idézetet,
    /// és a záró idézőjel lezárja a tokent; token elején álló `#` vagy `;` a sor végéig komment. Backslash (az OpenVPN-ben
    /// escape) és lezáratlan idézőjel esetén `nil`: ezeket elutasítjuk.
    static func tokenize(_ line: String) -> [OpenVPNToken]? {
        var tokens: [OpenVPNToken] = []
        var current: [UInt8] = []
        var inToken = false
        var quote: UInt8?
        func finish(quoted: Bool) {
            tokens.append(OpenVPNToken(text: String(decoding: current, as: UTF8.self), quoted: quoted))
            current = []
            inToken = false
        }
        for byte in line.utf8 {
            if byte == 0x5C { return nil }
            if let q = quote {
                if byte == q {
                    quote = nil
                    finish(quoted: true)
                } else {
                    current.append(byte)
                }
                continue
            }
            if byte == 0x20 || byte == 0x09 {
                if inToken { finish(quoted: false) }
                continue
            }
            if !inToken {
                if byte == 0x23 || byte == 0x3B { break }
                if byte == 0x22 || byte == 0x27 {
                    quote = byte
                    continue
                }
                inToken = true
            }
            current.append(byte)
        }
        if quote != nil { return nil }
        if inToken { finish(quoted: false) }
        return tokens
    }

    /// Egy direktíva-sor (tokenekre bontva) ellenőrzése; a `setenv opt <direktíva> ...` is ezen megy át.
    static func checkDirective(_ tokens: [String], inConnection: Bool = false) -> OpenVPNLineResult {
        guard let directive = directiveName(tokens[0]) else { return OpenVPNLineResult(messages: [L10n.tr("Invalid directive")]) }
        func fail(_ message: String) -> OpenVPNLineResult { OpenVPNLineResult(messages: [message], directive: directive) }
        if directive == "setenv" {
            if inConnection { return fail(L10n.tr("Directive not allowed in a <connection> block: %@", directive)) }
            guard tokens.count >= 2 else { return fail(L10n.tr("setenv: missing argument")) }
            if asciiLowercased(tokens[1]) == "opt" {
                guard tokens.count >= 3 else { return fail(L10n.tr("setenv opt: missing directive")) }
                var inner = checkDirective(Array(tokens.dropFirst(2)))
                inner.directive = directive
                return inner
            }
            guard matches(tokens[1], setenvNamePattern) else { return fail(L10n.tr("setenv not allowed") + hint) }
            if isDeniedSetenvName(tokens[1]) { return fail(L10n.tr("setenv not allowed: %@", tokens[1]) + hint) }
            guard tokens.count <= 3 else { return fail(L10n.tr("Wrong number of arguments: %@", directive)) }
            if tokens.count == 3, !argumentMatches(tokens[2], .text) { return fail(L10n.tr("Invalid argument: %@", directive)) }
            return OpenVPNLineResult(directive: directive)
        }
        let args = Array(tokens.dropFirst())
        // `script-security 0|1`: nem futtat felhasználói scriptet, és a MacVPN parancssori `--script-security 2`-je a
        // config után áll, így felülírja: SAFE (de `<connection>` blokkban, mint az OpenVPN-ben, nem). A 2 és 3 (és
        // bármi más) FORBIDDEN marad.
        if directive == "script-security", args == ["0"] || args == ["1"] {
            if inConnection { return fail(L10n.tr("Directive not allowed in a <connection> block: %@", directive)) }
            return OpenVPNLineResult(directive: directive)
        }
        // A `connection` csak inline blokként (`<connection>…</connection>`) érvényes; az egysoros alak (fájlnév) nem.
        if directive == "connection" { return fail(L10n.tr("Invalid directive")) }
        switch tier(of: directive) {
        case .forbidden:
            return fail(L10n.tr("Forbidden directive: %@", directive) + hint)
        case .risky:
            if inConnection { return fail(L10n.tr("Directive not allowed in a <connection> block: %@", directive)) }
            guard args.count <= 16 else { return fail(L10n.tr("Wrong number of arguments: %@", directive)) }
            guard args.allSatisfy(isHarmlessArgument) else { return fail(L10n.tr("Invalid argument: %@", directive)) }
            var result = OpenVPNLineResult(directive: directive)
            result.risky = (directive, riskyReasons[directive] ?? reasonUnknown)
            return result
        case .safe:
            break
        }
        guard let spec = argumentSpecs[directive] else { return fail(L10n.tr("Invalid directive")) }
        if inConnection, !connectionAllowed.contains(directive) {
            return fail(L10n.tr("Directive not allowed in a <connection> block: %@", directive))
        }
        if fileReferencing.contains(directive), let a = args.first, a != "[inline]" {
            return fail(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        if directive == "http-proxy", args.count >= 3, !["auto", "auto-nct", "[inline]"].contains(args[2]) {
            return fail(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        if directive == "socks-proxy", args.count >= 3, args[2] != "[inline]" {
            return fail(L10n.tr("External file reference, use an inline block: %@", directive))
        }
        guard (spec.min...spec.max).contains(args.count) else {
            return fail(L10n.tr("Wrong number of arguments: %@", directive))
        }
        for (i, arg) in args.enumerated() {
            guard let rule = spec.rule(at: i), argumentMatches(arg, rule) else {
                return fail(L10n.tr("Invalid argument: %@", directive))
            }
        }
        return OpenVPNLineResult(directive: directive)
    }

    static func argumentMatches(_ arg: String, _ rule: ArgRule) -> Bool {
        switch rule {
        case .pattern(let p): return matches(arg, p)
        case .number(let range):
            guard matches(arg, "^[0-9]{1,10}$"), let n = Int(arg) else { return false }
            return range.contains(n)
        case .text: return !arg.isEmpty && !arg.utf8.contains(0x5C)
        }
    }
}

/// Allowlist alapú. Rootként a `mvpn-validate` futtatja.
///
/// Soronként: vezérlőkarakter -> hiba; a `#`-tól kezdődő komment levágva, trimmelve, üres kihagyva;
/// `[...]` fejléc: csak `[interface]`/`[peer]` (kisbetűsítve), különben "Ismeretlen szakasz";
/// egyéb sor `=` nélkül -> hiba; kulcs = az első `=` előtti rész, szóköz/tab trimmelve, kisbetűsítve,
/// egyezzen `^[A-Za-z]+$`-val (különben általános "Nem engedélyezett kulcs", a kulcs idézése nélkül); `forbiddenKeys` -> "Tiltott kulcs"; ami nincs a szakasz allowlistjében
/// (szakaszon kívül sincs) -> "Nem engedélyezett kulcs".
/// Az érték formátuma kulcsonként kötött (`isValidValue`), és semmilyen érték nem kezdődhet `-`-szal ("Érvénytelen érték: kulcs").
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
            let value = trimSpaceTab(String(line[line.index(after: eq)...]))
            if !Self.isValidValue(key: key, value: value) {
                issues.append(ValidationIssue(line: lineNo, message: L10n.tr("Invalid value: %@", key)))
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

    /// Kulcsonkénti értékformátum (a wg/wg-quick elfogadott formái közül a szokásosak).
    static func isValidValue(key: String, value: String) -> Bool {
        guard !value.isEmpty, !value.hasPrefix("-") else { return false }
        let list = value.split(separator: ",", omittingEmptySubsequences: false).map { trimSpaceTab(String($0)) }
        switch key {
        case "privatekey", "publickey", "presharedkey": return matches(value, "^[A-Za-z0-9+/]{43}=$")
        case "address", "allowedips": return list.allSatisfy(isCIDR)
        case "dns": return list.allSatisfy { isIP($0) || matches($0, "^[A-Za-z0-9_]([A-Za-z0-9_-]*)(\\.[A-Za-z0-9_-]+)*\\.?$") }
        case "mtu": return isNumber(value, in: 576...9000)
        case "listenport": return isNumber(value, in: 0...65535)
        case "persistentkeepalive": return value == "off" || isNumber(value, in: 0...65535)
        case "table": return value == "off" || value == "auto" || isNumber(value, in: 0...Int(UInt32.max))
        case "fwmark":
            if value == "off" { return true }
            if matches(value, "^0[xX][0-9A-Fa-f]{1,8}$") { return true }
            return isNumber(value, in: 0...Int(UInt32.max))
        case "endpoint": return isEndpoint(value)
        default: return false
        }
    }

    static func isNumber(_ s: String, in range: ClosedRange<Int>) -> Bool {
        guard matches(s, "^[0-9]{1,10}$"), let n = Int(s) else { return false }
        return range.contains(n)
    }

    static func isIP(_ s: String) -> Bool { SSTPValidator.isIPv4(s) || SSTPValidator.isIPv6(s) }

    /// IPv4 vagy IPv6 cím, opcionális `/prefix`-szel (0–32, illetve 0–128).
    static func isCIDR(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= 2 else { return false }
        let v4 = SSTPValidator.isIPv4(parts[0])
        guard v4 || SSTPValidator.isIPv6(parts[0]) else { return false }
        guard parts.count == 2 else { return true }
        return isNumber(parts[1], in: 0...(v4 ? 32 : 128)) && parts[1].utf8.count <= 3
    }

    /// `host:port` vagy `[ipv6]:port`, port 1–65535.
    static func isEndpoint(_ s: String) -> Bool {
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return false }
            let address = String(s[s.index(after: s.startIndex)..<close])
            let rest = String(s[s.index(after: close)...])
            guard rest.hasPrefix(":") else { return false }
            return SSTPValidator.isIPv6(address) && isNumber(String(rest.dropFirst()), in: 1...65535)
        }
        guard let colon = s.lastIndex(of: ":") else { return false }
        let host = String(s[..<colon])
        let port = String(s[s.index(after: colon)...])
        return matches(host, "^[A-Za-z0-9_][A-Za-z0-9_.-]*$") && isNumber(port, in: 1...65535)
    }
}

/// Rootként a `mvpn-validate` futtatja (validálás és `--swan-names`). Default-deny: szakaszonkénti kulcs-engedélyezőlista
/// a telepített `swanctl.conf(5)` alapján (connections, local/remote, children, secrets, pools, authorities).
///
/// Soronként: vezérlőkarakter -> hiba; bármilyen `\` (0x5C) -> "Nem engedélyezett karakter: \\";
/// páratlan számú `"` a sorban -> "Páratlan idézőjel (többsoros string nem engedélyezett)" (a sor többi része kimarad);
/// komment levágása idézőjel-tudatosan (`#` csak `"`-on kívül kezd kommentet, escape nincs); trimmelt üres sor kihagyva.
/// A maradék a strongSwan settings-szintaxis szerint: `név {` szakaszt nyit, `}` zár, `név = érték` kulcs (az érték a sor
/// végéig vagy a következő `}`-ig tart, `"…"` idézhető). Szakaszon és kulcson:
/// - `include` (kulcs- vagy szakasz-pozícióban) -> "Tiltott: include"; `updown`, `file`, `crl_uris`, `ocsp_uris` -> "Tiltott kulcs";
/// - a szakasz típusa nem enged ilyen alszakaszt/kulcsot -> "Nem engedélyezett szakasz/kulcs" (név csak ismert kulcsszónál);
/// - a `certs`, `cacerts`, `pubkeys`, `cacert` értéke csak sima fájlnév-lista lehet (nincs `/`, `..`, vezető `.`): a swanctl
///   ezeket a saját x509/pubkey könyvtárából olvassa; `file:` URI semmilyen értékben nem lehet;
/// - egy értékben önálló `=` vagy idézőjelen kívüli `{` -> "Érvénytelen sor" (kulcs-csempészés gyanúja).
/// Soronként legfeljebb egy üzenet. Fájl végén nyitott szakasz -> "Lezáratlan szakasz"; váratlan `}` -> hiba.
/// `connections` és benne `children` szakasz kötelező.
public struct StrongSwanValidator: ConfigValidator {
    /// Szakasz-típusok.
    enum Context: Equatable {
        case root, connections, conn, local, remote, certificate, children, child
        case secrets, sharedSecret, privateKeySecret, tokenSecret, pools, pool, authorities, authority
        /// Nem engedélyezett szakasz belseje: már hibás, csak a kapcsos zárójeleket és a tiltott neveket követjük.
        case rejected
    }

    static let connKeys: Set<String> = [
        "version", "local_addrs", "remote_addrs", "local_port", "remote_port", "proposals", "vips", "aggressive", "pull",
        "dscp", "encap", "mobike", "dpd_delay", "dpd_timeout", "fragmentation", "childless", "send_certreq", "send_cert",
        "ocsp", "ppk_id", "ppk_required", "keyingtries", "unique", "reauth_time", "rekey_time", "over_time", "rand_time",
        "pools", "if_id_in", "if_id_out", "mediation", "mediated_by", "mediation_peer",
    ]
    static let localKeys: Set<String> = ["round", "certs", "pubkeys", "auth", "id", "eap_id", "aaa_id", "xauth_id"]
    static let remoteKeys: Set<String> = [
        "round", "id", "eap_id", "groups", "cert_policy", "certs", "cacerts", "ca_id", "pubkeys", "revocation", "auth",
    ]
    static let certificateKeys: Set<String> = ["handle", "slot", "module"]
    static let childKeys: Set<String> = [
        "ah_proposals", "esp_proposals", "sha256_96", "local_ts", "remote_ts", "rekey_time", "life_time", "rand_time",
        "rekey_bytes", "life_bytes", "rand_bytes", "rekey_packets", "life_packets", "rand_packets", "hostaccess", "mode",
        "policies", "policies_fwd_out", "dpd_action", "ipcomp", "inactivity", "reqid", "priority", "interface", "mark_in",
        "mark_in_sa", "mark_out", "set_mark_in", "set_mark_out", "if_id_in", "if_id_out", "label", "label_mode",
        "tfc_padding", "replay_window", "per_cpu_sas", "hw_offload", "copy_df", "copy_ecn", "copy_dscp", "icmp",
        "start_action", "close_action",
    ]
    static let tokenKeys: Set<String> = ["handle", "slot", "module", "pin"]
    static let poolKeys: Set<String> = [
        "addrs", "dns", "nbns", "dhcp", "netmask", "server", "subnet", "split_include", "split_exclude",
    ]
    static let authorityKeys: Set<String> = ["cacert", "handle", "slot", "module", "cert_uri_base"]
    /// Root által megnyitott fájlra hivatkozó kulcsok: csak fájlnév (a swanctl saját könyvtáraihoz képest).
    static let fileNameKeys: Set<String> = ["certs", "cacerts", "pubkeys", "cacert"]
    /// Tiltott kulcsok (bármely szakaszban; szakasznévként is): parancsfuttatás, tetszőleges fájl, hálózati URI.
    static let forbiddenKeys: Set<String> = ["updown", "file", "crl_uris", "ocsp_uris"]
    static let sectionKeywords: Set<String> = ["connections", "children", "secrets", "pools", "authorities", "local", "remote"]
    /// Az üzenetben idézhető nevek (csak ismert kulcsszavak, a config szabad szövege soha).
    static let knownNames: Set<String> = connKeys.union(localKeys).union(remoteKeys).union(certificateKeys).union(childKeys)
        .union(tokenKeys).union(poolKeys).union(authorityKeys).union(sectionKeywords).union(["secret", "id"])
    static let namePattern = "^[A-Za-z0-9_.-]+$"

    public init() {}

    static func subsection(_ name: String, in context: Context) -> Context? {
        switch context {
        case .root:
            switch name {
            case "connections": return .connections
            case "secrets": return .secrets
            case "pools": return .pools
            case "authorities": return .authorities
            default: return nil
            }
        case .connections: return .conn
        case .conn:
            if name == "children" { return .children }
            if name.hasPrefix("local") { return .local }
            if name.hasPrefix("remote") { return .remote }
            return nil
        case .local: return name.hasPrefix("cert") ? .certificate : nil
        case .remote: return name.hasPrefix("cert") || name.hasPrefix("cacert") ? .certificate : nil
        case .children: return .child
        case .secrets:
            for p in ["eap", "xauth", "ntlm", "ike", "ppk"] where name.hasPrefix(p) { return .sharedSecret }
            for p in ["private", "rsa", "ecdsa", "pkcs8", "pkcs12"] where name.hasPrefix(p) { return .privateKeySecret }
            return name.hasPrefix("token") ? .tokenSecret : nil
        case .pools: return .pool
        case .authorities: return .authority
        case .certificate, .child, .sharedSecret, .privateKeySecret, .tokenSecret, .pool, .authority, .rejected: return nil
        }
    }

    static func allows(key: String, in context: Context) -> Bool {
        switch context {
        case .conn: return connKeys.contains(key)
        case .local: return localKeys.contains(key)
        case .remote: return remoteKeys.contains(key)
        case .certificate: return certificateKeys.contains(key)
        case .child: return childKeys.contains(key)
        case .sharedSecret: return key == "secret" || key.hasPrefix("id")
        case .privateKeySecret: return key == "secret"
        case .tokenSecret: return tokenKeys.contains(key)
        case .pool: return poolKeys.contains(key) || matches(key, "^[0-9]{1,5}$")
        case .authority: return authorityKeys.contains(key)
        case .root, .connections, .children, .secrets, .pools, .authorities, .rejected: return false
        }
    }

    public func validate(_ text: String) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        var stack: [(context: Context, line: Int)] = []
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
            var scanner = LineScanner(bytes: Array(line.utf8), line: lineNo)
            scanner.run(stack: &stack, hasConnections: &hasConnections, hasChildren: &hasChildren)
            if let message = scanner.error { issues.append(ValidationIssue(line: lineNo, message: message)) }
        }
        for open in stack.reversed() {
            issues.append(ValidationIssue(line: open.line, message: L10n.tr("Unclosed section")))
        }
        if !hasConnections { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing connections block"))) }
        if !hasChildren { issues.append(ValidationIssue(line: 0, message: L10n.tr("Missing children block"))) }
        return issues
    }

    /// Egy (komment nélküli, páros idézőjelű, backslash nélküli) sor bájtszintű feldolgozása; az első hiba marad meg.
    struct LineScanner {
        let bytes: [UInt8]
        let line: Int
        var i = 0
        var error: String?

        init(bytes: [UInt8], line: Int) {
            self.bytes = bytes
            self.line = line
        }

        mutating func fail(_ message: String) { if error == nil { error = message } }
        var current: UInt8? { i < bytes.count ? bytes[i] : nil }
        mutating func skipSpace() { while let c = current, c == 0x20 || c == 0x09 { i += 1 } }
        static func isDelimiter(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x7B || c == 0x7D || c == 0x3D || c == 0x22 }

        mutating func run(stack: inout [(context: Context, line: Int)], hasConnections: inout Bool, hasChildren: inout Bool) {
            while true {
                skipSpace()
                guard let c = current else { return }
                if c == 0x7D {   // }
                    i += 1
                    if stack.popLast() == nil { fail(L10n.tr("Unexpected closing brace")) }
                    continue
                }
                let start = i
                while let c = current, !Self.isDelimiter(c) { i += 1 }
                let name = String(decoding: bytes[start..<i], as: UTF8.self)
                let lower = asciiLowercased(name)
                skipSpace()
                let context = stack.last?.context ?? .root
                let forbiddenMessage: String? = lower == "include" ? L10n.tr("Forbidden: include")
                    : StrongSwanValidator.forbiddenKeys.contains(lower) ? L10n.tr("Forbidden key: %@", lower) : nil
                guard !name.isEmpty, matches(name, StrongSwanValidator.namePattern), let next = current, next == 0x7B || next == 0x3D else {
                    fail(forbiddenMessage ?? L10n.tr("Invalid line"))
                    recover(stack: &stack)
                    return
                }
                i += 1
                if next == 0x7B {   // {
                    var sub: Context = .rejected
                    if let m = forbiddenMessage {
                        fail(m)
                    } else if let s = StrongSwanValidator.subsection(name, in: context) {
                        sub = s
                        if s == .connections { hasConnections = true }
                        if s == .children { hasChildren = true }
                    } else if context != .rejected {
                        fail(StrongSwanValidator.knownNames.contains(name)
                             ? L10n.tr("Section not allowed: %@", name) : L10n.tr("Section not allowed"))
                    }
                    stack.append((sub, line))
                    continue
                }
                // name = value
                var keyOK = false
                if let m = forbiddenMessage {
                    fail(m)
                } else if context != .rejected {
                    if StrongSwanValidator.allows(key: name, in: context) {
                        keyOK = true
                    } else {
                        fail(StrongSwanValidator.knownNames.contains(name)
                             ? L10n.tr("Key not allowed: %@", name) : L10n.tr("Key not allowed"))
                    }
                }
                guard let items = readValue() else {
                    fail(L10n.tr("Invalid line"))
                    recover(stack: &stack)
                    return
                }
                if items.contains(where: { asciiLowercased($0).contains("file:") }) {
                    fail(L10n.tr("Forbidden: file: URI"))
                } else if keyOK, StrongSwanValidator.fileNameKeys.contains(name) {
                    let names = items.joined(separator: " ").split(separator: ",", omittingEmptySubsequences: false)
                        .map { trimSpaceTab(String($0)) }
                    if !names.allSatisfy({ matches($0, "^[A-Za-z0-9_+@][A-Za-z0-9_.+@-]*$") && !$0.contains("..") }) {
                        fail(L10n.tr("Only a file name is allowed, no path: %@", name))
                    }
                }
            }
        }

        /// Érték az `=` után, a sor végéig vagy a következő (idézőjelen kívüli) `}`-ig. `nil`: önálló `=` vagy
        /// idézőjelen kívüli `{` az értékben (gyanús, ezért hiba).
        mutating func readValue() -> [String]? {
            var items: [String] = []
            while true {
                skipSpace()
                guard let c = current, c != 0x7D else { return items }
                if c == 0x22 {
                    i += 1
                    let start = i
                    while let q = current, q != 0x22 { i += 1 }
                    items.append(String(decoding: bytes[start..<i], as: UTF8.self))
                    i += 1
                    continue
                }
                let start = i
                while let q = current, q != 0x20, q != 0x09, q != 0x7D, q != 0x22 { i += 1 }
                let word = String(decoding: bytes[start..<i], as: UTF8.self)
                if word == "=" || word.hasPrefix("=") || word.contains("{") { return nil }
                items.append(word)
            }
        }

        /// Hiba után a sor maradékában csak a kapcsos zárójeleket követjük (idézőjelen kívül), hogy a szerkezet ne csússzon el.
        mutating func recover(stack: inout [(context: Context, line: Int)]) {
            var inQuote = false
            while let c = current {
                i += 1
                if c == 0x22 { inQuote.toggle() }
                if inQuote { continue }
                if c == 0x7B { stack.append((.rejected, line)) }
                if c == 0x7D { _ = stack.popLast() }
            }
        }
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
}
